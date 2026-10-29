import test from 'node:test';
import assert from 'node:assert/strict';

import { workload, type Proof } from '../src/workload.ts';

const MINUTE = 60_000;

/**
 * Coffre as far as a session's renewal goes: each sign-in is a session that ends at `end(now)`, the
 * hard end of its proof, and each renewal pushes the expiry `extend` on, up to that end.
 */
function coffre(t: test.TestContext, { end, expiresIn, extend }: { end: number; expiresIn: number; extend: number }) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.parse('2026-10-29T12:00:00Z') });
  const calls = { signIn: 0, renew: 0 };
  const sessions = new Map<string, { notAfter: number; expiresAt: number }>();
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const headers = { 'content-type': 'application/json', 'dpop-nonce': 'nonce' };
    if (url.pathname === '/api/auth/workload') {
      const token = `session-${++calls.signIn}`;
      const notAfter = Date.now() + end;
      const expiresAt = Math.min(Date.now() + expiresIn, notAfter);
      sessions.set(token, { notAfter, expiresAt });
      return Response.json({ token, expiresAt: new Date(expiresAt).toISOString(), notAfter: new Date(notAfter).toISOString(), places: ['market/prod'] }, { headers });
    }
    if (url.pathname === '/api/auth/workload/renew') {
      calls.renew++;
      const token = new Headers(init?.headers).get('authorization')?.replace(/^DPoP /, '') ?? '';
      const held = sessions.get(token);
      if (held === undefined) return Response.json({ reason: 'unknown' }, { status: 401, headers });
      held.expiresAt = Math.min(Math.max(held.expiresAt, Date.now() + extend), held.notAfter);
      return Response.json({ expiresAt: new Date(held.expiresAt).toISOString() }, { headers });
    }
    return Response.json({}, { status: 404, headers });
  };
  return { calls, fetch };
}

/** A proof that is always fresh. */
const proof: Proof = { name: 'kubernetes', kind: 'oidc', prove: async () => ({ oidc: 'token' }) };

/** The client's I/O (signing, the fake's answers) run, a turn of the event loop at a time. */
async function settle(turns: number) {
  for (let turn = 0; turn < turns; turn++) await new Promise((resolve) => setImmediate(resolve));
}

/** Wait, on real I/O, for a call the client is making (a signature on the thread pool) to reach the fake. */
async function until(done: () => boolean) {
  for (let turn = 0; turn < 20_000 && !done(); turn++) await new Promise((resolve) => setImmediate(resolve));
}

/** Time moved on a second at a time, with the I/O the client waits on run between. */
async function pass(t: test.TestContext, ms: number) {
  for (let elapsed = 0; elapsed < ms; elapsed += 1000) {
    t.mock.timers.tick(1000);
    await settle(1);
  }
  await settle(50);
}

async function open(t: test.TestContext, server: ReturnType<typeof coffre>) {
  const session = await workload({ url: 'https://secrets.acme.example', service: 'api-prod', proof, fetch: server.fetch, sigterm: false, log: () => undefined });
  t.after(() => session.close().catch(() => undefined));
  return session;
}

test("a session that ends where its proof does is never renewed, and the next proof replaces it before that end", async (t) => {
  // A projected Kubernetes token: it lasts 10 minutes, and a session never outlives it.
  const server = coffre(t, { end: 10 * MINUTE, expiresIn: 60 * MINUTE, extend: 60 * MINUTE });
  await open(t, server);
  assert.deepEqual(server.calls, { signIn: 1, renew: 0 });
  await pass(t, 8 * MINUTE);
  assert.deepEqual(server.calls, { signIn: 1, renew: 0 });
  // At 90% of the proof's life (9 minutes) the new session is asked for, before the old one ends.
  await pass(t, 2 * MINUTE);
  await until(() => server.calls.signIn === 2);
  assert.equal(server.calls.signIn, 2);
  assert.equal(server.calls.renew, 0);
  await pass(t, 8 * MINUTE);
  assert.equal(server.calls.renew, 0);
});

test('a session with headroom is renewed at half-life, as before', async (t) => {
  // An AWS-shaped session: 60 minutes of proof, a session that expires in 10 and renews by 10.
  const server = coffre(t, { end: 60 * MINUTE, expiresIn: 10 * MINUTE, extend: 10 * MINUTE });
  await open(t, server);
  await pass(t, 5 * MINUTE + 1000);
  await until(() => server.calls.renew === 1);
  assert.equal(server.calls.renew, 1);
  // Its expiry is now 15 minutes out: the next half-life is 5 minutes on.
  await pass(t, 4 * MINUTE);
  assert.equal(server.calls.renew, 1);
  await pass(t, MINUTE + 2000);
  await until(() => server.calls.renew === 2);
  assert.equal(server.calls.renew, 2);
});

test('a renewal that brings the expiry to the hard end is the last for that session', async (t) => {
  // Headroom at sign-in (10 of 30 minutes), then one renewal reaches the end: no half-lives toward a wall.
  const server = coffre(t, { end: 30 * MINUTE, expiresIn: 10 * MINUTE, extend: 60 * MINUTE });
  await open(t, server);
  await pass(t, 5 * MINUTE + 1000);
  await until(() => server.calls.renew === 1);
  assert.equal(server.calls.renew, 1);
  await pass(t, 20 * MINUTE);
  assert.equal(server.calls.renew, 1);
  assert.equal(server.calls.signIn, 1);
  // The proof is made again at 90% of its life (27 minutes), before the session's end.
  await pass(t, 3 * MINUTE);
  await until(() => server.calls.signIn === 2);
  assert.equal(server.calls.signIn, 2);
});
