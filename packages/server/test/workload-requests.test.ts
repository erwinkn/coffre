// A workload's session on the API, on the 0.16 contract (docs/design/0.16.md,
// "What the app reads of a workload, and decides nothing on"): its token
// sent as `Authorization: DPoP`, with a proof its key signed for the
// request. The app reads the session's row to find its service's gate and
// its key, holds the proof to the request, has the gate take it once, and
// only then asks the vault, which decides on its own rows. What the vault
// decides of a session is its own suite's (packages/vault/test/caller.test.ts);
// here, the app's part, what each refusal costs, and that an edited row
// opens nothing.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { amend, binding, emptyDatabase, environment, grant, instance, principal, project, role, rows, session, tokenOf, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processGates, type Gates } from '../src/gate.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const DEPLOY = 'token:deploy';
const API = 'token:api';

/** The deployment's gates, in process; `restart` loses them all, as a new process does. Each service whose gate was asked, in order. */
let held = processGates();
const asked: string[] = [];
const gates: Gates = (service) => {
  asked.push(service);
  return held(service);
};
const restart = () => void (held = processGates());

const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates });
const { world } = app;
after(() => app.close());

const market = project('market');
const prod = environment(market, 'prod');
const VIEWER = JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]);

/** A session: its service, its token, its key, and the row's id. */
type Held = { service: string; token: string; key: ProofKey; id: string };
let deploy: Held;
let api: Held;

async function signedIn(service: string, of: ReturnType<typeof binding>): Promise<[Held, ReturnType<typeof session>]> {
  const key = await generateProofKey();
  const token = generateToken('workload');
  const row = session(token, of, { jkt: await thumbprint(key.jwk), scope: VIEWER, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000) });
  return [{ service, token, key, id: row.id }, row];
}

/** `deploy` and `api` hold Developer on market; each has a binding of a workload's (a policy) and a session of it, reaching market as a Viewer. */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  restart();
  const deployBinding = binding(DEPLOY, { policy: '{}', scope: VIEWER });
  const apiBinding = binding(API, { policy: '{}', scope: VIEWER });
  const [deployHeld, deployRow] = await signedIn(DEPLOY, deployBinding);
  const [apiHeld, apiRow] = await signedIn(API, apiBinding);
  [deploy, api] = [deployHeld, apiHeld];
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.write']), role(false, 'viewer', ['secret.read'])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(DEPLOY), principal(API)),
    ...rows('grants', grant(DEPLOY, 'developer', { project: market }), grant(API, 'developer', { project: market })),
    ...rows('bindings', deployBinding, apiBinding),
    ...rows('credentials', deployRow, apiRow),
  );
  await app.request('/livez');
  // The first API call checks the schema, once.
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
  asked.length = 0;
});

type Answer = { status: number; body: { error?: string; reason?: string; message?: string; principal?: { type: string; id: string } }; headers: Headers };

const read = async (response: Response): Promise<Answer> => ({ status: response.status, body: (await response.json()) as Answer['body'], headers: response.headers });

/** The current nonce of `service`'s gate, as its last answer would carry it. */
const nonceOf = (service: string) => held(service).nonce();

/**
 * `GET /api/me` as `who`, through `through`: with a fresh proof of its key under its gate's current nonce, unless told
 * another nonce (null for none), key, proof (null for none) or scheme.
 */
async function me(who: Held, options: { nonce?: string | null; key?: ProofKey; proof?: string | null; scheme?: string; through?: typeof app } = {}): Promise<Answer> {
  const url = `${PUBLIC_URL}/api/me`;
  const nonce = options.nonce === null ? undefined : (options.nonce ?? (await nonceOf(who.service)));
  const proof = options.proof !== undefined ? options.proof : await createProof(options.key ?? who.key, { method: 'GET', url, token: who.token, ...(nonce === undefined ? {} : { nonce }) });
  const headers: Record<string, string> = { authorization: `${options.scheme ?? 'DPoP'} ${who.token}` };
  if (proof !== null) headers.dpop = proof;
  return read(await (options.through ?? app).request('/api/me', { headers }));
}

/** What a request cost: the vault's calls, the app's statements and the gates asked, by service. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number, string[]]> {
  const [calls, statements, gated] = [app.calls.length, app.statements, asked.length];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements, asked.slice(gated)];
}

const reasonOf = (answer: Answer) => [answer.status, answer.body.reason];

test("a session's request: one statement finds its gate and key, the gate takes its proof once, then one vault call; every answer carries the gate's nonce", async () => {
  // No nonce yet: the gate gives one, and nothing of the vault's is asked.
  const [first, firstCalls, firstStatements, firstGates] = await cost(() => me(deploy, { nonce: null }));
  assert.deepEqual(reasonOf(first), [401, 'use_dpop_nonce']);
  assert.match(first.headers.get('www-authenticate') ?? '', /use_dpop_nonce/);
  const nonce = first.headers.get('dpop-nonce');
  assert.equal(nonce, await nonceOf(DEPLOY));
  assert.deepEqual([firstCalls, firstStatements, firstGates], [[], 1, [DEPLOY]]);

  const [answer, calls, statements, gated] = await cost(() => me(deploy, { nonce: nonce! }));
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.deepEqual(answer.body.principal, { type: 'service', id: 'deploy' });
  assert.equal(answer.headers.get('dpop-nonce'), await nonceOf(DEPLOY));
  // The session's row, then /me's own statement; the vault once.
  assert.deepEqual([calls, statements, gated], [['caller'], 2, [DEPLOY]]);

  // A refusal of the vault's, past the gate, carries the nonce too.
  const missing = await read(await app.request('/api/no-such-path', { headers: { authorization: `DPoP ${deploy.token}`, dpop: await createProof(deploy.key, { method: 'GET', url: `${PUBLIC_URL}/api/no-such-path`, token: deploy.token, nonce: await nonceOf(DEPLOY) }) } }));
  assert.equal(missing.status, 404);
  assert.equal(missing.headers.get('dpop-nonce'), await nonceOf(DEPLOY));
});

test("a session's token is worthless without its key: as a bearer, with another key's proof, with a proof of another request, or with none; the vault is never asked", async () => {
  const thief = await generateProofKey();
  const [asBearer, bearerCalls, bearerStatements] = await cost(() => me(deploy, { scheme: 'Bearer' }));
  assert.deepEqual(reasonOf(asBearer), [401, 'workload']);
  assert.deepEqual([bearerCalls, bearerStatements], [[], 0]);
  const [otherKey, otherCalls, , otherGates] = await cost(() => me(deploy, { key: thief }));
  assert.deepEqual(reasonOf(otherKey), [401, 'jkt']);
  assert.match(otherKey.headers.get('www-authenticate') ?? '', /invalid_dpop_proof/);
  assert.equal(otherKey.headers.get('dpop-nonce'), null);
  assert.deepEqual([otherCalls, otherGates], [[], []]);
  // A proof of the holder's, captured, for another URL, method, token or none.
  const nonce = await nonceOf(DEPLOY);
  const url = `${PUBLIC_URL}/api/me`;
  for (const [proof, reason] of [
    [await createProof(deploy.key, { method: 'GET', url: `${PUBLIC_URL}/api/projects`, token: deploy.token, nonce }), 'htu'],
    [await createProof(deploy.key, { method: 'POST', url, token: deploy.token, nonce }), 'htm'],
    [await createProof(deploy.key, { method: 'GET', url, token: api.token, nonce }), 'ath'],
    [await createProof(deploy.key, { method: 'GET', url, nonce }), 'ath'],
    [await createProof(deploy.key, { method: 'GET', url, token: deploy.token, nonce, iat: Math.floor(Date.now() / 1000) - 600 }), 'iat'],
  ] as const) {
    const [answer, calls] = await cost(() => me(deploy, { proof }));
    assert.deepEqual(reasonOf(answer), [401, reason]);
    assert.deepEqual(calls, []);
  }
  // No proof, or one that does not parse: refused before anything is read.
  for (const [proof, reason] of [[null, 'dpop'], ['not.a.proof', 'malformed']] as const) {
    const [answer, calls, statements, gated] = await cost(() => me(deploy, { proof }));
    assert.deepEqual(reasonOf(answer), [401, reason]);
    assert.deepEqual([calls, statements, gated], [[], 0, []]);
  }
  // A token of another kind, or of no kind, sent as a session's: nothing is read.
  for (const token of [generateToken('service'), 'coffre_wl_short']) {
    const [answer, calls, statements] = await cost(() => me({ ...deploy, token }));
    assert.deepEqual([answer.status, answer.body.error, calls, statements], [401, 'unauthenticated', [], 0]);
  }
  // A token no session has: the vault's own words, with nothing asked of the gate or the vault.
  const [unknown, unknownCalls, , unknownGates] = await cost(() => me({ ...deploy, token: generateToken('workload') }));
  assert.deepEqual([unknown.status, unknown.body.error, unknown.body.message], [401, 'unauthenticated', 'that credential is unknown, expired or revoked']);
  assert.deepEqual([unknownCalls, unknownGates], [[], []]);
  assert.equal((await me(deploy)).status, 200);
});

test("each proof is taken once, under its gate's nonce: a replay is refused before the vault hears of it, and a gate made again asks for its new nonce", async () => {
  const proof = await createProof(deploy.key, { method: 'GET', url: `${PUBLIC_URL}/api/me`, token: deploy.token, nonce: await nonceOf(DEPLOY) });
  assert.equal((await me(deploy, { proof })).status, 200);
  const [replayed, calls] = await cost(() => me(deploy, { proof }));
  assert.deepEqual(reasonOf(replayed), [401, 'replayed']);
  assert.deepEqual(calls, []);
  // A proof made before a restart carries a nonce no gate holds now.
  const before = await createProof(deploy.key, { method: 'GET', url: `${PUBLIC_URL}/api/me`, token: deploy.token, nonce: await nonceOf(DEPLOY) });
  restart();
  const stale = await me(deploy, { proof: before });
  assert.deepEqual(reasonOf(stale), [401, 'use_dpop_nonce']);
  assert.equal(stale.headers.get('dpop-nonce'), await nonceOf(DEPLOY));
  assert.equal((await me(deploy)).status, 200);
});

test("each service has its own gate: a proof under another service's nonce is asked for its own gate's", async () => {
  const deployNonce = await nonceOf(DEPLOY);
  const [answer, calls, , gated] = await cost(() => me(api, { nonce: deployNonce }));
  assert.deepEqual(reasonOf(answer), [401, 'use_dpop_nonce']);
  assert.equal(answer.headers.get('dpop-nonce'), await nonceOf(API));
  assert.deepEqual([calls, gated], [[], [API]]);
  assert.equal((await me(api)).status, 200);
});

test("the row only routes: one edited behind the vault, to another key or another service, gets past the gate and no further", async () => {
  const thief = await generateProofKey();
  const edit = (set: ReturnType<typeof sql>, who: Held) => rowsOf(world.owner, sql`UPDATE credentials SET ${set} WHERE token_hash = ${tokenOf(who.token)} RETURNING id`);
  // The thief's key written into the row: the app takes the thief's proof, and the vault holds the session to its own.
  await edit(sql`jkt = ${await thumbprint(thief.jwk)}`, deploy);
  const [stolen, stolenCalls, , stolenGates] = await cost(() => me(deploy, { key: thief }));
  assert.equal(stolen.status, 401, JSON.stringify(stolen.body));
  assert.deepEqual([stolenCalls, stolenGates], [['caller'], [DEPLOY]]);
  // Another service written into the row: the proof goes to that service's gate, which takes its own nonce, and the vault says no.
  await edit(sql`principal = ${DEPLOY}`, api);
  const [moved, movedCalls, , movedGates] = await cost(() => me({ ...api, service: DEPLOY }));
  assert.equal(moved.status, 401, JSON.stringify(moved.body));
  assert.deepEqual([movedCalls, movedGates], [['caller'], [DEPLOY]]);
});

test("a session revoked, or its member removed, is the vault's to refuse: the app reads no more than its key and gate", async () => {
  await amend(world, 'credentials', sql`token_hash = ${tokenOf(deploy.token)}`, { revokedAt: new Date(Date.now() - 1000), revokedBy: DEPLOY });
  const [revoked, revokedCalls, revokedStatements] = await cost(() => me(deploy));
  assert.deepEqual([revoked.status, revoked.body.error], [401, 'unauthenticated']);
  assert.deepEqual([revokedCalls, revokedStatements], [['caller'], 1]);
  await amend(world, 'principals', sql`id = ${API}`, { status: 'removed' });
  const removed = await me(api);
  assert.deepEqual([removed.status, removed.body.error], [401, 'unauthenticated']);
});

test('a deployment that runs no gate takes no session, and one that takes no workloads knows none: nothing is read or asked', async () => {
  const gateless = await openApp({ auth, workloads: {} });
  const unbound = await openApp({ workloads: {}, gates });
  try {
    for (const through of [gateless, unbound]) await through.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
    for (const [through, status, reason] of [[gateless, 503, 'no_gate'], [unbound, 401, undefined]] as const) {
      const [calls, statements] = [through.calls.length, through.statements];
      const answer = await me(deploy, { through });
      assert.deepEqual(reasonOf(answer), [status, reason]);
      assert.deepEqual([through.calls.length - calls, through.statements - statements], [0, 0]);
    }
  } finally {
    await Promise.all([gateless.close(), unbound.close()]);
  }
});

/** `method path` as `who`, with a fresh proof under its gate's current nonce, through `through`. */
async function sent(who: Held, method: string, path: string, body?: unknown, through: typeof app = app): Promise<Answer> {
  const proof = await createProof(who.key, { method, url: `${PUBLIC_URL}${path}`, token: who.token, nonce: await nonceOf(who.service) });
  const headers: Record<string, string> = { authorization: `DPoP ${who.token}`, dpop: proof };
  if (body !== undefined) headers['content-type'] = 'application/json';
  return read(await through.request(path, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
}

test("a session the vault stops is answered as 0.14.7 answered it, at its caller, a use and a change alike, with the gate's nonce", async () => {
  const noReads = await openApp({ auth, workloads: { noReads: true }, gates });
  try {
    const of = sql`principal = ${DEPLOY}`;
    const stops: [string, () => Promise<unknown>, number, string, RegExp, typeof app][] = [
      ['pending', () => amend(world, 'bindings', of, { policy: '{"approve":true}' }), 401, 'unauthenticated', /waits for a manager/, app],
      ['source', () => amend(world, 'bindings', of, { policy: '{"sources":["198.51.100.0/24"]}' }), 401, 'unauthenticated', /^192\.0\.2\.7 is outside the binding's sources$/, app],
      ['frozen', () => amend(world, 'credentials', sql`token_hash = ${tokenOf(deploy.token)}`, { frozenAt: new Date() }), 403, 'forbidden', /^frozen: a manager stopped this use/, app],
      ['narrowed', () => amend(world, 'credentials', sql`token_hash = ${tokenOf(deploy.token)}`, { constraints: '{}' }), 403, 'forbidden', /narrowed session reaches only/, app],
      ['no_reads', () => amend(world, 'bindings', of, { policy: JSON.stringify({ reads: { 'market/prod': { keys: '*' } } }) }), 403, 'forbidden', /noReads/, noReads],
    ];
    for (const [reason, stop, status, error, message, through] of stops) {
      await amend(world, 'bindings', of, { policy: '{}' });
      await amend(world, 'credentials', sql`token_hash = ${tokenOf(deploy.token)}`, { frozenAt: null, constraints: null });
      await stop();
      for (const [method, path, body] of [['GET', '/api/me'], ['POST', '/api/reveals', { path: 'market/prod' }], ['PATCH', '/api/secrets/market/prod/KEY', { archived: true }]] as const) {
        const answer = await sent(deploy, method, path, body, through);
        assert.deepEqual([answer.status, answer.body.error, answer.body.reason], [status, error, reason], `${reason} at ${method} ${path}: ${JSON.stringify(answer.body)}`);
        assert.match(answer.body.message ?? '', message);
        assert.equal(answer.headers.get('dpop-nonce'), await nonceOf(DEPLOY));
      }
    }
  } finally {
    await noReads.close();
  }
});
