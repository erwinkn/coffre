// A touch of its own for each act a window does not cover (docs/design/passkeys.md, sections 3.5 and 4.4):
// approving a terminal, connecting an MCP client and approving an MCP client's change. A session a
// passkey confirmed a moment ago approves none of them alone; the act refused without one answers `403
// touch_required`, which asks a touch for that act alone, decides nothing and writes no entry; the touch is checked
// against the person's live passkeys, and its replay mark moved once, in the act's transaction.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { SoftAuthenticator } from '@coffre/conformance/authenticator';
import { eq } from 'drizzle-orm';

import { FRESH_MS } from '../src/api/fresh-routes.ts';
import { clientFor } from './api-fixture.ts';
import { credentials, deviceLogins, mcpApprovals, mcpConnections } from '@coffre/db/schema';
import { browserFor, callRaw, CLAUDE_CODE, db, deps, DEV, entries, fromPage, ORIGIN, RESOURCE, route, runtime, useMcp } from './mcp-fixture.ts';
import { addPasskey, touchFor, type Touch } from './passkey-rows.ts';

const REDIRECT = 'http://localhost:51234/callback';

useMcp(async () => {
  const root = clientFor(deps, 'admin@acme.example');
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.secrets.set('market/prod', { API_KEY: 'value', OLD_KEY: 'old' });
  await root.access.set(`user:${DEV}`, { market: 'maintainer' });
});

type Refused = { error: string; reason?: string; touch?: { options: { challenge: string; rpId: string; allowCredentials: { id: string }[] }; state: string } };

/**
 * DEV's browser session, a passkey's: signed in with the provider before it was added, then stepped up with a touch
 * (section 6.5), as the browser holds it a moment after. Confirmed now, which approves none of the acts here alone.
 */
async function confirmedBrowser(): Promise<{ session: string; passkey: string }> {
  const before = await browserFor(DEV);
  const passkey = await addPasskey(db.owner, deps.chainKey, DEV);
  const step = (await runtime.signin!.stepUpStep(before, '/'))!;
  const stepped = await runtime.signin!.stepUp(step.state, before, await touchFor(passkey, step.options), { requestId: randomUUID(), sourceIp: null, label: 'Firefox' });
  assert.ok(stepped.ok);
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, stepped.credential.id));
  assert.ok(row!.confirmedAt !== null && row!.passkeyId === passkey, 'the step-up confirmed the session');
  return { session: stepped.credential.token, passkey };
}

function post(session: string, path: string, body: Record<string, unknown>) {
  return route(path, { method: 'POST', headers: fromPage(session, { 'content-type': 'application/json' }), body: JSON.stringify(body) });
}

async function refusal(response: Response): Promise<Refused> {
  assert.equal(response.status, 403, await response.clone().text());
  return (await response.json()) as Refused;
}

const consent = (scope = 'read') => ({
  client_id: CLAUDE_CODE, redirect_uri: REDIRECT, response_type: 'code', scope, resource: RESOURCE,
  code_challenge: createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url'), code_challenge_method: 'S256',
});

test('approving a terminal takes a touch for its code: a confirmed session alone approves nothing, and the terminal starts confirmed', async () => {
  const { session, passkey } = await confirmedBrowser();
  const signin = runtime.signin!;
  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: null });
  const other = await signin.startDevice({ clientLabel: 'laptop', sourceIp: null });
  const undecided = async (code: string) => (await db.owner.select().from(deviceLogins).where(eq(deviceLogins.userCode, code)))[0]!.decidedAt === null;
  const approved = (await entries('device.approve')).length;

  // Refused, with a touch to ask for this code: nothing decided, no entry, the person's live passkey offered.
  const asked = await refusal(await post(session, `/api/device-logins/${started.userCode}`, { approve: true }));
  assert.equal(asked.error, 'touch_required');
  assert.deepEqual(asked.touch!.options.allowCredentials.map((offered) => offered.id).length, 1);
  assert.ok(await undecided(started.userCode));
  assert.equal((await entries('device.approve')).length, approved, 'a prompt writes no entry');

  // A touch asked for another code approves this one no more: asked again, and both still undecided.
  const elsewhere = await refusal(await post(session, `/api/device-logins/${other.userCode}`, { approve: true }));
  const crossed: Touch = { state: elsewhere.touch!.state, response: await touchFor(passkey, elsewhere.touch!.options) };
  assert.equal((await refusal(await post(session, `/api/device-logins/${started.userCode}`, { approve: true, touch: crossed }))).error, 'touch_required');
  assert.ok((await undecided(started.userCode)) && (await undecided(other.userCode)));

  // Another member's live passkey, at their generation, its signature good for this challenge: not the person's, so
  // refused, logged, undecided. And a key coffre holds no row of: the same.
  const admins = await addPasskey(db.owner, deps.chainKey, 'admin@acme.example');
  const borrowed = await refusal(await post(session, `/api/device-logins/${started.userCode}`, { approve: true, touch: { state: asked.touch!.state, response: await touchFor(admins, asked.touch!.options, ORIGIN) } }));
  assert.equal(borrowed.error, 'touch_failed');
  const stranger = await SoftAuthenticator.create('ES256', { synced: true });
  const forged = await stranger.assert({ rpId: asked.touch!.options.rpId, origin: ORIGIN, challenge: new Uint8Array(Buffer.from(asked.touch!.options.challenge, 'base64url')) });
  assert.equal((await refusal(await post(session, `/api/device-logins/${started.userCode}`, { approve: true, touch: { state: asked.touch!.state, response: forged } }))).error, 'touch_failed');
  assert.deepEqual((await entries('passkey.check')).filter((entry) => entry.decision === 'deny').map((entry) => [entry.metadata.purpose, entry.metadata.reason]), [['device', 'unknown_credential'], ['device', 'unknown_credential']]);
  assert.ok(await undecided(started.userCode));

  // The touch for this code: approved, naming the passkey, and the CLI session it redeems confirmed when it was decided.
  const touch: Touch = { state: asked.touch!.state, response: await touchFor(passkey, asked.touch!.options) };
  assert.equal((await post(session, `/api/device-logins/${started.userCode}`, { approve: true, touch })).status, 200);
  const [row] = await db.owner.select().from(deviceLogins).where(eq(deviceLogins.userCode, started.userCode));
  assert.equal(row!.passkeyId, passkey);
  assert.equal((await entries('device.approve')).at(-1)!.metadata.passkeyId, passkey);
  assert.deepEqual((await entries('passkey.check')).filter((entry) => entry.decision === 'allow').map((entry) => entry.metadata.purpose), ['step-up', 'device']);
  const polled = await signin.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  assert.equal(polled.status, 'approved');
  const [cli] = await db.owner.select().from(credentials).where(eq(credentials.id, (polled as Extract<typeof polled, { status: 'approved' }>).credential.id));
  assert.equal(cli!.passkeyId, passkey);
  assert.deepEqual(cli!.confirmedAt, row!.decidedAt);

  // Denying takes no touch.
  assert.equal((await post(session, `/api/device-logins/${other.userCode}`, { approve: false })).status, 200);
});

test('connecting an app takes a touch of its own, for the scopes chosen, and one touch connects one', async () => {
  const { session, passkey } = await confirmedBrowser();
  const request = consent('read write');
  const connected = async () => (await db.owner.select().from(mcpConnections)).length;

  const asked = await refusal(await post(session, '/api/oauth/authorizations', { request, approve: true, scopes: ['read', 'write'] }));
  assert.equal(asked.error, 'touch_required');
  assert.equal(await connected(), 0);
  const touch: Touch = { state: asked.touch!.state, response: await touchFor(passkey, asked.touch!.options) };

  // Another choice of scopes than the touch was asked for is asked again.
  assert.equal((await refusal(await post(session, '/api/oauth/authorizations', { request, approve: true, scopes: ['read'], touch }))).error, 'touch_required');
  assert.equal(await connected(), 0);

  const made = await post(session, '/api/oauth/authorizations', { request, approve: true, scopes: ['read', 'write'], touch });
  assert.equal(made.status, 200, await made.clone().text());
  const [connection] = await db.owner.select().from(mcpConnections);
  assert.equal(connection!.passkeyId, passkey);

  // The same touch again, within its five minutes: its replay mark moved, so it connects nothing more.
  assert.equal((await refusal(await post(session, '/api/oauth/authorizations', { request, approve: true, scopes: ['read', 'write'], touch }))).error, 'touch_failed');
  assert.equal(await connected(), 1);
  assert.deepEqual((await entries('passkey.check')).filter((entry) => entry.decision === 'deny').map((entry) => [entry.metadata.purpose, entry.metadata.reason]), [['connect', 'replay']]);
});

/** DEV connects Claude Code from `session`, with a touch of `passkey`, or with none for a person who holds none: its access token. */
async function connectTouched(session: string, passkey: string | null, scopes = ['read', 'write']): Promise<string> {
  const verifier = randomBytes(32).toString('base64url');
  const request = { ...consent(scopes.join(' ')), code_challenge: createHash('sha256').update(verifier).digest('base64url') };
  let decided: Response;
  if (passkey === null) decided = await post(session, '/api/oauth/authorizations', { request, approve: true, scopes });
  else {
    const asked = await refusal(await post(session, '/api/oauth/authorizations', { request, approve: true, scopes }));
    decided = await post(session, '/api/oauth/authorizations', { request, approve: true, scopes, touch: { state: asked.touch!.state, response: await touchFor(passkey, asked.touch!.options) } });
  }
  const code = new URL(((await decided.json()) as { redirect: string }).redirect).searchParams.get('code')!;
  const tokens = await route('/api/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT, client_id: CLAUDE_CODE }).toString(),
  });
  return ((await tokens.json()) as { access_token: string }).access_token;
}

/** A change the client asks for, and its page as `session` opens it. */
async function asked(token: string, session: string, tool: string, args: Record<string, unknown>) {
  const call = await callRaw(token, tool, args);
  const id = (call.body.result!.structuredContent!.approval as { id: string }).id;
  const shown = ((await (await route(`/api/approvals/${id}`, { headers: fromPage(session) })).json()) as { approval: { digest: string; basis: string | null } }).approval;
  const status = async () => (await db.owner.select().from(mcpApprovals).where(eq(mcpApprovals.id, id)))[0]!.status;
  return { id, shown, status };
}

test("an MCP client's change takes a touch on its page, for that change as shown; refused, it stays pending", async () => {
  const { session, passkey } = await confirmedBrowser();
  const token = await connectTouched(session, passkey);
  const { id, shown, status } = await asked(token, session, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  const archived = async () => (await clientFor(deps, 'admin@acme.example').secrets.history('market/prod/OLD_KEY')).archived;

  const refused = await refusal(await post(session, `/api/approvals/${id}`, { approve: true, digest: shown.digest, basis: shown.basis }));
  assert.equal(refused.error, 'touch_required');
  assert.equal(await status(), 'pending');
  assert.equal(await archived(), false);

  const touch: Touch = { state: refused.touch!.state, response: await touchFor(passkey, refused.touch!.options) };
  const approved = await post(session, `/api/approvals/${id}`, { approve: true, digest: shown.digest, basis: shown.basis, touch });
  assert.equal(approved.status, 200, await approved.clone().text());
  assert.equal(await archived(), true);
  assert.equal((await entries('mcp.approve')).at(-1)!.metadata.passkeyId, passkey);
});

test('a touch approves the change as it was asked for: another typed value, or what it replaces read anew, is asked again', async () => {
  const { session, passkey } = await confirmedBrowser();
  const token = await connectTouched(session, passkey);
  const root = clientFor(deps, 'admin@acme.example');
  const value = async (key: string) => (await root.secrets.reveal(`market/prod/${key}`)).values[key];

  // Touched for the value A: the same touch sent with B is the touch of another change, so asked again and pending.
  // That binding is what holds an agent driving the page to the value the person touched for.
  const typed = await asked(token, session, 'request_secret_value', { secret: 'market/prod/API_KEY' });
  const prompt = await refusal(await post(session, `/api/approvals/${typed.id}`, { approve: true, digest: typed.shown.digest, basis: typed.shown.basis, value: 'A' }));
  const touch: Touch = { state: prompt.touch!.state, response: await touchFor(passkey, prompt.touch!.options) };
  assert.equal((await refusal(await post(session, `/api/approvals/${typed.id}`, { approve: true, digest: typed.shown.digest, basis: typed.shown.basis, value: 'B', touch }))).error, 'touch_required');
  assert.equal(await typed.status(), 'pending');
  assert.equal(await value('API_KEY'), 'value');
  // The same touch with A, as asked: approved, and A written.
  const approved = await post(session, `/api/approvals/${typed.id}`, { approve: true, digest: typed.shown.digest, basis: typed.shown.basis, value: 'A', touch });
  assert.equal(approved.status, 200, await approved.clone().text());
  assert.equal(await value('API_KEY'), 'A');

  // Touched for what OLD_KEY held when the page opened; a version set since, the page opened again: the held touch was
  // for replacing the old one, so it is asked again, and the approval stays pending.
  const replacing = await asked(token, session, 'request_secret_value', { secret: 'market/prod/OLD_KEY' });
  const first = await refusal(await post(session, `/api/approvals/${replacing.id}`, { approve: true, digest: replacing.shown.digest, basis: replacing.shown.basis, value: 'C' }));
  const held: Touch = { state: first.touch!.state, response: await touchFor(passkey, first.touch!.options) };
  await root.secrets.set('market/prod', { OLD_KEY: 'meanwhile' });
  const reopened = ((await (await route(`/api/approvals/${replacing.id}`, { headers: fromPage(session) })).json()) as { approval: { basis: string | null } }).approval;
  assert.notEqual(reopened.basis, replacing.shown.basis);
  assert.equal((await refusal(await post(session, `/api/approvals/${replacing.id}`, { approve: true, digest: replacing.shown.digest, basis: reopened.basis, value: 'C', touch: held }))).error, 'touch_required');
  assert.equal(await replacing.status(), 'pending');
  assert.equal(await value('OLD_KEY'), 'meanwhile');
});

test("a touch is its session's: another of the person's sessions sending it is asked again, and it still approves on its own", async () => {
  const signin = runtime.signin!;
  // DEV's second browser, signed in before the passkey and stepped up with it after: the same person, generation and
  // passkey as the first session, another credential.
  const before = await browserFor(DEV);
  const { session, passkey } = await confirmedBrowser();
  const step = (await signin.stepUpStep(before, '/'))!;
  const stepped = await signin.stepUp(step.state, before, await touchFor(passkey, step.options), { requestId: randomUUID(), sourceIp: null, label: 'Safari' });
  assert.ok(stepped.ok);
  const second = stepped.credential.token;

  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: null });
  const undecided = async () => (await db.owner.select().from(deviceLogins).where(eq(deviceLogins.userCode, started.userCode)))[0]!.decidedAt === null;
  const prompt = await refusal(await post(session, `/api/device-logins/${started.userCode}`, { approve: true }));
  const touch: Touch = { state: prompt.touch!.state, response: await touchFor(passkey, prompt.touch!.options) };
  assert.equal((await refusal(await post(second, `/api/device-logins/${started.userCode}`, { approve: true, touch }))).error, 'touch_required');
  assert.ok(await undecided());
  assert.equal((await post(session, `/api/device-logins/${started.userCode}`, { approve: true, touch })).status, 200);
  assert.equal(await undecided(), false);
});

test("an MCP client's change that takes a fresh check: the approval's own touch stands for it, the window long closed; with no passkey yet, the person adds one first and the approval waits", async (t) => {
  const root = clientFor(deps, 'admin@acme.example');
  await root.members.add(`user:${DEV}`, { role: 'admin' });
  await root.members.add('user:carol@acme.example');
  const held = async () => (await root.members.access('user:carol@acme.example')).grants.length;
  const grant = { member: 'user:carol@acme.example', changes: { market: 'viewer' } };

  // No passkey: connected with no touch, and a change that widens someone's reach asks her to add one, deciding nothing.
  const plain = await browserFor(DEV);
  const untouched = await asked(await connectTouched(plain, null, ['read', 'manage-access']), plain, 'set_access', grant);
  const add = await refusal(await post(plain, `/api/approvals/${untouched.id}`, { approve: true, digest: untouched.shown.digest, basis: untouched.shown.basis }));
  assert.deepEqual([add.error, add.reason], ['fresh_check_required', 'add_passkey']);
  assert.equal(await untouched.status(), 'pending');
  assert.equal(await held(), 0);

  // With one, ten minutes after the touch that confirmed her session: the approval's touch is for this change, now.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const { session, passkey } = await confirmedBrowser();
  t.mock.timers.tick(2 * FRESH_MS);
  const token = await connectTouched(session, passkey, ['read', 'manage-access']);
  // Time goes on between touches, as it does: a touch's challenge must come after the last one its replay mark took.
  t.mock.timers.tick(1);
  const change = await asked(token, session, 'set_access', grant);
  const prompt = await refusal(await post(session, `/api/approvals/${change.id}`, { approve: true, digest: change.shown.digest, basis: change.shown.basis }));
  assert.equal(prompt.error, 'touch_required');
  const approved = await post(session, `/api/approvals/${change.id}`, {
    approve: true, digest: change.shown.digest, basis: change.shown.basis, touch: { state: prompt.touch!.state, response: await touchFor(passkey, prompt.touch!.options) },
  });
  assert.equal(approved.status, 200, await approved.clone().text());
  assert.equal(((await approved.json()) as { status: string }).status, 'approved');
  assert.equal(await held(), 1);
  // The grant's entry names what confirmed it: the approval's touch, not the session's older one (section 11).
  const granted = (await entries('access.grant')).at(-1)!;
  assert.deepEqual([granted.metadata.confirmedBy, granted.metadata.confirmedAt], [passkey, new Date().toISOString()]);
});
