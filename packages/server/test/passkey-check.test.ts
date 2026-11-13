// What stands behind a person's credential (docs/design/passkeys.md, sections
// 6.1 and 6.2; formal/Factor.tla, FactorApp): every request
// of a person's holds its credential to a live passkey, or to none while they
// hold none, as the policy says; every issue holds what it would issue to the
// same under the log's head; and what a request issues names its passkey. No
// sign-in confirms a session with a touch yet, so a confirmed
// session here is a row written as the app writes one.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, CoffreError, type CoffreClient } from '@coffre/client';
import { defineSignin, github, type PasskeyPolicy } from '@coffre/core/identity';
import { eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { AuthRowTampered } from '../src/auth-rows.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { passkeyStands } from '../src/passkey-check.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, loggedEntries, openTestDatabase, resetDatabase, testDeps, usesLogged, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials, deviceLogins, passkeys } from '@coffre/db/schema';
import * as rows from './passkey-rows.ts';
import { touching } from './passkey-rows.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'ada@acme.example';
const BOB = 'bob@acme.example';
const meta = () => ({ requestId: randomUUID(), sourceIp: null, label: null });

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'dev' });
  await root.secrets.set('market/dev', { API_KEY: 'dev-key' });
  await root.members.add(`user:${ADA}`, { role: 'developer' });
  await root.members.add(`user:${BOB}`, { role: 'developer' });
});

/** The deployment under `policy`: its sign-in, and the API as a request with a bearer token sees it, through the front door. */
function deployment(policy: PasskeyPolicy) {
  const config = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })], passkeys: policy });
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: config });
  const runtime = {
    db: deps.db, vault: deps.vault, chainKey: deps.chainKey, previousChainKeys: [], signin, workloads: null, mcp: null,
    auth: { mode: 'signin', signin: config }, publicUrl: ORIGIN, verifier: signin, waitUntil,
    schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, plugins: [],
  } as unknown as CoffreRuntime;
  const bearer = (token: string): CoffreClient => createClient({
    url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }),
  });
  return { signin, bearer };
}

const addPasskey = (email: string) => rows.addPasskey(db.owner, deps.chainKey, email);
const removePasskey = (id: string) => rows.removePasskey(db.owner, deps.chainKey, id);
const confirmedSession = (passkeyId: string) => rows.confirmedSession(db.owner, deps.chainKey, ADA, passkeyId);

/** What a request answers, by its code: `ok`, or the API's error. */
async function answer(request: Promise<unknown>): Promise<string> {
  try {
    await request;
    return 'ok';
  } catch (error) {
    if (error instanceof CoffreError) return error.code;
    throw error;
  }
}

test('a session no passkey confirmed is taken while its person holds none, refused while they hold one, as the policy says', async () => {
  const optional = deployment('optional');
  const session = await optional.signin.completeSignin({ provider: 'github', subject: 'ada', emails: [ADA], name: null }, meta());
  assert.ok(session.ok);
  const token = session.credential.token;
  assert.equal(await answer(optional.bearer(token).me()), 'ok');

  const key = await addPasskey(ADA);
  // Every way a request reads its credential: `GET /api/me`'s (with the vault's rows), a page's, any other route's.
  assert.equal(await answer(optional.bearer(token).me()), 'passkey_required');
  assert.equal(await answer(optional.bearer(token).projects.list()), 'passkey_required');
  // Another person's passkey says nothing of Ada's sessions.
  await removePasskey(key);
  await addPasskey(BOB);
  assert.equal(await answer(optional.bearer(token).me()), 'ok', 'her only passkey removed: the provider alone stands behind her again');

  await addPasskey(ADA);
  assert.equal(await answer(deployment('off').bearer(token).me()), 'ok', 'under off, nothing is asked');
  assert.equal(await answer(deployment('required').bearer(token).me()), 'passkey_required');
  await db.owner.update(passkeys).set({ removedAt: new Date(), removedBy: `user:${ADA}` }).where(eq(passkeys.principal, `user:${ADA}`));
  assert.equal(await answer(deployment('required').bearer(token).me()), 'passkey_required', 'under required, a session needs a passkey whatever she holds');
});

test('a session a passkey confirmed is taken while that passkey is live, and only then', async () => {
  const key = await addPasskey(ADA);
  const token = await confirmedSession(key);
  for (const policy of ['optional', 'required'] as const) assert.equal(await answer(deployment(policy).bearer(token).me()), 'ok', policy);

  await removePasskey(key);
  await addPasskey(ADA);
  for (const policy of ['optional', 'required'] as const) {
    assert.equal(await answer(deployment(policy).bearer(token).projects.list()), 'passkey_required', `${policy}: another live passkey does not stand for the removed one`);
  }
  assert.equal(await answer(deployment('off').bearer(token).me()), 'ok');
});

test('a passkey that is not the credential\'s person\'s, or whose row was changed around the app, stands behind nothing', async () => {
  const bobs = await addPasskey(BOB);
  const borrowed = await confirmedSession(bobs);
  assert.equal(await answer(deployment('optional').bearer(borrowed).me()), 'passkey_required');

  const key = await addPasskey(ADA);
  const token = await confirmedSession(key);
  // Put back after its removal with no MAC of the app's: refused as any row that fails its MAC, not as a passkey's.
  await db.owner.update(passkeys).set({ authMac: randomBytes(32) }).where(eq(passkeys.id, key));
  assert.equal(await answer(deployment('optional').bearer(token).me()), 'unauthenticated');
});

// The passkey's MAC is the check's to verify, where its answer reads the row, never the read's.
test('a credential the check exempts never fails on a passkey it does not need: a service\'s token, any under off', async () => {
  const key = await rows.addPasskey(db.owner, deps.chainKey, ROOT);
  const { bearer } = deployment('optional');
  const session = await rows.confirmedSession(db.owner, deps.chainKey, ROOT, key);
  await clientFor(deps, ROOT).members.add('token:ci');
  await clientFor(deps, ROOT).access.set('token:ci', { 'market/dev': 'viewer' });
  const issued = await bearer(session).tokens.issue('token:ci', { label: 'ci', expiresInDays: 30 });
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, issued.id));
  assert.equal(row!.passkeyId, key, 'named, as everything the session issues');

  await db.owner.update(passkeys).set({ authMac: randomBytes(32) }).where(eq(passkeys.id, key));
  assert.equal(await answer(bearer(issued.token).me()), 'ok', 'a service holds no passkey: its token is never checked against one');
  assert.equal(await answer(deployment('off').bearer(session).me()), 'ok', 'under off, nothing is asked');
  assert.equal(await answer(bearer(session).me()), 'unauthenticated', 'a session it backs fails as its own row would');
});

test('the check reads the passkey\'s MAC only where its answer depends on the row, as an MCP connection\'s check uses it', () => {
  const holder = { principal: `user:${ADA}`, generation: 1, passkeyId: randomUUID() };
  const forged = {
    id: holder.passkeyId, principal: holder.principal, generation: 1, userHandle: randomBytes(16), credentialId: randomBytes(32), publicKey: randomBytes(77),
    algorithm: -7, removedAt: null, removedBy: null, synced: true, name: 'YubiKey 5C', createdBy: holder.principal, authMac: randomBytes(32),
  } as unknown as NonNullable<Parameters<typeof passkeyStands>[3]['passkey']>;
  const read = { passkey: forged, held: true };
  assert.equal(passkeyStands(deps.chainKey, 'off', holder, read), true);
  assert.equal(passkeyStands(deps.chainKey, 'optional', { ...holder, passkeyId: null }, { passkey: null, held: true }), false);
  for (const policy of ['optional', 'required'] as const) assert.throws(() => passkeyStands(deps.chainKey, policy, holder, read), AuthRowTampered, policy);
});

test('the provider alone signs in nobody who holds a live passkey, unless the policy is off', async () => {
  await addPasskey(ADA);
  const account = { provider: 'github', subject: 'ada', emails: [ADA], name: null };
  const entries = async () => (await loggedEntries(db.owner)).length;
  const logged = await entries();
  const refused = await deployment('optional').signin.completeSignin(account, meta());
  assert.deepEqual(refused, { ok: false, reason: 'passkey_required' });
  assert.equal((await db.owner.select().from(credentials).where(eq(credentials.principal, `user:${ADA}`))).length, 0, 'no session written');
  // Whoever answered passed the provider, not the factor: no entry (passkeys.md, section 11).
  assert.equal(await entries(), logged, 'no entry written');
  assert.ok((await deployment('off').signin.completeSignin(account, meta())).ok);
});

test('what a request issues names its passkey: a device approval, the CLI session it redeems, a personal token and a handle', async () => {
  const key = await addPasskey(ADA);
  const { signin, bearer } = deployment('optional');
  const approving = bearer(await confirmedSession(key));

  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await touching(key, (touch) => approving.deviceLogins.decide(started.userCode, true, touch));
  const [approval] = await db.owner.select().from(deviceLogins).where(eq(deviceLogins.userCode, started.userCode));
  assert.equal(approval!.passkeyId, key);

  const polled = await signin.pollDevice(started.deviceCode, meta());
  assert.equal(polled.status, 'approved');
  const cli = (polled as Extract<typeof polled, { status: 'approved' }>).credential;
  const [session] = await db.owner.select().from(credentials).where(eq(credentials.id, cli.id));
  assert.equal(session!.passkeyId, key);
  assert.deepEqual(session!.confirmedAt, approval!.decidedAt, "the approval's touch confirmed it, when it was decided");

  const terminal = bearer(cli.token);
  const personal = await terminal.tokens.issue(`user:${ADA}`, { label: 'script', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const handle = await terminal.handles.create({ label: 'run', expiresInMinutes: 60, paths: ['market/dev'] });
  for (const made of [personal, handle]) {
    const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, made.id));
    assert.equal(row!.passkeyId, key, row!.kind);
    assert.equal(row!.confirmedAt, null, `${row!.kind}: a copy never passes a fresh check`);
  }
  assert.equal(await answer(bearer(personal.token).me()), 'ok');

  await removePasskey(key);
  assert.equal(await answer(bearer(personal.token).me()), 'passkey_required', 'the token holds the passkey as the session did');
  assert.equal(await answer(terminal.tokens.issue(`user:${ADA}`, { label: 'again', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } })), 'passkey_required');
});

test('a device approval whose passkey no longer stands behind it by the poll redeems nothing', async () => {
  const { signin, bearer } = deployment('optional');
  // Its passkey removed between the approval and the poll.
  const key = await addPasskey(ADA);
  const first = await signin.startDevice({ clientLabel: null, sourceIp: null });
  const approving = bearer(await confirmedSession(key));
  await touching(key, (touch) => approving.deviceLogins.decide(first.userCode, true, touch));
  await removePasskey(key);
  assert.deepEqual(await signin.pollDevice(first.deviceCode, meta()), { status: 'denied' });

  // Approved with none behind it, and her first passkey added before the poll.
  const session = await signin.completeSignin({ provider: 'github', subject: 'ada', emails: [ADA], name: null }, meta());
  assert.ok(session.ok);
  const second = await signin.startDevice({ clientLabel: null, sourceIp: null });
  await bearer(session.credential.token).deviceLogins.decide(second.userCode, true);
  await addPasskey(ADA);
  assert.deepEqual(await signin.pollDevice(second.deviceCode, meta()), { status: 'denied' });
  const cli = await db.owner.select().from(credentials).where(eq(credentials.kind, 'cli'));
  assert.equal(cli.filter((row) => row.passkeyId === null).length, 0, 'no CLI session written past the rule');
});

test('a reveal by a credential the check refuses gets the same 401 whatever it names, and uses nothing', async () => {
  const { signin, bearer } = deployment('optional');
  const session = await signin.completeSignin({ provider: 'github', subject: 'ada', emails: [ADA], name: null }, meta());
  assert.ok(session.ok);
  const ada = bearer(session.credential.token);
  assert.equal(await answer(ada.secrets.reveal('market/dev', ['API_KEY'])), 'ok');
  const used = (await usesLogged(db.owner)).length;

  await addPasskey(ADA);
  const answers = await Promise.all([
    answer(ada.secrets.reveal('market/dev', ['API_KEY'])),
    answer(ada.secrets.reveal('market/dev', ['NEVER_MADE'])),
    answer(ada.secrets.reveal('market/nowhere', ['API_KEY'])),
    answer(ada.secrets.reveal('market/dev')),
  ]);
  assert.deepEqual(answers, ['passkey_required', 'passkey_required', 'passkey_required', 'passkey_required']);
  assert.equal((await usesLogged(db.owner)).length, used, 'no use logged');
});

test('a reveal by a credential whose passkey fails its MAC gets the 401 any request does, by one key or several, and uses nothing', async () => {
  const { bearer } = deployment('optional');
  const key = await addPasskey(ADA);
  // A personal token the confirmed session issues, which names its passkey, as the vault knows it (the session's row is
  // the test's own, written around the vault's log).
  const issued = await bearer(await confirmedSession(key)).tokens.issue(`user:${ADA}`, { label: 'script', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const ada = bearer(issued.token);
  assert.equal(await answer(ada.secrets.reveal('market/dev', ['API_KEY'])), 'ok');
  const used = (await usesLogged(db.owner)).length;

  // The check ahead of the vault's call fails inside the boundary that answers it, never a 500.
  await db.owner.update(passkeys).set({ authMac: randomBytes(32) }).where(eq(passkeys.id, key));
  assert.equal(await answer(ada.me()), 'unauthenticated');
  assert.deepEqual(await Promise.all([answer(ada.secrets.reveal('market/dev', ['API_KEY'])), answer(ada.secrets.reveal('market/dev'))]), ['unauthenticated', 'unauthenticated']);
  assert.equal((await usesLogged(db.owner)).length, used, 'no use logged');
});

test('a key write or a member\'s add by a credential the check refuses is refused before it writes, by the fast path and today\'s alike', async () => {
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${BOB}`, { role: 'admin' });
  // The vault's fast-path calls, counted, and the refusals it records.
  const served = { writes: 0, adds: 0 };
  let recorded = 0;
  const vault = deps.vault;
  deps = { ...deps, vault: new Proxy(vault, {
    get(target, key) {
      const value = Reflect.get(target, key, target) as unknown;
      if (typeof value !== 'function') return value;
      if (key === 'writeKeys') return async (...args: unknown[]) => { const answer = await (value as (...a: unknown[]) => Promise<{ served: boolean }>).apply(target, args); if (answer.served) served.writes++; return answer; };
      if (key === 'admitRead') return async (...args: unknown[]) => { const answer = await (value as (...a: unknown[]) => Promise<{ served: boolean }>).apply(target, args); if (answer.served) served.adds++; return answer; };
      if (key === 'recordRefusal') return async (...args: unknown[]) => { recorded++; return (value as (...a: unknown[]) => Promise<unknown>).apply(target, args); };
      return (value as (...a: unknown[]) => unknown).bind(target);
    },
  }) };
  const { signin, bearer } = deployment('optional');
  const sessions = await Promise.all([ADA, BOB].map((email) => signin.completeSignin({ provider: 'github', subject: email, emails: [email], name: null }, meta())));
  const [ada, bob] = sessions.map((session) => {
    assert.ok(session.ok);
    return bearer(session.credential.token);
  });
  // Taken while they hold no passkey; but a member's add takes one, which Bob, an Admin with none, is asked to add first
  // (a fresh check, passkeys.md, section 4.1): the fast path's read served it all the same, and its ticket expires unused.
  assert.equal(await answer(ada!.secrets.set('market/dev', { API_KEY: 'ada-1' })), 'ok');
  assert.equal(await answer(bob!.members.add('user:carol@acme.example', { role: 'developer' })), 'fresh_check_required');
  await root.members.add('user:carol@acme.example', { role: 'developer' });
  // Ada, a Developer, may not add a member, which the handler decides; but first the router asks her for a passkey she
  // does not hold (section 4.5): a prompt, which writes nothing and records no refusal of the vault's.
  assert.equal(await answer(ada!.members.add('user:erin@acme.example', { role: 'developer' })), 'fresh_check_required');
  // The fast paths are the log's (`admit-held.test.ts`).
  assert.deepEqual(served, { writes: 1, adds: 1 }, 'the fast path served each');
  assert.equal(recorded, 0, 'a prompt records no refusal');
  const keyNow = async () => {
    const { values, version } = await root.secrets.reveal('market/dev', ['API_KEY']);
    return { values, version };
  };
  const membersNow = async () => (await root.members.list()).members.map((m) => m.member).sort();
  const before = await keyNow();
  const members = await membersNow();
  assert.ok(members.includes('user:carol@acme.example'));

  await Promise.all([addPasskey(ADA), addPasskey(BOB)]);
  const answers = await Promise.all([
    // A key's value: the fast path's shape, which the vault serves, and the check then refuses.
    answer(ada!.secrets.set('market/dev', { API_KEY: 'ada-2' })),
    // A dry run: today's path, as ever.
    answer(ada!.secrets.dryRun('market/dev', { API_KEY: 'ada-3' })),
    // A member's add: the fast path's shape.
    answer(bob!.members.add('user:dan@acme.example', { role: 'developer' })),
    // An add the vault refuses on its read: the passkey's refusal comes first, as on today's path, and the vault's
    // refusal is not recorded (its ticket expires unused).
    answer(ada!.members.add('user:erin@acme.example', { role: 'developer' })),
  ]);
  assert.deepEqual(answers, ['passkey_required', 'passkey_required', 'passkey_required', 'passkey_required']);
  assert.equal(recorded, 0, 'no refusal recorded for a credential the check refuses');
  assert.deepEqual(served, { writes: 2, adds: 2 }, 'where it serves them, the vault served the refused write and add too');
  assert.deepEqual(await keyNow(), before, 'the key is as it was');
  assert.deepEqual(await membersNow(), members, 'nobody was added');
});
