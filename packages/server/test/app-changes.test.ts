// 0.15's change path for the app's own rows, as the API drives it (docs/design/0.15-plan.md, "As built: PR 4b"):
// each write that makes or ends a credential is a change of 0.15's log, prepared by the vault before the app's
// transaction and committed in it, beside the row, and answers once sealed (R51). The vault's tests hold `prepare`
// and `app_change` themselves (packages/vault/test/app-changes.test.ts); these, the app's wiring. 0.15's log is on
// here whatever COFFRE_TEST_LOG says.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import type { CoffreClient } from '@coffre/client';
import { issuedGrant, sealedSessionScope, storedScope } from '@coffre/core/access';
import { defineSignin, github, type BindingPolicy } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { and, asc, eq, inArray } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { auditLog, credentials, logChanges } from './db/tables.ts';
import { clientFor, contextFor, credentialsLogged, holdSomething, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const SERVICE = 'ci';
const IP = '203.0.113.7';
const SIGNIN = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })] });

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let signin: SigninService;
let root: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, undefined, {}, { log: '0.15', sealThrough: sealedNow }) });
  signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
  root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.members.add(`token:${SERVICE}`);
  await holdSomething(db.owner, deps.vault, `token:${SERVICE}`, `user:${ROOT}`);
});

const meta = () => ({ requestId: randomUUID(), sourceIp: IP, label: 'Firefox' });

/** Each credential's changes in 0.15's log, op by op, by the id its payload names. */
async function opsByCredential(): Promise<Map<string, string[]>> {
  const ops = new Map<string, string[]>();
  for (const { payload } of await db.owner.select({ payload: logChanges.payload }).from(logChanges).orderBy(asc(logChanges.number))) {
    const { op, ref } = JSON.parse(payload) as { op: string; ref?: { kind: string; id: string } };
    if (ref?.kind === 'credential') ops.set(ref.id, [...(ops.get(ref.id) ?? []), op]);
  }
  return ops;
}

test('each way the API makes or ends a credential is a change of 0.15\'s log, beside its row', async () => {
  const browser = await signin.completeSignin({ provider: 'github', subject: 'dev', emails: [DEV], name: null }, meta());
  assert.ok(browser.ok);
  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: IP });
  await signin.decideDevice(await contextFor(deps, DEV), started.userCode, true);
  const cli = await signin.pollDevice(started.deviceCode, meta());
  assert.equal(cli.status, 'approved');
  const token = await root.tokens.issue(`token:${SERVICE}`, { label: 'ci', expiresInDays: 30 });
  const revoked = await root.tokens.issue(`token:${SERVICE}`, { label: 'old', expiresInDays: 30 });
  await root.tokens.revoke(`token:${SERVICE}`, revoked.id);
  let ops = await opsByCredential();
  assert.deepEqual(ops.get(browser.credential.id), ['credential.issue']);
  assert.deepEqual(ops.get(cli.status === 'approved' ? cli.credential.id : ''), ['credential.issue']);
  assert.deepEqual(ops.get(token.id), ['credential.issue']);
  assert.deepEqual(ops.get(revoked.id), ['credential.issue', 'credential.revoke']);
  // Signed out; then the member removed, which ends every way in they still had: each end is a change of its own.
  await signin.signOut(browser.credential.token, meta());
  await root.members.remove(`token:${SERVICE}`);
  ops = await opsByCredential();
  assert.deepEqual(ops.get(browser.credential.id), ['credential.issue', 'credential.revoke']);
  assert.deepEqual(ops.get(token.id), ['credential.issue', 'credential.revoke']);
  assert.deepEqual(ops.get(revoked.id), ['credential.issue', 'credential.revoke'], 'revoked already: removal ends it no more');
  await credentialsLogged(db.owner);
});

test('a sign-in account unlinked while another session of it is made reads its sessions again, and logs the end of each one it revokes', async (t) => {
  const account = { provider: 'github', subject: 'dev', emails: [DEV], name: null };
  const first = await signin.completeSignin(account, meta());
  assert.ok(first.ok);
  const asker = await contextFor(deps, DEV);
  const [identity] = await signin.listIdentities(asker);
  const prepare = deps.vault.prepare!;
  let raced: string | null = null;
  // Between the unlink's read of the account's sessions and its transaction, the account signs in again: the
  // transaction finds one session more than it prepared, so it reads them again, rather than revoke one with no change.
  t.mock.method(deps.vault as Required<Vault>, 'prepare', async (input: Parameters<typeof prepare>[0]) => {
    const prepared = await prepare(input);
    if (raced === null && input.changes.some((change) => change.kind === 'credential' && change.after.revoked)) {
      raced = '';
      const again = await signin.completeSignin(account, meta());
      assert.ok(again.ok);
      raced = again.credential.id;
    }
    return prepared;
  });
  await signin.unlinkIdentity(asker, identity!.id);
  assert.ok(raced !== null && raced !== '');
  const ops = await opsByCredential();
  for (const id of [first.credential.id, raced]) assert.deepEqual(ops.get(id), ['credential.issue', 'credential.revoke'], id);
  const sessions = await db.owner.select().from(credentials).where(eq(credentials.principal, `user:${DEV}`));
  assert.deepEqual(sessions.filter((row) => row.revokedAt === null), []);
  await credentialsLogged(db.owner);
});

test('a write answers once its change is sealed (R51): committed meanwhile, but not answered', async (t) => {
  const waitSealed = deps.vault.waitSealed!;
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  const asked: string[] = [];
  t.mock.method(deps.vault as Required<Vault>, 'waitSealed', async (input: { number: string }) => {
    asked.push(input.number);
    await held;
    return waitSealed(input);
  });
  let answered = false;
  // A browser sign-in, one of the app's writes through `prepare` (a token's issue is the vault's own, which waits for its seal itself).
  const issuing = signin.completeSignin({ provider: 'github', subject: 'dev', emails: [DEV], name: null }, meta()).then((issued) => ((answered = true), issued));
  for (let tries = 0; asked.length === 0; tries += 1) {
    assert.ok(tries < 500, 'the write asks for its seal');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  // Its row and entry committed, the call has not answered: it waits on its own entry's seal.
  const [newest] = await db.owner.select({ number: logChanges.number }).from(logChanges).orderBy(asc(logChanges.number));
  assert.ok(newest !== undefined);
  assert.equal(answered, false);
  release();
  const issued = await issuing;
  assert.ok(issued.ok);
  assert.deepEqual((await opsByCredential()).get(issued.credential.id), ['credential.issue']);
});

test('a workload session\'s sealed scope keeps the keys its binding lets it read: no wider than what 0.14 decides on', () => {
  const [project, prod, key] = [randomUUID(), randomUUID(), randomUUID()];
  // The binding reaches prod as a viewer, and reads one key there.
  const binding = { scope: storedScope([issuedGrant({ projectId: project, environmentId: prod, role: 'viewer' })]) };
  const policy = { reads: { [prod]: { keys: [key] } } } as unknown as BindingPolicy;
  const sealed = JSON.parse(sealedSessionScope(null, binding, policy)) as { environmentId: string | null; reads?: unknown }[];
  assert.deepEqual(sealed.find((grant) => grant.environmentId === prod)?.reads, [key]);
  // As stored without its reads, the grant on prod would reach every key there.
  assert.equal((JSON.parse(storedScope(JSON.parse(sealedSessionScope(null, binding, policy)))) as { reads?: unknown }[]).some((grant) => grant.reads !== undefined), false);
});

test("a revoke weighed on a policy that changes before the vault's statement is refused, 409, and revokes nothing (T149, RevokePolicyHeld)", async (t) => {
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'dev' });
  const token = await root.tokens.issue(`token:${SERVICE}`, { label: 'ci', expiresInDays: 30 });
  const revoke = deps.vault.revokeCredential!;
  // Between the app's check of who may and the vault's statement, an Owner protects an environment: the policy moves on.
  t.mock.method(deps.vault as Required<Vault>, 'revokeCredential', async (input: Parameters<typeof revoke>[0]) => {
    await root.environments.protect('market/dev');
    return revoke(input);
  }, { times: 1 });
  await assert.rejects(root.tokens.revoke(`token:${SERVICE}`, token.id), { status: 409, reason: 'policy_changed' });
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, token.id));
  assert.equal(row!.revokedAt, null, 'nothing revoked');
  // Asked again, it is weighed on the policy as it is now.
  await root.tokens.revoke(`token:${SERVICE}`, token.id);
  assert.deepEqual((await opsByCredential()).get(token.id), ['credential.issue', 'credential.revoke']);
});

test("a credential 0.14 made, which the log never held, is revoked and signed out as 0.14 does, with 0.14's entry: the vault revokes only the log's (T149)", async () => {
  const issued = await root.tokens.issue(`token:${SERVICE}`, { label: 'ci', expiresInDays: 30 });
  const session = await signin.completeSignin({ provider: 'github', subject: 'dev', emails: [DEV], name: null }, meta());
  assert.ok(session.ok);
  // As 0.14 left them: no seal, no change.
  await db.owner.update(credentials).set({ seal: null }).where(inArray(credentials.id, [issued.id, session.credential.id]));
  await db.owner.delete(logChanges);
  await root.tokens.revoke(`token:${SERVICE}`, issued.id);
  await signin.signOut(session.credential.token, meta());
  const ended = await db.owner.select({ id: credentials.id, revokedAt: credentials.revokedAt }).from(credentials).where(inArray(credentials.id, [issued.id, session.credential.id]));
  assert.ok(ended.every((row) => row.revokedAt !== null));
  const entries = await db.owner.select({ action: auditLog.action }).from(auditLog).where(and(inArray(auditLog.action, ['token.revoke', 'sign_out']), eq(auditLog.decision, 'allow')));
  assert.deepEqual(entries.map(({ action }) => action).sort(), ['sign_out', 'token.revoke']);
});
