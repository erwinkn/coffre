// 0.15's cutover from 0.14 as a deploy meets it (docs/design/0.15-plan.md, PR 9): an instance kept by 0.14's log
// alone, written through the API, then a vault of 0.15's log on the same database and keys, and the app's half of the
// cutover (cutover.ts), which vouches under its key for what only that key says: each credential and binding 0.14
// accepts, and each place its chain deleted. The vault's half and its refusals are packages/vault/test/cutover.test.ts's.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import type { CoffreClient } from '@coffre/client';
import { deriveLogKey } from '@coffre/core/audit';
import { defineSignin, github, google, hashToken, signin } from '@coffre/core/identity';
import { newUseRequestId, type NamedUseOutcome, type UseOutcome } from '@coffre/core/vault';
import { appendEntries } from '@coffre/db/log';
import { asc, eq, like, sql, type SQL } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { runScheduled } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { CUTTING_OVER_NOW, cutoverReady, type CutoverKnown } from '../src/cutover.ts';
import { finishRotation, rotateStep } from '../src/key-rotation.ts';
import { resolvePath } from '../src/db/queries.ts';
import { createRuntime } from '../src/runtime.ts';
import { auditLog, credentials, environments, identities, logChanges, logFence, projects, secrets, vaultGrants, vaultMembers } from './db/tables.ts';
import { TEST_HOT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly, TEST_ENGINE, withLogUnlocked } from './db/engine.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, sealedNow, nothingHeld, testDeps, testVault, type FixtureDeps, type TestVault } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const PUBLIC_URL = 'https://secrets.acme.example';
const SIGNIN = defineSignin({ publicUrl: PUBLIC_URL, providers: [github({ clientId: 'a', clientSecret: 'b' })] });
const CI = 'token:ci';

let db: Awaited<ReturnType<typeof openTestDatabase>>;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

/** Under 0.14's log alone, as 0.14.5 keeps it: its vault, and the API over it. */
let old: { vault: TestVault; deps: FixtureDeps; root: CoffreClient };

beforeEach(async () => {
  await resetDatabase(db.owner);
  // Uses go in today's partition, at or past the floor of `at` (schema 0022), as a deployment's checkpointer keeps them.
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  if (TEST_ENGINE === 'postgres') {
    const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
    await db.owner.execute(sql`SELECT make_day(${day(Date.now() - 86_400_000)}::date), make_day(${day(Date.now())}::date), make_day(${day(Date.now() + 86_400_000)}::date)`);
  }
  const vault = testVault([ROOT], {}, undefined, {}, { log: '0.14' });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  deps.signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: SIGNIN });
  old = { vault, deps, root: clientFor(deps, ROOT) };
  await old.root.members.add(CI);
});

/** The deploy: a vault of 0.15's log on the same keys, not cut over, and the app over it, whose door cuts it over. */
function deploy(signin = SIGNIN, config: { bulkLimit?: { count: number; windowMinutes: number } } = {}) {
  const hotDatabase = TEST_ENGINE === 'postgres' ? TEST_HOT_DATABASE_URL : process.env.COFFRE_TEST_DATABASE_URL!;
  const vault = testVault([ROOT], { hotDatabase, ...config }, { kek: old.vault.kek }, {}, { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld, cutover: 'app' });
  // The same app, its key the same: a deploy changes neither.
  const deps = testDeps(db.runtime, [ROOT], { vault, chainKey: old.deps.chainKey });
  deps.signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: SIGNIN });
  const runtime = { db: deps.db, vault, chainKey: deps.chainKey, previousChainKeys: [], publicUrl: PUBLIC_URL, auth: { mode: 'signin' as const, signin }, cutover: { done: false } as CutoverKnown };
  return { vault, deps, root: clientFor(deps, ROOT), cutover: async () => (await cutoverReady(runtime))?.why ?? null, runtime };
}

let request = 0n;

/** A use of `secretId` by credential `credential`, through 0.15's use path. */
function use(vault: TestVault, credential: string, secretId: string): Promise<UseOutcome> {
  const at = Date.now();
  request += 1n;
  return vault.use!({ credential, secretId, place: null, purpose: 'run', requestId: ((randomBytes(6).readUIntBE(0, 6) * 1000) + Number(request % 1000n)).toString(), at, deadline: at + 3000 });
}

const codeOf = (outcome: UseOutcome) => (outcome.ok ? 'ok' : 'code' in outcome ? outcome.code : outcome.busy);

async function environmentOf(project: string, slug: string): Promise<string> {
  const [row] = await db.owner.select({ id: environments.id }).from(environments).innerJoin(projects, eq(projects.id, environments.projectId))
    .where(sql`${projects.slug} LIKE ${`${project}%`} AND ${environments.slug} LIKE ${`${slug}%`}`);
  assert.ok(row !== undefined, `${project}/${slug}`);
  return row.id;
}

async function keyIn(environmentId: string, key: string): Promise<string> {
  const [row] = await db.owner.select({ id: secrets.id }).from(secrets).where(sql`${secrets.environmentId} = ${environmentId} AND ${secrets.key} = ${key}`);
  assert.ok(row !== undefined, key);
  return row.id;
}

function objectKey(kind: string, id: string): string {
  const hex = createHash('sha256').update(`coffre.object.v1\0${kind}\0${id}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

async function opsOf(kind: string, id: string): Promise<string[]> {
  return (await db.owner.select({ payload: logChanges.payload }).from(logChanges).where(eq(logChanges.object, objectKey(kind, id))).orderBy(asc(logChanges.number)))
    .map(({ payload }) => (JSON.parse(payload) as { op: string }).op);
}

test("an instance kept by 0.14, cut over by the app's door: its token serves through 0.15's use; a deleted project's environments `dev~deleted` and their keys archived and refused, never stale; an archived key restored by its unarchive", async () => {
  await old.root.projects.create('market');
  for (const slug of ['dev', 'prod', 'qa']) await old.root.environments.create(`market/${slug}`);
  await old.root.secrets.set('market/dev', { A: 'one', B: 'two' });
  await old.root.access.set(CI, { 'market/dev': 'viewer' });
  // A key archived, an environment deleted alone, and a project deleted, its keys erased: as 0.14.5 leaves each.
  await old.root.secrets.set('market/dev', { B: null });
  await old.root.environments.update('market/qa', { archived: true });
  await old.root.environments.delete('market/qa');
  await old.root.projects.create('gone');
  await old.root.environments.create('gone/dev');
  await old.root.secrets.set('gone/dev', { G: 'gone' });
  await old.root.access.set(CI, { 'gone/dev': 'viewer' });
  const gone = await environmentOf('gone', 'dev');
  const goneKey = await keyIn(gone, 'G');
  await old.root.projects.update('gone', { archived: true });
  await old.root.projects.delete('gone');
  const token = await old.root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const [{ slug: goneSlug }] = await db.owner.select({ slug: projects.slug }).from(projects).where(like(projects.slug, 'gone~%'));
  const before = await resolvePath(db.owner, { project: goneSlug!, environment: 'dev' }, { tombstones: true });

  const now = deploy();
  assert.equal(await now.cutover(), null);
  const dev = await environmentOf('market', 'dev');
  const [a, b] = [await keyIn(dev, 'A'), await keyIn(dev, 'B')];
  assert.equal(codeOf(await use(now.vault, token.id, a)), 'ok');
  // The deleted project's environment: `dev~deleted`, sealed deleted; its key archived, no object, refused, never stale.
  const [goneRow] = await db.owner.select({ slug: environments.slug }).from(environments).where(eq(environments.id, gone));
  assert.equal(goneRow!.slug, 'dev~deleted');
  assert.deepEqual(await opsOf('environment', gone), ['genesis']);
  assert.deepEqual(await opsOf('secret', goneKey), []);
  const [goneSecret] = await db.owner.select({ archivedAt: secrets.archivedAt }).from(secrets).where(eq(secrets.id, goneKey));
  assert.ok(goneSecret!.archivedAt !== null);
  assert.ok(!['ok', 'stale', 'tampered'].includes(codeOf(await use(now.vault, token.id, goneKey))));
  // The old path names the deleted project's environment as it did, its slug now `dev~deleted` (resolvePath, T130).
  const after = await resolvePath(db.owner, { project: goneSlug!, environment: 'dev' }, { tombstones: true });
  assert.deepEqual([after?.project?.id, after?.environment?.id], [before?.project?.id, before?.environment?.id]);
  assert.equal(after?.environment?.id, gone);
  // The environment deleted alone: sealed deleted, as its tombstone says.
  const qa = await environmentOf('market', 'qa');
  assert.deepEqual(await opsOf('environment', qa), ['genesis']);
  // The archived key: its object and its delete (T144); its unarchive, through the API now, restores it, and it serves.
  assert.deepEqual(await opsOf('secret', b), ['genesis', 'secret.delete']);
  await now.root.secrets.update('market/dev/B', { archived: false });
  assert.deepEqual(await opsOf('secret', b), ['genesis', 'secret.delete', 'secret.write']);
  assert.equal(codeOf(await use(now.vault, token.id, b)), 'ok');
  // Done for the configuration's life: asked again, nothing.
  assert.equal(await now.cutover(), null);
});

/**
 * A role's name is a key of the roles' object, which the cutover seals as it is: a role named `issue` spells, in the
 * roles' change, what a token's issue record does. The audit pages know an issue by how its payload starts too, so
 * the roles' change is neither listed nor counted as one (T164, review r1 of W261).
 */
test("0.14's reads from before the cutover are listed beside 0.15's after it, on the whole log's page, each member's and each place's, newest first (T166, T175)", async () => {
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.secrets.set('market/dev', { A: 'one' });
  await old.root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await old.root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  // A read 0.14's log keeps, as its entry; then the deploy, and a read 0.15's keeps, as its use, sealed and listed.
  assert.equal((await old.root.secrets.reveal('market/dev/A')).values.A, 'one');
  const now = deploy();
  assert.equal(await now.cutover(), null);
  assert.equal(codeOf(await use(now.vault, token.id, await keyIn(await environmentOf('market', 'dev'), 'A'))), 'ok');
  await now.vault.listReads();
  const readsOf = async (query: { path?: string; actor?: string }) => (await now.root.audit.list({ ...query, sealed: '1', limit: 100 })).entries
    .filter((entry) => entry.action === 'secret.read' && entry.decision === 'allow' && entry.key === 'A').map((entry) => [entry.log, entry.version]);
  assert.deepEqual(await readsOf({}), [['0.15', 1], ['0.14', 1]]);
  // Each place's page lists both too (T175): 0.15's read is placed when listed, 0.14's entry where it always was.
  for (const path of ['market', 'market/dev', 'market/dev/A']) {
    assert.deepEqual(await readsOf({ path }), [['0.15', 1], ['0.14', 1]], path);
    assert.equal((await now.root.audit.list({ path, sealed: '1', limit: 1 })).readsOmitted, undefined, path);
  }
  assert.deepEqual(await readsOf({ actor: CI }), [['0.15', 1]]);
  assert.deepEqual(await readsOf({ actor: `user:${ROOT}` }), [['0.14', 1]]);
  // And a client older than 0.15, which pages 0.14's log alone: its history as it was.
  const old14 = (await now.root.audit.list({ limit: 100 })).entries.filter((entry) => entry.action === 'secret.read' && entry.key === 'A');
  assert.deepEqual(old14.map((entry) => entry.log), ['0.14']);
});

test("a custom role named `issue`, sealed by the cutover, is no token's issue on the audit pages: neither listed nor counted", async () => {
  await old.root.roles.set('issue', { name: 'Issue', description: '', permissions: ['secret.read', 'secret.use'], protected: ['secret.use'] });
  const now = deploy();
  assert.equal(await now.cutover(), null);
  const spelled = await db.owner.select({ actor: logChanges.actor }).from(logChanges).where(like(logChanges.payload, '%"issue":{%'));
  assert.ok(spelled.length > 0, "the roles' change spells it");
  const hidden = (await now.root.audit.list({ sealed: '1', hidden: '1', limit: 500 })).hidden ?? [];
  assert.equal(hidden.find(({ action }) => action === 'token.create'), undefined);
  const listed = (await now.root.audit.list({ sealed: '1', detail: '1', limit: 500 })).entries;
  assert.deepEqual(listed.filter((entry) => entry.log === '0.15').map((entry) => entry.action), []);
});

test('a token whose row 0.14 would not take is vouched for by nobody: edited around the app, given a hard end, or put back over its revoke; each unsealed, refused, never served', async () => {
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.secrets.set('market/dev', { A: 'one' });
  await old.root.access.set(CI, { 'market/dev': 'viewer' });
  const issue = async (label: string) => ({ ...(await old.root.tokens.issue(CI, { label, expiresInDays: 30 })), label });
  const [edited, revoked, standing] = [await issue('edited'), await issue('revoked'), await issue('standing')];
  // Its end moved around the app: its MAC no longer holds.
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 365 * 86_400_000) }).where(eq(credentials.id, edited.id));
  // A hard end given around the app, which no MAC of 0.14's covers and 0.14 reads only of a binding's (review r6).
  const ended = await issue('hard end');
  await db.owner.update(credentials).set({ notAfter: new Date(Date.now() + 86_400_000) }).where(eq(credentials.id, ended.id));
  // Revoked, then its row put back as it was, its MAC and all: 0.14's own check takes it, its revoke's entry says otherwise.
  const [kept] = await db.owner.select().from(credentials).where(eq(credentials.id, revoked.id));
  await old.root.tokens.revoke(CI, revoked.id);
  await db.owner.update(credentials).set({ revokedAt: null, revokedBy: null, authMac: kept!.authMac }).where(eq(credentials.id, revoked.id));

  const now = deploy();
  assert.equal(await now.cutover(), null);
  const a = await keyIn(await environmentOf('market', 'dev'), 'A');
  assert.equal(codeOf(await use(now.vault, standing.id, a)), 'ok');
  for (const token of [edited, revoked, ended]) {
    assert.deepEqual(await opsOf('credential', token.id), [], token.label);
    // No seal: not the vault's, refused as `tampered`, as every row planted around the app is.
    assert.equal(codeOf(await use(now.vault, token.id, a)), 'tampered', token.label);
  }
});

test("a session whose sign-in account 0.14 unlinked is vouched for by nobody, though a writer puts back its rows and the account's, MACs and all (review r1)", async () => {
  const DEV = 'dev@acme.example';
  await old.root.members.add(`user:${DEV}`);
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.secrets.set('market/dev', { A: 'one' });
  await old.root.access.set(`user:${DEV}`, { 'market/dev': 'viewer' });
  const signin = old.deps.signin!;
  const signed = await signin.completeSignin({ provider: 'github', subject: 'dev', emails: [DEV], name: null }, { requestId: randomUUID(), sourceIp: '203.0.113.7', label: 'Firefox' });
  assert.ok(signed.ok);
  const session = signed.credential.id;
  const [identity] = await signin.listIdentities(await contextFor(old.deps, DEV));
  const [keptSession] = await db.owner.select().from(credentials).where(eq(credentials.id, session));
  const [keptIdentity] = await db.owner.select().from(identities).where(eq(identities.id, identity!.id));
  // Unlinked: its sessions ended with it, one entry, `account.unlink`, naming the account, none naming the session.
  await signin.unlinkIdentity(await contextFor(old.deps, DEV), identity!.id);
  await db.owner.update(credentials).set({ revokedAt: null, revokedBy: null, authMac: keptSession!.authMac }).where(eq(credentials.id, session));
  await db.owner.update(identities).set({ revokedAt: null, revokedBy: null, authMac: keptIdentity!.authMac }).where(eq(identities.id, identity!.id));

  const now = deploy();
  assert.equal(await now.cutover(), null);
  assert.deepEqual(await opsOf('credential', session), []);
  const a = await keyIn(await environmentOf('market', 'dev'), 'A');
  assert.ok(!(await use(now.vault, session, a)).ok);
});

test("a browser session of a sign-in provider the deployment no longer configures is vouched for by nobody, as 0.14 takes it for none (review r6)", async () => {
  const DEV = 'dev@acme.example';
  await old.root.members.add(`user:${DEV}`);
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.secrets.set('market/dev', { A: 'one' });
  await old.root.access.set(`user:${DEV}`, { 'market/dev': 'viewer' });
  const signed = await old.deps.signin!.completeSignin({ provider: 'github', subject: 'dev', emails: [DEV], name: null }, { requestId: randomUUID(), sourceIp: '203.0.113.7', label: 'Firefox' });
  assert.ok(signed.ok);
  // Deployed signing in through Google alone: the session's GitHub account is no provider of its now.
  const now = deploy(defineSignin({ publicUrl: PUBLIC_URL, providers: [google({ clientId: 'a', clientSecret: 'b' })] }));
  assert.equal(await now.cutover(), null);
  assert.deepEqual(await opsOf('credential', signed.credential.id), []);
  assert.ok(!(await use(now.vault, signed.credential.id, await keyIn(await environmentOf('market', 'dev'), 'A'))).ok);
});

test("an APP_KEY rotated at the deploy that turns 0.15's log on: the rotation signs 0.14's sessions out first, logging nothing, then the door cuts over (review r3)", async () => {
  const DEV = 'dev@acme.example';
  await old.root.members.add(`user:${DEV}`);
  const signed = await old.deps.signin!.completeSignin({ provider: 'github', subject: 'dev', emails: [DEV], name: null }, { requestId: randomUUID(), sourceIp: '203.0.113.7', label: 'Firefox' });
  assert.ok(signed.ok);
  const now = deploy();
  const keys = { chainKey: randomBytes(32), previousChainKeys: [old.deps.chainKey] };
  // The door's order: the rotation to the new key, each step a transaction, then the cutover.
  let state = await rotateStep(db.runtime, keys, { vault: now.vault });
  while (state.kind === 'rotating') state = await rotateStep(db.runtime, keys, { vault: now.vault });
  assert.equal(state.kind, 'sealing');
  assert.equal((await finishRotation(db.runtime, keys, { vault: now.vault })).kind, 'settled');
  assert.deepEqual(await db.owner.select().from(logChanges), [], 'nothing of 0.15\'s before the cutover');
  assert.equal(await cutoverReady({ ...now.runtime, ...keys }), null);
  // Signed out by the rotation: its session is no credential 0.14 takes, and none is sealed.
  assert.deepEqual(await opsOf('credential', signed.credential.id), []);
});

test("a revoke checkpointed under 0.14, its entry edited and the token's row put back, refuses the cutover: damaged history is never taken for no revoke (review r4)", async () => {
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await old.root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const [kept] = await db.owner.select().from(credentials).where(eq(credentials.id, token.id));
  await old.root.tokens.revoke(CI, token.id);
  assert.ok((await old.vault.checkpoint()).ok);
  await withLogUnlocked(db.owner, (tx) => tx.update(auditLog).set({ metadata: '{}' }).where(eq(auditLog.action, 'token.revoke')));
  await db.owner.update(credentials).set({ revokedAt: null, revokedBy: null, authMac: kept!.authMac }).where(eq(credentials.id, token.id));
  const now = deploy();
  assert.match((await now.cutover()) ?? '', /does not verify|not the prefix|history is damaged/);
  assert.deepEqual(await db.owner.select().from(logChanges), []);
});

test("a deleted project renamed back around the app refuses the cutover: the door says so until it is put right, and nothing is sealed meanwhile", async () => {
  await old.root.projects.create('gone');
  await old.root.environments.create('gone/dev');
  await old.root.projects.update('gone', { archived: true });
  await old.root.projects.delete('gone');
  const [{ id, slug }] = await db.owner.select({ id: projects.id, slug: projects.slug }).from(projects).where(like(projects.slug, 'gone~%'));
  await db.owner.update(projects).set({ slug: 'gone' }).where(eq(projects.id, id));
  const now = deploy();
  const refused = await now.cutover();
  assert.match(refused ?? '', /not the tombstone its project.delete gave it/);
  assert.deepEqual(await db.owner.select().from(logChanges), []);
  await db.owner.update(projects).set({ slug }).where(eq(projects.id, id));
  // Held: until it lapses, the door answers from the refusal and tries nothing.
  assert.equal(await now.cutover(), refused);
  now.runtime.cutover.held!.until = 0;
  assert.equal(await now.cutover(), null);
});

test("the door tries a due cutover once at a time, and holds a failure as a refusal: the requests meanwhile answer from the hold and ask the vault nothing (review, Fable)", async () => {
  const now = deploy();
  const cutover = now.vault.cutover!.bind(now.vault);
  let asked = 0;
  let tries = 0;
  let failing = true;
  // The try waits until the other request has asked too, and has had its answer.
  let both: () => void = () => {};
  const asking = new Promise<void>((resolve) => (both = resolve));
  let probes = 0;
  now.vault.cutover = async (input) => {
    asked += 1;
    if (input === undefined) {
      const answer = await cutover(input);
      probes += 1;
      if (probes === 2) setImmediate(both);
      return answer;
    }
    tries += 1;
    if (!failing) return cutover(input);
    await asking;
    throw new Error('canceling statement due to lock timeout');
  };
  const failed = 'the cutover failed: canceling statement due to lock timeout';
  // Both ask whether it is due; one tries it, the other answers from the hold.
  assert.deepEqual(await Promise.all([now.cutover(), now.cutover()]), [failed, CUTTING_OVER_NOW]);
  assert.equal(tries, 1);
  const before = asked;
  // Held as failed, which the door says apart from a refusal (T170).
  assert.deepEqual(await cutoverReady(now.runtime), { why: failed, failed: true });
  assert.equal(asked, before);
  failing = false;
  now.runtime.cutover.held!.until = 0;
  assert.equal(await now.cutover(), null);
  assert.equal(await now.cutover(), null);
  assert.equal(tries, 2);
});

/**
 * An older request's answer, a refusal, come late: its probe's, or its try's,
 * held back until a second request has cut over. It never takes that back.
 */
async function lateRefusal(late: 'probe' | 'try') {
  const now = deploy();
  const cutover = now.vault.cutover!.bind(now.vault);
  let release: () => void = () => {};
  const released = new Promise<void>((resolve) => (release = resolve));
  let waiting = false;
  now.vault.cutover = async (input) => {
    if (!waiting && (late === 'probe' || input !== undefined)) {
      waiting = true;
      await released;
      return { ok: false, refused: 'refused', why: 'an answer from before the cutover' };
    }
    return cutover(input);
  };
  const older = now.cutover();
  while (!waiting) await new Promise((resolve) => setImmediate(resolve));
  // Its try outlived its hold: the second request tries, and cuts over.
  if (late === 'try') now.runtime.cutover.held!.until = 0;
  assert.equal(await now.cutover(), null);
  release();
  assert.equal(await older, null);
  assert.deepEqual(now.runtime.cutover, { done: true, held: undefined });
  assert.equal(await now.cutover(), null);
}

test("a probe's refusal, answered before a cutover another request made since, never takes it back (review r8)", () => lateRefusal('probe'));

test("a try that outlived its hold, refused, never takes back the cutover another request made since (review r8)", () => lateRefusal('try'));

test("a try that outlived its hold, refused while a newer try runs, leaves the newer one's hold as it is (review r8)", async () => {
  const now = deploy();
  const cutover = now.vault.cutover!.bind(now.vault);
  const gates: (() => void)[] = [];
  let tries = 0;
  // Each try waits for its gate; the older one then answers a refusal, the newer one cuts over.
  now.vault.cutover = async (input) => {
    if (input === undefined) return cutover(input);
    tries += 1;
    const older = tries === 1;
    await new Promise<void>((resolve) => gates.push(resolve));
    return older ? { ok: false, refused: 'refused', why: 'an answer from before the cutover' } : cutover(input);
  };
  const turn = () => new Promise((resolve) => setImmediate(resolve));
  const first = now.cutover();
  while (gates.length < 1) await turn();
  now.runtime.cutover.held!.until = 0;
  const second = now.cutover();
  while (gates.length < 2) await turn();
  const newer = now.runtime.cutover.held;
  gates[0]!();
  assert.equal(await first, 'an answer from before the cutover');
  assert.equal(now.runtime.cutover.held, newer);
  assert.equal(await now.cutover(), CUTTING_OVER_NOW);
  gates[1]!();
  assert.equal(await second, null);
  assert.equal(await now.cutover(), null);
});

test("a deployment with no cutover due answers its first requests at once, together: nothing holds them (review r8 of the hold)", async () => {
  const now = deploy();
  assert.equal(await now.cutover(), null);
  // Its runtime made again, the log cut over: two first requests at once, neither held.
  const runtime = { ...now.runtime, cutover: { done: false } as CutoverKnown };
  assert.deepEqual(await Promise.all([cutoverReady(runtime), cutoverReady(runtime)]), [null, null]);
});

/**
 * `work` with the refusal of 0.14's writes dropped, as the database's owner may drop it (migration 0047's trigger):
 * off, then on again, however `work` ends. SQLite has no switch: the trigger is dropped and made again.
 */
async function refusalDropped<T>(work: () => Promise<T>): Promise<T> {
  if (TEST_ENGINE === 'postgres') {
    await db.owner.execute(sql`ALTER TABLE audit_log DISABLE TRIGGER audit_log_refuse_old`);
    try {
      return await work();
    } finally {
      await db.owner.execute(sql`ALTER TABLE audit_log ENABLE TRIGGER audit_log_refuse_old`);
    }
  }
  const sqlite = db.owner as unknown as { all<Row>(query: SQL): Promise<Row[]>; run(query: SQL): Promise<unknown> };
  const [trigger] = await sqlite.all<{ sql: string }>(sql`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'audit_log_refuse_old'`);
  await sqlite.run(sql`DROP TRIGGER audit_log_refuse_old`);
  try {
    return await work();
  } finally {
    await sqlite.run(sql.raw(trigger!.sql));
  }
}

/** A member's row and grants as they stand: what a writer copies, to put back later. */
async function memberRows(principal: string) {
  return {
    member: (await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, principal)))[0]!,
    grants: await db.owner.select().from(vaultGrants).where(eq(vaultGrants.principal, principal)),
  };
}

async function putBack({ member, grants }: Awaited<ReturnType<typeof memberRows>>): Promise<void> {
  await db.owner.delete(vaultGrants).where(eq(vaultGrants.principal, member.principal));
  if (grants.length > 0) await db.owner.insert(vaultGrants).values(grants);
  await db.owner.update(vaultMembers).set(member).where(eq(vaultMembers.principal, member.principal));
}

test("0.14's writes refused once the cutover is there: an old isolate's write fails whole, its app's or its vault's, its reads and uses go on; 0.15's own write lands (OldWritesRefused, PR 9b)", async () => {
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.secrets.set('market/dev', { A: 'one' });
  await old.root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await old.root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const now = deploy();
  assert.equal(await now.cutover(), null);
  const a = await keyIn(await environmentOf('market', 'dev'), 'A');
  const entries = async () => (await db.owner.select({ seq: auditLog.seq }).from(auditLog)).length;
  const logged = await entries();
  const before = await memberRows(CI);

  // The old isolate's app writes a value, its vault changes an access, it issues a token: each refused whole, nothing left.
  await assert.rejects(old.root.secrets.set('market/dev', { A: 'two' }), (error: { status?: number }) => error.status === 500);
  await assert.rejects(old.root.access.set(CI, { 'market/dev': 'developer' }), (error: { status?: number }) => error.status === 500);
  await assert.rejects(old.root.tokens.issue(CI, { label: 'late', expiresInDays: 30 }), (error: { status?: number }) => error.status === 500);
  assert.equal(await entries(), logged);
  assert.deepEqual(await memberRows(CI), before);
  assert.deepEqual((await db.owner.select({ label: credentials.label }).from(credentials).where(eq(credentials.label, 'late'))), []);
  // Its reads go on, logged as 0.14 logs them; and the token it issued before serves through 0.15's use.
  assert.deepEqual((await old.root.secrets.reveal('market/dev', ['A'])).values, { A: 'one' });
  assert.equal(codeOf(await use(now.vault, token.id, a)), 'ok');

  // 0.15's app and vault write as before: their entries say they are 0.15's.
  await now.root.secrets.set('market/dev', { A: 'two' });
  await now.root.access.set(CI, { 'market/dev': 'developer' });
  assert.equal(codeOf(await use(now.vault, token.id, a)), 'ok');
  const marked = await db.owner.select({ action: auditLog.action, log015: auditLog.log015 }).from(auditLog).where(sql`${auditLog.seq} >= ${logged}`);
  assert.ok(marked.some((entry) => entry.action === 'secret.write') && marked.some((entry) => entry.action === 'access.grant'), JSON.stringify(marked));
  assert.ok(marked.filter((entry) => !['secret.read', 'credential.use'].includes(entry.action)).every((entry) => entry.log015 === true), JSON.stringify(marked));
});

test("a use's probe of 0.14's log reads past an access entry forged in the vault's name, reported; a late write the dropped trigger let land is refused, its row put back too (UsesSeeOldWrites, OldWritesRefused; PR 9b)", async () => {
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.secrets.set('market/dev', { A: 'one' });
  await old.root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await old.root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const now = deploy();
  assert.equal(await now.cutover(), null);
  const a = await keyIn(await environmentOf('market', 'dev'), 'A');
  assert.equal(codeOf(await use(now.vault, token.id, a)), 'ok');

  // A writer without the vault's key appends an access entry in its name about the token's account: the probe finds it
  // newer than the account's newest change accounts for, and its MAC tells it apart. The use is decided as before.
  await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('vault', randomBytes(32)), [{ actor: 'system:vault', action: 'access.grant', decision: 'allow', subjectPrincipal: CI, metadata: '{}' }], undefined, undefined, [], true));
  assert.equal(codeOf(await use(now.vault, token.id, a)), 'ok');
  // The use writes nothing of it; the next decision about the account reports it.
  const reports = async () => (await db.owner.select({ code: auditLog.code }).from(auditLog).where(sql`${auditLog.action} = 'vault.tampered' AND ${auditLog.subjectPrincipal} = ${CI}`)).map((report) => report.code);
  assert.deepEqual(await reports(), []);
  await now.vault.access(CI);
  assert.deepEqual(await reports(), ['forged_entry']);

  // The refusal dropped by the database's owner: the old isolate's vault widens the account's access, and lands.
  const before = await memberRows(CI);
  await refusalDropped(() => old.root.access.set(CI, { 'market/dev': 'developer' }));
  // Its row no longer its seal's: refused.
  assert.equal(codeOf(await use(now.vault, token.id, a)), 'tampered');
  // A writer puts the account's row and grants back as 0.14's cutover sealed them: their seal holds again, and the probe,
  // which reads 0.14's newest authentic access entry, still refuses it.
  await putBack(before);
  assert.equal(codeOf(await use(now.vault, token.id, a)), 'stale');
});

test("an access entry forged in the vault's name holds no use: its check writes nothing, so a use answers while an old isolate holds 0.14's head and the vault has settling left to do (a bulk cap changed at the deploy), and the next decision reports it (reviews r3, r4 of PR 9b)", postgresOnly("0.14's head is a row lock of Postgres"), async () => {
  await old.root.projects.create('market');
  await old.root.environments.create('market/dev');
  await old.root.secrets.set('market/dev', { A: 'one' });
  await old.root.access.set(CI, { 'market/dev': 'viewer' });
  const token = await old.root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  // The deploy changes the bulk cap: the vault's settling logs it, under 0.14's head, before its first decision.
  const now = deploy(SIGNIN, { bulkLimit: { count: 7, windowMinutes: 15 } });
  assert.equal(await now.cutover(), null);
  await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('vault', randomBytes(32)), [{ actor: 'system:vault', action: 'access.grant', decision: 'allow', subjectPrincipal: CI, metadata: '{}' }], undefined, undefined, [], true));
  const named = (deadline = 3000): Promise<NamedUseOutcome> => {
    const at = Date.now();
    return now.vault.useNamed!({ tokenHash: hashToken(token.token).toString('base64'), place: { project: 'market', environment: 'dev' }, key: 'A', accepts: { signin: true, issuers: [] }, purpose: 'use', requestId: newUseRequestId(), at, deadline: at + deadline });
  };
  const reports = async () => (await db.owner.select({ code: auditLog.code }).from(auditLog).where(sql`${auditLog.action} = 'vault.tampered' AND ${auditLog.subjectPrincipal} = ${CI}`)).length;
  // 0.14's head held, as an old isolate's write holds it, around a named use: answered, and served, well within its deadline.
  let release = () => {};
  const released = new Promise<void>((resolve) => (release = resolve));
  const holding = db.owner.transaction(async (tx) => {
    await tx.execute(sql`SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE`);
    await released;
  });
  await new Promise((resolve) => setTimeout(resolve, 50));
  const started = Date.now();
  const held = await named(400).finally(() => release());
  const took = Date.now() - started;
  await holding;
  assert.ok(took < 400, `answered after ${took} ms`);
  assert.ok(held.served && held.outcome.ok, JSON.stringify(held));
  assert.equal(await reports(), 0);
  // The next decision about the account, the head free, reports it.
  await now.vault.access(CI);
  assert.equal(await reports(), 1);
});

test("the scheduled job, run before any request, as a Node server runs it at its start, cuts over first, then checkpoints", async () => {
  await old.root.projects.create('market');
  const now = deploy();
  const config = resolveConfig({ publicUrl: PUBLIC_URL, vault: now.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: now.deps.chainKey.toString('base64') });
  const runtime = createRuntime(config, now.deps.db, now.vault, { json: async () => assert.fail('the job fetches nothing') });
  await runScheduled(runtime);
  assert.equal(runtime.cutover?.done, true);
  assert.ok((await db.owner.select({ number: logChanges.number }).from(logChanges)).length > 0, "0.15's log holds the cutover");
  // And it runs as it did, once cut over.
  await runScheduled(runtime);
});
