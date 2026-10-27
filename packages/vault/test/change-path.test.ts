// 0.15's change path (docs/design/0.15-plan.md, PR 4a): every change a vault decision makes to an input of 0.15's log is
// one call of `change_input` (migration 0023), in the decision's transaction, after 0.14's writes. Each case names the
// part of formal/HotPathOne.tla or formal/Migration015.tla it holds, and runs on both engines unless it says otherwise:
// SQLite runs `change_input`'s twin (store.ts), under its one writer.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { EVERYWHERE, ROLES, type Permission } from '@coffre/core/access';
import { tablesOf } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { forgetLogHeads } from '@coffre/db/log';
import { asc, eq, sql } from 'drizzle-orm';
import pg from 'pg';

import { Changes, genesisCall, loggedChange, NotLogged, payloadOf, type ChangeKeys } from '../src/changes.ts';
import type { Sealed } from '../src/checkpointer.ts';
import type { ResolvedVaultConfig } from '../src/config.ts';
import { decideUse, type UseRequest } from '../src/decide.ts';
import { noEdits, objectKey, sealKey, sealOf, type CredentialInput, type EnvironmentInput, type Input, type Op, type Ref, type SecretInput } from '../src/inputs.ts';
import { authentic, changeEntry, entryMac, logMacKey } from '../src/log-entry.ts';
import { readUse, replay, type LoggedChange, type Replayed } from '../src/log-replay.ts';
import * as store from '../src/store.ts';
import type { VaultOptions } from '../src/vault.ts';
import { sealThroughDouble } from './audit-tree.ts';
import { emptyDatabase, OWNER_URL, VAULT_URL, newProject, openTestDatabase, places, postgresOnly, rows, sealed, withLogUnlocked, type TestDatabase, openLocalVault } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const BO = 'user:bo@acme.example';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

function configure(): ResolvedVaultConfig {
  return {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  };
}

function keysOf(config: ResolvedVaultConfig): ChangeKeys {
  return { seals: config.signingKeys.map((seed) => sealKey(seed)), mac: logMacKey(config.signingKeys[0]!) };
}

/** A vault keeping 0.15's log, whatever the suite's setting, its changes sealed at once unless `options` says how. */
async function world(options: VaultOptions = {}, config = configure()) {
  const vault = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed, ...options });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const where = await places(db.owner);
  return { vault, config, keys: keysOf(config), ...where };
}

type LogRow = { number: bigint; at: number; requestId: string; object: string; actor: string; payload: string; seal: Buffer | null; mac: Buffer };

/** 0.15's log of changes, by number, as stored. */
async function changeRows(): Promise<LogRow[]> {
  const { logChanges } = tablesOf(db.owner);
  const found = await db.owner.select().from(logChanges).orderBy(asc(logChanges.number));
  return found.map((row) => ({ ...row, number: BigInt(row.number), seal: row.seal ?? null }));
}

/** The changes of the log as the replay takes them: each names its object, and each MAC holds under the vault's key. */
async function logged(keys: ChangeKeys): Promise<LoggedChange[]> {
  const holds = authentic(keys.mac);
  return (await changeRows()).map((row) => {
    assert.ok(holds(changeEntry(row)), `entry ${row.number}'s MAC is the vault's`);
    const change = loggedChange(row);
    assert.ok(change !== null, `entry ${row.number} names its object`);
    return change;
  });
}

/** What the log says of `of`, op by op. */
async function opsOf(keys: ChangeKeys, of: Ref): Promise<string[]> {
  return (await logged(keys)).filter((change) => objectKey(change.ref) === objectKey(of)).map((change) => change.op.op);
}

/** The log replayed (HotPathOne's ReplaySound): no fault, and each of `refs` the rows' object, under the seal the rows carry. */
async function holdsReplay(keys: ChangeKeys, refs: readonly (Ref & { kind: store.ReadKind })[]): Promise<Replayed> {
  const replayed = replay(keys.seals, await logged(keys));
  assert.deepEqual(replayed.faults, []);
  for (const ref of refs) {
    const live = await store.readObject(db.owner, ref);
    const logged = replayed.rows.get(objectKey(ref));
    assert.ok(live.row !== null && logged !== undefined, `${ref.kind} ${ref.id} is in the rows and the log`);
    assert.deepEqual(sealOf(keys.seals[0]!, ref, live.row), sealOf(keys.seals[0]!, ref, logged.row), `${ref.kind} ${ref.id}: the rows are the replay's`);
    assert.deepEqual(live.seal, logged.seal, `${ref.kind} ${ref.id}: its row carries its newest change's seal`);
  }
  return replayed;
}

/** A change as the vault makes it: `op` to `ref`, leaving `after`, from `sealFrom`, its entry MAC'd. */
function made(keys: ChangeKeys, ref: Ref, op: Op, after: Input, sealFrom: Buffer | null, requestId: string = randomUUID()): store.ChangeCall {
  const seal = sealOf(keys.seals[0]!, ref, after);
  const row = { at: Date.now(), requestId, object: objectKey(ref), actor: ROOT, payload: payloadOf(ref, op), seal };
  const writes = ref.kind === 'environment' || ref.kind === 'roles' || ref.kind === 'policy';
  return { ref, ...row, value: writes ? JSON.stringify(after) : null, sealFrom, mac: entryMac(keys.mac, { tree: 'changes', row }) };
}

/** One call of `change_input`, in a transaction of the vault's own login. */
function change(calls: store.ChangeCall[]): Promise<(bigint | null)[]> {
  return db.vault.transaction((tx) => store.changeInputs(tx, calls));
}

/** The cutover's genesis of `input` (plan PR 9), as `genesisCall` makes it: what the tests stand in for the cutover with. */
async function genesis(keys: ChangeKeys, ref: Ref, input: Input): Promise<void> {
  const [number] = await change([genesisCall(keys, ref, input, Date.now(), 'system:cutover')]);
  assert.ok(number !== null, `${ref.kind} ${ref.id} sealed`);
}

const member = (principal: string) => ({ kind: 'principal' as const, id: principal });

test('every change a decision makes to a member is an entry of 0.15\'s log, op by op, beside 0.14\'s, and the log replays to the rows', async () => {
  const w = await world();
  const grant = (principal: string, environmentId: string, role: string | null) =>
    w.vault.setAccess({ actor: ROOT, principal, changes: [{ projectId: w.project, environmentId, role, expiresAt: null }] });
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  assert.ok((await grant(ADA, w.dev, 'viewer')).ok);
  assert.ok((await grant(ADA, w.prod, 'developer')).ok);
  assert.ok((await grant(ADA, w.prod, 'viewer')).ok);
  assert.ok((await grant(ADA, w.prod, null)).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'auditor' })).ok);
  // A service account admitted with its first grant, as one call: both changes, in the order the writes make them.
  assert.ok((await w.vault.setAccess({ actor: ROOT, principal: 'token:ci', admit: true, changes: [{ projectId: w.project, environmentId: w.dev, role: 'viewer', expiresAt: null }] })).ok);
  assert.ok((await w.vault.remove({ actor: ROOT, principal: ADA })).ok);

  assert.deepEqual(await opsOf(w.keys, member(ADA)), [
    'member.add', 'access.grant', 'access.grant', 'access.grant', 'access.revoke', 'member.role',
    // The removal: every grant revoked, the role back to a Member's, then the removal, as its writes make them.
    'access.revoke', 'member.role', 'member.remove',
  ]);
  assert.deepEqual(await opsOf(w.keys, member('token:ci')), ['member.add', 'access.grant']);
  // The deployment's Owner, made at the vault's start, and the cap it wrote first.
  assert.deepEqual(await opsOf(w.keys, member(ROOT)), ['member.add']);
  assert.deepEqual(await opsOf(w.keys, { kind: 'policy', id: 'instance' }), ['bulk.limit']);
  await holdsReplay(w.keys, [member(ADA), member('token:ci'), member(ROOT), { kind: 'policy', id: 'instance' }]);
  // 0.14's log has every one of them too, until 0.16 (dual fencing).
  const old = await rows<{ seq: string; action: string }>(db.owner, sql`SELECT seq, action FROM audit_log WHERE subject_principal = ${ADA} AND decision = 'allow' ORDER BY seq`);
  assert.deepEqual(old.map(({ action }) => action), ['member.add', 'access.grant', 'access.grant', 'access.grant', 'access.revoke', 'member.role', 'access.revoke', 'member.remove']);
  // And each change names the newest of 0.14's entries it accounts for: its decision's newest about her, the access_seq
  // her row names (UsesSeeOldWrites, plan PR 5).
  const cited = (await changeRows()).filter((row) => row.object === objectKey(member(ADA))).map((row) => (JSON.parse(row.payload) as { old?: string }).old);
  assert.deepEqual(cited.at(-1), old.at(-1)!.seq.toString());
  const [{ accessSeq }] = await db.owner.select({ accessSeq: tablesOf(db.owner).vaultMembers.accessSeq }).from(tablesOf(db.owner).vaultMembers).where(eq(tablesOf(db.owner).vaultMembers.principal, ADA));
  assert.equal(cited.at(-1), accessSeq.toString());
  assert.ok(cited.every((seq) => seq !== undefined));
});

test('a change to a member row put back from before a revoke is refused, though 0.14\'s log was cut to match it (ChangeChecksSeal)', async () => {
  const w = await world();
  const { vaultMembers, vaultGrants, auditLog } = tablesOf(db.owner);
  const third = (await places(db.owner)).dev;
  const grant = (environmentId: string, projectId: string, role: string | null) =>
    w.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId, environmentId, role, expiresAt: null }] });
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  assert.ok((await grant(w.dev, w.project, 'viewer')).ok); // A
  assert.ok((await grant(w.prod, w.project, 'developer')).ok); // B
  // Mallory keeps Ada's rows as they are with A and B, sealed {A, B} by the log's newest change then.
  const [kept] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, ADA));
  const keptGrants = await db.owner.select().from(vaultGrants).where(eq(vaultGrants.principal, ADA));
  const keptSeq = (await rows<{ seq: string }>(db.owner, sql`SELECT max(seq) AS seq FROM audit_log`))[0]!.seq;
  assert.ok((await grant(w.prod, w.project, null)).ok); // B revoked: the log seals {A}
  const revoked = (await changeRows()).at(-1)!;

  // She puts the rows back, and cuts 0.14's revoke from its log, so that 0.14's own check, which would refuse the row
  // first, finds it current: only 0.15's log still says B was revoked.
  await withLogUnlocked(db.owner, async (owned) => {
    await owned.delete(auditLog).where(sql`${auditLog.seq} > ${keptSeq}`);
    const [{ hash }] = await owned.select({ hash: auditLog.hash }).from(auditLog).where(eq(auditLog.seq, BigInt(keptSeq)));
    await owned.update(tablesOf(owned).auditChainHead).set({ nextSeq: BigInt(keptSeq) + 1n, headHash: hash });
  });
  // A vault that starts after the cut, as a new isolate does, which remembers no head past it.
  forgetLogHeads();
  await db.owner.update(vaultMembers).set(kept!).where(eq(vaultMembers.principal, ADA));
  await db.owner.delete(vaultGrants).where(eq(vaultGrants.principal, ADA));
  await db.owner.insert(vaultGrants).values(keptGrants);
  const before = (await changeRows()).length;

  // A grant of C would seal {A, B, C}: B served again. It is refused, and nothing is written or logged.
  const refused = await grant(third, (await rows<{ project_id: string }>(db.owner, sql`SELECT project_id FROM environments WHERE id = ${third}`))[0]!.project_id, 'viewer');
  assert.equal(!refused.ok && refused.refusal.code, 'tampered');
  assert.equal((await changeRows()).length, before);
  assert.deepEqual((await changeRows()).at(-1)!.seal, revoked.seal);
  assert.deepEqual((await db.owner.select().from(vaultGrants).where(eq(vaultGrants.principal, ADA))).map((row) => row.environmentId).sort(), [w.dev, w.prod].sort());
  // The vault reported it, in 0.14's log as any tampered row.
  const reports = await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered' AND subject_principal = ${ADA}`);
  assert.deepEqual(reports.map(({ code }) => code), ['stale']);
});

test('change_input refuses a row that is not its object\'s newest change\'s, under the lock, whatever the vault read (ChangeChecksSeal)', async () => {
  const w = await world();
  const { vaultMembers } = tablesOf(db.owner);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  const [{ seal: added }] = await db.owner.select({ seal: vaultMembers.seal }).from(vaultMembers).where(eq(vaultMembers.principal, ADA));
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'auditor' })).ok);
  // The row's seal put back to the one before: the vault, asked from that seal, would CAS from what it read.
  await db.owner.update(vaultMembers).set({ seal: added }).where(eq(vaultMembers.principal, ADA));
  const call = (requestId: string) => made(w.keys, member(ADA), { op: 'member.role', role: 'admin', scope: EVERYWHERE }, { kind: 'principal', principal: ADA, status: 'active', role: 'admin', scope: EVERYWHERE, grants: [] }, added!, requestId);
  await assert.rejects(change([call(randomUUID())]), (error) => store.isStale(error));
  assert.equal((await opsOf(w.keys, member(ADA))).length, 2);
});

test('change_input: a retry finds its entry, another payload under its request is refused, and of two changes from one seal the second does nothing (fence-one)', async () => {
  const w = await world();
  await genesis(w.keys, { kind: 'environment', id: w.prod }, environment(w.project, w.prod, 'prod'));
  const from = (await store.readObject(db.owner, { kind: 'environment', id: w.prod })).seal;
  const ref = { kind: 'environment' as const, id: w.prod };
  const protect = (on: boolean, sealFrom: Buffer | null, requestId?: string) =>
    made(w.keys, ref, { op: 'environment.protect', protected: on }, { ...environment(w.project, w.prod, 'prod'), protected: on }, sealFrom, requestId);
  // The replay of a change: its entry's number again, and one entry.
  const first = protect(true, from);
  const [number] = await change([first]);
  assert.ok(number !== null);
  assert.deepEqual(await change([first]), [number]);
  // Another payload under its request id: refused, whatever else it says.
  await assert.rejects(change([protect(false, from, first.requestId)]), (error: Error) => isUniqueViolation(error) && !store.isStale(error));
  // Two changes from one seal (ChangeCAS): the second finds another and does nothing.
  assert.deepEqual(await change([protect(false, from)]), [null]);
  assert.equal((await opsOf(w.keys, { kind: 'environment', id: w.prod })).length, 2);
  const [row] = await db.owner.select({ protected: tablesOf(db.owner).environments.protected }).from(tablesOf(db.owner).environments).where(eq(tablesOf(db.owner).environments.id, w.prod));
  assert.equal(row!.protected, true);
});

test('change_input refuses an op it does not take, and a payload that names another object than its arguments', async () => {
  const w = await world();
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  const { seal } = await store.readObject(db.owner, member(ADA));
  const call = (payload: string): store.ChangeCall => ({
    ref: member(ADA), requestId: randomUUID(), at: Date.now(), actor: ROOT, payload, value: null, sealFrom: seal, seal: randomBytes(16), mac: randomBytes(16),
  });
  await assert.rejects(change([call(payloadOf(member(ADA), { op: 'credential.revoke' }))]));
  await assert.rejects(change([call(payloadOf(member(BO), { op: 'member.remove' }))]));
  await assert.rejects(change([call(JSON.stringify({ op: 'member.remove' }))]));
  assert.deepEqual(await opsOf(w.keys, member(ADA)), ['member.add']);
});

test('a change to a row a writer edited, its seal kept, is refused as tampered before anything is written', async () => {
  const w = await world();
  await genesis(w.keys, { kind: 'environment', id: w.dev }, environment(w.project, w.dev, 'dev'));
  // Mallory points dev at another parent; the seal stays.
  const { environments } = tablesOf(db.owner);
  await db.owner.update(environments).set({ parentId: w.prod }).where(eq(environments.id, w.dev));
  const changes = new Changes(w.keys);
  changes.stage({ kind: 'environment', id: w.dev }, { op: 'environment.rename', slug: 'development' }, ROOT);
  await assert.rejects(db.vault.transaction((tx) => changes.prepare(tx)), (error) => error instanceof NotLogged && error.fault === 'tampered');
});

test('renaming staging to prod takes a Developer scoped to staging off it, live and replayed alike (environment.rename)', async () => {
  const w = await world();
  const { environments, credentials, secrets } = tablesOf(db.owner);
  const project = await newProject(db.owner);
  const staging = randomUUID();
  await db.owner.insert(environments).values({ id: staging, projectId: project, slug: 'staging', name: 'Staging' });
  const secretId = randomUUID();
  await db.owner.insert(secrets).values({ id: secretId, projectId: project, environmentId: staging, key: 'DATABASE_URL' });
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: { projects: 'all', environments: { only: ['staging'] } } })).ok);
  const credentialId = randomUUID();
  await db.owner.insert(credentials).values({
    id: credentialId, kind: 'browser', authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, principal: ADA,
    createdBy: ADA, expiresAt: new Date(Date.now() + 3_600_000),
  });
  // The cutover seals what the use reads (plan PR 9): the environment, the roles, Ada's session and the key. PR 5's
  // statement reads a credential's and a key's rows; here their objects are the cutover's.
  const credential: CredentialInput = { kind: 'credential', id: credentialId, principal: ADA, caller: 'person', scope: null, expiresAt: null, revoked: false };
  const secret: SecretInput = { kind: 'secret', id: secretId, projectId: project, environmentId: staging, version: randomUUID(), nature: 'secret', key: { kekProvider: 'local', kekId: 'k', kekVersion: '1', bytes: 'AA==' }, source: null };
  await genesis(w.keys, { kind: 'environment', id: staging }, environment(project, staging, 'staging'));
  await genesis(w.keys, { kind: 'roles', id: 'instance' }, noEdits());
  await genesis(w.keys, { kind: 'credential', id: credentialId }, credential);
  await genesis(w.keys, { kind: 'secret', id: secretId }, secret);

  const request = (): UseRequest => ({ credential: credentialId, secretId, place: null, purpose: 'reveal', keepsSensitive: false, at: Date.now() });
  /** The use decided on the rows (live, as the use's statement reads them) and on the log's replay: they agree. */
  const decide = async () => {
    const refs = [member(ADA), { kind: 'environment' as const, id: staging }, { kind: 'roles' as const, id: 'instance' }, { kind: 'policy' as const, id: 'instance' }];
    const replayed = await holdsReplay(w.keys, refs);
    const live = new Map<string, { row: Input; seal: Buffer | null }>();
    const newest = new Map<string, Buffer | null>();
    for (const ref of refs) {
      const { row, seal } = await store.readObject(db.owner, ref);
      live.set(objectKey(ref), { row: row!, seal });
      newest.set(objectKey(ref), (await store.newestChange(db.owner, ref))?.seal ?? null);
    }
    for (const [ref, row] of [[{ kind: 'credential' as const, id: credentialId }, credential], [{ kind: 'secret' as const, id: secretId }, secret]] as const) {
      live.set(objectKey(ref), { row, seal: sealOf(w.keys.seals[0]!, ref, row) });
      newest.set(objectKey(ref), (await store.newestChange(db.owner, ref))?.seal ?? null);
    }
    const asked = request();
    const now = decideUse(w.keys.seals, readUse(live, newest, replayed.limit, new Map(), asked), asked);
    const then = decideUse(w.keys.seals, readUse(replayed.rows, replayed.newest, replayed.limit, new Map(), asked), asked);
    assert.equal(now, then, 'live and replayed decide alike');
    return now;
  };
  assert.equal(await decide(), null, 'a Developer of every staging reads staging');

  const rename = new Changes(w.keys);
  rename.stage({ kind: 'environment', id: staging }, { op: 'environment.rename', slug: 'prod' }, ROOT);
  await db.vault.transaction(async (tx) => {
    await rename.prepare(tx);
    await rename.commit(tx, Date.now());
  });
  const [renamed] = await db.owner.select({ slug: environments.slug }).from(environments).where(eq(environments.id, staging));
  assert.equal(renamed!.slug, 'prod');
  assert.equal(await decide(), 'no_grant', 'staging is prod now, which her scope does not reach');
  assert.deepEqual(await opsOf(w.keys, { kind: 'environment', id: staging }), ['genesis', 'environment.rename']);

  // Archived, then back: the row's archived_at moves with the object, which the log replays.
  for (const archived of [true, false]) {
    const archive = new Changes(w.keys);
    archive.stage({ kind: 'environment', id: staging }, { op: 'environment.archive', archived }, ROOT);
    await db.vault.transaction(async (tx) => {
      await archive.prepare(tx);
      await archive.commit(tx, Date.now());
    });
    const [row] = await db.owner.select({ archivedAt: environments.archivedAt }).from(environments).where(eq(environments.id, staging));
    assert.equal(row!.archivedAt !== null, archived);
    await holdsReplay(w.keys, [{ kind: 'environment', id: staging }]);
  }
});

test('protecting an environment the cutover sealed is a change of its object; one before the cutover is 0.14\'s alone', async () => {
  const w = await world();
  const { environments } = tablesOf(db.owner);
  await genesis(w.keys, { kind: 'environment', id: w.prod }, environment(w.project, w.prod, 'prod'));
  const protect = (ids: string[], on: boolean) => w.vault.changePolicy({ actor: ROOT, change: { kind: 'protect', projectId: w.project, environmentIds: ids, protected: on } });
  assert.ok((await protect([w.prod, w.dev], true)).ok);
  assert.ok((await protect([w.prod], false)).ok);
  assert.ok((await protect([w.prod], true)).ok);
  assert.deepEqual(await opsOf(w.keys, { kind: 'environment', id: w.prod }), ['genesis', 'environment.protect', 'environment.protect', 'environment.protect']);
  // Each names the policy.change entry it came with.
  const policies = await rows<{ seq: string }>(db.owner, sql`SELECT seq FROM audit_log WHERE action = 'policy.change' AND decision = 'allow' ORDER BY seq`);
  const cited = (await changeRows()).filter((row) => row.object === objectKey({ kind: 'environment', id: w.prod })).map((row) => (JSON.parse(row.payload) as { old?: string }).old);
  assert.deepEqual(cited, [undefined, ...policies.map(({ seq }) => seq.toString())]);
  // Dev has no seal and no change: 0.14's log holds its protection, which the cutover will seal.
  assert.deepEqual(await opsOf(w.keys, { kind: 'environment', id: w.dev }), []);
  const flags = await db.owner.select({ id: environments.id, protected: environments.protected }).from(environments).where(eq(environments.projectId, w.project));
  assert.deepEqual(Object.fromEntries(flags.map((row) => [row.id, row.protected])), { [w.prod]: true, [w.dev]: null });
  await holdsReplay(w.keys, [{ kind: 'environment', id: w.prod }]);
  assert.deepEqual([...(await w.vault.policy()).protected].sort(), [w.dev, w.prod].sort());
});

test('protecting two sealed environments in one call is two changes, each from its own seal; a deleted one changes nothing in 0.15\'s log', async () => {
  const w = await world();
  const { environments } = tablesOf(db.owner);
  const gone = randomUUID();
  await db.owner.insert(environments).values({ id: gone, projectId: w.project, slug: 'old~1', name: 'Old' });
  await genesis(w.keys, { kind: 'environment', id: w.dev }, environment(w.project, w.dev, 'dev'));
  await genesis(w.keys, { kind: 'environment', id: w.prod }, environment(w.project, w.prod, 'prod'));
  // A deleted one's object holds its slug before the tombstone (objects.ts; 0025).
  await genesis(w.keys, { kind: 'environment', id: gone }, { ...environment(w.project, gone, 'old'), deleted: true });
  // An Owner protects all three, from a page shown before one of them was deleted: 0.14 takes it, as it did.
  const outcome = await w.vault.changePolicy({ actor: ROOT, change: { kind: 'protect', projectId: w.project, environmentIds: [w.dev, w.prod, gone], protected: true } });
  assert.ok(outcome.ok, JSON.stringify(outcome));
  for (const id of [w.dev, w.prod]) assert.deepEqual(await opsOf(w.keys, { kind: 'environment', id }), ['genesis', 'environment.protect']);
  assert.deepEqual(await opsOf(w.keys, { kind: 'environment', id: gone }), ['genesis']);
  await holdsReplay(w.keys, [w.dev, w.prod, gone].map((id) => ({ kind: 'environment' as const, id })));
});

test('a policy row planted with no seal is refused, not taken for one from before the cutover', async () => {
  const config = configure();
  const { logConfig } = tablesOf(db.owner);
  await db.owner.insert(logConfig).values({ name: 'policy', value: JSON.stringify({ kind: 'policy', bulk: { count: 1_000_000, windowMs: 60_000 } }) });
  const vault = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  assert.deepEqual(await opsOf(keysOf(config), { kind: 'policy', id: 'instance' }), []);
  const reports = await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered'`);
  assert.deepEqual(reports.map(({ code }) => code), ['mac']);
});

test('an Owner the deployment names again after a removal is restored by the vault at its start, a change of the log', async () => {
  const config = configure();
  const eve = 'user:eve@acme.example';
  const first = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed });
  assert.equal((await first.access(ROOT)).role, 'owner');
  assert.ok((await first.admit({ actor: ROOT, principal: eve, role: 'owner' })).ok);
  assert.ok((await first.remove({ actor: ROOT, principal: eve })).ok);
  const named = await openLocalVault(db.vault, { ...config, owners: [...config.owners, 'eve@acme.example'] }, { log: '0.15', sealThrough: sealed });
  assert.equal((await named.access(eve)).role, 'owner');
  assert.deepEqual(await opsOf(keysOf(config), member(eve)), ['member.add', 'member.role', 'member.remove', 'member.restore']);
  await holdsReplay(keysOf(config), [member(eve)]);
});

test('an Owner\'s role edit is a change of the roles object, once the cutover has made it', async () => {
  const w = await world();
  const define = (role: string, permissions: Permission[]) => w.vault.changePolicy({
    actor: ROOT, change: { kind: 'role', role, definition: { ...ROLES.viewer, name: role, permissions, protected: permissions } },
  });
  // Before the cutover, 0.14's policy holds the edits, and 0.15's log none.
  assert.ok((await define('reader', ['secret.read', 'secret.use'])).ok);
  assert.deepEqual(await opsOf(w.keys, { kind: 'roles', id: 'instance' }), []);
  await genesis(w.keys, { kind: 'roles', id: 'instance' }, { ...noEdits(), roles: (await w.vault.policy()).roles.reader === undefined ? {} : { reader: (await w.vault.policy()).roles.reader! } });
  assert.ok((await define('user', ['secret.use'])).ok);
  assert.ok((await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'reader', definition: null } })).ok);
  assert.deepEqual(await opsOf(w.keys, { kind: 'roles', id: 'instance' }), ['genesis', 'role.define', 'role.define']);
  // Each edit names the policy.change entry it came with (UsesSeeOldWrites).
  const policies = await rows<{ seq: string }>(db.owner, sql`SELECT seq FROM audit_log WHERE action = 'policy.change' AND decision = 'allow' ORDER BY seq`);
  const cited = (await changeRows()).filter((row) => row.object === objectKey({ kind: 'roles', id: 'instance' })).map((row) => (JSON.parse(row.payload) as { old?: string }).old);
  assert.deepEqual(cited, [undefined, ...policies.slice(-2).map(({ seq }) => seq.toString())]);
  const replayed = await holdsReplay(w.keys, [{ kind: 'roles', id: 'instance' }]);
  const roles = replayed.rows.get(objectKey({ kind: 'roles', id: 'instance' }))!.row;
  assert.deepEqual(roles.kind === 'roles' && Object.keys(roles.roles), ['user']);
});

test('the vault writes its bulk cap into the log at its start, once, and again when the deployment changes it', async () => {
  const config = configure();
  const policy = { kind: 'policy' as const, id: 'instance' };
  const start = async (count: number) => {
    const vault = await openLocalVault(db.vault, { ...config, bulkLimit: { count, windowMs: 60_000 } }, { log: '0.15', sealThrough: sealed });
    assert.ok((await vault.access(ROOT)).status);
  };
  await start(10);
  await start(10);
  await start(20);
  assert.deepEqual(await opsOf(keysOf(config), policy), ['bulk.limit', 'bulk.limit']);
  const replayed = await holdsReplay(keysOf(config), [policy]);
  assert.deepEqual(replayed.limit, { count: 20, windowMs: 60_000 });
});

test('a change answers only once its entry is sealed (R51, CommitBeforeAnswer)', async () => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  // The start's own changes are sealed at once; the one this case watches waits until released.
  const seal = sealThroughDouble(async () => {
    if (seal.asked.length > 2) await held;
    return {} as Sealed;
  });
  const w = await world({ sealThrough: seal });
  let answered = false;
  const admitted = w.vault.admit({ actor: ROOT, principal: ADA }).then((outcome) => {
    answered = true;
    return outcome;
  });
  // Committed, and visible to anyone, while the call has not answered: it waits on its seal, for its own entry.
  await waitFor(async () => (await opsOf(w.keys, member(ADA))).length > 0, 'the change commits');
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(answered, false);
  assert.equal(seal.asked.at(-1), (await changeRows()).at(-1)!.number);
  release();
  assert.ok((await admitted).ok);
  // A seal that fails fails the call, though the change stands: it never answers done.
  const failing = await world({ sealThrough: sealThroughDouble(() => new Error('its entry is not in the signed tree')) }, w.config);
  await assert.rejects(failing.vault.admit({ actor: ROOT, principal: BO }), /signed tree/);
});

test('a change waits for every use in flight, and every use asked meanwhile waits for its commit (ChangeLocks, LockToCommit)', postgresOnly('SQLite has one writer: the fence is implicit'), async () => {
  const w = await world();
  await genesis(w.keys, { kind: 'environment', id: w.prod }, environment(w.project, w.prod, 'prod'));
  const from = (await store.readObject(db.owner, { kind: 'environment', id: w.prod })).seal;
  const protect = made(w.keys, { kind: 'environment', id: w.prod }, { op: 'environment.protect', protected: true }, { ...environment(w.project, w.prod, 'prod'), protected: true }, from);
  const [use, changer] = [new pg.Client({ connectionString: OWNER_URL }), new pg.Client({ connectionString: VAULT_URL })];
  await Promise.all([use.connect(), changer.connect()]);
  const call = (c: store.ChangeCall) => changer.query(
    'SELECT change_input($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) AS number',
    [c.ref.kind, c.ref.id, c.requestId, c.at, c.actor, c.payload, c.value, c.sealFrom, c.seal, c.mac],
  );
  try {
    // A use in flight holds the fence shared, as use_credential takes it: the change, with no 0.14 entry to fence it
    // too, waits for it in change_input.
    await use.query('BEGIN');
    await use.query('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');
    await changer.query('BEGIN');
    let ran = false;
    const changing = call(protect).then((result) => ((ran = true), result));
    await waitFor(async () => (await fenceWaiters()) > 0, 'the change waits for the use');
    assert.equal(ran, false);
    await use.query('COMMIT');
    assert.ok((await changing).rows[0].number !== null);
    // The change has run, not committed: a use asked now waits for the commit, and then reads what it wrote.
    await use.query('BEGIN');
    const using = use.query('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');
    await waitFor(async () => (await fenceWaiters()) > 0, 'the use waits for the change');
    await changer.query('COMMIT');
    await using;
    const read = await use.query('SELECT protected FROM environments WHERE id = $1', [w.prod]);
    assert.equal(read.rows[0].protected, true);
    await use.query('COMMIT');
  } finally {
    await Promise.all([use.end(), changer.end()]);
  }
});

test('a 0.15 change beside a 0.14 decision holding its member\'s row: row, head, fence, and neither waits on the other in a circle (RowFirst, ChangeHeadFirst)', postgresOnly('SQLite has one writer'), async () => {
  const w = await world();
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  const old = new pg.Client({ connectionString: OWNER_URL });
  await old.connect();
  try {
    // 0.14's vault: the member's queue and row, then, a moment later, the head, then an entry that changes access,
    // which takes the fence (OldWritesFence).
    await old.query('BEGIN');
    await old.query(`SELECT pg_advisory_xact_lock(1668245101, hashtext(principal)) FROM vault_members WHERE principal = $1 FOR NO KEY UPDATE`, [ADA]);
    const changed = w.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: w.project, environmentId: w.dev, role: 'viewer', expiresAt: null }] });
    await waitFor(async () => (await waiting()) > 0, 'the change waits for the row');
    await old.query('SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE');
    await old.query(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
      SELECT next_seq, 'vault', 'fixture', 0, 'system:fixture', 'access.grant', 'allow', head_hash, decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex') FROM audit_chain_head`);
    await old.query('ROLLBACK');
    const outcome = await changed;
    assert.ok(outcome.ok, JSON.stringify(outcome));
    await holdsReplay(w.keys, [member(ADA)]);
  } finally {
    await old.end();
  }
});

test('changes and reads at once, on the same members, all answer, and the log replays to the rows', postgresOnly('SQLite runs one call at a time'), async () => {
  const w = await world();
  const vaults = await Promise.all([1, 2, 3].map(async () => openLocalVault(await db.connect(4), w.config, { log: '0.15', sealThrough: sealed })));
  const people = [ADA, BO, 'user:cy@acme.example'];
  for (const person of people) assert.ok((await w.vault.admit({ actor: ROOT, principal: person })).ok);
  const work: Promise<{ ok: boolean }>[] = [];
  for (let round = 0; round < 6; round += 1) {
    for (const [i, person] of people.entries()) {
      const vault = vaults[(round + i) % vaults.length]!;
      const environmentId = round % 2 === 0 ? w.dev : w.prod;
      work.push(vault.setAccess({ actor: ROOT, principal: person, changes: [{ projectId: w.project, environmentId, role: round % 3 === 2 ? null : 'viewer', expiresAt: null }] }));
      work.push(vault.access(person).then(() => ({ ok: true })));
    }
  }
  const outcomes = await Promise.all(work);
  assert.deepEqual(outcomes.filter((outcome) => !outcome.ok), []);
  await holdsReplay(w.keys, people.map(member));
});

/** An environment's object as a fixture's row holds it. */
function environment(projectId: string, id: string, slug: string): EnvironmentInput {
  return { kind: 'environment', id, projectId, slug, owner: null, parentId: null, protected: false, deleted: false, archived: false };
}

/** Sessions waiting for the fence (its advisory key, 1668244070 / 0). */
async function fenceWaiters(): Promise<number> {
  const [row] = await rows<{ n: string }>(db.owner, sql`SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory' AND classid = 1668244070 AND objid = 0 AND NOT granted`);
  return Number(row!.n);
}

/** Sessions waiting for any lock. */
async function waiting(): Promise<number> {
  const [row] = await rows<{ n: string }>(db.owner, sql`SELECT count(*) AS n FROM pg_locks WHERE NOT granted`);
  return Number(row!.n);
}

async function waitFor(condition: () => Promise<boolean>, what: string): Promise<void> {
  for (let tries = 0; !(await condition()); tries += 1) {
    assert.ok(tries < 500, what);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
