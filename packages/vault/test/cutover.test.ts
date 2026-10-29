// 0.15's cutover from 0.14 (docs/design/0.15-plan.md, PR 9; formal/Migration015.tla): the first 0.15 vault start
// seals what 0.14 left as 0.14 accepts it, once, and anchors the new log at 0.14's head. Each case writes an instance
// under 0.14's log alone (the vault's decisions, and the app's rows as the owner, as 0.14's app writes them), then
// cuts it over, as the app asks for it, and holds what was sealed to what 0.14 accepted. What only the app's key
// says (a credential's or a binding's MAC, a deletion's entry) the app vouches for: here, the case does
// (packages/server/test/cutover.test.ts holds the app's half). Both engines, but what says otherwise.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { ROLES } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { CutoverInput, CutoverOutcome, SecretRef, Vault } from '@coffre/core/vault';
import { tablesOf, type Queryable } from '@coffre/db';
import { postgresSession } from '@coffre/db/connect';
import { appendEntries } from '@coffre/db/log';
import { asc, eq, sql } from 'drizzle-orm';

import { keptObjects, loggedChange } from '../src/changes.ts';
import type { Sealed } from '../src/checkpointer.ts';
import type { ResolvedVaultConfig } from '../src/config.ts';
import { CUTOVER_OBJECT } from '../src/cutover.ts';
import { objectKey, sealKey, sealOf, type Input, type Ref } from '../src/inputs.ts';
import { openLocalVault as openRaw } from '../src/local.ts';
import { replay } from '../src/log-replay.ts';
import { vaultLogKey } from '../src/log.ts';
import * as store from '../src/store.ts';
import { emptyDatabase, ENGINE, openLocalVault, openTestDatabase, OWNER_URL, places, postgresOnly, rows, run, sealed, storedVersions, withLogUnlocked, withTriggersLifted, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const CI = 'token:ci';

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
    bulkLimit: { count: 500, windowMs: 10 * 60_000 },
  };
}

/** Nothing vouched for: what a case's app says when it made no credential or binding, and deleted nothing. */
const NONE: Omit<CutoverInput, 'checked'> = { credentials: [], bindings: [], deleted: [] };


/**
 * An instance kept by 0.14's log alone: its vault's decisions, and a project with dev and prod, written as 0.14's
 * app writes them. `key` stores a key with a value in an environment, its version current, as the app would.
 */
async function instance014() {
  const config = configure();
  const old = await openLocalVault(db.vault, config, { log: '0.14' });
  assert.equal((await old.access(ROOT)).role, 'owner');
  const where = await places(db.owner);
  const key = async (environmentId: string): Promise<SecretRef> => {
    const secret = await where.secret(environmentId);
    const wrapped = await old.wrap({ principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] });
    assert.ok(wrapped.ok, JSON.stringify(wrapped));
    const [{ secretVersionId }] = await storedVersions(db.owner, [{ secret, wrapped: wrapped.wrapped[0]! }]);
    await run(db.owner, sql`UPDATE secrets SET current_version_id = ${secretVersionId}, current_version = 1 WHERE id = ${secret.secretId}`);
    return secret;
  };
  return { config, old, ...where, key };
}

/** A vault of 0.15's log over the same database and configuration, as a deploy starts one: not cut over yet. */
async function vault015(config: ResolvedVaultConfig, database: Queryable = db.vault) {
  return openRaw(database as never, config, { log: '0.15', sealThrough: sealed });
}

/** 0.14's head now, as the app reads it after checking its entries to it. */
async function head(): Promise<{ seq: string; hash: string }> {
  const [row] = await rows<{ next_seq: string | number; head_hash: Buffer | Uint8Array }>(db.owner, sql`SELECT next_seq, head_hash FROM audit_chain_head`);
  return { seq: (BigInt(row!.next_seq) - 1n).toString(), hash: Buffer.from(row!.head_hash).toString('hex') };
}

/** The cutover as the app asks for it: where to check from, then what it vouches for, checked to the head. */
async function cutOver(vault: Pick<Vault, 'cutover'>, vouched: Omit<CutoverInput, 'checked'> = NONE): Promise<CutoverOutcome> {
  const asked = await vault.cutover!();
  if (!asked.ok || asked.done) return asked;
  return vault.cutover!({ checked: { from: asked.from, to: await head() }, ...vouched });
}

/** The changes of 0.15's log, oldest first, but the cutover's own: as the replay takes them. */
async function changes() {
  const { logChanges } = tablesOf(db.owner);
  return (await db.owner.select().from(logChanges).orderBy(asc(logChanges.number)))
    .filter((row) => row.object !== CUTOVER_OBJECT)
    .map((row) => loggedChange({ ...row, number: BigInt(row.number), seal: row.seal ?? null })!);
}

/** What 0.15's log says of `ref`, op by op. */
async function opsOf(ref: Ref): Promise<string[]> {
  return (await changes()).filter((change) => objectKey(change.ref) === objectKey(ref)).map((change) => change.op.op);
}

/** The cutover's change, and the 0.14 entry it names. */
async function marker() {
  const { logChanges } = tablesOf(db.owner);
  const found = await db.owner.select().from(logChanges).where(eq(logChanges.object, CUTOVER_OBJECT));
  return found.map((row) => JSON.parse(row.payload) as { op: string; anchor: { seq: string; hash: string }; from: { seq: string; hash: string } });
}

/** The log replayed has no fault, and each of `refs` is its rows' object, under its row's seal. */
async function holdsReplay(config: ResolvedVaultConfig, refs: readonly (Ref & { kind: store.ReadKind })[]): Promise<void> {
  const keys = config.signingKeys.map((seed) => sealKey(seed));
  const replayed = replay(keys, await changes());
  assert.deepEqual(replayed.faults, []);
  for (const ref of refs) {
    const live = await store.readObject(db.owner, ref);
    const logged = replayed.rows.get(objectKey(ref));
    assert.ok(live.row !== null && logged !== undefined, `${ref.kind} ${ref.id} is in the rows and the log`);
    assert.deepEqual(sealOf(keys[0]!, ref, live.row), sealOf(keys[0]!, ref, logged.row), `${ref.kind} ${ref.id}: the rows are the replay's`);
    assert.deepEqual(live.seal, logged.seal, `${ref.kind} ${ref.id}: its row carries its newest change's seal`);
  }
}

test("a 0.14 instance cut over: each member sealed as 0.14 accepts them, naming their newest access entry; the roles and protection from 0.14's newest policy; the deployment's cap; anchored at its own 0.14 entry", async () => {
  const w = await instance014();
  assert.ok((await w.old.admit({ actor: ROOT, principal: ADA })).ok);
  assert.ok((await w.old.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: w.project, environmentId: w.dev, role: 'developer', expiresAt: null }] })).ok);
  assert.ok((await w.old.setAccess({ actor: ROOT, principal: CI, admit: true, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  // An Owner's role edit and prod protected, in 0.14's policy.
  const reader = { ...ROLES.viewer, name: 'Reader', permissions: ['secret.read' as const, 'secret.use' as const], protected: ['secret.read' as const, 'secret.use' as const] };
  const edited = await w.old.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'reader', definition: reader } });
  assert.ok(edited.ok, JSON.stringify(edited));
  assert.ok((await w.old.changePolicy({ actor: ROOT, change: { kind: 'protect', projectId: w.project, environmentIds: [w.prod], protected: true } })).ok);
  const secret = await w.key(w.dev);
  // Nothing of 0.15's yet: 0.14's log alone.
  assert.deepEqual(await changes(), []);

  const vault = await vault015(w.config);
  // Nothing of 0.15's is served before the cutover: no decision, no use.
  await assert.rejects(vault.setAccess({ actor: ROOT, caller: 'person', principal: ADA, changes: [] }), /not cut over from 0.14 yet/);
  const asked = await vault.cutover!();
  assert.ok(asked.ok && !asked.done, JSON.stringify(asked));
  const outcome = await vault.cutover!({ checked: { from: asked.from, to: await head() }, ...NONE });
  assert.deepEqual(outcome, { ok: true, done: true });

  // Each member, the roles, the policy, both environments and the key: one genesis each, and the cutover after them.
  for (const principal of [ROOT, ADA, CI]) assert.deepEqual(await opsOf({ kind: 'principal', id: principal }), ['genesis'], principal);
  for (const ref of [{ kind: 'roles', id: 'instance' }, { kind: 'policy', id: 'instance' }, { kind: 'environment', id: w.dev }, { kind: 'environment', id: w.prod }, { kind: 'secret', id: secret.secretId }] as const) {
    assert.deepEqual(await opsOf(ref), ['genesis'], `${ref.kind} ${ref.id}`);
  }
  await holdsReplay(w.config, [
    { kind: 'principal', id: ROOT }, { kind: 'principal', id: ADA }, { kind: 'principal', id: CI }, { kind: 'roles', id: 'instance' }, { kind: 'policy', id: 'instance' },
    { kind: 'environment', id: w.dev }, { kind: 'environment', id: w.prod }, { kind: 'secret', id: secret.secretId },
  ]);
  const objects = new Map((await changes()).map((change) => [objectKey(change.ref), change.op.op === 'genesis' ? change.op.value : null]));
  // The roles as 0.14's policy edited them; prod protected, dev not; the cap the deployment's.
  const roles = objects.get(objectKey({ kind: 'roles', id: 'instance' })) as Extract<Input, { kind: 'roles' }>;
  assert.deepEqual(Object.keys(roles.roles), ['reader']);
  assert.equal((objects.get(objectKey({ kind: 'environment', id: w.prod })) as Extract<Input, { kind: 'environment' }>).protected, true);
  assert.equal((objects.get(objectKey({ kind: 'environment', id: w.dev })) as Extract<Input, { kind: 'environment' }>).protected, false);
  assert.deepEqual((objects.get(objectKey({ kind: 'policy', id: 'instance' })) as Extract<Input, { kind: 'policy' }>).bulk, w.config.bulkLimit);
  // Each member's genesis names their newest access entry, as their row does (UsesSeeOldWrites).
  const { logChanges, vaultMembers } = tablesOf(db.owner);
  for (const principal of [ROOT, ADA, CI]) {
    const [{ accessSeq }] = await db.owner.select({ accessSeq: vaultMembers.accessSeq }).from(vaultMembers).where(eq(vaultMembers.principal, principal));
    const [genesis] = await db.owner.select({ payload: logChanges.payload }).from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'principal', id: principal })));
    assert.equal((JSON.parse(genesis!.payload) as { old?: string }).old, accessSeq.toString(), principal);
  }
  // The roles' and the environments' name the policy.change they came from.
  const [policy] = await rows<{ seq: string | number }>(db.owner, sql`SELECT max(seq) AS seq FROM audit_log WHERE action = 'policy.change' AND decision = 'allow'`);
  const [rolesGenesis] = await db.owner.select({ payload: logChanges.payload }).from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'roles', id: 'instance' })));
  assert.equal((JSON.parse(rolesGenesis!.payload) as { old?: string }).old, String(policy!.seq));

  // The anchor: its own 0.14 entry, the head as it stands, which the vault wrote under its MAC.
  const [cutover] = await marker();
  const [entry] = await rows<{ seq: string | number; action: string; author: string; decision: string }>(db.owner, sql`SELECT seq, action, author, decision FROM audit_log ORDER BY seq DESC LIMIT 1`);
  assert.deepEqual([entry!.action, entry!.author, entry!.decision, String(entry!.seq)], ['log.cutover', 'vault', 'allow', cutover!.anchor.seq]);
  assert.equal(cutover!.anchor.hash, (await head()).hash);
  // Every change of the log is numbered before the cutover's: its geneses only (AnchorHolds).
  const [{ last }] = await rows<{ last: string | number }>(db.owner, sql`SELECT max(number) AS last FROM log_changes`);
  const [{ number }] = await rows<{ number: string | number }>(db.owner, sql`SELECT number FROM log_changes WHERE object = ${CUTOVER_OBJECT}`);
  assert.equal(String(last), String(number));
  // 0.14's chain still verifies, its new entry the vault's.
  assert.equal((await w.old.verifyLog({})).ok, true);
});

test('cut over once: a start that finds the marker reads it with no lock and does nothing; a later cutover call is done', async () => {
  const w = await instance014();
  const first = await vault015(w.config);
  assert.deepEqual(await cutOver(first), { ok: true, done: true });
  const before = (await changes()).length;
  const again = await vault015(w.config);
  assert.deepEqual(await again.cutover!(), { ok: true, done: true });
  assert.deepEqual(await cutOver(again), { ok: true, done: true });
  assert.equal((await changes()).length, before);
  assert.equal((await marker()).length, 1);
});

test('two vaults cutting over at once make one cutover: the second finds the marker under the locks', postgresOnly('SQLite runs one writer at a time'), async () => {
  const w = await instance014();
  const [one, two] = [await vault015(w.config), await vault015(w.config, await db.connect())];
  const [a, b] = [await one.cutover!(), await two.cutover!()];
  assert.ok(a.ok && !a.done && b.ok && !b.done);
  const to = await head();
  const outcomes = await Promise.all([one.cutover!({ checked: { from: a.from, to }, ...NONE }), two.cutover!({ checked: { from: b.from, to }, ...NONE })]);
  assert.deepEqual(outcomes, [{ ok: true, done: true }, { ok: true, done: true }]);
  assert.equal((await marker()).length, 1);
  assert.deepEqual(await opsOf({ kind: 'principal', id: ROOT }), ['genesis']);
});

test("a cutover committed and not yet sealed serves nothing: another vault that finds its marker waits for the seal, as the one that wrote it does (R51)", async () => {
  const w = await instance014();
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  // One checkpointer for both, as a deployment has: it seals nothing until released.
  let sealed = false;
  const sealThrough = async () => {
    await held;
    sealed = true;
    return {} as Sealed;
  };
  const first = await openRaw(db.vault as never, w.config, { log: '0.15', sealThrough });
  const cutting = cutOver(first);
  // Committed, its seal awaited.
  await waitFor(async () => (await marker()).length === 1);
  const second = await openRaw(db.vault as never, w.config, { log: '0.15', sealThrough });
  let answered = false;
  const asked = second.cutover!().then((outcome) => ((answered = true), outcome));
  const deciding = second.setAccess({ actor: ROOT, caller: 'person', principal: ADA, changes: [] }).then(() => (answered = true), () => (answered = true));
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(answered, false, 'nothing answered before the seal');
  release();
  assert.deepEqual(await cutting, { ok: true, done: true });
  assert.deepEqual(await asked, { ok: true, done: true });
  await deciding;
  assert.ok(sealed);
});

test("places 0.14 deleted: a deleted project's standing environment becomes `dev~deleted`, sealed deleted, its keys archived with no object; an environment deleted alone sealed deleted (T130)", async () => {
  const w = await instance014();
  const { environments, projects, secrets, secretVersions } = tablesOf(db.owner);
  const live = await w.key(w.prod);
  const gone = await w.key(w.dev);
  // An environment deleted alone, beside: its own dated tombstone, its key erased and left unarchived, as 0.14 leaves it.
  const alone = randomUUID();
  await db.owner.insert(environments).values({ id: alone, projectId: w.project, slug: 'qa~deleted-2026-10-05', name: 'QA' });
  // Then the project deleted: 0.14 tombstones its slug alone, and erases every key's versions, leaving them unarchived.
  const tombstone = 'market~deleted-2026-10-27';
  await db.owner.update(projects).set({ slug: tombstone }).where(eq(projects.id, w.project));
  await db.owner.update(secretVersions).set({ wrappedDek: Buffer.alloc(0), ciphertext: Buffer.alloc(0) }).where(eq(secretVersions.secretId, gone.secretId));
  const deleted: CutoverInput['deleted'] = [{ kind: 'project', id: w.project, tombstone }, { kind: 'environment', id: alone, tombstone: 'qa~deleted-2026-10-05' }];
  assert.deepEqual(await cutOver(await vault015(w.config), { ...NONE, deleted }), { ok: true, done: true });

  const slugs = Object.fromEntries((await db.owner.select({ id: environments.id, slug: environments.slug }).from(environments).where(eq(environments.projectId, w.project))).map((row) => [row.id, row.slug]));
  assert.deepEqual(slugs, { [w.dev]: 'dev~deleted', [w.prod]: 'prod~deleted', [alone]: 'qa~deleted-2026-10-05' });
  for (const id of [w.dev, w.prod, alone]) {
    assert.deepEqual(await opsOf({ kind: 'environment', id }), ['genesis']);
    const { row } = await store.readObject(db.owner, { kind: 'environment', id });
    assert.equal(row?.kind === 'environment' && row.deleted, true, id);
  }
  // Every key under a deleted place: archived, no object, no change, as the live deletion leaves it.
  for (const key of [live, gone]) {
    assert.deepEqual(await opsOf({ kind: 'secret', id: key.secretId }), [], key.path);
    const [row] = await db.owner.select({ archivedAt: secrets.archivedAt, seal: secrets.seal }).from(secrets).where(eq(secrets.id, key.secretId));
    assert.ok(row!.archivedAt !== null && row!.seal === null, key.path);
  }
  await holdsReplay(w.config, [w.dev, w.prod, alone].map((id) => ({ kind: 'environment' as const, id })));
});

test('a slug and 0.14\'s chain disagreeing about a deletion refuse the cutover, nothing sealed: a deleted project renamed back, a live one given a tombstone, an environment tombstoned with no entry', async () => {
  const cases: [string, (w: Awaited<ReturnType<typeof instance014>>) => Promise<CutoverInput['deleted']>, RegExp][] = [
    ['renamed back', async (w) => [{ kind: 'project', id: w.project, tombstone: 'market~deleted-2026-10-27' }], /not the tombstone its project.delete gave it/],
    ['tombstoned live', async (w) => {
      await db.owner.update(tablesOf(db.owner).projects).set({ slug: 'market~deleted-2026-10-27' }).where(eq(tablesOf(db.owner).projects.id, w.project));
      return [];
    }, /a tombstone no authentic project.delete gave it/],
    ['an environment tombstoned', async (w) => {
      await db.owner.update(tablesOf(db.owner).environments).set({ slug: 'dev~deleted' }).where(eq(tablesOf(db.owner).environments.id, w.dev));
      return [];
    }, /a tombstone no authentic deletion gave it/],
  ];
  for (const [name, setUp, why] of cases) {
    await emptyDatabase(db.owner);
    const w = await instance014();
    const deleted = await setUp(w);
    const outcome = await cutOver(await vault015(w.config), { ...NONE, deleted });
    assert.ok(!outcome.ok && outcome.refused === 'refused' && why.test(outcome.why), `${name}: ${JSON.stringify(outcome)}`);
    assert.deepEqual(await changes(), [], name);
    assert.deepEqual(await marker(), [], name);
    // Said in 0.14's log, denied, once.
    const [said] = await rows<{ action: string; decision: string }>(db.owner, sql`SELECT action, decision FROM audit_log WHERE action = 'log.cutover'`);
    assert.deepEqual([said?.action, said?.decision], ['log.cutover', 'deny'], name);
  }
});

test('a key archived before the cutover gets its object and its delete, so its unarchive restores it (T144)', async () => {
  const w = await instance014();
  const { secrets } = tablesOf(db.owner);
  const key = await w.key(w.dev);
  await db.owner.update(secrets).set({ archivedAt: new Date() }).where(eq(secrets.id, key.secretId));
  assert.deepEqual(await cutOver(await vault015(w.config)), { ok: true, done: true });
  const ref = { kind: 'secret' as const, id: key.secretId };
  assert.deepEqual(await opsOf(ref), ['genesis', 'secret.delete']);
  const [row] = await db.owner.select({ seal: secrets.seal, archivedAt: secrets.archivedAt }).from(secrets).where(eq(secrets.id, key.secretId));
  assert.ok(row!.seal === null && row!.archivedAt !== null);
  // What an unarchive restores: the object its rows make, unarchived, as the genesis sealed it.
  const kept = (await keptObjects(w.config.signingKeys.map(sealKey), db.owner, [ref])).get(objectKey(ref));
  const { row: asRows } = await store.readObject(db.owner, ref, { archived: true });
  assert.deepEqual(kept?.object, asRows);
});

test("a key whose current version is not its newest, or not its own, rolled back around the app, is left unsealed, reported: 0.14 reads no source so (reviews r2, r5)", async () => {
  const w = await instance014();
  const { secretVersions } = tablesOf(db.owner);
  const key = await w.key(w.prod);
  const [first] = await db.owner.select({ id: secretVersions.id }).from(secretVersions).where(eq(secretVersions.secretId, key.secretId));
  const second = { ...key, version: 2 };
  const wrapped = await w.old.wrap({ principal: ROOT, items: [{ secret: second, key: randomBytes(32).toString('base64') }] });
  assert.ok(wrapped.ok);
  const [{ secretVersionId }] = await storedVersions(db.owner, [{ secret: second, wrapped: wrapped.wrapped[0]! }]);
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${secretVersionId}, current_version = 2 WHERE id = ${key.secretId}`);
  const kept = await w.key(w.prod);
  // Version 1 put back as current: a value rolled back, which 0.14's read through a reference refuses (`versions`).
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${first!.id}, current_version = 1 WHERE id = ${key.secretId}`);
  // Another of its versions given to another key (review r5): A's v1 and v2 genuine; v1 moved under a spare key as its
  // v2, and A's current pointed at it. A's newest is still a 2, its own v2: only the version's key tells.
  const other = await w.key(w.prod);
  const [v1] = await db.owner.select({ id: secretVersions.id }).from(secretVersions).where(eq(secretVersions.secretId, other.secretId));
  const otherSecond = { ...other, version: 2 };
  const wrappedSecond = await w.old.wrap({ principal: ROOT, items: [{ secret: otherSecond, key: randomBytes(32).toString('base64') }] });
  assert.ok(wrappedSecond.ok);
  const [{ secretVersionId: v2 }] = await storedVersions(db.owner, [{ secret: otherSecond, wrapped: wrappedSecond.wrapped[0]! }]);
  void v2;
  const spare = await w.key(w.prod);
  await withTriggersLifted(db.owner, 'secret_versions', (tx) => run(tx, sql`UPDATE secret_versions SET secret_id = ${spare.secretId}, version = 2 WHERE id = ${v1!.id}`));
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${v1!.id}, current_version = 2 WHERE id = ${other.secretId}`);
  assert.deepEqual(await cutOver(await vault015(w.config)), { ok: true, done: true });
  assert.deepEqual(await opsOf({ kind: 'secret', id: key.secretId }), []);
  assert.deepEqual(await opsOf({ kind: 'secret', id: other.secretId }), []);
  // The spare too: given another's version as its v2, its own current is not its newest.
  assert.deepEqual(await opsOf({ kind: 'secret', id: spare.secretId }), []);
  assert.deepEqual(await opsOf({ kind: 'secret', id: kept.secretId }), ['genesis']);
  const reports = await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered'`);
  assert.deepEqual(reports.map(({ code }) => code), ['stale', 'stale', 'stale']);
});

test("nothing of 0.15's log is written before the cutover: an Owner the deployment names, asked about, is made none until it is (review r2, AnchorHolds)", async () => {
  const w = await instance014();
  const named = await openRaw(db.vault as never, { ...w.config, owners: [...w.config.owners, 'eve@acme.example'] }, { log: '0.15', sealThrough: sealed });
  const eve = await named.access('user:eve@acme.example');
  assert.notEqual(eve.status, 'active');
  assert.deepEqual(await rows(db.owner, sql`SELECT number FROM log_changes`), []);
  assert.deepEqual(await rows(db.owner, sql`SELECT seq FROM audit_log WHERE action = 'member.add' AND subject_principal = 'user:eve@acme.example'`), []);
  // A change the app would log, an object it makes, waits for the cutover too; one of 0.14's rows alone logs nothing.
  const columns = { id: randomUUID(), principal: CI, kind: 'service', scope: null, revoked: false, expiresAt: Date.now() + 60_000, generation: 0 };
  await assert.rejects(named.prepare!({ actor: ROOT, changes: [{ kind: 'credential', id: columns.id, before: null, after: columns }] }), /not cut over from 0.14 yet/);
  const outcome = await named.prepare!({ actor: ROOT, changes: [{ kind: 'credential', id: columns.id, before: { columns, seal: null }, after: { ...columns, revoked: true } }] });
  assert.ok(outcome.ok && outcome.changes.every((change) => change.payload === null), JSON.stringify(outcome));
  // Cut over, the next ask makes them one, a change of the log after the cutover's.
  assert.deepEqual(await cutOver(named), { ok: true, done: true });
  assert.equal((await named.access('user:eve@acme.example')).role, 'owner');
  assert.deepEqual(await opsOf({ kind: 'principal', id: 'user:eve@acme.example' }), ['member.add']);
});

test("a reference 0.14 ended is ended in its row before its holder's genesis, which reads no source; one no authentic reference.create made, whose holder was moved since, or whose row says it ended with no reference.end (review r6), leaves its holder unsealed, reported", async () => {
  const w = await instance014();
  const { secretReferences } = tablesOf(db.owner);
  const source = await w.key(w.prod);
  const holder = async () => (await w.secret(w.dev)).secretId;
  const [ended, standing, planted, moved, marked] = [await holder(), await holder(), await holder(), await holder(), await holder()];
  const columns = { projectId: w.project, environmentId: w.dev, sourceProjectId: w.project, sourceEnvironmentId: w.prod, sourceSecretId: source.secretId, createdBy: ROOT };
  const reference = async (id: string) => {
    const made = randomUUID();
    const outcome = await w.old.reference({ principal: ROOT, items: [{ id: made, holder: { projectId: w.project, environmentId: w.dev, secretId: id, path: 'p/dev/HELD' }, source: { secretId: source.secretId } }] });
    assert.ok(outcome.ok, JSON.stringify(outcome));
    await db.owner.insert(secretReferences).values({ id: made, secretId: id, ...columns, createdSeq: BigInt(outcome.seqs[0]!) });
    return { reference: made, seq: outcome.seqs[0]! };
  };
  const endedVia = await reference(ended);
  const standingVia = await reference(standing);
  const [endedRow, standingRow] = [endedVia.reference, standingVia.reference];
  // 0.14's end: its vault entry alone, no row's end.
  assert.ok((await w.old.endReferences({ principal: ROOT, reason: 'broken', items: [endedVia] })).ok);
  // A reference row no reference.create made: planted, naming an entry of another kind (Root's admission, the first).
  await db.owner.insert(secretReferences).values({ id: randomUUID(), secretId: planted, ...columns, createdSeq: 0n });
  // A genuine one's holder moved to prod around the vault, its id and reference row kept: prod's readers would read
  // the source through it, where 0.14 refuses them (review r1).
  await reference(moved);
  await run(db.owner, sql`UPDATE secrets SET environment_id = ${w.prod} WHERE id = ${moved}`);
  // A genuine one's row marked ended around the vault, with no reference.end: 0.14 still reads through it (review r6).
  await reference(marked);
  await run(db.owner, sql`UPDATE secret_references SET ended_at = CURRENT_TIMESTAMP WHERE secret_id = ${marked}`);

  assert.deepEqual(await cutOver(await vault015(w.config)), { ok: true, done: true });
  const objectOf = async (id: string) => (await store.readObject(db.owner, { kind: 'secret', id })).row as Extract<Input, { kind: 'secret' }> | null;
  // Ended: its row's end written, its object reads nothing (`ended`).
  const [row] = await db.owner.select({ endedAt: secretReferences.endedAt }).from(secretReferences).where(eq(secretReferences.id, endedRow));
  assert.ok(row!.endedAt !== null);
  assert.deepEqual([(await objectOf(ended))?.source, await opsOf({ kind: 'secret', id: ended })], [null, ['genesis']]);
  // Standing: its source, through its row.
  assert.deepEqual([(await objectOf(standing))?.source, (await objectOf(standing))?.reference], [source.secretId, standingRow]);
  // Planted, or moved: no genesis, each reported.
  assert.deepEqual(await opsOf({ kind: 'secret', id: planted }), []);
  assert.deepEqual(await opsOf({ kind: 'secret', id: moved }), []);
  assert.deepEqual(await opsOf({ kind: 'secret', id: marked }), []);
  const reports = await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered'`);
  assert.deepEqual(reports.map(({ code }) => code), ['mac', 'mac', 'mac']);
  await holdsReplay(w.config, [{ kind: 'secret', id: ended }, { kind: 'secret', id: standing }]);
});

test("history before 0.14's newest checkpoint damaged refuses the cutover: a reference's end, checkpointed, its entry edited, is never taken for no end (review r4, VerifyChain)", async () => {
  const w = await instance014();
  const { secretReferences, auditLog } = tablesOf(db.owner);
  const source = await w.key(w.prod);
  const holder = (await w.secret(w.dev)).secretId;
  const id = randomUUID();
  const outcome = await w.old.reference({ principal: ROOT, items: [{ id, holder: { projectId: w.project, environmentId: w.dev, secretId: holder, path: 'p/dev/HELD' }, source: { secretId: source.secretId } }] });
  assert.ok(outcome.ok);
  await db.owner.insert(secretReferences).values({ id, secretId: holder, projectId: w.project, environmentId: w.dev, sourceProjectId: w.project, sourceEnvironmentId: w.prod, sourceSecretId: source.secretId, createdSeq: BigInt(outcome.seqs[0]!), createdBy: ROOT });
  assert.ok((await w.old.endReferences({ principal: ROOT, reason: 'broken', items: [{ reference: id, seq: outcome.seqs[0]! }] })).ok);
  // Checkpointed, so the walk from the newest checkpoint never reads it; then its entry edited in place.
  const signed = await w.old.checkpoint();
  assert.ok(signed.ok, JSON.stringify(signed));
  await withLogUnlocked(db.owner, (tx) => tx.update(auditLog).set({ metadata: '{}', relatedSeq: null }).where(eq(auditLog.action, 'reference.end')));
  const refused = await cutOver(await vault015(w.config));
  assert.ok(!refused.ok && refused.refused === 'refused' && /does not verify|not the prefix/.test(refused.why), JSON.stringify(refused));
  assert.deepEqual(await changes(), []);
});

test("a member whose row 0.14's check refuses is left unsealed, reported, every other sealed: never a writer's row in the log (VerifyRows)", async () => {
  const w = await instance014();
  assert.ok((await w.old.admit({ actor: ROOT, principal: ADA })).ok);
  assert.ok((await w.old.admit({ actor: ROOT, principal: CI })).ok);
  // A grant written around the vault: Ada's row's MAC no longer holds.
  const { vaultGrants } = tablesOf(db.owner);
  await db.owner.insert(vaultGrants).values({ principal: ADA, projectId: w.project, environmentId: null, environmentSlug: null, role: 'owner', grantedAt: Date.now(), grantedBy: ROOT });
  assert.deepEqual(await cutOver(await vault015(w.config)), { ok: true, done: true });
  assert.deepEqual(await opsOf({ kind: 'principal', id: ADA }), []);
  assert.deepEqual(await opsOf({ kind: 'principal', id: CI }), ['genesis']);
  const reports = await rows<{ code: string; subject_principal: string }>(db.owner, sql`SELECT code, subject_principal FROM audit_log WHERE action = 'vault.tampered'`);
  assert.deepEqual(reports.map((report) => [report.code, report.subject_principal]), [['mac', ADA]]);
});

test('what the app vouched for, held to its rows: a credential sealed as vouched; one moved since, or an app entry since, asks the app again; one not vouched for stays unsealed (VouchedHeld)', async () => {
  const w = await instance014();
  assert.ok((await w.old.admit({ actor: ROOT, principal: CI })).ok);
  const { credentials } = tablesOf(db.owner);
  const credential = async () => {
    const id = randomUUID();
    const expiresAt = new Date(Math.floor(Date.now() / 1000) * 1000 + 3_600_000);
    await db.owner.insert(credentials).values({ id, kind: 'service', authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, principal: CI, createdBy: ROOT, expiresAt });
    return { id, principal: CI, kind: 'service', scope: null, revoked: false, expiresAt: expiresAt.getTime(), generation: 0 };
  };
  const [vouched, unvouched] = [await credential(), await credential()];
  const vault = await vault015(w.config);
  const asked = await vault.cutover!();
  assert.ok(asked.ok && !asked.done);
  // Revoked since the app read it.
  await db.owner.update(credentials).set({ revokedAt: new Date() }).where(eq(credentials.id, vouched.id));
  const moved = await vault.cutover!({ checked: { from: asked.from, to: await head() }, ...NONE, credentials: [vouched] });
  assert.ok(!moved.ok && moved.refused === 'moved', JSON.stringify(moved));
  await db.owner.update(credentials).set({ revokedAt: null }).where(eq(credentials.id, vouched.id));
  // An entry of the app's written since the head it checked to: what it vouched for may have moved.
  const checkedTo = await head();
  const appKey = { author: 'app' as const, keyId: 'app:test', key: randomBytes(32) };
  await db.owner.transaction((tx) => appendEntries(tx, appKey, [{ actor: ROOT, action: 'token.revoke', decision: 'allow', metadata: JSON.stringify({ targetCredentialId: vouched.id }) }]));
  const late = await vault.cutover!({ checked: { from: asked.from, to: checkedTo }, ...NONE, credentials: [vouched] });
  assert.ok(!late.ok && late.refused === 'moved', JSON.stringify(late));
  assert.deepEqual(await changes(), []);
  // As read again: sealed, the other one not.
  assert.deepEqual(await vault.cutover!({ checked: { from: asked.from, to: await head() }, ...NONE, credentials: [vouched] }), { ok: true, done: true });
  assert.deepEqual(await opsOf({ kind: 'credential', id: vouched.id }), ['genesis']);
  assert.deepEqual(await opsOf({ kind: 'credential', id: unvouched.id }), []);
  const [sealedRow] = await db.owner.select({ seal: credentials.seal }).from(credentials).where(eq(credentials.id, vouched.id));
  assert.ok(sealedRow!.seal !== null);
});

test("a binding made on 0.14, vouched for, is sealed with the instance it was made on, and a run signs in through it right after the cutover; one not vouched for, or edited since, signs nobody in (T160)", async () => {
  const w = await instance014();
  assert.ok((await w.old.admit({ actor: ROOT, principal: CI })).ok);
  const { serviceBindings } = tablesOf(db.owner);
  const ISSUER = 'https://token.actions.githubusercontent.com';
  const ORIGIN = 'https://secrets.acme.example';
  // As 0.14's app made them: no seal, and no origin, a column of 0.15's.
  const binding = async () => {
    const id = randomUUID();
    const row = { id, principal: CI, generation: 0, profile: 'github', issuer: ISSUER, jwksUri: `${ISSUER}/.well-known/jwks`, claims: '{"repository_id":"1"}', scope: null, policy: null };
    await db.owner.insert(serviceBindings).values({ ...row, authMac: randomBytes(32), label: null, createdBy: ROOT, createdAt: new Date() });
    return { ...row, origin: ORIGIN, revoked: false };
  };
  const [vouched, unvouched, edited, named] = [await binding(), await binding(), await binding(), await binding()];
  // An instance written into one of 0.14's around the app, which its MAC does not cover: no row of 0.14's names one (review r2).
  await db.owner.update(serviceBindings).set({ origin: 'https://elsewhere.example' }).where(eq(serviceBindings.id, named.id));
  const vault = await vault015(w.config);
  assert.deepEqual(await cutOver(vault, { ...NONE, bindings: [vouched, edited, named] }), { ok: true, done: true });
  assert.deepEqual(await opsOf({ kind: 'binding', id: named.id }), []);
  assert.deepEqual(await opsOf({ kind: 'binding', id: vouched.id }), ['genesis']);
  assert.deepEqual(await opsOf({ kind: 'binding', id: unvouched.id }), []);
  const rowsOf_ = async () => Object.fromEntries((await db.owner.select({ id: serviceBindings.id, seal: serviceBindings.seal, origin: serviceBindings.origin }).from(serviceBindings)).map((row) => [row.id, row]));
  const rows_ = await rowsOf_();
  const keys = w.config.signingKeys.map(sealKey);
  // Sealed with the instance it was made on, which its row now says too: its runs' tokens name it (PR 3b).
  assert.deepEqual(rows_[vouched.id]!.seal, sealOf(keys[0]!, { kind: 'binding', id: vouched.id }, { kind: 'binding', ...vouched, scope: null }));
  assert.equal(rows_[vouched.id]!.origin, ORIGIN);
  assert.deepEqual([rows_[unvouched.id]!.seal, rows_[unvouched.id]!.origin], [null, null]);
  // Edited around the app after it was sealed: a claim widened.
  await db.owner.update(serviceBindings).set({ claims: '{"repository_id":"2"}' }).where(eq(serviceBindings.id, edited.id));

  const signIn = async (columns: typeof vouched) => {
    const [row] = await db.owner.select({ seal: serviceBindings.seal }).from(serviceBindings).where(eq(serviceBindings.id, columns.id));
    const now = Date.now();
    return vault.signIn!({
      principal: CI, binding: { columns, seal: row!.seal == null ? null : Buffer.from(row!.seal).toString('base64') },
      credential: {
        id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_svc_x', label: 'deploys', scope: null,
        places: null, expiresAt: now + 5 * 60_000, notAfter: null, jkt: null, authMac: randomBytes(32).toString('base64'),
      },
      appKey: 'app:0123456789abcdef', spent: randomBytes(32).toString('base64'), validUntil: now + 60_000, record: { proof: 'oidc', issuer: ISSUER, run: { run_id: '7001' } },
      idToken: null, dpop: null,
    });
  };
  const made = await signIn(vouched);
  assert.ok(made.ok, JSON.stringify(made));
  for (const [name, columns] of [['not vouched for', unvouched], ['edited since', { ...edited, claims: '{"repository_id":"2"}' }], ['naming another instance', { ...named, origin: 'https://elsewhere.example' }]] as const) {
    const refused = await signIn(columns);
    assert.ok(!refused.ok, `${name}: ${JSON.stringify(refused)}`);
  }
});

test("0.14's chain broken since its newest checkpoint refuses the cutover: a vault entry edited past its MAC (VerifyChain)", async () => {
  const w = await instance014();
  assert.ok((await w.old.admit({ actor: ROOT, principal: ADA })).ok);
  const { auditLog } = tablesOf(db.owner);
  await withLogUnlocked(db.owner, async (tx) => {
    await tx.update(auditLog).set({ metadata: '{"forged":true}' }).where(eq(auditLog.subjectPrincipal, ADA));
  });
  const outcome = await cutOver(await vault015(w.config));
  assert.ok(!outcome.ok && outcome.refused === 'refused' && /does not verify/.test(outcome.why), JSON.stringify(outcome));
  assert.deepEqual(await changes(), []);
});

test('the cutover takes the issue lock before the fence, beside a barrier that holds the issue lock and waits for the fence: neither waits on the other in a circle (CutoverIssueFirst, T132)', postgresOnly('the locks are advisory locks of Postgres'), async () => {
  const w = await instance014();
  const vault = await vault015(w.config);
  const asked = await vault.cutover!();
  assert.ok(asked.ok && !asked.done);
  // The checkpointer's barrier, half way: the issue lock exclusive, then (below) the fence.
  const barrier = postgresSession(OWNER_URL);
  try {
    await barrier.unsafe('BEGIN');
    await barrier.unsafe('SELECT pg_advisory_xact_lock(1668244070, 1)');
    const cutover = vault.cutover!({ checked: { from: asked.from, to: await head() }, ...NONE });
    // The cutover waits for the issue lock, holding 0.14's head: never the fence.
    await waitFor(async () => (await rows(db.owner, sql`SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = 1668244070 AND objid = 1 AND NOT granted`)).length > 0);
    await barrier.unsafe("SET LOCAL lock_timeout = '2s'");
    await barrier.unsafe('SELECT pg_advisory_xact_lock(1668244070, 0)');
    await barrier.unsafe('COMMIT');
    assert.deepEqual(await cutover, { ok: true, done: true });
  } finally {
    await barrier.end();
  }
});

async function waitFor(holds: () => Promise<boolean>): Promise<void> {
  for (let tries = 0; tries < 200; tries += 1) {
    if (await holds()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail('waited too long');
}

test('the log cut over, every 0.14 entry named by its vault key: the anchor holds under `vaultLogKey`', async () => {
  const w = await instance014();
  assert.deepEqual(await cutOver(await vault015(w.config)), { ok: true, done: true });
  const [cutover] = await marker();
  const [entry] = await rows<{ key_id: string }>(db.owner, sql`SELECT key_id FROM audit_log WHERE seq = ${BigInt(cutover!.anchor.seq)}`);
  assert.equal(entry!.key_id, vaultLogKey(w.config.signingKeys[0]!).keyId);
  void ENGINE;
});
