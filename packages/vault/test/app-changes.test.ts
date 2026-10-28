// 0.15's change path for the app's own rows (docs/design/0.15-plan.md, "As built: PR 4b"): the vault seals a change
// from the row's columns as the app read them and as it will write them (`prepare`), and the app's transaction commits
// it beside its row (`app_change`, migration 0025). Each case names the part of formal/HotPathOne.tla or
// formal/Migration015.tla it holds, and runs on both engines unless it says otherwise: SQLite runs `app_change`'s twin
// (@coffre/db/log), under its one writer. The app's transaction is the owner's here: the grants are test:schema's.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { TOMBSTONE } from '@coffre/core/schemas';
import type { CredentialColumns, ObjectChange, PreparedChange } from '@coffre/core/vault';
import { tablesOf, type Transaction } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { postgresSession, type PostgresClient } from '@coffre/db/connect';
import { appChanges, appendEntries, isStaleChange } from '@coffre/db/log';
import { asc, eq, sql } from 'drizzle-orm';

import { genesisCall, loggedChange, type ChangeKeys } from '../src/changes.ts';
import type { Sealed } from '../src/checkpointer.ts';
import type { ResolvedVaultConfig } from '../src/config.ts';
import { objectKey, sealKey, sealOf, type EnvironmentInput, type Ref } from '../src/inputs.ts';
import { authentic, changeEntry, logMacKey } from '../src/log-entry.ts';
import { replay, type LoggedChange } from '../src/log-replay.ts';
import { credentialObject, environmentObject } from '../src/objects.ts';
import * as store from '../src/store.ts';
import type { VaultOptions } from '../src/vault.ts';
import { sealThroughDouble } from './audit-tree.ts';
import { emptyDatabase, newProject, openLocalVault, openTestDatabase, OWNER_URL, postgresOnly, rows, sealed, type TestDatabase } from './database.ts';

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
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  };
}

/** A vault keeping 0.15's log, whatever the suite's setting, its changes sealed at once unless `options` says how. */
async function world(options: VaultOptions = {}) {
  const config = configure();
  const vault = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed, ...options });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  // The service account the tokens are of: a credential's principal is a member (its row's foreign key).
  assert.ok((await vault.admit({ actor: ROOT, principal: CI })).ok);
  const keys: ChangeKeys = { seals: config.signingKeys.map((seed) => sealKey(seed)), mac: logMacKey(config.signingKeys[0]!) };
  return { vault, keys };
}

type World = Awaited<ReturnType<typeof world>>;

/** A credential's row, as the app writes it, with the columns its object takes. */
type Row = { id: string; principal: string; kind: string; scope: string | null; revokedAt: Date | null; expiresAt: Date };

function columns(row: Row): CredentialColumns {
  return { id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: row.revokedAt !== null, expiresAt: row.expiresAt.getTime() };
}

const SCOPE = JSON.stringify([{ projectId: randomUUID(), environmentId: null, role: 'viewer', permissions: { normal: ['secret.read'], protected: [] }, sensitive: false }]);

function token(at = Date.now()): Row {
  return { id: randomUUID(), principal: CI, kind: 'service', scope: SCOPE, revokedAt: null, expiresAt: new Date(at + 3_600_000) };
}

/** The row as stored, with its seal; null if there is none. */
async function stored(id: string): Promise<(Row & { seal: Buffer | null }) | null> {
  const { credentials } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, id));
  return row === undefined ? null : { ...row, seal: row.seal ?? null };
}

/** The changes the vault prepares for a row going from `before` (as read now, with its seal) to `after`. */
async function prepare(w: World, after: Row, before: Row | null = null, seal?: Buffer | null): Promise<PreparedChange[]> {
  const read = before === null ? null : await stored(before.id);
  const change: ObjectChange = {
    kind: 'credential', id: after.id, before: before === null ? null : { columns: columns(before), seal: (seal === undefined ? read?.seal ?? null : seal)?.toString('base64') ?? null }, after: columns(after),
  };
  const outcome = await w.vault.prepare!({ actor: ROOT, changes: [change] });
  assert.ok(outcome.ok, JSON.stringify(outcome));
  return outcome.changes;
}

/**
 * The app's transaction: its row written as `after`, then its changes committed, as `audited` does, after 0.14's
 * entries; rolled back, as `AppChanges.commit` makes it, if a seal moved since the change was prepared (`Moved`).
 */
async function write(after: Row, calls: readonly PreparedChange[], exists: boolean): Promise<(bigint | null)[]> {
  const { credentials } = tablesOf(db.owner);
  return db.owner.transaction(async (tx: Transaction) => {
    if (exists) await tx.update(credentials).set({ revokedAt: after.revokedAt, expiresAt: after.expiresAt, scope: after.scope }).where(eq(credentials.id, after.id));
    else await tx.insert(credentials).values({ ...after, authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, createdBy: ROOT });
    const numbers = await appChanges(tx, calls);
    if (numbers.includes(null)) throw new Moved();
    return numbers;
  });
}

class Moved extends Error {}

/** 0.15's log of changes as the replay takes them, each MAC the vault's. */
async function logged(keys: ChangeKeys): Promise<LoggedChange[]> {
  const { logChanges } = tablesOf(db.owner);
  const holds = authentic(keys.mac);
  return (await db.owner.select().from(logChanges).orderBy(asc(logChanges.number))).map((raw) => {
    const row = { ...raw, number: BigInt(raw.number), seal: raw.seal ?? null };
    assert.ok(holds(changeEntry(row)), `entry ${row.number}'s MAC is the vault's`);
    const change = loggedChange(row);
    assert.ok(change !== null, `entry ${row.number} names its object`);
    return change;
  });
}

/** The log replayed (HotPathOne's ReplaySound): the credential's row is the replay's object, under its newest change's seal. */
async function holdsReplay(keys: ChangeKeys, id: string): Promise<void> {
  const replayed = replay(keys.seals, await logged(keys));
  assert.deepEqual(replayed.faults, []);
  const ref: Ref = { kind: 'credential', id };
  const live = await stored(id);
  const log = replayed.rows.get(objectKey(ref));
  assert.ok(live !== null && log !== undefined, 'the credential is in the rows and the log');
  assert.deepEqual(credentialObject(columns(live)), log.row, 'the row is the replay\'s object');
  assert.deepEqual(live.seal, log.seal, 'the row carries its newest change\'s seal');
  assert.deepEqual(live.seal, sealOf(keys.seals[0]!, ref, credentialObject(columns(live))), 'the seal is the vault\'s over the row');
}

async function opsOf(keys: ChangeKeys, id: string): Promise<string[]> {
  return (await logged(keys)).filter((change) => change.ref.kind === 'credential' && change.ref.id === id).map((change) => change.op.op);
}

test('a credential\'s life, each write of the app\'s one change beside its row, and the log replays to the row', async () => {
  const w = await world();
  const row = token();
  assert.ok((await write(row, await prepare(w, row), false)).every((number) => number !== null && number > 0n));
  await holdsReplay(w.keys, row.id);
  // Its end moved, its scope written, then revoked: each as the replay applies it, in that order, from the seal before.
  const moved = { ...row, expiresAt: new Date(row.expiresAt.getTime() + 60_000), scope: JSON.stringify([]) };
  assert.equal((await write(moved, await prepare(w, moved, row), true)).length, 2);
  await holdsReplay(w.keys, row.id);
  const revoked = { ...moved, revokedAt: new Date() };
  await write(revoked, await prepare(w, revoked, moved), true);
  await holdsReplay(w.keys, row.id);
  assert.deepEqual(await opsOf(w.keys, row.id), ['credential.issue', 'credential.scope', 'credential.renew', 'credential.revoke']);
  // Columns no object holds (its MAC, its last use) are no change.
  assert.deepEqual(await prepare(w, revoked, revoked), []);
});

test('a revoke undone in the database, its old seal put back, is refused at the next change (ChangeChecksSeal)', async () => {
  const w = await world();
  const row = token();
  await write(row, await prepare(w, row), false);
  const live = (await stored(row.id))!.seal;
  const revoked = { ...row, revokedAt: new Date() };
  await write(revoked, await prepare(w, revoked, row), true);
  // The writer puts back the live row, with the seal the vault made over it once: valid, but not the newest change's.
  const { credentials } = tablesOf(db.owner);
  await db.owner.update(credentials).set({ revokedAt: null, seal: live }).where(eq(credentials.id, row.id));
  // The vault takes the seal (it is its own); the change, under the fence, finds it is not the newest, and fails.
  const renewed = { ...row, expiresAt: new Date(row.expiresAt.getTime() + 60_000) };
  const calls = await prepare(w, renewed, row);
  await assert.rejects(write(renewed, calls, true), (error: unknown) => isStaleChange(error));
  assert.deepEqual(await opsOf(w.keys, row.id), ['credential.issue', 'credential.revoke'], 'nothing logged');
  assert.equal((await stored(row.id))!.expiresAt.getTime(), row.expiresAt.getTime(), 'nothing written: the transaction failed');
});

test('of two changes prepared from one seal, the second does nothing; a retry finds its entry; another payload under its request is refused (ChangeCAS, fence-one)', async () => {
  const w = await world();
  const row = token();
  await write(row, await prepare(w, row), false);
  const renewed = { ...row, expiresAt: new Date(row.expiresAt.getTime() + 60_000) };
  const revoked = { ...row, revokedAt: new Date() };
  const [renew, revoke] = [await prepare(w, renewed, row), await prepare(w, revoked, row)];
  const [first] = await write(renewed, renew, true);
  assert.ok(first !== null && first > 0n);
  // The revoke was sealed from the seal the renewal moved: nothing is done, and the app reads again.
  await assert.rejects(write({ ...renewed, revokedAt: revoked.revokedAt }, revoke, true), Moved);
  assert.equal((await stored(row.id))!.revokedAt, null, 'nothing written');
  // The renewal's call again, as a connection lost after its commit would send it: its entry's number, nothing new.
  assert.deepEqual(await db.owner.transaction((tx: Transaction) => appChanges(tx, renew)), [first]);
  // Another change under its request id.
  const forged = { ...renew[0]!, payload: renew[0]!.payload!.replace('credential.renew', 'credential.revoke') };
  await assert.rejects(db.owner.transaction((tx: Transaction) => appChanges(tx, [forged])), (error: unknown) => isUniqueViolation(error));
  await holdsReplay(w.keys, row.id);
});

test('a row the vault never sealed is refused as tampered before anything is written; one the app says it never sealed is 0.14\'s, and logs nothing', async () => {
  const w = await world();
  const row = token();
  await write(row, await prepare(w, row), false);
  // The writer widens the token's scope and keeps its seal: the vault's seal is not over it.
  const widened = { ...row, scope: JSON.stringify([{ projectId: null, environmentId: null, role: 'owner', permissions: { normal: [], protected: [] }, sensitive: true }]) };
  const outcome = await w.vault.prepare!({ actor: ROOT, changes: [{ kind: 'credential', id: row.id, before: { columns: columns(widened), seal: (await stored(row.id))!.seal!.toString('base64') }, after: { ...columns(widened), revoked: true } }] });
  assert.equal(outcome.ok ? null : outcome.refusal.code, 'tampered');
  // A row from before the cutover, unsealed, with no change: its change only checks that, logging nothing (plan PR 9 seals it).
  const old = token();
  const { credentials } = tablesOf(db.owner);
  await db.owner.insert(credentials).values({ ...old, authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, createdBy: ROOT });
  const revoked = { ...old, revokedAt: new Date() };
  const calls = await prepare(w, revoked, old, null);
  assert.deepEqual(calls.map((call) => call.requestId), [null]);
  assert.deepEqual(await write(revoked, calls, true), [0n]);
  assert.deepEqual(await opsOf(w.keys, old.id), []);
  // An unsealed row whose object the log has changes of is not 0.14's: its seal was taken off (stale).
  await db.owner.update(credentials).set({ seal: null }).where(eq(credentials.id, row.id));
  await assert.rejects(write({ ...row, revokedAt: new Date() }, await prepare(w, { ...row, revokedAt: new Date() }, row, null), true), (error: unknown) => isStaleChange(error));
});

test('app_change takes only the app\'s ops, each naming its object', async () => {
  const w = await world();
  const row = token();
  const [issue] = await prepare(w, row);
  const as = (payload: string): PreparedChange => ({ ...issue!, requestId: randomUUID(), payload });
  for (const payload of [
    JSON.stringify({ op: 'genesis', value: credentialObject(columns(row)), ref: { kind: 'credential', id: row.id } }),
    JSON.stringify({ op: 'member.add', role: 'member', scope: {}, ref: { kind: 'credential', id: row.id } }),
    JSON.stringify({ op: 'credential.revoke', ref: { kind: 'credential', id: randomUUID() } }),
  ]) {
    await assert.rejects(write(row, [as(payload)], false), (error: Error) => /no change|names the object/.test(`${error.message} ${(error.cause as Error | undefined)?.message ?? ''}`));
  }
});

test('the vault answers a change of the app\'s once its entry is sealed (R51, CommitBeforeAnswer)', async () => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  // The vault's own changes as it starts are sealed at once; the one this case watches waits until released.
  let holding = false;
  const seal = sealThroughDouble(async () => {
    if (holding) await held;
    return {} as Sealed;
  });
  const w = await world({ sealThrough: seal });
  holding = true;
  const row = token();
  const [number] = await write(row, await prepare(w, row), false);
  let answered = false;
  const waiting = w.vault.waitSealed!({ number: number!.toString() }).then((outcome) => ((answered = true), outcome));
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(answered, false);
  assert.deepEqual(seal.asked.at(-1), number);
  release();
  assert.ok((await waiting).ok);
});

test('a deleted environment\'s object holds its slug before the tombstone: the cutover seals it, and its row stays as it was (0025)', async () => {
  const w = await world();
  const { environments } = tablesOf(db.owner);
  const project = await newProject(db.owner);
  const id = randomUUID();
  const slug = `dev${TOMBSTONE}deleted-2026-10-27`;
  await db.owner.insert(environments).values({ id, projectId: project, slug, name: 'Dev' });
  const read = async () => (await db.owner.select().from(environments).where(eq(environments.id, id)))[0]!;
  const object = (row: Awaited<ReturnType<typeof read>>): EnvironmentInput => environmentObject({ ...row, archived: row.archivedAt !== null, projectArchived: false });
  const before = object(await read());
  assert.deepEqual([before.slug, before.deleted], ['dev', true]);
  const ref: Ref = { kind: 'environment', id };
  const [number] = await db.vault.transaction((tx: Transaction) => store.changeInputs(tx, [genesisCall(w.keys, ref, before, Date.now(), 'system:cutover')]));
  assert.ok(number !== null, 'the cutover seals a deleted environment');
  const row = await read();
  assert.equal(row.slug, slug, 'its tombstone kept');
  // The use path's mapping of the row (objects.ts) is the object sealed: authentic, and its newest change's.
  assert.deepEqual(row.seal ?? null, sealOf(w.keys.seals[0]!, ref, object(row)));
  assert.deepEqual(row.seal ?? null, (await store.newestChange(db.owner, ref))?.seal ?? null);
});

test('a change of the app\'s waits for every use in flight, and the uses after it for its commit (ChangeLocks, LockToCommit)', postgresOnly('SQLite has one writer: the fence is implicit'), async () => {
  const w = await world();
  const row = token();
  await write(row, await prepare(w, row), false);
  // A revoke: an input every use of the credential reads, under the fence exclusive.
  const revoked = { ...row, revokedAt: new Date() };
  const calls = await prepare(w, revoked, row);
  const use = postgresSession(OWNER_URL);
  try {
    await use.unsafe('BEGIN');
    await use.unsafe('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');
    let committed = false;
    const writing = write(revoked, calls, true).then((numbers) => ((committed = true), numbers));
    await waitFor(async () => (await fenceWaiters()) > 0, 'the change waits for the use');
    assert.equal(committed, false);
    await use.unsafe('COMMIT');
    assert.ok((await writing)[0] !== null);
  } finally {
    await use.end();
  }
});

test('an issue never waits for a use, nor a use for an issue; the barrier waits for the issue on the issue lock, not on the fence (IssueOwnLock, BarrierWaitsIssues, BarrierIssueFirst; T123, R58)', postgresOnly('SQLite has one writer: the fence is implicit'), async () => {
  const w = await world();
  const [use, issuing, barrier] = [0, 1, 2].map(() => postgresSession(OWNER_URL));
  try {
    // A use in flight: the issue does not wait for it.
    await use.unsafe('BEGIN');
    await use.unsafe('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');
    const first = token();
    const writing = write(first, await prepare(w, first), false);
    const done = await Promise.race([writing, new Promise((resolve) => setTimeout(() => resolve('waiting'), 2000))]);
    assert.notEqual(done, 'waiting', 'the issue waits for no use');
    await use.unsafe('COMMIT');
    assert.ok((await writing)[0]! > 0n);

    // An issue in flight, its change numbered, not yet committed.
    const row = token();
    const [c] = await prepare(w, row);
    await issuing.unsafe('BEGIN');
    await issuing.unsafe(`INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at, scope)
      VALUES ($1, $2, $3, $4, 'x', 0, $5, $6, $7, $8)`, [row.id, row.kind, randomBytes(32), randomBytes(32), row.principal, ROOT, row.expiresAt, row.scope]);
    const [issued] = await issuing.unsafe('SELECT app_change($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL) AS number', [
      c!.kind, c!.id, c!.requestId, c!.at, c!.actor, c!.payload, null, Buffer.from(c!.seal!, 'base64'), Buffer.from(c!.mac!, 'base64'),
    ]);
    // It holds the issue lock, shared, and not the fence.
    assert.deepEqual(await advisoryHeld(issuing), ['1 ShareLock']);
    // A use meanwhile takes the fence at once.
    await use.unsafe(`SET lock_timeout = '200ms'`);
    await use.unsafe('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');

    // The barrier waits for the issue, on the issue lock, holding nothing a use waits for.
    let closed = false;
    const closing = barrier.unsafe('SELECT upto::text FROM close_one()').then((rows) => ((closed = true), rows[0]!.upto as string));
    await waitFor(async () => (await waitersOn(1)) > 0, 'the barrier waits for the issue');
    assert.equal(closed, false);
    await use.unsafe('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');
    assert.equal(await waitersOn(0), 0, 'nothing waits for the fence');

    // The issue commits: the barrier closes over it.
    await issuing.unsafe('COMMIT');
    assert.ok(BigInt(await closing) >= BigInt(issued!.number), 'the barrier closes every number handed out before it');
    await holdsReplay(w.keys, row.id);
  } finally {
    await Promise.all([use, issuing, barrier].map((client) => client.end()));
  }
});

test('an issue of a row its transaction did not write takes the fence, as any change does: a use may name it', postgresOnly('SQLite has one writer: the fence is implicit'), async () => {
  const w = await world();
  const row = token();
  const calls = await prepare(w, row);
  // The row, committed before the transaction that issues it: a 0.14 row, say, seen by any use.
  const { credentials } = tablesOf(db.owner);
  await db.owner.insert(credentials).values({ ...row, authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, createdBy: ROOT });
  const use = postgresSession(OWNER_URL);
  try {
    await use.unsafe('BEGIN');
    await use.unsafe('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');
    const writing = db.owner.transaction((tx: Transaction) => appChanges(tx, calls));
    await waitFor(async () => (await fenceWaiters()) > 0, 'the issue waits for the use');
    await use.unsafe('COMMIT');
    assert.ok((await writing)[0] !== null);
  } finally {
    await use.end();
  }
});

test('an issue of a row a savepoint inserted takes the fence: its xmin is the savepoint\'s, not the transaction\'s', postgresOnly('SQLite has one writer: the fence is implicit'), async () => {
  const w = await world();
  const row = token();
  const [c] = await prepare(w, row);
  const issuing = postgresSession(OWNER_URL);
  try {
    await issuing.unsafe('BEGIN');
    await issuing.unsafe('SAVEPOINT s');
    await issuing.unsafe(`INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at, scope)
      VALUES ($1, $2, $3, $4, 'x', 0, $5, $6, $7, $8)`, [row.id, row.kind, randomBytes(32), randomBytes(32), row.principal, ROOT, row.expiresAt, row.scope]);
    await issuing.unsafe('RELEASE SAVEPOINT s');
    await issuing.unsafe('SELECT app_change($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)', [
      c!.kind, c!.id, c!.requestId, c!.at, c!.actor, c!.payload, null, Buffer.from(c!.seal!, 'base64'), Buffer.from(c!.mac!, 'base64'),
    ]);
    assert.deepEqual(await advisoryHeld(issuing), ['0 ExclusiveLock', '1 ShareLock']);
    await issuing.unsafe('COMMIT');
  } finally {
    await issuing.end();
  }
});

test('a 0.14 row\'s call (no request, no op) takes the fence, even on a row its transaction wrote', postgresOnly('SQLite has one writer: the fence is implicit'), async () => {
  await world();
  const row = token();
  const { credentials } = tablesOf(db.owner);
  // A row of 0.14's, unsealed, committed: the app revokes it, in a transaction that writes it, then calls app_change.
  await db.owner.insert(credentials).values({ ...row, authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, createdBy: ROOT });
  const app = postgresSession(OWNER_URL);
  try {
    await app.unsafe('BEGIN');
    await app.unsafe('UPDATE credentials SET revoked_at = now() WHERE id = $1', [row.id]);
    const [called] = await app.unsafe('SELECT app_change($1, $2, NULL, $3, $4, NULL, NULL, NULL, NULL, NULL) AS number', ['credential', row.id, Date.now(), ROOT]);
    assert.equal(called!.number, '0', 'it logs nothing');
    assert.deepEqual(await advisoryHeld(app), ['0 ExclusiveLock', '1 ShareLock']);
    await app.unsafe('ROLLBACK');
  } finally {
    await app.end();
  }
});

test('0.14\'s trigger: an entry that changes access takes the issue lock, then the fence; a token.exchange, neither (IssueBeforeFence, ExchangeOnlyIssues)', postgresOnly('SQLite has no trigger'), async () => {
  const key = deriveLogKey('app', randomBytes(32));
  const held = (action: string) => db.owner.transaction(async (tx: Transaction) => {
    await appendEntries(tx, key, [{ actor: ROOT, action, decision: 'allow' }]);
    return (await rows<{ lock: string }>(tx, sql`SELECT objid || ' ' || mode AS lock FROM pg_locks
      WHERE locktype = 'advisory' AND classid = 1668244070 AND pid = pg_backend_pid() ORDER BY objid`)).map(({ lock }) => lock);
  });
  assert.deepEqual(await held('token.revoke'), ['0 ExclusiveLock', '1 ShareLock']);
  assert.deepEqual(await held('token.exchange'), []);
  assert.deepEqual(await held('sign_in'), []);
});

test('an app\'s change beside a 0.14 decision on its principal: head, row, fence, and neither waits on the other in a circle (AppHeadFirst)', postgresOnly('SQLite has one writer'), async () => {
  const w = await world();
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA })).ok);
  const row = { ...token(), principal: ADA, kind: 'browser', scope: null };
  const calls = await prepare(w, row);
  const { credentials } = tablesOf(db.owner);
  // Its row, unsealed, before the transaction that writes it again and seals it.
  await db.owner.insert(credentials).values({ ...row, authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, createdBy: ADA });
  const app = postgresSession(OWNER_URL);
  try {
    // The app's transaction, as `audited` takes its locks: the head, then its row; its change comes last.
    await app.unsafe('BEGIN');
    await app.unsafe('SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE');
    await app.unsafe(`UPDATE credentials SET label = 'written' WHERE id = $1`, [row.id]);
    // A 0.14 decision on Ada: her member row, then the head, which the app holds.
    const decided = w.vault.admit({ actor: ROOT, principal: ADA, role: 'owner' });
    await waitFor(async () => (await waiting()) > 0, 'the decision waits for the head');
    // The app's change, the fence after the head and its row, and never Ada's member row: it does not wait for the decision.
    const c = calls[0]!;
    const result = await app.unsafe('SELECT app_change($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL) AS number', [
      c.kind, c.id, c.requestId, c.at, c.actor, c.payload, c.sealFrom === null ? null : Buffer.from(c.sealFrom, 'base64'), Buffer.from(c.seal!, 'base64'), Buffer.from(c.mac!, 'base64'),
    ] as never[]);
    assert.ok(result[0]!.number !== null);
    await app.unsafe('COMMIT');
    assert.ok((await decided).ok);
    await holdsReplay(w.keys, row.id);
  } finally {
    await app.end();
  }
});

/** Sessions waiting for the fence (its advisory key, 1668244070 / 0). */
async function fenceWaiters(): Promise<number> {
  const [row] = await rows<{ n: string }>(db.owner, sql`SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory' AND classid = 1668244070 AND objid = 0 AND NOT granted`);
  return Number(row!.n);
}

/** Sessions waiting for the fence's key (0) or the issue lock's (1). */
async function waitersOn(objid: 0 | 1): Promise<number> {
  const [row] = await rows<{ n: string }>(db.owner, sql`SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory' AND classid = 1668244070 AND objid = ${objid} AND NOT granted`);
  return Number(row!.n);
}

/** The fence's locks and the issue lock's a client holds, as "<objid> <mode>". */
async function advisoryHeld(client: PostgresClient): Promise<string[]> {
  const held = await client.unsafe<{ lock: string }[]>(`SELECT objid || ' ' || mode AS lock FROM pg_locks
    WHERE locktype = 'advisory' AND classid = 1668244070 AND pid = pg_backend_pid() AND granted ORDER BY objid`);
  return held.map(({ lock }) => lock);
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
