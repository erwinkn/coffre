// 0.15's change path for the app's keys and environments (docs/design/0.15-plan.md, "As built: PR 4b", part 2): each
// write of the app's to a key or an environment is a change the vault seals before the app's transaction (`prepare`) and
// the transaction commits beside its rows (`app_change`, 0025). These cases play the app's writes on use-world's sealed
// world, then hold the use path's live answers to the replay of the log (R53): a write that left a row other than its
// change sealed would make a use `stale` or `tampered` where the replay allows or refuses otherwise. Both engines.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { ROLES } from '@coffre/core/access';
import { encrypt, freshDek } from '@coffre/core/envelope';
import { deletedWithProject, tombstoneOf } from '@coffre/core/schemas';
import type { EnvironmentColumns, ObjectChange, SecretColumns, UseInput, UseOutcome, Via, VersionColumns } from '@coffre/core/vault';
import { tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { appChanges, isStaleChange } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { keptObjects, loggedChange, NotLogged, prepareChanges, type ChangeKeys } from '../src/changes.ts';
import { CUTOVER_OBJECT } from '../src/cutover.ts';
import { objectKey, type Ref } from '../src/inputs.ts';
import { newestSealedChanges, newestSealedQuery } from '../src/store.ts';
import { logMacKey } from '../src/log-entry.ts';
import { purposeOf, replay, type Logged } from '../src/log-replay.ts';
import { environmentObject, secretObject } from '../src/objects.ts';
import { ENGINE, openTestDatabase, rows, run, sealed, sqlitePlan, withLogUnlocked, withOldWrites, withTriggersLifted, type TestDatabase } from './database.ts';
import { ask, CONFIG, emptyLog, isolate, ROOT, SEAL, SIGNING_KEY, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

const KEYS: ChangeKeys = { seals: [SEAL], mac: logMacKey(SIGNING_KEY) };

type World = Awaited<ReturnType<typeof world>>;

class Moved extends Error {}

/** The app's changes sealed (`Vault.prepare`): an unarchive's against what its key's log last sealed. */
async function prepared(changes: ObjectChange[]) {
  const restored = changes.flatMap((change) => (change.kind === 'secret' && change.restores === true ? [{ kind: 'secret' as const, id: change.id }] : []));
  return prepareChanges(KEYS, Date.now(), ROOT, changes, await keptObjects(KEYS.seals, db.owner, restored));
}

/** The app's write: its changes sealed before (`prepare`), then its rows and the changes in one transaction, as `audited` commits them. */
async function write(changes: ObjectChange[], rowsOf: (tx: Transaction) => Promise<void>): Promise<bigint[]> {
  const calls = await prepared(changes);
  return db.owner.transaction(async (tx: Transaction) => {
    await rowsOf(tx);
    const numbers = await appChanges(tx, calls);
    if (numbers.includes(null)) throw new Moved();
    return numbers as bigint[];
  });
}

/** A key as the app reads it (the server's `secretObjects`): its columns, whether archived, and its seal. */
async function readKey(id: string): Promise<{ columns: SecretColumns; archived: boolean; seal: string | null }> {
  const [row] = await rows<{
    project_id: string; environment_id: string; archived: boolean | number; seal: Buffer | null; version: string | null; sensitive: boolean | number | null; plaintext: string | null;
    kek_provider: string | null; kek_id: string | null; kek_version: string | null; wrapped_dek: Buffer | null; source: string | null; reference: string | null;
  }>(db.owner, sql`
    SELECT s.project_id, s.environment_id, s.archived_at IS NOT NULL AS archived, s.seal, s.current_version_id AS version, v.sensitive, v.plaintext,
           v.kek_provider, v.kek_id, v.kek_version, v.wrapped_dek,
           (SELECT CASE WHEN r.ended_at IS NULL THEN r.source_secret_id END FROM secret_references r WHERE r.secret_id = s.id ORDER BY r.created_seq DESC LIMIT 1) AS source,
           (SELECT CASE WHEN r.ended_at IS NULL THEN r.id END FROM secret_references r WHERE r.secret_id = s.id ORDER BY r.created_seq DESC LIMIT 1) AS reference
      FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id WHERE s.id = ${id}`);
  assert.ok(row !== undefined, `key ${id} has a row`);
  const version: VersionColumns | null = row.version === null ? null : {
    id: row.version, sensitive: Boolean(row.sensitive), plaintext: row.plaintext, kekProvider: row.kek_provider!, kekId: row.kek_id!, kekVersion: row.kek_version!,
    wrappedDek: Buffer.from(row.wrapped_dek!).toString('base64'),
  };
  return {
    columns: { id, projectId: row.project_id, environmentId: row.environment_id, source: row.version === null ? row.source : null, reference: row.version === null ? row.reference : null, version },
    archived: Boolean(row.archived),
    seal: row.seal === null ? null : Buffer.from(row.seal).toString('base64'),
  };
}

async function readEnvironment(id: string): Promise<{ columns: EnvironmentColumns; seal: string | null }> {
  const [row] = await rows<{ project_id: string; slug: string; owner: string | null; parent_id: string | null; protected: boolean | number | null; archived: boolean | number; project_archived: boolean | number; seal: Buffer | null }>(db.owner,
    sql`SELECT e.project_id, e.slug, e.owner, e.parent_id, e.protected, e.archived_at IS NOT NULL AS archived, p.archived_at IS NOT NULL AS project_archived, e.seal
      FROM environments e LEFT JOIN projects p ON p.id = e.project_id WHERE e.id = ${id}`);
  assert.ok(row !== undefined);
  return {
    columns: { id, projectId: row.project_id, slug: row.slug, owner: row.owner, parentId: row.parent_id, protected: row.protected === null ? null : Boolean(row.protected), archived: Boolean(row.archived),
      projectArchived: Boolean(row.project_archived) },
    seal: row.seal === null ? null : Buffer.from(row.seal).toString('base64'),
  };
}

/** A key's change from its row as read now (archived: no object; brought back as its rows hold it, a restore) to `after`. */
async function keyChange(id: string, after: SecretColumns | null): Promise<ObjectChange> {
  const read = await readKey(id);
  if (read.archived && after !== null && JSON.stringify(after) === JSON.stringify(read.columns)) return { kind: 'secret', id, before: null, after, restores: true };
  return { kind: 'secret', id, before: read.archived ? null : { columns: read.columns, seal: read.seal }, after };
}

/** A new version of `w`'s key `id`: its value encrypted under a fresh data key, wrapped, and the row that stores it; a plain one's text too. */
async function newVersion(w: World, id: string, value: string, environmentId = w.dev, { plain = false } = {}): Promise<{ columns: VersionColumns; insert: (tx: Queryable) => Promise<void> }> {
  const version = randomUUID();
  const dek = freshDek();
  const context = { projectId: w.project, environmentId, secretId: id };
  const sealed = encrypt(Buffer.from(value), context, dek);
  const wrapped = await CONFIG.keks.wrap(dek, context, { deadline: Date.now() + 5000, signal: new AbortController().signal });
  const t = tablesOf(db.owner);
  return {
    columns: { id: version, sensitive: false, plaintext: plain ? value : null, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, wrappedDek: Buffer.from(wrapped.bytes).toString('base64') },
    insert: async (tx) => {
      const [{ n }] = await rows<{ n: number | string }>(tx, sql`SELECT current_version + 1 AS n FROM secrets WHERE id = ${id}`) as [{ n: number | string }];
      await (tx as Transaction).insert(t.secretVersions).values({
        id: version, secretId: id, version: Number(n), envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
        wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT, sensitive: false,
        plaintext: plain ? value : null,
      });
      await run(tx, sql`UPDATE secrets SET current_version_id = ${version}, current_version = ${Number(n)} WHERE id = ${id}`);
    },
  };
}

/** Every live answer, by entry number. */
const answered = new Map<string, UseOutcome>();
beforeEach(() => answered.clear());

async function used(w: World, secretId: string, extra: Partial<UseInput> = {}): Promise<UseOutcome> {
  const outcome = await (await isolate()).use(ask(w, secretId, extra));
  if (!('busy' in outcome) && outcome.number !== null) answered.set(outcome.number, outcome);
  return outcome;
}

const codeOf = (outcome: UseOutcome) => (outcome.ok ? null : 'code' in outcome ? outcome.code : outcome.busy);

/**
 * The log replayed: no fault, each object the rows hold under its newest change's seal, and every use decided as it was
 * live, `stale` and `tampered` included: the app's writes leave no row its log would not.
 */
async function replayAgrees(): Promise<void> {
  const changes = await rows<{ number: string | number; at: string | number; object: string; payload: string; seal: Buffer | null }>(db.owner,
    sql`SELECT number, at, object, payload, seal FROM log_changes WHERE object <> ${CUTOVER_OBJECT}`);
  const uses = await rows<{ number: string | number; at: string | number; credential: string; secret: string; purpose: number; place: string | null }>(db.owner,
    sql`SELECT number, at, credential, secret, purpose, place FROM log_uses`);
  const entries: Logged[] = [
    ...changes.map((row) => {
      const change = loggedChange({ number: BigInt(row.number), at: Number(row.at), object: row.object, payload: row.payload, seal: row.seal === null ? null : Buffer.from(row.seal) });
      assert.ok(change !== null, `entry ${row.number} names its object`);
      return change;
    }),
    ...uses.map((row) => ({
      kind: 'use' as const, number: BigInt(row.number),
      request: { credential: row.credential, secretId: row.secret, place: row.place, at: Number(row.at), ...purposeOf(Number(row.purpose))! },
    })),
  ].sort((a, b) => (a.number < b.number ? -1 : 1));
  let checked = 0;
  const result = replay([SEAL], entries, (entry, code) => {
    const live = answered.get(entry.number.toString());
    if (live === undefined) return;
    assert.equal(codeOf(live), code, `entry ${entry.number}: live and replay disagree`);
    checked += 1;
  });
  assert.deepEqual(result.faults, []);
  assert.equal(checked, answered.size, 'every live use replayed');
}

/** The ops logged for an object, in order. */
async function opsOf(ref: Ref): Promise<string[]> {
  return (await rows<{ payload: string }>(db.owner, sql`SELECT payload FROM log_changes WHERE object = ${objectKey(ref)} ORDER BY number`))
    .map(({ payload }) => (JSON.parse(payload) as { op: string }).op);
}

test('a key written, archived and unarchived through the app: each one change beside its rows, and each use live as replayed', async () => {
  const w = await world();
  const id = await w.key('first');
  assert.ok((await used(w, id)).ok);
  // A new value: a version of its own, sealed whole (`secret.write`).
  const next = await newVersion(w, id, 'second');
  const before = await readKey(id);
  await write([await keyChange(id, { ...before.columns, version: next.columns })], next.insert);
  const outcome = await used(w, id);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.equal(outcome.value.versionId, next.columns.id);
  // Archived: no object, its seal none (`secret.delete`); a use finds no key, live as replayed.
  await write([await keyChange(id, null)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${id}`));
  assert.equal((await readKey(id)).seal, null);
  const archived = await used(w, id);
  assert.ok(!archived.ok && !['stale', 'tampered'].includes(codeOf(archived)!), JSON.stringify(archived));
  // Unarchived: made again from no object (`secret.write`), its value as it was.
  const kept = (await readKey(id)).columns;
  await write([await keyChange(id, kept)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = NULL WHERE id = ${id}`));
  assert.ok((await used(w, id)).ok);
  assert.deepEqual(await opsOf({ kind: 'secret', id }), ['genesis', 'secret.write', 'secret.delete', 'secret.write']);
  await replayAgrees();
});

test('a key\'s change holds its version\'s id, nature and wrapped key, never its ciphertext nor a digest of it', async () => {
  const w = await world();
  const id = await w.key();
  const next = await newVersion(w, id, 'a value no log holds');
  await write([await keyChange(id, { ...(await readKey(id)).columns, version: next.columns })], next.insert);
  const [stored] = await rows<{ ciphertext: Buffer; iv: Buffer; auth_tag: Buffer }>(db.owner, sql`SELECT ciphertext, iv, auth_tag FROM secret_versions WHERE id = ${next.columns.id}`);
  const [{ payload }] = await rows<{ payload: string }>(db.owner, sql`SELECT payload FROM log_changes WHERE object = ${objectKey({ kind: 'secret', id })} ORDER BY number DESC LIMIT 1`) as [{ payload: string }];
  const logged = JSON.parse(payload) as Record<string, unknown>;
  assert.deepEqual(Object.keys(logged).sort(), ['digest', 'environmentId', 'key', 'nature', 'op', 'projectId', 'ref', 'reference', 'source', 'version']);
  // A digest is a plain value's, of its text: a secret's object holds none.
  assert.equal(logged.digest, null);
  for (const bytes of [stored!.ciphertext, stored!.iv, stored!.auth_tag]) {
    for (const text of [Buffer.from(bytes).toString('base64'), Buffer.from(bytes).toString('hex')]) assert.ok(!payload.includes(text), 'no part of the envelope but its wrapped key');
  }
});

test('an archive undone around the app, its row live again with no seal, is refused at the next change and at every use (ChangeChecksSeal)', async () => {
  const w = await world();
  const id = await w.key();
  await write([await keyChange(id, null)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${id}`));
  // A writer brings the key back: the row reads live, with no seal, which the app takes for 0.14's, logging nothing.
  await run(db.owner, sql`UPDATE secrets SET archived_at = NULL WHERE id = ${id}`);
  const back = await used(w, id);
  assert.ok(!back.ok && ['stale', 'tampered'].includes(codeOf(back)!), JSON.stringify(back));
  const next = await newVersion(w, id, 'over it');
  const change = await keyChange(id, { ...(await readKey(id)).columns, version: next.columns });
  assert.equal(change.before?.seal, null);
  await assert.rejects(write([change], next.insert), (error: unknown) => isStaleChange(error));
  assert.deepEqual(await opsOf({ kind: 'secret', id }), ['genesis', 'secret.delete']);
});

test('a key\'s row moved to another environment, its seal kept, is refused as tampered; a write moving a key is no change', async () => {
  const w = await world();
  const id = await w.key();
  const read = await readKey(id);
  const elsewhere = randomUUID();
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'secret', id, before: { columns: { ...read.columns, environmentId: elsewhere }, seal: read.seal }, after: null }], new Map()),
    (error: unknown) => error instanceof NotLogged && error.fault === 'tampered');
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'secret', id, before: { columns: read.columns, seal: read.seal }, after: { ...read.columns, environmentId: elsewhere } }], new Map()),
    /does nothing|no change the log knows/);
});

test('an environment made protected, renamed, archived and restored through the app: its row each time its change\'s, and a use through it as replayed', async () => {
  const w = await world();
  const id = await w.key();
  const env = await readEnvironment(w.dev);
  // Renamed: `environment.rename`; the member's grant is on its id, so the use goes on, its seal current.
  await write([{ kind: 'environment', id: w.dev, before: env, after: { ...env.columns, slug: 'development' } }],
    async (tx) => run(tx, sql`UPDATE environments SET slug = 'development' WHERE id = ${w.dev}`));
  assert.ok((await used(w, id)).ok);
  const renamed = await readEnvironment(w.dev);
  await write([{ kind: 'environment', id: w.dev, before: renamed, after: { ...renamed.columns, archived: true } }],
    async (tx) => run(tx, sql`UPDATE environments SET archived_at = ${new Date().toISOString()} WHERE id = ${w.dev}`));
  const archived = await readEnvironment(w.dev);
  await write([{ kind: 'environment', id: w.dev, before: archived, after: { ...archived.columns, archived: false } }],
    async (tx) => run(tx, sql`UPDATE environments SET archived_at = NULL WHERE id = ${w.dev}`));
  assert.ok((await used(w, id)).ok);
  // Made, protected from its first moment (a protected fork's), its row carrying the protection its object holds.
  const fork = randomUUID();
  const made: EnvironmentColumns = { id: fork, projectId: w.project, slug: 'staging', owner: null, parentId: w.dev, protected: true, archived: false, projectArchived: false };
  await write([{ kind: 'environment', id: fork, before: null, after: made }], async (tx) => {
    await tx.insert(tablesOf(tx).environments).values({ id: fork, projectId: w.project, slug: 'staging', name: 'staging', parentId: w.dev, protected: true });
  });
  const stored = await readEnvironment(fork);
  assert.deepEqual(environmentObject(stored.columns), environmentObject(made));
  assert.deepEqual(await opsOf({ kind: 'environment', id: w.dev }), ['genesis', 'environment.rename', 'environment.archive', 'environment.archive']);
  assert.deepEqual(await opsOf({ kind: 'environment', id: fork }), ['environment.create']);
  // What the app may not write: a protection (the vault's), a parent, another project.
  for (const after of [{ ...stored.columns, protected: false }, { ...stored.columns, parentId: null }, { ...stored.columns, projectId: randomUUID() }]) {
    assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'environment', id: fork, before: stored, after }], new Map()), /no change the log knows/);
  }
  await replayAgrees();
});

/**
 * An environment deleted with its keys, its slug made `tombstone`: each key
 * erased, deleted and archived, and a use there refused live as replayed,
 * never stale. Its object is the same whichever tombstone: the slug before it,
 * deleted.
 */
async function deletedWithKeys(tombstone: string): Promise<void> {
  const w = await world();
  const ids = [await w.key('one'), await w.key('two')];
  assert.ok((await used(w, ids[0]!)).ok);
  const env = await readEnvironment(w.dev);
  const changes: ObjectChange[] = [
    { kind: 'environment', id: w.dev, before: env, after: { ...env.columns, slug: tombstone } },
    ...await Promise.all(ids.map((id) => keyChange(id, null))),
  ];
  await write(changes, async (tx) => {
    await run(tx, sql`UPDATE environments SET slug = ${tombstone} WHERE id = ${w.dev}`);
    await run(tx, sql`UPDATE secret_versions SET ciphertext = ${Buffer.alloc(0)}, wrapped_dek = ${Buffer.alloc(0)}, plaintext = NULL WHERE secret_id IN (${sql.join(ids.map((id) => sql`${id}`), sql`, `)})`);
    await run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id IN (${sql.join(ids.map((id) => sql`${id}`), sql`, `)})`);
  });
  for (const id of ids) {
    const outcome = await used(w, id);
    assert.ok(!outcome.ok && !['stale', 'tampered'].includes(codeOf(outcome)!), JSON.stringify(outcome));
  }
  const deleted = environmentObject((await readEnvironment(w.dev)).columns);
  assert.deepEqual([deleted.slug, deleted.deleted], ['dev', true]);
  assert.deepEqual(await opsOf({ kind: 'environment', id: w.dev }), ['genesis', 'environment.delete']);
  // A deleted environment changes no more.
  const now = await readEnvironment(w.dev);
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'environment', id: w.dev, before: now, after: { ...now.columns, archived: true } }], new Map()), /does nothing/);
  await replayAgrees();
}

test('an environment deleted with its keys: its slug a tombstone, each key erased, deleted and archived; a use there is refused live as replayed, never stale', () =>
  deletedWithKeys(tombstoneOf('dev', new Date())));

test("a project's environment deleted with it, `dev~deleted`: the same object, refused live as replayed, never stale", () =>
  deletedWithKeys(deletedWithProject('dev')));

test('a key erased but left unarchived, as 0.14 leaves it, would be `tampered` to a use: why the deletion archives it', async () => {
  const w = await world();
  const id = await w.key();
  const read = await readKey(id);
  // Its object is gone (`secret.delete`), its seal none; the row still live, its version emptied.
  await write([{ kind: 'secret', id, before: { columns: read.columns, seal: read.seal }, after: null }],
    async (tx) => run(tx, sql`UPDATE secret_versions SET ciphertext = ${Buffer.alloc(0)}, wrapped_dek = ${Buffer.alloc(0)} WHERE secret_id = ${id}`));
  const outcome = await used(w, id);
  assert.equal(codeOf(outcome), 'tampered');
  assert.equal(secretObject(read.columns).kind, 'secret');
});

test('of two changes prepared from one key\'s seal, the second does nothing, and its write rolls back (ChangeCAS)', async () => {
  const w = await world();
  const id = await w.key();
  const [first, second] = [await newVersion(w, id, 'first'), await newVersion(w, id, 'second')];
  const columns = (await readKey(id)).columns;
  const [one, two] = [await keyChange(id, { ...columns, version: first.columns }), await keyChange(id, { ...columns, version: second.columns })];
  await write([one], first.insert);
  await assert.rejects(write([two], second.insert), Moved);
  assert.equal((await readKey(id)).columns.version?.id, first.columns.id, 'the second write rolled back');
  assert.deepEqual(await opsOf({ kind: 'secret', id }), ['genesis', 'secret.write']);
});

test('a key put back to an earlier version with that version\'s seal: valid, but not its newest change\'s, so the next change is refused (ChangeChecksSeal)', async () => {
  const w = await world();
  const id = await w.key('first');
  const old = await readKey(id);
  const next = await newVersion(w, id, 'second');
  await write([await keyChange(id, { ...old.columns, version: next.columns })], next.insert);
  // A writer puts back the first version, and its seal, which the vault made once.
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${old.columns.version!.id}, seal = ${Buffer.from(old.seal!, 'base64')} WHERE id = ${id}`);
  assert.ok(!(await used(w, id)).ok, 'a use refuses it');
  const archive = await keyChange(id, null);
  assert.equal(archive.before?.seal, old.seal, 'the vault takes the seal: it is its own');
  await assert.rejects(write([archive], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${id}`)), (error: unknown) => isStaleChange(error));
  assert.deepEqual(await opsOf({ kind: 'secret', id }), ['genesis', 'secret.write']);
});

// --- an unarchive restores what the log sealed (0030; formal/SealedObjects.tla, T134) ---------------------------------

/** `id` archived through the app: its object gone, its row's seal none. */
async function archive(id: string): Promise<void> {
  await write([await keyChange(id, null)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${id}`));
}

/** `id` unarchived through the app, as its rows hold it now (`restores`). */
async function unarchive(id: string): Promise<bigint[]> {
  const change = await keyChange(id, (await readKey(id)).columns);
  assert.equal(change.kind === 'secret' && change.restores, true, 'an unarchive restores');
  return write([change], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = NULL WHERE id = ${id}`));
}

/** Its unarchive refused before anything is written (`prepare`: rows no change of its log sealed), and every use still finds no key. */
async function refusesUnarchive(w: World, id: string): Promise<void> {
  const ops = await opsOf({ kind: 'secret', id });
  await assert.rejects(unarchive(id), (error: unknown) => error instanceof NotLogged && error.fault === 'stale');
  assert.deepEqual(await opsOf({ kind: 'secret', id }), ops, 'nothing logged');
  const read = await readKey(id);
  assert.ok(read.archived && read.seal === null, 'still archived, no seal');
  const outcome = await used(w, id);
  assert.ok(!outcome.ok && !['stale', 'tampered'].includes(codeOf(outcome)!), JSON.stringify(outcome));
}

test("a key's rows edited while it is archived (another version, its wrapped key, an older version put back): its unarchive is refused, nothing sealed; put back, it restores the value it had, live as replayed (T134)", async () => {
  const w = await world();
  const id = await w.key('first');
  const first = (await readKey(id)).columns.version!;
  const next = await newVersion(w, id, 'second');
  await write([await keyChange(id, { ...(await readKey(id)).columns, version: next.columns })], next.insert);
  await archive(id);
  // A version planted, as current: a new value.
  const planted = await newVersion(w, id, 'planted');
  await planted.insert(db.owner);
  await refusesUnarchive(w, id);
  // The genuine version back, its wrapped key swapped for the planted one's.
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${next.columns.id} WHERE id = ${id}`);
  await withTriggersLifted(db.owner, 'secret_versions', (tx) => run(tx, sql`UPDATE secret_versions SET wrapped_dek = ${Buffer.from(planted.columns.wrappedDek, 'base64')} WHERE id = ${next.columns.id}`));
  await refusesUnarchive(w, id);
  await withTriggersLifted(db.owner, 'secret_versions', (tx) => run(tx, sql`UPDATE secret_versions SET wrapped_dek = ${Buffer.from(next.columns.wrappedDek, 'base64')} WHERE id = ${next.columns.id}`));
  // The first version put back: a value the log sealed once, not the one it last did.
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${first.id} WHERE id = ${id}`);
  await refusesUnarchive(w, id);
  // As the archive left it: unarchived, its last value.
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${next.columns.id} WHERE id = ${id}`);
  await unarchive(id);
  const outcome = await used(w, id);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.equal(outcome.value.versionId, next.columns.id);
  assert.deepEqual(await opsOf({ kind: 'secret', id }), ['genesis', 'secret.write', 'secret.delete', 'secret.write']);
  await replayAgrees();
});

test("an archived holder's reference rows edited (a row planted to another source, its source moved, its row's end marked): its unarchive is refused, never sealing the edit (T134)", async () => {
  const w = await world();
  const [source, other] = [await w.key('the source'), await w.key('another')];
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  await archive(holder);
  // A newer row to another source: the holder would read it.
  await plant(w, vault, holder, other);
  await refusesUnarchive(w, holder);
  await run(db.owner, sql`DELETE FROM secret_references WHERE secret_id = ${holder} AND id <> ${via.reference}`);
  // The genuine row's source moved.
  await run(db.owner, sql`UPDATE secret_references SET source_secret_id = ${other} WHERE id = ${via.reference}`);
  await refusesUnarchive(w, holder);
  await run(db.owner, sql`UPDATE secret_references SET source_secret_id = ${source} WHERE id = ${via.reference}`);
  // Its end marked by the writer, no end of the vault's: no denial sealed either.
  await run(db.owner, sql`UPDATE secret_references SET ended_at = ${new Date().toISOString()} WHERE id = ${via.reference}`);
  await refusesUnarchive(w, holder);
  await run(db.owner, sql`UPDATE secret_references SET ended_at = NULL WHERE id = ${via.reference}`);
  await unarchive(holder);
  const outcome = await used(w, holder);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  await replayAgrees();
});

test("an unarchive whose key's log moved on between its prepare and its commit, its rows put back as read, is refused under the fence (T134, RestorePinned)", async () => {
  const w = await world();
  const id = await w.key('first');
  await archive(id);
  const read = await readKey(id);
  const restore = await keyChange(id, read.columns);
  const calls = await prepared([restore]);
  assert.ok(calls[0]!.restores !== null, 'it carries the seal it restores');
  // Meanwhile: unarchived, written, archived again; a writer puts the rows back as the prepare read them.
  await unarchive(id);
  const next = await newVersion(w, id, 'second');
  await write([await keyChange(id, { ...(await readKey(id)).columns, version: next.columns })], next.insert);
  await archive(id);
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${read.columns.version!.id} WHERE id = ${id}`);
  const ops = await opsOf({ kind: 'secret', id });
  await assert.rejects(db.owner.transaction(async (tx: Transaction) => {
    await run(tx, sql`UPDATE secrets SET archived_at = NULL WHERE id = ${id}`);
    await appChanges(tx, calls);
  }), (error: unknown) => isStaleChange(error));
  assert.deepEqual(await opsOf({ kind: 'secret', id }), ops, 'nothing logged');
  // Without the pin, `app_change` would have sealed the first value over the second: the rows are what the prepare read.
  assert.deepEqual((await readKey(id)).columns, read.columns);
});

/** `count` sealed changes of `object` and, newest, its archive's (no seal), as if written long ago: its history. */
async function history(object: string, count: number): Promise<void> {
  const [{ top }] = await rows<{ top: string | number | null }>(db.owner, sql`SELECT max(number) AS top FROM log_changes`) as [{ top: string | number | null }];
  const from = Number(top ?? 0) + 1;
  await run(db.owner, sql`WITH RECURSIVE g(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM g WHERE n < ${count})
    INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT ${from} + n, 0, ${object} || '-' || (${from} + n), ${object}, 'system:x', '{"op":"x"}', CASE WHEN n < ${count} THEN ${randomBytes(16)} END, ${randomBytes(16)} FROM g`);
}

test("what an unarchive restores is read with one probe of each key's changes, however long their history: never a walk of it (T134, R48)", { timeout: 600_000 }, async () => {
  const refs: Ref[] = [{ kind: 'secret', id: randomUUID() }, { kind: 'secret', id: randomUUID() }];
  const cost = async (): Promise<number | string> => {
    if (ENGINE === 'sqlite') return (await sqlitePlan(newestSealedQuery(refs))).join('; ');
    const [row] = await rows<Record<string, unknown>>(db.owner, sql`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${newestSealedQuery(refs)}`);
    const json = Object.values(row!)[0];
    const plan = (typeof json === 'string' ? JSON.parse(json) : json) as { Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }[];
    return plan[0]!.Plan['Shared Hit Blocks'] + plan[0]!.Plan['Shared Read Blocks'];
  };
  const grown = async (count: number) => {
    for (const ref of refs) await history(objectKey(ref), count);
    if (ENGINE === 'postgres') await run(db.owner, sql`VACUUM ANALYZE log_changes`);
    const found = await newestSealedChanges(db.owner, refs);
    // Each key's newest sealed change, the one just below its archive.
    for (const ref of refs) assert.ok(found.get(objectKey(ref))?.seal !== undefined, 'found');
    return cost();
  };
  const small = await grown(1_000);
  const large = await grown(100_000);
  if (ENGINE === 'sqlite') {
    // Each key's newest sealed number by its index, then its row by number: never every row of a key.
    assert.ok(!/\bSCAN\b/.test(String(large)) && /log_changes_object_idx/.test(String(large)) && /SEARCH c USING INTEGER PRIMARY KEY/.test(String(large)), String(large));
    return;
  }
  assert.ok(Number(large) - Number(small) <= 4, `${small} buffers at 1k changes a key, ${large} at 100k`);
});

test("a key the log never held, archived (0.14's alone, before the cutover): its unarchive logs nothing, as any of 0.14's rows (T134)", async () => {
  const w = await world();
  const id = randomUUID();
  const t = tablesOf(db.owner);
  await db.owner.insert(t.secrets).values({ id, projectId: w.project, environmentId: w.dev, key: `OLD_${id.slice(0, 4)}`, archivedAt: new Date() });
  const calls = await prepared([await keyChange(id, (await readKey(id)).columns)]);
  assert.deepEqual(calls.map((call) => call.requestId), [null]);
  await unarchive(id);
  assert.deepEqual(await opsOf({ kind: 'secret', id }), []);
});

test("`app_change` takes a restored seal only on a key's object made again from none", async () => {
  const w = await world();
  const id = await w.key();
  const next = await newVersion(w, id, 'second');
  const [call] = await prepared([await keyChange(id, { ...(await readKey(id)).columns, version: next.columns })]);
  await assert.rejects(db.owner.transaction(async (tx: Transaction) => {
    await next.insert(tx);
    await appChanges(tx, [{ ...call!, restores: call!.seal }]);
  }), (error: unknown) => /restores one/.test(String(error)) || /restores one/.test(String((error as { cause?: unknown }).cause)));
});

// --- what an object covers (0029; formal/SealedObjects.tla) ------------------------------------------------------

/**
 * A vault deciding with 0.15's log, its changes answering at once (no checkpointer here), Root its Owner, admitted
 * afresh: each test empties the log (`emptyLog`), and a member row sealed by a change no longer there is stale.
 */
async function deciding() {
  const { vault } = await isolate({ sealThrough: sealed });
  await run(db.owner, sql`DELETE FROM vault_grants WHERE principal = ${ROOT}`);
  await run(db.owner, sql`DELETE FROM vault_members WHERE principal = ${ROOT}`);
  await vault.access(ROOT);
  return vault;
}

/** A reference in `dev` to `source`, made as the app makes one: the vault's `reference.create`, then the holder's row, its reference row and its change. */
async function reference(w: World, vault: Awaited<ReturnType<typeof deciding>>, source: string): Promise<{ holder: string; via: Via }> {
  const holder = randomUUID();
  const id = randomUUID();
  const made = await vault.reference({ principal: ROOT, caller: 'person', items: [{ id, holder: { projectId: w.project, environmentId: w.dev, secretId: holder, path: 'p/dev/HELD' }, source: { secretId: source } }] });
  assert.ok(made.ok, JSON.stringify(made));
  const t = tablesOf(db.owner);
  await write([{ kind: 'secret', id: holder, before: null, after: { id: holder, projectId: w.project, environmentId: w.dev, source, reference: id, version: null } }], async (tx) => {
    await tx.insert(t.secrets).values({ id: holder, projectId: w.project, environmentId: w.dev, key: `HELD_${holder.slice(0, 4)}` });
    await tx.insert(t.secretReferences).values({
      id, projectId: w.project, environmentId: w.dev, secretId: holder, sourceProjectId: w.project, sourceEnvironmentId: w.dev, sourceSecretId: source,
      createdSeq: BigInt(made.seqs[0]!), createdBy: ROOT,
    });
  });
  return { holder, via: { reference: id, seq: made.seqs[0]! } };
}

const endedAt = async (holder: string) => (await rows<{ ended_at: unknown }>(db.owner, sql`SELECT ended_at FROM secret_references WHERE secret_id = ${holder}`)).map((row) => row.ended_at);

test("a reference broken: its end in its row and the holder's change (`secret.write`, no source), in the vault's decision beside 0.14's entry; every use after refused `ended`, live as replayed (T125)", async () => {
  const w = await world();
  const source = await w.key('the source');
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  assert.ok((await used(w, holder)).ok);
  const ended = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(ended.ok, JSON.stringify(ended));
  const [at] = await endedAt(holder);
  assert.ok(at !== null && at !== undefined, 'the row says it ended');
  assert.deepEqual(await opsOf({ kind: 'secret', id: holder }), ['secret.write', 'secret.write']);
  const [{ payload }] = await rows<{ payload: string }>(db.owner, sql`SELECT payload FROM log_changes WHERE object = ${objectKey({ kind: 'secret', id: holder })} ORDER BY number DESC LIMIT 1`) as [{ payload: string }];
  assert.equal((JSON.parse(payload) as { source: unknown }).source, null);
  assert.equal(codeOf(await used(w, holder)), 'ended');
  // Its source, read on its own, is no different.
  assert.ok((await used(w, source)).ok);
  // A value written over it after: the holder's own, from the ended object.
  const next = await newVersion(w, holder, 'its own now');
  await write([await keyChange(holder, { ...(await readKey(holder)).columns, version: next.columns })], next.insert);
  assert.ok((await used(w, holder)).ok);
  await replayAgrees();
});

test('an end undone around the vault, its row read live again, is refused as tampered; an end the holder no longer stands on changes nothing (T125)', async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] })).ok);
  await run(db.owner, sql`UPDATE secret_references SET ended_at = NULL WHERE secret_id = ${holder}`);
  assert.equal(codeOf(await used(w, holder)), 'tampered');
  // A reference the vault made, whose write stored nothing: abandoned, it is no holder's, and no object changes.
  const id = randomUUID();
  const made = await vault.reference({ principal: ROOT, caller: 'person', items: [{ id, holder: { projectId: w.project, environmentId: w.dev, secretId: randomUUID(), path: 'p/dev/LOST' }, source: { secretId: source } }] });
  assert.ok(made.ok);
  const before = await rows(db.owner, sql`SELECT number FROM log_changes`);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'abandoned', items: [{ reference: id, seq: made.seqs[0]! }] })).ok);
  assert.equal((await rows(db.owner, sql`SELECT number FROM log_changes`)).length, before.length);
});

test("a reference broken while its holder is archived: its row's end, and its kept object logged ended (written ended, deleted again), so the holder unarchived reads it ended, live as replayed (T125, T134)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  await write([await keyChange(holder, null)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${holder}`));
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] })).ok);
  // Still no object (the delete after the write); its row says it ended, and the object its unarchive restores too.
  assert.deepEqual(await opsOf({ kind: 'secret', id: holder }), ['secret.write', 'secret.delete', 'secret.write', 'secret.delete']);
  assert.equal((await readKey(holder)).seal, null);
  const [at] = await endedAt(holder);
  assert.ok(at !== null && at !== undefined);
  const archived = await used(w, holder);
  assert.ok(!archived.ok && !['stale', 'tampered'].includes(codeOf(archived)!), JSON.stringify(archived));
  // Unarchived as it is: an ended reference's object, no source, the one its log kept.
  await write([await keyChange(holder, (await readKey(holder)).columns)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = NULL WHERE id = ${holder}`));
  assert.equal(codeOf(await used(w, holder)), 'ended');
  await replayAgrees();
});

test("an archived holder's end cleared by a writer: its unarchive would restore the reference live, but its log kept it ended, so it is refused `stale` and nothing is sealed (T134, EndWhileArchived)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  await write([await keyChange(holder, null)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${holder}`));
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] })).ok);
  await run(db.owner, sql`UPDATE secret_references SET ended_at = NULL WHERE secret_id = ${holder}`);
  const restore = await keyChange(holder, (await readKey(holder)).columns);
  assert.equal(restore.kind === 'secret' && restore.restores, true);
  await assert.rejects(prepared([restore]), (error: unknown) => error instanceof NotLogged && error.fault === 'stale');
  assert.deepEqual(await opsOf({ kind: 'secret', id: holder }), ['secret.write', 'secret.delete', 'secret.write', 'secret.delete']);
});

test("a reference broken while its archived holder's rows are a writer's (moved to another environment): refused as tampered and reported, nothing changed; put back, the break holds (T134, Fable's review)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  await archive(holder);
  const home = w.dev;
  const elsewhere = await fork(w);
  await run(db.owner, sql`UPDATE secrets SET environment_id = ${elsewhere} WHERE id = ${holder}`);
  const ops = await opsOf({ kind: 'secret', id: holder });
  const refused = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok && refused.refusal.code === 'tampered', JSON.stringify(refused));
  assert.deepEqual(await opsOf({ kind: 'secret', id: holder }), ops);
  assert.deepEqual((await endedAt(holder)).map((at) => at !== null), [false]);
  const reported = await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered'`);
  assert.ok(reported.some(({ code }) => code === 'stale'), JSON.stringify(reported));
  await run(db.owner, sql`UPDATE secrets SET environment_id = ${home} WHERE id = ${holder}`);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] })).ok);
  await unarchive(holder);
  assert.equal(codeOf(await used(w, holder)), 'ended');
  await replayAgrees();
});

test("a reference broken whose holder 0.14's log alone holds (no seal, no change: before the cutover): its row's end alone, no change, so no genesis seals it live (T125)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const holder = randomUUID();
  const id = randomUUID();
  const made = await vault.reference({ principal: ROOT, caller: 'person', items: [{ id, holder: { projectId: w.project, environmentId: w.dev, secretId: holder, path: 'p/dev/OLD' }, source: { secretId: source } }] });
  assert.ok(made.ok);
  // The app's rows as 0.14 writes them: no seal, no change.
  const t = tablesOf(db.owner);
  await db.owner.insert(t.secrets).values({ id: holder, projectId: w.project, environmentId: w.dev, key: `OLD_${holder.slice(0, 4)}` });
  await db.owner.insert(t.secretReferences).values({
    id, projectId: w.project, environmentId: w.dev, secretId: holder, sourceProjectId: w.project, sourceEnvironmentId: w.dev, sourceSecretId: source,
    createdSeq: BigInt(made.seqs[0]!), createdBy: ROOT,
  });
  const before = (await rows(db.owner, sql`SELECT number FROM log_changes`)).length;
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [{ reference: id, seq: made.seqs[0]! }] })).ok);
  assert.equal((await rows(db.owner, sql`SELECT number FROM log_changes`)).length, before);
  const [at] = await endedAt(holder);
  assert.ok(at !== null && at !== undefined, 'its row says it ended');
  assert.equal(secretObject((await readKey(holder)).columns).source, null, 'a genesis from its rows seals it ended');
});

test("a reference row a writer planted beside the holder's, to the same source: the holder's object names its genuine row, so every use and the break are refused as tampered, the holder never served (Fable's review)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  assert.ok((await used(w, holder)).ok);
  // The writer's row: newer, same holder, same source; the holder's object now reads it, and its seal does not cover that.
  await plant(w, vault, holder, source);
  assert.equal(codeOf(await used(w, holder)), 'tampered');
  const refused = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok && refused.refusal.code === 'tampered', JSON.stringify(refused));
  assert.equal(codeOf(await used(w, holder)), 'tampered');
});

/** A row a writer plants beside `holder`'s references, newer, to `source`: its created_seq another reference.create's. */
async function plant(w: World, vault: Awaited<ReturnType<typeof deciding>>, holder: string, source: string): Promise<void> {
  const other = await vault.reference({ principal: ROOT, caller: 'person', items: [{ id: randomUUID(), holder: { projectId: w.project, environmentId: w.dev, secretId: randomUUID(), path: 'p/dev/X' }, source: { secretId: source } }] });
  assert.ok(other.ok);
  await db.owner.insert(tablesOf(db.owner).secretReferences).values({
    id: randomUUID(), projectId: w.project, environmentId: w.dev, secretId: holder, sourceProjectId: w.project, sourceEnvironmentId: w.dev, sourceSecretId: source,
    createdSeq: BigInt(other.seqs[0]!), createdBy: ROOT,
  });
}

test('a reference abandoned while another request committed one for the same holder and source: the committed one stands (review r5)', async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  // B's reference, stored and logged; A's, made by the vault for the same holder and source, its write abandoned.
  const { holder } = await reference(w, vault, source);
  const a = randomUUID();
  const made = await vault.reference({ principal: ROOT, caller: 'person', items: [{ id: a, holder: { projectId: w.project, environmentId: w.dev, secretId: holder, path: 'p/dev/HELD' }, source: { secretId: source } }] });
  assert.ok(made.ok);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'abandoned', items: [{ reference: a, seq: made.seqs[0]! }] })).ok);
  assert.deepEqual((await endedAt(holder)).map((at) => at !== null), [false]);
  assert.ok((await used(w, holder)).ok);
  await replayAgrees();
});

test("a break while a writer has moved the holder's rows (a row planted to another source) is refused as tampered; once they are put back, the break holds (review r6)", async () => {
  const w = await world();
  const source = await w.key('genuine source');
  const other = await w.key('other source');
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  await plant(w, vault, holder, other);
  assert.equal(codeOf(await used(w, holder)), 'tampered');
  const refused = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok && refused.refusal.code === 'tampered', JSON.stringify(refused));
  // The writer takes the planted row away: the holder reads its genuine one again under its seal, and is broken now.
  await run(db.owner, sql`DELETE FROM secret_references WHERE secret_id = ${holder} AND id <> ${via.reference}`);
  assert.ok((await used(w, holder)).ok);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] })).ok);
  assert.equal(codeOf(await used(w, holder)), 'ended');
});

test("a break whose named row a writer marked ended, beside a planted row to the same source: the holder's object reads neither, so uses and the break are refused as tampered, the end never skipped (review r6)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  await plant(w, vault, holder, source);
  await run(db.owner, sql`UPDATE secret_references SET ended_at = ${new Date().toISOString()} WHERE id = ${via.reference}`);
  assert.equal(codeOf(await used(w, holder)), 'tampered');
  const refused = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok && refused.refusal.code === 'tampered', JSON.stringify(refused));
});

test("a break while a writer has renamed the reference's row: the holder's object names the genuine one, so every use and the break are refused as tampered; renamed back, the break holds (review r7, ReferenceInObject)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  const renamed = randomUUID();
  await run(db.owner, sql`UPDATE secret_references SET id = ${renamed} WHERE id = ${via.reference}`);
  assert.equal(codeOf(await used(w, holder)), 'tampered');
  const refused = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok && refused.refusal.code === 'tampered', JSON.stringify(refused));
  await run(db.owner, sql`UPDATE secret_references SET id = ${via.reference} WHERE id = ${renamed}`);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] })).ok);
  assert.equal(codeOf(await used(w, holder)), 'ended');
});

test("a break while a writer has marked a live holder archived: its log says it has an object, so the break is refused; unmarked, the break holds and is never undone by clearing marks (review r7, LivenessFromLog)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  await run(db.owner, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${holder}`);
  const refused = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok && ['stale', 'tampered'].includes(refused.refusal.code), JSON.stringify(refused));
  assert.deepEqual((await endedAt(holder)).map((at) => at !== null), [false], 'no row ended: the break did not happen');
  await run(db.owner, sql`UPDATE secrets SET archived_at = NULL WHERE id = ${holder}`);
  assert.ok((await used(w, holder)).ok);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] })).ok);
  // The writer clears the row's end: the holder's object reads the source again, which its seal does not cover.
  await run(db.owner, sql`UPDATE secret_references SET ended_at = NULL WHERE secret_id = ${holder}`);
  assert.equal(codeOf(await used(w, holder)), 'tampered');
});

test("a reference abandoned while another request's, for the same holder and source, stands on an archived holder: only the abandoned one's row (none) ends, the other stands once unarchived (review r8)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder } = await reference(w, vault, source);
  await write([await keyChange(holder, null)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = ${new Date().toISOString()} WHERE id = ${holder}`));
  const a = randomUUID();
  const made = await vault.reference({ principal: ROOT, caller: 'person', items: [{ id: a, holder: { projectId: w.project, environmentId: w.dev, secretId: holder, path: 'p/dev/HELD' }, source: { secretId: source } }] });
  assert.ok(made.ok);
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'abandoned', items: [{ reference: a, seq: made.seqs[0]! }] })).ok);
  assert.deepEqual((await endedAt(holder)).map((at) => at !== null), [false]);
  await write([await keyChange(holder, (await readKey(holder)).columns)], async (tx) => run(tx, sql`UPDATE secrets SET archived_at = NULL WHERE id = ${holder}`));
  assert.ok((await used(w, holder)).ok);
});

test("two references of one holder 0.14's log alone holds, ended in one call: each named row ends, and nothing else (review r8)", async () => {
  const w = await world();
  const [one, two] = [await w.key('one'), await w.key('two')];
  const vault = await deciding();
  const holder = randomUUID();
  const t = tablesOf(db.owner);
  await db.owner.insert(t.secrets).values({ id: holder, projectId: w.project, environmentId: w.dev, key: `OLD_${holder.slice(0, 4)}` });
  const vias: Via[] = [];
  for (const source of [one, two]) {
    const id = randomUUID();
    const made = await vault.reference({ principal: ROOT, caller: 'person', items: [{ id, holder: { projectId: w.project, environmentId: w.dev, secretId: holder, path: 'p/dev/OLD' }, source: { secretId: source } }] });
    assert.ok(made.ok);
    await db.owner.insert(t.secretReferences).values({
      id, projectId: w.project, environmentId: w.dev, secretId: holder, sourceProjectId: w.project, sourceEnvironmentId: w.dev, sourceSecretId: source,
      createdSeq: BigInt(made.seqs[0]!), createdBy: ROOT,
    });
    vias.push({ reference: id, seq: made.seqs[0]! });
  }
  assert.ok((await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: vias })).ok);
  assert.deepEqual((await endedAt(holder)).map((at) => at !== null), [true, true]);
  assert.equal(secretObject((await readKey(holder)).columns).source, null);
});

test("a break after a writer planted a forged `reference.end` (the vault's name, no valid MAC): only an authentic end counts, so the break happens and the holder reads it ended (review r9)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  // Chained as the log's newest entry, the head naming it, so that the vault's next append takes it for the last.
  await withLogUnlocked(db.owner, async (tx) => {
    const [head] = await rows<{ next: string | number; hash: Buffer | Uint8Array }>(tx, sql`SELECT next_seq AS next, head_hash AS hash FROM audit_chain_head`);
    const hash = randomBytes(32);
    await run(tx, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, related_seq, metadata, prev_hash, mac, hash)
      VALUES (${BigInt(head!.next)}, 'vault', 'vault:forged', ${Date.now()}, ${ROOT}, 'reference.end', 'allow', ${BigInt(via.seq)}, '{}', ${Buffer.from(head!.hash)}, ${randomBytes(32)}, ${hash})`);
    await run(tx, sql`UPDATE audit_chain_head SET next_seq = ${BigInt(head!.next) + 1n}, head_hash = ${hash}`);
  });
  assert.ok((await used(w, holder)).ok, '0.15 reads no end entry');
  const ended = await vault.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(ended.ok, JSON.stringify(ended));
  assert.equal(codeOf(await used(w, holder)), 'ended');
});

test("a break by a staging-scoped Developer after a writer renamed the holder's environment to `staging`: who may end it is decided on the environment's sealed object, so the break is refused (review r10)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  const dana = `user:dana-${randomUUID().slice(0, 8)}@acme.example`;
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: dana, role: 'developer', scope: { projects: 'all', environments: { only: ['staging'] } } })).ok);
  await run(db.owner, sql`UPDATE environments SET slug = 'staging' WHERE id = ${w.dev}`);
  const refused = await vault.endReferences({ principal: dana, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok, JSON.stringify(refused));
  await run(db.owner, sql`UPDATE environments SET slug = 'dev' WHERE id = ${w.dev}`);
  assert.deepEqual((await endedAt(holder)).map((at) => at !== null), [false]);
  assert.ok((await used(w, holder)).ok, 'the reference stands');
});

test("a break by a Developer in a protected environment after a writer marked its project deleted: 0.15's reader, on the sealed protection, refuses it as 0.14's would without the edit (review r11)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  const dana = `user:dana-${randomUUID().slice(0, 8)}@acme.example`;
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: dana })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: dana, changes: [{ projectId: w.project, environmentId: null, role: 'developer', expiresAt: null }] })).ok);
  // A Developer who writes in a normal environment, and only uses in a protected one (an Owner's edit of the role).
  assert.ok((await vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'role', role: 'developer', definition: { ...ROLES.developer, protected: ['secret.use'] } } })).ok);
  assert.ok((await vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'protect', projectId: w.project, environmentIds: [w.dev], protected: true } })).ok);
  assert.ok(!(await vault.endReferences({ principal: dana, caller: 'person', reason: 'broken', items: [via] })).ok, 'refused while nothing is edited');
  // Nor beside a reference held in an environment 0.14's log alone holds, which 0.14's reader alone decides (review r12).
  const legacy = randomUUID();
  const t = tablesOf(db.owner);
  await db.owner.insert(t.environments).values({ id: legacy, projectId: w.project, slug: 'legacy', name: 'legacy', protected: false });
  const old = randomUUID();
  const oldRef = randomUUID();
  // Made by an isolate still on 0.14's log, as its environment was: 0.15's vault decides on no row its log does not hold
  // (T159), and since PR 9b nothing of 0.14's writes after the cutover, so such a holder is one a writer let through.
  const { vault: older } = await isolate({ log: '0.14' });
  const made = await withOldWrites(db.owner, () => older.reference({
    principal: ROOT, caller: 'person', items: [{ id: oldRef, holder: { projectId: w.project, environmentId: legacy, secretId: old, path: 'p/legacy/OLD' }, source: { secretId: source } }],
  }));
  assert.ok(made.ok, JSON.stringify(made));
  await db.owner.insert(t.secrets).values({ id: old, projectId: w.project, environmentId: legacy, key: 'OLD' });
  await db.owner.insert(t.secretReferences).values({
    id: oldRef, projectId: w.project, environmentId: legacy, secretId: old, sourceProjectId: w.project, sourceEnvironmentId: w.dev, sourceSecretId: source,
    createdSeq: BigInt(made.seqs[0]!), createdBy: ROOT,
  });
  const [{ slug }] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM projects WHERE id = ${w.project}`) as [{ slug: string }];
  await run(db.owner, sql`UPDATE projects SET slug = ${`${slug}~deleted`} WHERE id = ${w.project}`);
  const refused = await vault.endReferences({ principal: dana, caller: 'person', reason: 'broken', items: [via] });
  assert.ok(!refused.ok, JSON.stringify(refused));
  const batch = await vault.endReferences({ principal: dana, caller: 'person', reason: 'broken', items: [via, { reference: oldRef, seq: made.seqs[0]! }] });
  assert.ok(!batch.ok, JSON.stringify(batch));
  await run(db.owner, sql`UPDATE projects SET slug = ${slug} WHERE id = ${w.project}`);
  assert.deepEqual((await endedAt(holder)).map((at) => at !== null), [false]);
  assert.ok((await vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'role', role: 'developer', definition: null } })).ok);
});

test("with 0.14's log, a reference's end is 0.14's entry alone, which the cut-over log refuses whole: no row's end, no change (T125, PR 9b)", async () => {
  const w = await world();
  const source = await w.key();
  const vault = await deciding();
  const { holder, via } = await reference(w, vault, source);
  const { vault: old } = await isolate({ log: '0.14' });
  const before = await rows(db.owner, sql`SELECT number FROM log_changes`);
  await assert.rejects(old.endReferences({ principal: ROOT, caller: 'person', reason: 'broken', items: [via] }),
    (error: Error & { cause?: Error }) => /is cut over from 0\.14/.test(`${error.message} ${error.cause?.message ?? ''}`));
  assert.deepEqual(await endedAt(holder), [null]);
  assert.equal((await rows(db.owner, sql`SELECT number FROM log_changes`)).length, before.length);
});

/** A project archived or restored as the app does it (`patchProject`): its row, and `project.archive` on each of its live environments. */
async function archiveProject(w: World, archived: boolean, environments: readonly string[]): Promise<void> {
  const reads = await Promise.all(environments.map(readEnvironment));
  await write(environments.map((id, i) => ({ kind: 'environment' as const, id, before: reads[i]!, after: { ...reads[i]!.columns, projectArchived: archived } })),
    async (tx) => run(tx, sql`UPDATE projects SET archived_at = ${archived ? new Date().toISOString() : null} WHERE id = ${w.project}`));
}

/** A fork of `dev`, made through the app. */
async function fork(w: World): Promise<string> {
  const id = randomUUID();
  const slug = `fork-${id.slice(0, 4)}`;
  const made: EnvironmentColumns = { id, projectId: w.project, slug, owner: null, parentId: w.dev, protected: false, archived: false, projectArchived: false };
  await write([{ kind: 'environment', id, before: null, after: made }], async (tx) => {
    await tx.insert(tablesOf(tx).environments).values({ id, projectId: w.project, slug, name: slug, parentId: w.dev, protected: false });
  });
  return id;
}

test("a project archived and restored through the app: each live environment's change (`project.archive`), and a use through a fork of it refused as 0.14 refuses it, live as replayed (T126)", async () => {
  const w = await world();
  const id = await w.key();
  const through = await fork(w);
  assert.ok((await used(w, id, { place: through })).ok);
  await archiveProject(w, true, [w.dev, through]);
  assert.equal(codeOf(await used(w, id, { place: through })), 'bad_claim');
  assert.deepEqual(environmentObject((await readEnvironment(through)).columns).projectArchived, true);
  await archiveProject(w, false, [w.dev, through]);
  assert.ok((await used(w, id, { place: through })).ok);
  assert.deepEqual(await opsOf({ kind: 'environment', id: through }), ['environment.create', 'project.archive', 'project.archive']);
  await replayAgrees();
});

test("an environment's own archival and its project's are apart: either edited around the app is refused as tampered, and no restore seals the edit in (T126, ArchivedApart)", async () => {
  const w = await world();
  const id = await w.key();
  const through = await fork(w);
  const own = await readEnvironment(through);
  await write([{ kind: 'environment', id: through, before: own, after: { ...own.columns, archived: true } }],
    async (tx) => run(tx, sql`UPDATE environments SET archived_at = ${new Date().toISOString()} WHERE id = ${through}`));
  await archiveProject(w, true, [w.dev, through]);
  // A writer clears the fork's own archival while its project is archived: one bit for both would not see it.
  await run(db.owner, sql`UPDATE environments SET archived_at = NULL WHERE id = ${through}`);
  assert.equal(codeOf(await used(w, id, { place: through })), 'tampered');
  const edited = await readEnvironment(through);
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'environment', id: through, before: edited, after: { ...edited.columns, projectArchived: false } }], new Map()),
    (error: unknown) => error instanceof NotLogged && error.fault === 'tampered');
  // The project's archival cleared around the app: a use in its environment refused too.
  await run(db.owner, sql`UPDATE environments SET archived_at = ${new Date().toISOString()} WHERE id = ${through}`);
  await run(db.owner, sql`UPDATE projects SET archived_at = NULL WHERE id = ${w.project}`);
  assert.equal(codeOf(await used(w, id)), 'tampered');
});

test("a plain value's text under its seal: its digest in its object and its change, and an edit around the app refused as tampered, the key's use and a reference's (T129)", async () => {
  const w = await world();
  const id = await w.key();
  const plain = await newVersion(w, id, 'eu-west-3', w.dev, { plain: true });
  await write([await keyChange(id, { ...(await readKey(id)).columns, version: plain.columns })], plain.insert);
  const [{ payload }] = await rows<{ payload: string }>(db.owner, sql`SELECT payload FROM log_changes WHERE object = ${objectKey({ kind: 'secret', id })} ORDER BY number DESC LIMIT 1`) as [{ payload: string }];
  const logged = JSON.parse(payload) as { nature: string; key: unknown; digest: unknown };
  assert.deepEqual([logged.nature, logged.key, logged.digest], ['plain', null, createHash('sha256').update('eu-west-3').digest('base64')]);
  const vault = await deciding();
  const { holder } = await reference(w, vault, id);
  // A plain value is the app's to hand back: a use refuses it, as 0.14's vault never decides one, but reads it under its seal.
  assert.equal(codeOf(await used(w, id)), 'bad_claim');
  assert.equal(codeOf(await used(w, holder)), 'bad_claim');
  await replayAgrees();
  // A writer who can lift a version's erase-only trigger (the database's owner) edits the text.
  await withTriggersLifted(db.owner, 'secret_versions', (tx) => run(tx, sql`UPDATE secret_versions SET plaintext = 'attacker.example' WHERE id = ${plain.columns.id}`));
  assert.equal(codeOf(await used(w, id)), 'tampered');
  assert.equal(codeOf(await used(w, holder)), 'tampered');
  // And the next write of it, prepared from the edited text, is refused: the vault seals no edit in.
  const archive = await keyChange(id, null);
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [archive], new Map()), (error: unknown) => error instanceof NotLogged && error.fault === 'tampered');
});

