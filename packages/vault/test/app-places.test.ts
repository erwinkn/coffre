// 0.15's change path for the app's keys and environments (docs/design/0.15-plan.md, "As built: PR 4b", part 2): each
// write of the app's to a key or an environment is a change the vault seals before the app's transaction (`prepare`) and
// the transaction commits beside its rows (`app_change`, 0025). These cases play the app's writes on use-world's sealed
// world, then hold the use path's live answers to the replay of the log (R53): a write that left a row other than its
// change sealed would make a use `stale` or `tampered` where the replay allows or refuses otherwise. Both engines.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { encrypt, freshDek } from '@coffre/core/envelope';
import { tombstoneOf } from '@coffre/core/schemas';
import type { EnvironmentColumns, ObjectChange, SecretColumns, UseOutcome, VersionColumns } from '@coffre/core/vault';
import { tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { appChanges, isStaleChange } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { loggedChange, NotLogged, prepareChanges, type ChangeKeys } from '../src/changes.ts';
import { objectKey, type Ref } from '../src/inputs.ts';
import { logMacKey } from '../src/log-entry.ts';
import { purposeOf, replay, type Logged } from '../src/log-replay.ts';
import { environmentObject, secretObject } from '../src/objects.ts';
import { openTestDatabase, rows, run, type TestDatabase } from './database.ts';
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

/** The app's write: its changes sealed before (`prepare`), then its rows and the changes in one transaction, as `audited` commits them. */
async function write(changes: ObjectChange[], rowsOf: (tx: Transaction) => Promise<void>): Promise<bigint[]> {
  const calls = prepareChanges(KEYS, Date.now(), ROOT, changes);
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
    project_id: string; environment_id: string; archived: boolean | number; seal: Buffer | null; version: string | null; sensitive: boolean | number | null; plain: boolean | number | null;
    kek_provider: string | null; kek_id: string | null; kek_version: string | null; wrapped_dek: Buffer | null; source: string | null;
  }>(db.owner, sql`
    SELECT s.project_id, s.environment_id, s.archived_at IS NOT NULL AS archived, s.seal, s.current_version_id AS version, v.sensitive, v.plaintext IS NOT NULL AS plain,
           v.kek_provider, v.kek_id, v.kek_version, v.wrapped_dek,
           (SELECT r.source_secret_id FROM secret_references r WHERE r.secret_id = s.id ORDER BY r.created_seq DESC LIMIT 1) AS source
      FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id WHERE s.id = ${id}`);
  assert.ok(row !== undefined, `key ${id} has a row`);
  const version: VersionColumns | null = row.version === null ? null : {
    id: row.version, sensitive: Boolean(row.sensitive), plain: Boolean(row.plain), kekProvider: row.kek_provider!, kekId: row.kek_id!, kekVersion: row.kek_version!,
    wrappedDek: Buffer.from(row.wrapped_dek!).toString('base64'),
  };
  return {
    columns: { id, projectId: row.project_id, environmentId: row.environment_id, source: row.version === null ? row.source : null, version },
    archived: Boolean(row.archived),
    seal: row.seal === null ? null : Buffer.from(row.seal).toString('base64'),
  };
}

async function readEnvironment(id: string): Promise<{ columns: EnvironmentColumns; seal: string | null }> {
  const [row] = await rows<{ project_id: string; slug: string; owner: string | null; parent_id: string | null; protected: boolean | number | null; archived: boolean | number; seal: Buffer | null }>(db.owner,
    sql`SELECT project_id, slug, owner, parent_id, protected, archived_at IS NOT NULL AS archived, seal FROM environments WHERE id = ${id}`);
  assert.ok(row !== undefined);
  return {
    columns: { id, projectId: row.project_id, slug: row.slug, owner: row.owner, parentId: row.parent_id, protected: row.protected === null ? null : Boolean(row.protected), archived: Boolean(row.archived) },
    seal: row.seal === null ? null : Buffer.from(row.seal).toString('base64'),
  };
}

/** A key's change from its row as read now (archived: no object) to `after`. */
async function keyChange(id: string, after: SecretColumns | null): Promise<ObjectChange> {
  const read = await readKey(id);
  return { kind: 'secret', id, before: read.archived ? null : { columns: read.columns, seal: read.seal }, after };
}

/** A new version of `w`'s key `id`: its value encrypted under a fresh data key, wrapped, and the row that stores it. */
async function newVersion(w: World, id: string, value: string, environmentId = w.dev): Promise<{ columns: VersionColumns; insert: (tx: Queryable) => Promise<void> }> {
  const version = randomUUID();
  const dek = freshDek();
  const context = { projectId: w.project, environmentId, secretId: id };
  const sealed = encrypt(Buffer.from(value), context, dek);
  const wrapped = await CONFIG.keks.wrap(dek, context, { deadline: Date.now() + 5000, signal: new AbortController().signal });
  const t = tablesOf(db.owner);
  return {
    columns: { id: version, sensitive: false, plain: false, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, wrappedDek: Buffer.from(wrapped.bytes).toString('base64') },
    insert: async (tx) => {
      const [{ n }] = await rows<{ n: number | string }>(tx, sql`SELECT current_version + 1 AS n FROM secrets WHERE id = ${id}`) as [{ n: number | string }];
      await (tx as Transaction).insert(t.secretVersions).values({
        id: version, secretId: id, version: Number(n), envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
        wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT, sensitive: false,
      });
      await run(tx, sql`UPDATE secrets SET current_version_id = ${version}, current_version = ${Number(n)} WHERE id = ${id}`);
    },
  };
}

/** Every live answer, by entry number. */
const answered = new Map<string, UseOutcome>();
beforeEach(() => answered.clear());

async function used(w: World, secretId: string): Promise<UseOutcome> {
  const outcome = await (await isolate()).use(ask(w, secretId));
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
    sql`SELECT number, at, object, payload, seal FROM log_changes`);
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
  assert.deepEqual(Object.keys(logged).sort(), ['environmentId', 'key', 'nature', 'op', 'projectId', 'ref', 'source', 'version']);
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
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'secret', id, before: { columns: { ...read.columns, environmentId: elsewhere }, seal: read.seal }, after: null }]),
    (error: unknown) => error instanceof NotLogged && error.fault === 'tampered');
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'secret', id, before: { columns: read.columns, seal: read.seal }, after: { ...read.columns, environmentId: elsewhere } }]),
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
  const made: EnvironmentColumns = { id: fork, projectId: w.project, slug: 'staging', owner: null, parentId: w.dev, protected: true, archived: false };
  await write([{ kind: 'environment', id: fork, before: null, after: made }], async (tx) => {
    await tx.insert(tablesOf(tx).environments).values({ id: fork, projectId: w.project, slug: 'staging', name: 'staging', parentId: w.dev, protected: true });
  });
  const stored = await readEnvironment(fork);
  assert.deepEqual(environmentObject(stored.columns), environmentObject(made));
  assert.deepEqual(await opsOf({ kind: 'environment', id: w.dev }), ['genesis', 'environment.rename', 'environment.archive', 'environment.archive']);
  assert.deepEqual(await opsOf({ kind: 'environment', id: fork }), ['environment.create']);
  // What the app may not write: a protection (the vault's), a parent, another project.
  for (const after of [{ ...stored.columns, protected: false }, { ...stored.columns, parentId: null }, { ...stored.columns, projectId: randomUUID() }]) {
    assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'environment', id: fork, before: stored, after }]), /no change the log knows/);
  }
  await replayAgrees();
});

test('an environment deleted with its keys: its slug a tombstone, each key erased, deleted and archived; a use there is refused live as replayed, never stale', async () => {
  const w = await world();
  const ids = [await w.key('one'), await w.key('two')];
  assert.ok((await used(w, ids[0]!)).ok);
  const env = await readEnvironment(w.dev);
  const tombstone = tombstoneOf('dev', new Date());
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
  assert.throws(() => prepareChanges(KEYS, Date.now(), ROOT, [{ kind: 'environment', id: w.dev, before: now, after: { ...now.columns, archived: true } }]), /does nothing/);
  await replayAgrees();
});

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
