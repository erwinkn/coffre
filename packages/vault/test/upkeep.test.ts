import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { randomBytes, randomUUID } from 'node:crypto';

import { inclusionProof, leafHash, nodesFrom, tileMap, verifyInclusion } from '@coffre/core/log';
import { rowsOf } from '@coffre/db/dialect';
import { credentials, deviceLogins, enrollmentCodes } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { put } from '../src/change.ts';
import { pending } from '../src/entry.ts';
import { checked, nameOf, type Fresh } from '../src/rows.ts';
import { headText, Signer, type Finding, type Store } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import * as world from './world.ts';

/**
 * The signer's minute after its check (upkeep.ts), on Postgres: the oldest
 * uses pruned, a block at a time, a slice of the log re-checked against
 * what was signed, and the rows that lapsed deleted, against a database
 * writer and a signer that dies.
 */
const vault = await openTestVault();
after(() => vault.close());

const DAY = 24 * 60 * 60_000;
let store: ReturnType<typeof memoryStore>;
let signer: Signer;
const open = (keepUsesDays: number | null = 90, on: Store = store) => Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store: on, keepUsesDays });

beforeEach(async () => {
  await emptyDatabase(vault.owner);
  store = memoryStore();
  signer = await open();
});

/** `count` entries, dated now, committed as a use commits one: under the aging tree, or the kept one. */
async function write(count: number, kept = false): Promise<void> {
  const entries = Array.from({ length: count }, (_, i) => pending(vault.keys[0]!, { kept, action: kept ? 'member.role' : 'secret.read', actor: null, credential: null, request: null, ip: null, objects: [`secret:k${i}`], detail: {} }, vault.now(), []));
  const rows = JSON.stringify(entries.map(({ body, mac }) => ({ kept, body, mac: mac.toString('hex') })));
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) SELECT kept, body, decode(mac, 'hex') FROM jsonb_to_recordset(${rows}::jsonb) AS t(kept boolean, body text, mac text)`);
  while (await signer.run(false));
}
/** A minute on, and its check, with the runs it asks for after: what they found. */
async function minute(): Promise<Finding[]> {
  vault.tick(60_000);
  for (let again = await signer.run(true); again; again = await signer.run(false));
  return signer.take();
}

type Head = { keptSize: number; keptRoot: string; agingSize: number; agingRoot: string; agingFrom: number };
/** The head under the vault's MAC, and every entry in the log proves against it from the tiles as stored: the aging tree's from `agingFrom`. */
async function proven(): Promise<Head> {
  const [head] = await rowsOf<Head & { size: number; signedAt: number; mac: Buffer }>(
    vault.owner,
    sql`SELECT size::int, kept_size::int AS "keptSize", encode(kept_root, 'hex') AS "keptRoot", aging_size::int AS "agingSize", encode(aging_root, 'hex') AS "agingRoot", aging_from::int AS "agingFrom", (extract(epoch FROM signed_at) * 1000)::float8 AS "signedAt", mac FROM log_head`,
  );
  assert.ok(head !== undefined && checked(vault.keys, (key) => key.entries, headText(head), head.mac) !== undefined, 'the head is under the vault\'s MAC');
  for (const kept of [true, false]) {
    const [from, size, root] = kept ? [0, head.keptSize, head.keptRoot] : [head.agingFrom, head.agingSize, head.agingRoot];
    const nodes = nodesFrom(tileMap(await rowsOf<{ level: number; index: number; hashes: Buffer }>(vault.owner, sql`SELECT level::int, number::int AS index, hashes FROM log_tiles WHERE kept = ${kept}`)));
    const entries = await rowsOf<{ leaf: number; body: string }>(vault.owner, sql`SELECT leaf::int, body FROM log WHERE kept = ${kept} ORDER BY leaf`);
    assert.deepEqual(entries.map((entry) => entry.leaf), Array.from({ length: size - from }, (_, n) => from + n));
    for (const { leaf, body } of entries) assert.ok(verifyInclusion(leafHash(Buffer.from(body)), leaf, size, inclusionProof(nodes, leaf, size), Buffer.from(root, 'hex')), `leaf ${leaf}`);
  }
  // The index names each entry in the log by each object it mentions, and nothing else.
  const index = sql`SELECT object, seq FROM log_index`;
  const mentioned = sql`SELECT o.object, l.seq FROM log l, jsonb_array_elements_text(l.body::jsonb -> 'objects') AS o(object)`;
  assert.deepEqual(await rowsOf(vault.owner, sql`(${index} EXCEPT ${mentioned}) UNION ALL (${mentioned} EXCEPT ${index})`), [], 'the index is the log\'s');
  const { keptSize, keptRoot, agingSize, agingRoot, agingFrom } = head;
  return { keptSize, keptRoot, agingSize, agingRoot, agingFrom };
}
/** What pruning leaves of the aging tree: its first leaf, its index rows' first entry, and its level-0 tiles. */
const left = async () =>
  (
    await rowsOf<{ leaf: number | null; indexed: number | null; tiles: number[] | null }>(
      vault.owner,
      sql`SELECT (SELECT min(leaf)::int FROM log WHERE NOT kept) AS leaf, (SELECT min(seq)::int FROM log_index) AS indexed,
        (SELECT array_agg(number::int ORDER BY number) FROM log_tiles WHERE NOT kept AND level = 0) AS tiles`,
    )
  )[0]!;

test('a block of uses is pruned once every one of its 256 is past the keep, and never the last; what is kept proves, under the same head', async () => {
  // Block 0 at day 0, block 1 straddling days 0 and 1, block 2 at day 1, and two uses of block 3, the last.
  await write(256 + 100);
  vault.tick(DAY);
  await write(156 + 256 + 2);
  await write(3, true);
  assert.deepEqual(await minute(), []);
  const signed = await proven();
  assert.equal(signed.agingFrom, 0);
  // 90 days after day 0, to the millisecond: nothing is past it yet.
  vault.tick(89 * DAY - 2 * 60_000);
  assert.deepEqual([await minute(), (await proven()).agingFrom], [[], 0]);
  // Past it: block 0 goes, and block 1 waits for its youngest.
  assert.deepEqual([await minute(), await proven()], [[], { ...signed, agingFrom: 256 }]);
  assert.deepEqual(await left(), { leaf: 256, indexed: 256, tiles: [1, 2, 3] });
  // A day on, blocks 1 and 2, and never block 3, which holds the tree's last entry: the check reads where the log ends.
  vault.tick(DAY);
  assert.deepEqual([await minute(), await proven()], [[], { ...signed, agingFrom: 768 }]);
  vault.tick(1000 * DAY);
  assert.deepEqual([await minute(), await proven()], [[], { ...signed, agingFrom: 768 }]);
  assert.deepEqual((await left()).tiles, [3]);
  // The tree of changes is never pruned, and both trees go on growing as signed.
  await write(300);
  await write(1, true);
  assert.deepEqual(await minute(), []);
  const grown = await proven();
  assert.deepEqual([grown.keptSize, grown.agingSize, grown.agingFrom], [4, 770 + 300, 768]);
  // And a new signer from the same storage keeps from where this one did.
  signer = await open();
  assert.deepEqual([await minute(), (await proven()).agingFrom], [[], 768]);
});

test('with the keep null, nothing is pruned; with a backlog, 40 blocks a minute at most', async () => {
  await write(42 * 256 + 1);
  signer = await open(null);
  vault.tick(10_000 * DAY);
  assert.deepEqual([await minute(), (await proven()).agingFrom], [[], 0]);
  signer = await open(90);
  assert.deepEqual([await minute(), (await proven()).agingFrom], [[], 40 * 256]);
  assert.deepEqual([await minute(), (await proven()).agingFrom], [[], 42 * 256]);
});

test('an entry made to look old prunes nothing: its age is the one it was signed with, and the re-check names it', async () => {
  await write(256);
  vault.tick(DAY);
  await write(256 + 1);
  assert.deepEqual(await minute(), []);
  // Block 1, a day younger, dated with block 0 where the log holds it.
  const [{ at }] = (await rowsOf<{ at: string }>(vault.owner, sql`SELECT body::jsonb ->> 'at' AS at FROM log WHERE NOT kept AND leaf = 0`)) as [{ at: string }];
  const signed = await rowsOf<{ body: string }>(vault.owner, sql`SELECT body FROM log WHERE NOT kept AND leaf BETWEEN 256 AND 511 ORDER BY leaf`);
  await vault.owner.execute(sql`UPDATE log SET body = jsonb_set(body::jsonb, '{at}', ${at}::jsonb)::text WHERE NOT kept AND leaf BETWEEN 256 AND 511`);
  // Day 90 and two minutes: block 0 is past the keep, block 1 is not, whatever the log says.
  vault.tick(89 * DAY);
  const found = await minute();
  assert.equal((await left()).leaf, 256);
  assert.deepEqual(found, signed.map(({ body }) => ({ found: 'lost', of: leafHash(Buffer.from(body)).toString('hex') })));
  // Said once a walk.
  assert.deepEqual(await minute(), []);
});

test('a use deleted from a block past the keep keeps the block: a finding, said once a walk, never taken for pruned', async () => {
  await write(256 + 1);
  assert.deepEqual(await minute(), []);
  const [{ body }] = (await rowsOf<{ body: string }>(vault.owner, sql`DELETE FROM log WHERE NOT kept AND leaf = 7 RETURNING body`)) as [{ body: string }];
  const gone = [{ found: 'lost', of: leafHash(Buffer.from(body)).toString('hex') }];
  vault.tick(91 * DAY);
  assert.deepEqual([await minute(), (await left()).leaf], [gone, 0]);
  assert.deepEqual(await minute(), []);
  vault.tick(DAY);
  assert.deepEqual([await minute(), (await left()).leaf], [gone, 0]);
});

test('the re-check walks the log round and round, three blocks a minute, and finds a signed entry edited or deleted within one walk', async () => {
  await write(5 * 256, true);
  await write(4 * 256 + 10);
  // A first walk, over a log nobody touched: nothing.
  const walked: Finding[][] = [];
  for (let n = 0; n < 4; n += 1) walked.push(await minute());
  assert.deepEqual(walked, [[], [], [], []]);
  // The writer edits a change of block 1, deletes a use of block 3 and all of block 2; replaces a tile of the aging tree's block 0.
  const [{ edited }] = (await rowsOf<{ edited: string }>(vault.owner, sql`SELECT body AS edited FROM log WHERE kept AND leaf = 300`)) as [{ edited: string }];
  await vault.owner.execute(sql`UPDATE log SET body = replace(body, 'member.role', 'member.gone') WHERE kept AND leaf = 300`);
  const [{ deleted }] = (await rowsOf<{ deleted: string }>(vault.owner, sql`DELETE FROM log WHERE NOT kept AND leaf = 800 RETURNING body AS deleted`)) as [{ deleted: string }];
  await vault.owner.execute(sql`DELETE FROM log WHERE NOT kept AND leaf BETWEEN 512 AND 767`);
  await vault.owner.execute(sql`UPDATE log_tiles SET hashes = overlay(hashes PLACING '\\x00'::bytea FROM 1 FOR 1) WHERE NOT kept AND level = 0 AND number = 0`);
  // The next walk starts a day after the last, and takes four minutes: ten blocks, three a minute.
  vault.tick(DAY);
  const found: Finding[][] = [];
  for (let n = 0; n < 5; n += 1) found.push(await minute());
  const hash = (body: string) => leafHash(Buffer.from(body)).toString('hex');
  assert.deepEqual(found, [[{ found: 'lost', of: hash(edited) }], [{ found: 'lost', of: 'aging 0-255' }], [{ found: 'lost', of: 'aging 512-767' }, { found: 'lost', of: hash(deleted) }], [], []]);
});

test('a walk ends where the log was when it began: a log growing faster than the re-check reads still comes round to the changes, across a restart', async () => {
  signer = await open(null);
  await write(2 * 256, true);
  // 1,024 uses a minute, where a minute re-checks 768 entries.
  const found: Finding[][] = [];
  const grow = async () => {
    await write(4 * 256);
    found.push(await minute());
  };
  // The first walk reads the changes' two blocks, then four of uses, as far as the log was at its start.
  await grow();
  const [{ deleted }] = (await rowsOf<{ deleted: string }>(vault.owner, sql`DELETE FROM log WHERE kept AND leaf = 7 RETURNING body AS deleted`)) as [{ deleted: string }];
  vault.tick(DAY);
  await grow();
  // The signer dies; the next comes up where the walk was, and so does its end.
  signer = await open(null);
  for (let n = 0; n < 3; n += 1) await grow();
  assert.deepEqual(found, [[], [], [{ found: 'lost', of: leafHash(Buffer.from(deleted)).toString('hex') }], [], []]);
});

test('the re-check finds nothing on a pruned log, walk after walk; it skips what was pruned, by what the signer kept', async () => {
  await write(6 * 256);
  vault.tick(91 * DAY);
  await write(2 * 256 + 1);
  await write(1, true);
  assert.deepEqual(await minute(), []);
  assert.equal((await proven()).agingFrom, 6 * 256);
  for (let n = 0; n < 6; n += 1) {
    vault.tick(DAY);
    assert.deepEqual([await minute(), await minute()], [[], []]);
  }
  // A use the writer deletes below the kept point is gone already for the signer, and nothing to find; one above, a finding.
  await vault.owner.execute(sql`INSERT INTO log (seq, kept, leaf, body) VALUES (1000000, false, 5, '{}')`);
  await vault.owner.execute(sql`DELETE FROM log WHERE NOT kept AND leaf = ${6 * 256}`);
  vault.tick(DAY);
  assert.deepEqual([...(await minute()), ...(await minute())].map((each) => each.found), ['lost']);
});

test('a signer that dies between pruning\'s writes is finished by the next, which finds nothing', async () => {
  /** The store, made to fail the write that `fails` picks, once. */
  const failing = (fails: (changes: ReadonlyMap<string, unknown>) => boolean): Store => ({
    read: () => store.read(),
    async write(changes) {
      if (fails(changes)) throw new Error('the object is gone');
      await store.write(changes);
    },
  });
  for (const dies of ['at the record', 'before the delete', 'after it'] as const) {
    await emptyDatabase(vault.owner);
    store = memoryStore();
    signer = await open();
    await write(3 * 256 + 1);
    assert.deepEqual(await minute(), []);
    // Pruning is due: what to keep from goes to storage, then the statement, then its end to storage.
    const pruning = () => (store.kept.get('moving') as { taken: unknown[] } | undefined)?.taken.length === 0;
    const ending = (changes: ReadonlyMap<string, unknown>) => changes.has('moving') && changes.get('moving') === undefined && pruning();
    vault.tick(91 * DAY);
    let failed = false;
    if (dies === 'before the delete') {
      // The record is written; the object dies before its statement runs.
      const db = vault.db;
      const gone = () => Promise.reject(new Error('the object is gone'));
      signer = await Signer.open({ db: new Proxy(db, { get: (target, key) => (pruning() ? ((failed = true), gone) : Reflect.get(target, key)) as unknown }), keys: vault.keys, now: vault.now, store, keepUsesDays: 90 });
    } else if (dies === 'at the record') signer = await open(90, failing((changes) => changes.has('agingFrom') && (failed = true)));
    else signer = await open(90, failing((changes) => ending(changes) && (failed = true)));
    await assert.rejects(signer.run(true));
    assert.ok(failed);
    // On disk: the first use kept, and the move to finish; or, dead at the record, neither, and nothing deleted.
    const recorded = dies === 'at the record' ? [undefined, undefined] : [3 * 256, 0];
    assert.deepEqual([store.kept.get('agingFrom'), (store.kept.get('moving') as { pruning: number } | undefined)?.pruning], recorded);
    assert.equal((await left()).leaf, dies === 'after it' ? 3 * 256 : 0);
    // Meanwhile a writer swaps bodies to go for ones that do not parse, in block 0 with the tile to hash to one of them: not as
    // signed, they stay, all of block 0, and stop nothing.
    const swapped = dies === 'before the delete' ? [...Array.from({ length: 256 }, (_, leaf) => leaf), 300] : [];
    if (swapped.length > 0) {
      await vault.owner.execute(sql`UPDATE log SET body = CASE leaf WHEN 5 THEN 'x' ELSE '{"objects": 5}' END WHERE NOT kept AND leaf IN (5, 6, 300)`);
      await vault.owner.execute(sql`UPDATE log_tiles SET hashes = overlay(hashes PLACING sha256(decode('00', 'hex') || convert_to('{"objects": 5}', 'UTF8')) FROM 6 * 32 + 1 FOR 32) WHERE NOT kept AND level = 0 AND number = 0`);
    }
    // The next signer finishes it, once, and finds nothing: not the rows that were to go, nor their absence.
    signer = await open();
    assert.deepEqual(await minute(), []);
    const stayed = await rowsOf<{ leaf: number }>(vault.owner, sql`SELECT leaf::int FROM log WHERE NOT kept AND leaf < ${3 * 256} ORDER BY leaf`);
    assert.deepEqual(stayed.map(({ leaf }) => leaf), swapped);
    await vault.owner.execute(sql`WITH gone AS (DELETE FROM log WHERE NOT kept AND leaf < ${3 * 256} RETURNING seq) DELETE FROM log_index WHERE seq IN (SELECT seq FROM gone)`);
    assert.equal((await proven()).agingFrom, 3 * 256);
    assert.deepEqual(await left(), { leaf: 3 * 256, indexed: 3 * 256, tiles: [3] });
    assert.equal(store.kept.has('moving'), false);
    vault.tick(DAY);
    assert.deepEqual(await minute(), []);
  }
});

test('a minute whose upkeep fails is not checked: a writer who holds what it reads has the signer said stopped, as when its check fails', async () => {
  // A block before the last, not yet past the keep: each minute's pruning reads it.
  await write(257);
  assert.deepEqual(await minute(), []);
  const checked = signer.checked;
  let release!: () => void;
  const locked = vault.owner.transaction(async (tx) => {
    await tx.execute(sql`LOCK TABLE log_tiles IN ACCESS EXCLUSIVE MODE`);
    await new Promise<void>((resolve) => (release = resolve));
  });
  try {
    await new Promise((resolve) => setTimeout(resolve, 100));
    vault.tick(60_000);
    await assert.rejects(signer.run(true));
    assert.equal(signer.checked, checked);
  } finally {
    release();
    await locked;
  }
  assert.deepEqual(await minute(), []);
  assert.equal(signer.checked, vault.now());
});

const HOUR = 60 * 60_000;
const ada = world.user('ada');
const ci = 'token:ci';
/** When, from the vault's clock now. */
const since = (ms: number) => new Date(vault.now() + ms);
const login = (expiresAt: Date): Fresh<typeof deviceLogins> => ({
  id: randomUUID(), deviceCodeHash: randomBytes(32), userCode: randomUUID().slice(0, 9), clientLabel: null, clientIp: null, createdAt: since(-3 * DAY), expiresAt,
  decidedAt: null, decision: null, generation: 0, principal: null, consumedAt: null,
});
const code = (of: { id: string }, expiresAt: Date): Fresh<typeof enrollmentCodes> => ({
  id: randomUUID(), bindingId: of.id, codeHash: randomBytes(32), codeHint: 'coffre_enr_…', scope: '{}', createdAt: since(-3 * DAY), createdBy: ci, createdWith: null, expiresAt, supersededAt: null,
});
/** ID tokens spent and MCP approvals, which carry no MAC: rows the owner writes. */
async function plain(spent: Date[], approvals: { of: string; expiresAt: Date }[]): Promise<void> {
  if (spent.length > 0) await vault.owner.execute(sql`INSERT INTO spent_id_tokens (hash, spent_at) SELECT sha256(convert_to(gen_random_uuid()::text, 'UTF8')), s::timestamptz FROM jsonb_array_elements_text(${JSON.stringify(spent)}::jsonb) AS s`);
  for (const { of, expiresAt } of approvals) {
    await vault.owner.execute(sql`INSERT INTO mcp_approvals (id, connection_id, tool, arguments, digest, status, created_at, expires_at)
      VALUES (${randomUUID()}, ${of}, 'archive_secret', '{}', sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'pending', ${new Date(expiresAt.getTime() - 5 * 60_000).toISOString()}, ${expiresAt.toISOString()})`);
  }
}
/** What is left of each kind: ids, sorted; spent ID tokens by count. */
const remaining = async () =>
  (
    await rowsOf<{ credentials: string[] | null; logins: string[] | null; codes: string[] | null; spent: number; approvals: string[] | null; waiting: number }>(
      vault.owner,
      sql`SELECT (SELECT array_agg(id::text ORDER BY id) FROM credentials) AS credentials, (SELECT array_agg(id::text ORDER BY id) FROM device_logins) AS logins,
        (SELECT array_agg(id::text ORDER BY id) FROM enrollment_codes) AS codes, (SELECT count(*)::int FROM spent_id_tokens) AS spent,
        (SELECT array_agg(id::text ORDER BY id) FROM mcp_approvals) AS approvals, (SELECT count(*)::int FROM log_pending) AS waiting`,
    )
  )[0]!;
const ids = (...rows: { id: string }[]) => rows.map(({ id }) => id).sort();
/** A credential live for a month: the clock runs on across tests, past the fixtures' own expiry. */
const live = (label: string, more: Partial<Fresh<typeof credentials>> = {}) => world.credential(label, ada, { expiresAt: since(30 * DAY), ...more });

test('the rows that lapsed go a day past their expiry, by a change the mirror follows, and the next minute finds nothing; a code once no credential names it', async () => {
  const binding = world.binding(ci);
  const [stale, lately, codeNamed, codeLive, codeFree] = [since(-2 * DAY), since(-2 * HOUR), since(-2 * DAY), since(30 * DAY), since(-2 * DAY)];
  const [named, lasting, free] = [code(binding, codeNamed), code(binding, codeLive), code(binding, codeFree)];
  const old = world.credential('old', ada, { expiresAt: stale });
  const recent = world.credential('recent', ada, { expiresAt: lately });
  const kept = live('kept');
  const workload = world.session('w', binding, { enrollmentId: named.id, expiresAt: lately });
  const mcp = live('mcp', { kind: 'mcp', client: '{}' });
  const [oldLogin, recentLogin] = [login(stale), login(lately)];
  await world.write(vault, ...world.rows('principals', world.principal(ada), world.principal(ci)), ...world.rows('bindings', binding),
    put(enrollmentCodes, named), put(enrollmentCodes, lasting), put(enrollmentCodes, free),
    ...world.rows('credentials', old, recent, kept, workload, mcp), put(deviceLogins, oldLogin), put(deviceLogins, recentLogin));
  await plain([since(-3 * HOUR), since(-HOUR)], [{ of: mcp.id, expiresAt: stale }, { of: mcp.id, expiresAt: lately }]);
  const approvals = (await remaining()).approvals!;

  assert.deepEqual(await minute(), []);
  assert.deepEqual(await remaining(), {
    credentials: ids(recent, kept, workload, mcp), logins: ids(recentLogin), codes: ids(named, lasting), spent: 1,
    approvals: (await rowsOf<{ id: string }>(vault.owner, sql`SELECT id::text FROM mcp_approvals WHERE expires_at = ${lately.toISOString()}`)).map(({ id }) => id), waiting: 0,
  });
  assert.equal(approvals.length, 2);
  const [entry] = await rowsOf<{ kept: boolean; body: string }>(vault.owner, sql`SELECT kept, body FROM log WHERE body::jsonb ->> 'action' = 'upkeep.expire'`);
  assert.equal(entry?.kept, false, 'under the tree that ages out');
  assert.deepEqual(JSON.parse(entry.body).objects, [`credential:${old.id}`, `device_login:${oldLogin.id}`, `enrollment_code:${free.id}`]);
  assert.deepEqual(await minute(), [], 'the mirror followed');

  // A day on: the sessions and the login go, then, once nothing names it, the code.
  vault.tick(DAY);
  assert.deepEqual(await minute(), []);
  assert.deepEqual(await remaining(), { credentials: ids(kept, mcp), logins: null, codes: ids(named, lasting), spent: 0, approvals: null, waiting: 0 });
  assert.deepEqual(await minute(), []);
  assert.deepEqual((await remaining()).codes, ids(lasting));
});

test('a minute deletes 100 of each kind at most, the oldest first', async () => {
  const connection = live('mcp', { kind: 'mcp', client: '{}' });
  const lapsed = Array.from({ length: 250 }, (_, n) => world.credential(`c${n}`, ada, { expiresAt: since(-2 * DAY - n * 60_000) }));
  await world.write(vault, ...world.rows('principals', world.principal(ada)), ...world.rows('credentials', connection, ...lapsed));
  await plain(Array.from({ length: 250 }, () => since(-3 * HOUR)), Array.from({ length: 250 }, () => ({ of: connection.id, expiresAt: since(-2 * DAY) })));
  const counts = async () => {
    const { credentials: left, spent, approvals } = await remaining();
    return [left!.length - 1, spent, approvals?.length ?? 0];
  };
  for (const left of [150, 50, 0]) {
    assert.deepEqual(await minute(), []);
    assert.deepEqual(await counts(), [left, left, left]);
    // The oldest first: what is left of the credentials expired last.
    assert.deepEqual((await remaining()).credentials, ids(connection, ...lapsed.slice(0, left)));
  }
});

test('a credential whose expiry a writer moved back stays: under its MAC, it is not the vault\'s', async () => {
  const moved = live('moved');
  await world.write(vault, ...world.rows('principals', world.principal(ada)), ...world.rows('credentials', moved));
  assert.deepEqual(await minute(), []);
  await vault.owner.update(credentials).set({ expiresAt: since(-2 * DAY) }).where(sql`id = ${moved.id}`);
  assert.deepEqual(await minute(), []);
  assert.deepEqual((await remaining()).credentials, ids(moved));
});

test('the upkeep\'s entry is expected: a writer who deletes it before it is signed is found', async () => {
  const old = world.credential('old', ada, { expiresAt: since(-2 * DAY) });
  await world.write(vault, ...world.rows('principals', world.principal(ada)), ...world.rows('credentials', old));
  vault.tick(60_000);
  assert.equal(await signer.run(true), true, 'its entry waits, and the signer runs again at once');
  await vault.owner.execute(sql`DELETE FROM log_pending`);
  while (await signer.run(false));
  assert.deepEqual((await signer.take()).map(({ found }) => found), ['missing']);
  assert.deepEqual(await minute(), [{ found: 'row', of: nameOf(credentials, old) }], 'and the credential it deleted is not what the log says');
});

test('a cleanup a writer holds up fails its minute after the deletion it committed is expected, and before the re-check reads: both are said', async () => {
  await write(3);
  assert.deepEqual(await minute(), []);
  const old = world.credential('old', ada, { expiresAt: since(-2 * DAY) });
  await world.write(vault, ...world.rows('principals', world.principal(ada)), ...world.rows('credentials', old));
  await plain([since(-3 * HOUR)], []);
  const [{ row }] = (await rowsOf<{ row: unknown }>(vault.owner, sql`SELECT to_jsonb(c) AS row FROM credentials c WHERE id = ${old.id}`)) as [{ row: unknown }];
  const [{ body }] = (await rowsOf<{ body: string }>(vault.owner, sql`DELETE FROM log WHERE NOT kept AND leaf = 1 RETURNING body`)) as [{ body: string }];
  vault.tick(DAY);
  const checked = signer.checked;
  let release!: () => void;
  const locked = vault.owner.transaction(async (tx) => {
    await tx.execute(sql`SELECT 1 FROM spent_id_tokens FOR UPDATE`);
    await new Promise<void>((resolve) => (release = resolve));
  });
  try {
    await new Promise((resolve) => setTimeout(resolve, 100));
    vault.tick(60_000);
    await assert.rejects(signer.run(true));
    assert.equal(signer.checked, checked);
    // The deletion committed: the writer drops its entry and puts the credential back, as it was.
    assert.deepEqual((await remaining()).credentials, null);
    await vault.owner.execute(sql`DELETE FROM log_pending`);
    await vault.owner.execute(sql`INSERT INTO credentials SELECT * FROM jsonb_populate_record(NULL::credentials, ${JSON.stringify(row)}::jsonb)`);
  } finally {
    release();
    await locked;
  }
  const found = await minute();
  assert.deepEqual(found.map(({ found }) => found).sort(), ['lost', 'missing']);
  assert.deepEqual(found.find(({ found }) => found === 'lost'), { found: 'lost', of: leafHash(Buffer.from(body)).toString('hex') });
  assert.equal(signer.checked, vault.now());
});
