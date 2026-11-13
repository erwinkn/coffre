// The checkpointer over 0.15's log as migration 0022 lays it out, through
// the vault's own login: the barrier and the window, write_checkpoint and
// its tiles, and the reads proofs and the verifier make
// (docs/design/audit-tree.md). The owner plays the change and use paths
// (plans PR 4 and 5), which write the entries, and a database writer where
// a case says so.
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { after, before, beforeEach, test } from 'node:test';

import { leafHash, macData, pairSigners, pairVerifiers, parseCheckpoint, splitNote, verifyInclusion, verifyLog, type PairNotes, type PairSigners, type PairVerifiers } from '@coffre/core/merkle';
import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { Checkpointer } from '../src/checkpointer.ts';
import { authentic, entryMac, logMacKey, type LogMacKey, type UseRow } from '../src/log-entry.ts';
import { logWriter } from './log-entries.ts';
import { logStore, postgresWindow, tileKeys } from '../src/log-store.ts';
import { variableMemory } from './audit-tree.ts';
import { openTestDatabase, rows, run, VAULT_URL, type TestDatabase } from './database.ts';

let db: TestDatabase;
let signers: PairSigners;
let verifiers: PairVerifiers;
let macKey: LogMacKey;
let log: ReturnType<typeof logWriter>;
const use = (...args: Parameters<typeof log.use>) => log.use(...args);
const change = () => log.change();

before(async () => {
  db = await openTestDatabase();
  const seed = randomBytes(32);
  signers = await pairSigners('coffre.test/audit', seed);
  verifiers = await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey });
  macKey = logMacKey(seed);
  log = logWriter(db.owner, macKey);
  // Today's and tomorrow's uses, as the checkpointer will make them ahead (plan PR 7).
  await log.days();
});
after(() => db?.close());
beforeEach(() => log.empty());

/** The floor a pair signed. */
const decodeFloor = (notes: PairNotes) => parseCheckpoint(splitNote(notes.changes).text).floor;

/** Ranges of 512 leaves, so that a test crosses some; one size for the file, whose database keeps the ranges made. */
const RANGE = 512;

async function open(memory = variableMemory(), windowMax?: number) {
  const alerts: string[] = [];
  const store = logStore(db.vault, { tileRange: RANGE });
  const cp = await Checkpointer.open(store, signers, { memory, authentic: authentic(macKey), alert: (m) => alerts.push(m), ...(windowMax === undefined ? {} : { windowMax }) });
  return { cp, store, memory, alerts };
}

test('ticks seal both trees through the vault login, and the log verifies, every entry provable', async () => {
  const { cp, store, memory, alerts } = await open();
  const numbers: bigint[] = [];
  for (let t = 0; t < 4; t += 1) {
    for (let i = 0; i < 30; i += 1) numbers.push(await use());
    numbers.push(await change());
    const tick = await cp.tick();
    assert.ok(tick.signed, tick.failures.join('; '));
  }
  assert.deepEqual([cp.pair.pair.changes.size, cp.pair.pair.uses.size], [4, 120]);
  const [row] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_checkpoints`);
  assert.equal(Number(row!.n), 5, 'genesis and four pairs, one row each');
  const v = await verifyLog(store, { verifiers, anchors: [JSON.parse(memory.record!)], check: (e) => (authentic(macKey)(e) ? null : 'mac') });
  assert.ok(v.ok && v.sealed === 124, v.problems.join('\n'));
  for (const number of [numbers[0]!, numbers[30]!, numbers[45]!, numbers.at(-1)!]) {
    const p = (await cp.prove(number))!;
    assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair[p.tree].root), `${number}`);
  }
  // A change as the change path will ask: sealed, proved in the changes tree.
  const pending = await change();
  const sealed = await cp.sealThrough(pending);
  assert.equal(sealed.proof.tree, 'changes');
  assert.equal(sealed.witnessed, null);
  assert.deepEqual(alerts, []);
});

test('the uses tree\'s leaf tiles land in ranges made ahead; a restart from the database seals on', async () => {
  const memory = variableMemory();
  const { cp } = await open(memory);
  for (let t = 0; t < 3; t += 1) {
    for (let i = 0; i < 300; i += 1) await use();
    assert.ok((await cp.tick()).signed);
  }
  const ranges = await rows<{ name: string }>(db.owner, sql`
    SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
     WHERE i.inhparent = 'log_tiles_uses_leaves'::regclass ORDER BY 1`);
  for (const name of ['log_tiles_uses_0', 'log_tiles_uses_512', 'log_tiles_uses_1024']) assert.ok(ranges.some((r) => r.name === name), `${name} in ${ranges.map((r) => r.name)}`);
  const [tiles] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_tiles WHERE tree = 'uses' AND level = 0`);
  assert.equal(Number(tiles!.n), 4, '900 leaves: three full tiles and the partial one');
  const again = await open(memory);
  for (let i = 0; i < 10; i += 1) await use();
  assert.ok((await again.cp.tick()).signed);
  assert.equal(again.cp.pair.pair.uses.size, 910);
  const v = await verifyLog(again.store, { verifiers });
  assert.ok(v.ok, v.problems.join('\n'));
});

test('a forged entry, a floor lowered by a writer, and a tile changed under the signer are each refused', async () => {
  {
    const { cp } = await open();
    await use();
    assert.ok((await cp.tick()).signed);
    await use(Date.now(), true);
    const t = await cp.tick();
    assert.ok(!t.signed && /MAC does not hold/.test(t.failures.join()), t.failures.join());
  }
  {
    await run(db.owner, sql`DELETE FROM log_uses`);
    const { cp } = await open();
    await use();
    assert.ok((await cp.tick()).signed);
    // BarrierChecksFloor: a writer lowers the unsigned floor row.
    await run(db.owner, sql`UPDATE checkpoint_fence SET at_floor = at_floor - 60000`);
    await use();
    const t = await cp.tick();
    assert.ok(!t.signed && /floor of at is .* lowered by a writer/.test(t.failures.join()), t.failures.join());
  }
  {
    await log.empty();
    const { cp } = await open();
    for (let i = 0; i < 3; i += 1) await use();
    assert.ok((await cp.tick()).signed);
    // The partial leaf tile, cut short by a writer: the next write, which grows it, is refused whole.
    await run(db.owner, sql`UPDATE log_tiles SET hashes = substr(hashes, 1, 32) WHERE tree = 'uses' AND level = 0`);
    await run(db.owner, sql`UPDATE log_tiles SET hashes = ${randomBytes(64)} WHERE tree = 'uses' AND level = 0`);
    await use();
    await assert.rejects(cp.tick(), (e: Error) => /shrink or change/.test(`${e.message} ${(e.cause as Error | undefined)?.message}`));
    const [count] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_checkpoints`);
    assert.equal(Number(count!.n), 2, 'no pair written over the tiles that disagree');
  }
});

test('T168a: a MAC is its key\'s tag then its HMAC; another key\'s tag, another key\'s HMAC under this tag, or no tag at all fails closed, and a restart seals on', async () => {
  const memory = variableMemory();
  const { cp } = await open(memory);
  await use();
  await change();
  assert.ok((await cp.tick()).signed);
  const other = logMacKey(randomBytes(32));
  // The whole HMAC, as 0.15 wrote it before the tag: its first 16 bytes were the MAC.
  const hmac = (key: LogMacKey, row: Omit<UseRow, 'number' | 'mac'>) =>
    createHmac('sha256', key.key).update(macData('uses', [BigInt(row.at), row.requestId, row.credential, row.secret, row.purpose, row.place])).digest();
  const forgeries: [string, Parameters<typeof log.use>[1]][] = [
    ['another key\'s MAC', (row) => entryMac(other, { tree: 'uses', row })],
    ['another key\'s tag over this key\'s HMAC', (row) => Buffer.concat([other.tag, entryMac(macKey, { tree: 'uses', row }).subarray(4)])],
    ['this key\'s tag over another key\'s HMAC', (row) => Buffer.concat([macKey.tag, entryMac(other, { tree: 'uses', row }).subarray(4)])],
    ['16 bytes of this key\'s HMAC, no tag', (row) => hmac(macKey, row).subarray(0, 16)],
  ];
  for (const [what, forged] of forgeries) {
    const number = await use(Date.now(), forged);
    const t = await cp.tick();
    assert.ok(!t.signed, what);
    assert.deepEqual(t.failures, [`${number}: its MAC does not hold`], what);
    await run(db.owner, sql`DELETE FROM log_uses WHERE number = ${number}`);
  }
  // Every MAC the writers make is the key's tag, then 12 bytes of its HMAC.
  const [stored] = await rows<{ mac: Uint8Array | ArrayBuffer }>(db.owner, sql`SELECT mac FROM log_uses ORDER BY number LIMIT 1`);
  const mac = Buffer.from(stored!.mac as Uint8Array);
  assert.equal(mac.length, 16);
  assert.ok(mac.subarray(0, 4).equals(macKey.tag));
  // A restart over the same memory: its pairs open, the entries it sealed check under the key, and it seals on.
  await cp.close();
  const again = await open(memory);
  assert.ok(samePairs(again.cp.pair.notes, cp.pair.notes));
  await use();
  await change();
  assert.ok((await again.cp.tick()).signed);
  const v = await verifyLog(again.store, { verifiers, anchors: [JSON.parse(memory.record!)], check: (e) => (authentic(macKey)(e) ? null : 'mac') });
  assert.ok(v.ok && v.sealed === 4, v.problems.join('\n'));
});

const samePairs = (a: PairNotes, b: PairNotes) => a.changes === b.changes && a.uses === b.uses;

test('reads are bounded by their windows: locate finds a use in an old window by its floor, not by scanning', async () => {
  const { cp, store } = await open();
  const first = await use();
  assert.ok((await cp.tick()).signed);
  for (let t = 0; t < 3; t += 1) {
    await use();
    await change();
    assert.ok((await cp.tick()).signed);
  }
  const found = (await store.locate(first))!;
  assert.deepEqual([found.entry.tree, found.index], ['uses', 0]);
  const p = (await cp.prove(first))!;
  assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair.uses.root));
  // The window read and the locate each scan the uses' one index from a floor, never the table.
  const plan = await rows<{ 'QUERY PLAN': string }>(db.vault, sql`EXPLAIN SELECT 1 FROM log_uses u WHERE u.at >= ${Date.now() - 10_000} AND u.number > 0 AND u.number <= 10`);
  assert.ok(plan.some((r) => /Index|Bitmap/.test(r['QUERY PLAN'])), plan.map((r) => r['QUERY PLAN']).join('\n'));
  // A change, as stored: the leaf the checkpointer sealed.
  const [raw] = await rows<{ number: string }>(db.owner, sql`SELECT number FROM log_changes ORDER BY number LIMIT 1`);
  const c = (await store.locate(BigInt(raw!.number)))!;
  assert.equal(c.entry.tree, 'changes');
});

test('review r3: entries and locate read one window\'s bounds, at any index, an empty window between', async () => {
  const { cp, store } = await open();
  const windows: bigint[][] = [];
  for (let t = 0; t < 4; t += 1) {
    const numbers: bigint[] = [];
    if (t !== 2) for (let i = 0; i < 5; i += 1) numbers.push(await use());
    if (t === 1) numbers.push(await change());
    windows.push(numbers);
    // A tick of nothing new signs nothing: an empty window is a pair at the same place, so the third window comes from
    // a skipped number alone.
    if (t === 2) await log.change().then(async (n) => (numbers.push(n), undefined));
    assert.ok((await cp.tick()).signed);
  }
  const pairs = await store.pairs(-1n, 10);
  // The middle windows' entries, exactly, read by the verifier's `entries`.
  const middle = await store.entries(pairs[1]!.upto, pairs[3]!.upto);
  assert.deepEqual(middle.map((e) => e.number), [...windows[1]!, ...windows[2]!]);
  // A use in the last window, not its first: its index counts every use before it in the tree.
  const last = windows[3]!;
  const found = (await store.locate(last[3]!))!;
  assert.deepEqual([found.entry.tree, found.index], ['uses', 5 + 5 + 3]);
  const p = (await cp.prove(last[3]!))!;
  assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair.uses.root));
  // The change of the second window, by its key: the first in its tree.
  assert.deepEqual([(await store.locate(windows[1]!.at(-1)!))!.index], [0]);
});

test('T119: locate finds a use among its window\'s leaves, by its time in one probe when known; a use changed since its tick is refused', async () => {
  const { cp, store } = await open();
  // A window across a leaf tile's edge: 300 uses, the asked one in the second tile.
  for (let i = 0; i < 100; i += 1) await use();
  assert.ok((await cp.tick()).signed);
  const at = Date.now();
  const numbers: bigint[] = [];
  for (let i = 0; i < 300; i += 1) numbers.push(await use(i === 250 ? at : undefined));
  assert.ok((await cp.tick()).signed);
  const asked = numbers[250]!;
  for (const time of [undefined, at]) {
    const found = (await store.locate(asked, time === undefined ? {} : { at: time }))!;
    assert.deepEqual([found.entry.tree, found.index], ['uses', 350]);
    const p = (await cp.prove(asked, time === undefined ? {} : { at: time }))!;
    assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair.uses.root));
  }
  // At another time, it is not there.
  assert.equal(await store.locate(asked, { at: at - 1 }), null);
  // A writer changes it after its tick: its leaf is in none of the window's tiles.
  await run(db.owner, sql`UPDATE log_uses SET purpose = 2 WHERE number = ${asked}`);
  await assert.rejects(store.locate(asked), /use \d+ is in none of its window's leaves: the database changed it since its tick/);
});

test('Fable review: a tile read is planned over the ranges it reads, not every range', async () => {
  // Forty ranges, as many days of a busy instance's retention would make.
  for (let r = 0; r < 40; r += 1) await run(db.owner, sql`SELECT make_tiles(${r * RANGE}::bigint, ${(r + 1) * RANGE}::bigint)`);
  const keys = [{ level: 0, index: 3 }, { level: 1, index: 0 }];
  const plan = await rows<{ 'QUERY PLAN': string }>(db.vault, sql`EXPLAIN SELECT t.level, t.leaf, t.hashes FROM log_tiles t WHERE t.tree = 'uses' AND (${tileKeys(keys)})`);
  const ranges = new Set(plan.flatMap((r) => r['QUERY PLAN'].match(/log_tiles_uses_\d+(?= )/g) ?? []));
  assert.ok(ranges.size <= 2, `${ranges.size} of 40 ranges planned:\n${plan.map((r) => r['QUERY PLAN']).join('\n')}`);
});

test('PR 8 review r1 (W240): a read of the entries above a pair takes the first `limit` of them, by number, both trees', async () => {
  const { cp, store } = await open();
  await use();
  assert.ok((await cp.tick()).signed);
  const upto = cp.pair.pair.upto;
  const above = [await use(), await change(), await use(), await use()];
  const all = await store.entries(upto, 2n ** 62n);
  assert.deepEqual(all.map((e) => e.number), above);
  assert.deepEqual((await store.entries(upto, 2n ** 62n, { limit: 3 })).map((e) => e.number), above.slice(0, 3));
});

test('PR 8 review r2 (W240): a use renumbered into a change\'s place is refused before its window is read, and a window the rows make too wide is never scanned', async () => {
  const memory = variableMemory();
  const { cp, store } = await open(memory);
  await use();
  assert.ok((await cp.tick()).signed);
  const lost = await change();
  const moved = await use();
  assert.ok((await cp.tick()).signed);
  // The writer forges the sealing checkpoint's uses size: scanned, a window of 2^63 leaves.
  await run(db.owner, sql`UPDATE log_checkpoints SET uses_size = 9223372036854775807 WHERE upto = ${cp.pair.pair.upto}`);
  await assert.rejects(store.locate(moved), /window is \d+ to \d+ in the uses tree: no window of 1,048,576 leaves or fewer/);
  // Then deletes the change and renumbers the use into its place: asked for a change, it is refused as a use at once.
  await run(db.owner, sql`DELETE FROM log_changes WHERE number = ${lost}`);
  await run(db.owner, sql`UPDATE log_uses SET number = ${lost} WHERE number = ${moved}`);
  await assert.rejects(store.locate(lost, { tree: 'changes' }), /entry \d+ is in the uses tree, not the changes: a use holds its number/);
  // A checkpointer that did not seal it proves it from the database, and refuses (T171: the one whose tick sealed it
  // proves it from what it kept, sealed before the writer came; the verifier's walk reports the loss).
  const reopened = (await open(memory)).cp;
  await assert.rejects(reopened.sealThrough(lost), /cannot be proved in the signed changes tree: entry \d+ is in the uses tree/);
});

test('PR 8 review r3 (W240): a bounded read stops at its limit in the database too: 100,000 changes above, a few pages read', async () => {
  // Changes a writer planted above the newest pair, as many as a long log holds.
  await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_number'), 0, 'planted-' || g, gen_random_uuid(), 'x', '{}', NULL, '\\x00000000000000000000000000000000'::bytea FROM generate_series(1, 100000) g`);
  await run(db.owner, sql`ANALYZE log_changes`);
  const buffers = async (limit?: number) => {
    const [plan] = await rows<{ 'QUERY PLAN': [{ Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }] }>(db.vault,
      sql`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${postgresWindow(-1n, 2n ** 62n, sql`0`, undefined, limit)}`);
    const top = plan!['QUERY PLAN'][0].Plan;
    return top['Shared Hit Blocks'] + top['Shared Read Blocks'];
  };
  const whole = await buffers();
  const bounded = await buffers(2_001);
  assert.ok(bounded < 200 && bounded * 10 < whole, `${bounded} buffers bounded, ${whole} whole`);
});


test('T245: the window by number reads its first entries in one step of the index, however long the backlog: 400,000 uses behind, a few pages', async () => {
  // A backlog as a stall leaves: uses numbered past the newest pair, stamped now, in today's day.
  await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac)
    SELECT nextval('log_number'), (extract(epoch FROM now()) * 1000)::bigint, g, gen_random_uuid(), gen_random_uuid(), 1, '\\x00000000000000000000000000000000'::bytea
      FROM generate_series(1, 400000) g`);
  // The rows earlier tests deleted gone from the indexes too, as a vacuum leaves a live log.
  await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0) log_changes, log_uses`);
  const window = postgresWindow(-1n, 2n ** 62n, sql`0`, undefined, 10_001, true);
  type Node = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Index Name'?: string; Plans?: Node[] };
  const indexesOf = (node: Node): string[] => [...(node['Index Name'] === undefined ? [] : [node['Index Name']]), ...(node.Plans ?? []).flatMap(indexesOf)];
  const measured = async (unindexed: boolean) => {
    let read = { buffers: 0, indexes: [] as string[] };
    await db.owner.transaction(async (tx) => {
      // 0.15's read, without the index: in a transaction that puts it back.
      if (unindexed) await run(tx, sql`DROP INDEX log_uses_by_number_idx`);
      const [plan] = await rows<{ 'QUERY PLAN': [{ Plan: Node }] }>(tx, sql`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${window}`);
      const top = plan!['QUERY PLAN'][0].Plan;
      read = { buffers: top['Shared Hit Blocks'] + top['Shared Read Blocks'], indexes: indexesOf(top) };
      if (unindexed) tx.rollback();
    }).catch((error: unknown) => {
      if (!unindexed || !(error instanceof Error && /rollback/i.test(error.message))) throw error;
    });
    return read;
  };
  const [indexed, sorted] = [await measured(false), await measured(true)];
  // Measured: 182 buffers by the index after 3.5 million uses, where the sort read 50,003 (T245).
  const said = `${indexed.buffers} buffers by [${indexed.indexes.join(', ')}], ${sorted.buffers} sorting the backlog`;
  assert.ok(indexed.indexes.some((name) => name.endsWith('_by_number_idx')), said);
  assert.ok(indexed.buffers < 400 && indexed.buffers * 5 < sorted.buffers, said);
});

test("a pair's entries listed read the pair's own times, not every entry since a stall's floor: 100,000 entries listed, a few pages", async () => {
  const now = Date.now();
  await run(db.owner, sql`INSERT INTO audit_events (at, number, log, author, action, shown, allowed, actor, places, detail, mac)
    SELECT ${now}::bigint - 100000 + g, g, 16, 'vault', 'secret.read', true, true, 'user:ada@acme.example', '{}', '{}', '\\x00000000000000000000000000000000'::bytea
      FROM generate_series(1, 100000) g`);
  await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0) audit_events`);
  // What the check (`listed`) asks of a pair of 1,000 after a stall: its own entries' times, by the primary key.
  const listed = sql`SELECT e.number FROM audit_events e WHERE e.at >= ${now - 100000 + 50001}::bigint AND e.at <= ${now - 100000 + 51000}::bigint
    AND e.log IN (15, 16) AND e.number > 50000 AND e.number <= 51000`;
  const [plan] = await rows<{ 'QUERY PLAN': [{ Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Actual Rows': number } }] }>(db.vault, sql`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${listed}`);
  const top = plan!['QUERY PLAN'][0].Plan;
  assert.equal(top['Actual Rows'], 1000);
  assert.ok(top['Shared Hit Blocks'] + top['Shared Read Blocks'] < 100, `${top['Shared Hit Blocks'] + top['Shared Read Blocks']} buffers for a pair's 1,000`);
});

// T245 review r8 (R48): the whole of `close()` as a backlog drains, part after part, each statement it sends run again
// under EXPLAIN as the vault's login: the part 2,000 uses in, then the part 20,000 in, ten times the uses sealed behind
// the cursor. Uses stamped one after another (the cursor's floor follows them), and uses that share one `at`, a burst
// of a millisecond or a clock that stood still: there the floor stays put, and `lowestAbove`, the lowest `at` of the
// uses left above the part, walks the `at` index through every use the backlog's parts sealed before it (7,069 pages
// past 390,000). A floor read from the skew bound would cost one step but sign a floor other than the lowest `at`
// above (HotPathOne.tla's ChunkFloor) and miss a use the clock stamped low, which the test after the next seals: T248,
// the model first (R45).
for (const [what, stamp, todo] of [
  ['uses stamped one after another', (t0: number) => sql`${t0}::bigint + g`, false],
  ['uses sharing one `at`', (t0: number) => sql`${t0}::bigint`, 'T248: `lowestAbove` walks the uses sealed at the shared `at` (HotPathOne.tla first, R45)'],
] as const) {
  test(`T245, review r8: close() reads as many pages 20,000 uses into a backlog as 2,000 in, ${what}`, { todo, timeout: 300_000 }, async () => {
    const PART = 1_000;
    // Stamped before the barrier's floor, as a stall leaves them: each part then signs the lowest `at` left above it.
    const t0 = Date.now() - 60_000;
    await run(db.owner, sql`SELECT make_day(${new Date(t0).toISOString().slice(0, 10)}::date)`);
    await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac)
      SELECT nextval('log_number'), ${stamp(t0)}, g, gen_random_uuid(), gen_random_uuid(), 1, '\\x00000000000000000000000000000000'::bytea
        FROM generate_series(1, 22 * ${PART}) g`);
    await run(db.owner, sql`VACUUM (ANALYZE, PARALLEL 0) log_uses`);
    // The vault's store on a client of its own, each statement it sends kept.
    const sent: { text: string; values: unknown[] }[] = [];
    const client = postgresClient(VAULT_URL, { max: 1 });
    const unsafe = client.unsafe;
    (client as { unsafe: unknown }).unsafe = (text: string, values: unknown[] = [], ...rest: unknown[]) => {
      sent.push({ text, values });
      return (unsafe as (...args: unknown[]) => unknown)(text, values, ...rest);
    };
    const pagesOf = async (statement: { text: string; values: unknown[] }) => {
      const [row] = await client.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, statement.values as never[]);
      const [{ Plan: plan }] = (row as unknown as { 'QUERY PLAN': [{ Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }] })['QUERY PLAN'];
      return plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
    };
    try {
      const store = logStore(createDatabase(client), { tileRange: RANGE });
      // The cursor as the checkpointer moves it: past the part's last entry, from the floor it signs (`signedFloor`).
      let [after, from] = [0n, t0];
      const measured = new Map<number, { text: string; pages: number }[]>();
      for (let part = 1; part <= 20; part += 1) {
        sent.length = 0;
        const closed = await store.close(after, from, PART);
        assert.ok(closed.more !== null && closed.more !== undefined, `part ${part} left more`);
        assert.equal(closed.entries.length, PART);
        if (part === 2 || part === 20) {
          // The barrier (close_one) raises the floor again, as each tick's does; the reads after it are the window's.
          const reads = sent.filter(({ text }) => /^\s*(select|with)\b/i.test(text) && !text.includes('close_one'));
          measured.set(part, await Promise.all(reads.map(async (statement) => ({ text: statement.text.replace(/\s+/g, ' ').slice(0, 80), pages: await pagesOf(statement) }))));
        }
        after = closed.entries.at(-1)!.number;
        from = Math.max(from, Math.min(closed.floor.set, closed.more.above ?? closed.floor.set));
      }
      const [early, late] = [measured.get(2)!, measured.get(20)!];
      assert.ok(early.length >= 2, `the window and the lowest \`at\` above it measured: ${early.map(({ text }) => text).join('; ')}`);
      assert.deepEqual(late.map(({ text }) => text), early.map(({ text }) => text), 'the parts ran other statements');
      for (const [i, { text, pages }] of early.entries()) {
        assert.ok(late[i]!.pages <= 2 * pages + 16, `${text}: ${late[i]!.pages} pages 20,000 uses in, ${pages} 2,000 in`);
      }
    } finally {
      await client.end();
    }
  });
}

test('T169: a backlog far past the window drains a part a tick, each part a pair whose floor is the lowest `at` left above it, and the whole log verifies, every entry provable', async () => {
  const { cp, store, memory, alerts } = await open(variableMemory(), 200);
  await use();
  assert.ok((await cp.tick()).signed);
  // A backlog as a stall leaves: 1,050 uses and some changes, each use stamped at or above the floor the last barrier
  // left (FloorChecked), then a barrier well after them, whose floor is above most: each part signs the lowest `at`
  // left above it.
  const numbers: bigint[] = [];
  const t0 = cp.pair.pair.floor + 100;
  for (let i = 0; i < 1050; i += 1) {
    numbers.push(await use(t0 + i * 2));
    if (i % 100 === 0) numbers.push(await change());
  }
  await new Promise((resolve) => setTimeout(resolve, 3000));
  const parts: { entries: number; more: boolean }[] = [];
  for (;;) {
    const t = await cp.tick();
    assert.ok(t.signed && t.failures.length === 0, t.failures.join('; '));
    parts.push({ entries: t.entries, more: t.more });
    if (!t.more) break;
  }
  assert.deepEqual(parts.map((p) => p.entries), [200, 200, 200, 200, 200, 61]);
  assert.equal(cp.pair.pair.upto, numbers.at(-1));
  assert.deepEqual(alerts, []);
  const v = await verifyLog(store, { verifiers, anchors: [JSON.parse(memory.record!)], check: (e) => (authentic(macKey)(e) ? null : 'mac') });
  assert.ok(v.ok && v.sealed === 1 + numbers.length, v.problems.join('\n'));
  for (const number of [numbers[0]!, numbers[300]!, numbers[700]!, numbers.at(-1)!]) assert.ok(await cp.prove(number), `${number} provable`);
  // Each part's floor is the lowest `at` left above it, below the barrier's: the next part was read from it.
  const floors = (await store.pairs(0n, 100)).map((p) => decodeFloor(p.notes));
  assert.ok(floors.every((f, i) => i === 0 || f >= floors[i - 1]!), 'floors never come down');
  assert.ok(new Set(floors).size >= 4, `the parts signed floors of their own: ${floors.join(', ')}`);
});

test("T169: Postgres's clock stepping back under a capped window (a later use stamped two minutes low): every use is sealed and the walk verifies; a use past its pair's ceiling gets no proof, never a wrong one", async () => {
  // From the genesis pair, whose floor is the schema's: the first part's floor is then the low use's `at`.
  const { cp, store, memory, alerts } = await open(variableMemory(), 200);
  const now = Date.now();
  const numbers: bigint[] = [];
  for (let i = 0; i < 300; i += 1) numbers.push(await use(now));
  // Numbered after them, stamped as if the database's clock had stepped back by two minutes.
  const low = await use(now - 120_000);
  for (;;) {
    const t = await cp.tick();
    assert.ok(t.signed && t.failures.length === 0, t.failures.join('; '));
    if (!t.more) break;
  }
  assert.equal(cp.pair.pair.upto, low, 'every number sealed, the low one included');
  assert.deepEqual(alerts, []);
  // The first part signed the low use's `at` as its floor, so its own uses sit past its ceiling (63 s; CeilingHolds
  // broken, as HotPathOneChunksClock expects). The walk reads the log in batches to a later pair's ceiling, and finds
  // every entry where its pair says. A proof of one, which reads to its own pair's ceiling, finds nothing: no proof is
  // handed out, and none that is wrong.
  const v = await verifyLog(store, { verifiers, anchors: [JSON.parse(memory.record!)], check: (e) => (authentic(macKey)(e) ? null : 'mac') });
  assert.ok(v.ok && v.sealed === 1 + numbers.length, v.problems.join('\n'));
  const proof = await cp.prove(numbers[0]!).catch((error: Error) => error);
  assert.ok(proof === null || proof instanceof Error, 'no proof of a use past its pair\'s ceiling');
  assert.ok(await cp.prove(low), 'the low use is proved where its pair says');
});

for (const [what, first] of [['two uses', () => use()], ['a change and a use', () => change()]] as const) {
  test(`T169, review r2: ${what} a writer gave one number, across a part's cut, are refused and alarmed, never sealed through`, async () => {
    const { cp, alerts } = await open(variableMemory(), 1);
    const a = await first();
    const b = await use();
    await use();
    // The second takes the first's number: the part of one entry would end at it, its twin past the cut.
    await run(db.owner, sql`UPDATE log_uses SET number = ${a} WHERE number = ${b}`);
    const t = await cp.tick();
    assert.equal(t.signed, false);
    assert.match(t.failures.join('\n'), new RegExp(`${a}: outside the window .*two entries with one number`));
    assert.ok(alerts.some((m) => /two entries with one number/.test(m)), 'alarmed');
    assert.equal(cp.pair.pair.upto, 0n, 'nothing sealed through it');
  });
}
