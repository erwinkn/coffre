// W212: what one checkpoint costs Postgres and the signer, for each tree
// shape, as the log grows. Each tick seals `--leaves` new leaves (a share
// `--change-rate` of them changes), signs the shape's heads, and writes its rows
// and checkpoints in one statement, as #365's checkpointer does. The shape
// starts as a log of `--start` leaves (its edge random: shapes.ts), so a day or
// a year of log costs what it would without writing it all first. Ticks run
// back to back; a CHECKPOINT every `--checkpoint-every` ticks stands for
// Postgres's 5-minute checkpoint at a 500 ms tick, so full-page writes count.
// The entries themselves, and the sealing read, are the same in every shape
// and left out: #365 measured them (seal 2.2 ms p50 at 500 entries).
//
//   node experiments/merkle/shapes/bench.ts --url postgresql://… --shape one --start 0 --ticks 20000
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { checkpointBody, signerFrom, signNote } from '../src/note.ts';
import { shapeAt, SHAPES, type Leaf, type ShapeName } from './shapes.ts';

const { values } = parseArgs({ options: {
  url: { type: 'string' }, shape: { type: 'string', default: 'one' }, start: { type: 'string', default: '0' }, ticks: { type: 'string', default: '600' },
  leaves: { type: 'string', default: '500' }, 'change-rate': { type: 'string', default: '0.001' }, 'checkpoint-every': { type: 'string', default: '600' },
  'day-offset': { type: 'string' }, label: { type: 'string', default: '' },
} });
const name = values.shape as ShapeName;
if (!SHAPES.includes(name)) throw new Error(`--shape: one of ${SHAPES.join(', ')}`);
const START = Number(values.start);
const TICKS = Number(values.ticks);
const LEAVES = Number(values.leaves);
const CHANGE_RATE = Number(values['change-rate']);
const DAY = 86_400_000;
const shape = shapeAt(name, START, { changeRate: CHANGE_RATE, dayLeaves: DAY, tickLeaves: LEAVES, dayOffset: values['day-offset'] === undefined ? undefined : Number(values['day-offset']) });
// One origin, and key, per log: `split`'s two trees are two logs, as a witness keyed by origin needs them to be.
const origin = (tree: number) => (name === 'split' ? `coffre.example/audit/${tree === 1 ? 'changes' : 'uses'}` : 'coffre.example/audit');
const signers = new Map(await Promise.all([0, 1].map(async (tree) => [tree, await signerFrom(origin(tree), randomBytes(32))] as const)));

const db = new pg.Client({ connectionString: values.url });
await db.connect();
const tiles = `w212_tiles_${name.replace('-', '_')}`;
const checkpoints = `w212_checkpoints_${name.replace('-', '_')}`;
await db.query(`DROP TABLE IF EXISTS ${tiles}, ${checkpoints}`);
await db.query(`CREATE TABLE ${tiles} (tree int NOT NULL, level smallint NOT NULL, idx bigint NOT NULL, hashes bytea NOT NULL, PRIMARY KEY (tree, level, idx))`);
await db.query(`CREATE TABLE ${checkpoints} (n bigserial PRIMARY KEY, tree int NOT NULL, upto bigint NOT NULL, size bigint NOT NULL, root bytea NOT NULL, note text NOT NULL)`);
const WRITE = {
  name: `write_${name}`,
  text: `WITH t AS (
           INSERT INTO ${tiles} (tree, level, idx, hashes) SELECT * FROM unnest($1::int[], $2::smallint[], $3::bigint[], $4::bytea[])
           ON CONFLICT (tree, level, idx) DO UPDATE SET hashes = excluded.hashes)
         INSERT INTO ${checkpoints} (tree, upto, size, root, note) SELECT * FROM unnest($5::int[], $6::bigint[], $7::bigint[], $8::bytea[], $9::text[])
         RETURNING pg_current_wal_insert_lsn()::text AS lsn`,
};
const lsn = async () => (await db.query('SELECT pg_current_wal_insert_lsn()::text AS lsn')).rows[0].lsn as string;
const walBetween = async (a: string, b: string) => Number((await db.query('SELECT pg_wal_lsn_diff($2, $1)::bigint AS d', [a, b])).rows[0].d);

const per = { wal: [] as number[], dbMs: [] as number[], cpuMs: [] as number[], rows: [] as number[], bytes: [] as number[] };
await db.query('CHECKPOINT');
const wal0 = await lsn();
let previous = wal0;
let index = START;
for (let t = 0; t < TICKS; t += 1) {
  if (t > 0 && t % Number(values['checkpoint-every']) === 0) await db.query('CHECKPOINT');
  const raw = randomBytes(LEAVES * 32);
  const leaves: Leaf[] = Array.from({ length: LEAVES }, (_, i) => ({
    hash: raw.subarray(i * 32, (i + 1) * 32), change: Math.random() < CHANGE_RATE, day: Math.floor((index + i) / DAY),
  }));
  index += LEAVES;
  const cpu0 = process.cpuUsage();
  const { rows, heads } = shape.seal(leaves);
  const notes = await Promise.all(heads.map((h) => {
    const signer = signers.get(name === 'split' ? h.tree : 0)!;
    return signNote(`${checkpointBody({ origin: signer.name, size: h.size, root: h.root, upto: String(index), at: Date.now() })}${h.extra === undefined ? '' : `${h.extra}\n`}`, [signer]);
  }));
  const cpu = process.cpuUsage(cpu0);
  const t0 = performance.now();
  const { rows: [r] } = await db.query({ ...WRITE, values: [
    rows.map((x) => x.tree), rows.map((x) => x.level), rows.map((x) => x.index), rows.map((x) => x.hashes),
    heads.map((h) => h.tree), heads.map(() => index), heads.map((h) => h.size), heads.map((h) => h.root), notes,
  ] });
  per.dbMs.push(performance.now() - t0);
  per.cpuMs.push((cpu.user + cpu.system) / 1000);
  per.rows.push(rows.length + heads.length);
  per.bytes.push(rows.reduce((s, x) => s + x.hashes.length, 0) + notes.reduce((s, n) => s + n.length, 0));
  // Everything written since the last tick: this tick's statement, its commit, and whatever the background did.
  per.wal.push(await walBetween(previous, r.lsn));
  previous = r.lsn;
}
const walTotal = await walBetween(wal0, await lsn());
await db.query(`VACUUM ${tiles}, ${checkpoints}`);
const { rows: [size] } = await db.query(`SELECT pg_total_relation_size($1) AS tiles, pg_total_relation_size($2) AS checkpoints`, [tiles, checkpoints]);
const { rows: [stat] } = await db.query('SELECT n_tup_ins::int AS ins, n_tup_upd::int AS upd FROM pg_stat_user_tables WHERE relname = $1', [tiles]);

const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)] ?? NaN;
};
const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
const sealed = TICKS * LEAVES;
console.log(JSON.stringify({
  label: values.label, shape: name, start: START, ticks: TICKS, leaves: LEAVES,
  rowsPerTick: mean(per.rows), bytesPerTick: mean(per.bytes),
  walPerTick: { mean: walTotal / TICKS, p50: pct(per.wal, 50), p99: pct(per.wal, 99) },
  dbMs: { p50: pct(per.dbMs, 50), p99: pct(per.dbMs, 99) }, cpuMs: { p50: pct(per.cpuMs, 50), p99: pct(per.cpuMs, 99) },
  tileInserts: stat.ins, tileUpdates: stat.upd,
  storedPerLeaf: { tiles: Number(size.tiles) / sealed, checkpoints: Number(size.checkpoints) / sealed },
}));
await db.end();
