// What a use costs on disk and in WAL (W208), in a scratch database: the
// use row as schema-one.sql has it ("current") and slimmer ones, each with
// its indexes, filled with 1M uses at 1,000 a second (one per ms), then
// 20,000 more, one per transaction as the hot path writes them, for WAL.
//
//   current   number, at, kind, principal, credential, request_id (a uuid as text), payload
//             (JSON text), seal (null), mac (32 bytes), written_at; one index, unique
//             (at, request_id)
//   slim      number, at, request_id (a random bigint, unique within its ms), credential (uuid),
//             secret (uuid), mac (32 bytes); the same index. No kind (the partition says
//             it), no principal (the credential's, which never changes), no environment (the
//             secret's), no written_at (the benches').
//   slim16    slim with the MAC truncated to 16 bytes.
//   wired     (W211) schema-one.sql's own `uses`, as seed-one.ts makes it: a day's partition filled
//             with 1M rows, then WAL per use over --wal real calls of `use_credential`, one per
//             transaction, as the hot path makes them (the bulk cap's rare writes included), and
//             again with covers (each credential's repeats of its last allowed use).
//
//   node experiments/lanes/size-one.ts --url postgresql://… (a server where a scratch database may be made) [--rows 1000000]
import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import { credentialId, limits, newRequestId, secretId, use, type Covers } from './src/one.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, rows: { type: 'string', default: '1000000' }, wal: { type: 'string', default: '20000' } } });
if (values.url === undefined) throw new Error('--url names a database on the server to use');
const ROWS = Number(values.rows);
const WAL = Number(values.wal);
const scratch = new URL(values.url);
scratch.pathname = '/w208_size';

const SCHEMAS: Record<string, { table: string; fill: string; one: (n: number, at: number) => { sql: string; params: unknown[] } }> = {
  current: {
    table: `CREATE TABLE t (number bigint NOT NULL, at bigint NOT NULL, kind text NOT NULL, principal text NOT NULL, credential text, request_id text NOT NULL,
      payload text NOT NULL, seal bytea, mac bytea NOT NULL, written_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
    fill: `INSERT INTO t (number, at, kind, principal, credential, request_id, payload, mac)
      SELECT i, $1::bigint + i, 'use', 'svc-' || (i % 100), 'cred-svc-' || (i % 100), gen_random_uuid()::text,
        json_build_object('environment', gen_random_uuid(), 'secret', gen_random_uuid())::text, sha256(i::text::bytea) FROM generate_series(1, $2::bigint) i`,
    one: (n, at) => ({
      sql: `INSERT INTO t (number, at, kind, principal, credential, request_id, payload, mac) VALUES ($1, $2, 'use', $3, $4, $5, $6, $7)`,
      params: [n, at, `svc-${n % 100}`, `cred-svc-${n % 100}`, randomUUID(), JSON.stringify({ environment: randomUUID(), secret: randomUUID() }), randomBytes(32)],
    }),
  },
  slim: {
    table: 'CREATE TABLE t (number bigint NOT NULL, at bigint NOT NULL, request_id bigint NOT NULL, credential uuid NOT NULL, secret uuid NOT NULL, mac bytea NOT NULL)',
    fill: `INSERT INTO t SELECT i, $1::bigint + i, (random() * 9e18)::bigint, gen_random_uuid(), gen_random_uuid(), sha256(i::text::bytea) FROM generate_series(1, $2::bigint) i`,
    one: (n, at) => ({ sql: 'INSERT INTO t VALUES ($1, $2, $3, $4, $5, $6)', params: [n, at, randomBytes(8).readBigInt64BE().toString(), randomUUID(), randomUUID(), randomBytes(32)] }),
  },
  slim16: {
    table: 'CREATE TABLE t (number bigint NOT NULL, at bigint NOT NULL, request_id bigint NOT NULL, credential uuid NOT NULL, secret uuid NOT NULL, mac bytea NOT NULL)',
    fill: `INSERT INTO t SELECT i, $1::bigint + i, (random() * 9e18)::bigint, gen_random_uuid(), gen_random_uuid(), substring(sha256(i::text::bytea) FROM 1 FOR 16) FROM generate_series(1, $2::bigint) i`,
    one: (n, at) => ({ sql: 'INSERT INTO t VALUES ($1, $2, $3, $4, $5, $6)', params: [n, at, randomBytes(8).readBigInt64BE().toString(), randomUUID(), randomUUID(), randomBytes(16)] }),
  },
};
const INDEXES = 'CREATE UNIQUE INDEX t_request ON t (at, request_id)';

const admin = new pg.Client({ connectionString: values.url });
await admin.connect();
await admin.query('DROP DATABASE IF EXISTS w208_size');
await admin.query('CREATE DATABASE w208_size');
try {
  const db = new pg.Client({ connectionString: scratch.toString() });
  await db.connect();
  const at0 = Date.now() - ROWS;
  console.log(`${ROWS} uses each; bytes per use: heap, indexes, total; WAL per use over ${WAL} more, one per transaction (commit records included)`);
  for (const [name, s] of Object.entries(SCHEMAS)) {
    await db.query('DROP TABLE IF EXISTS t');
    await db.query(s.table);
    await db.query(INDEXES);
    // Filled as the uses come: in number order, which is also the order of `at`.
    await db.query(s.fill, [String(at0), String(ROWS)]);
    await db.query('VACUUM ANALYZE t');
    const { rows: [z] } = await db.query(`SELECT pg_relation_size('t') AS heap, pg_indexes_size('t') AS idx,
      (SELECT avg(pg_column_size(t.*)) FROM t) AS tuple`);
    const { rows: [before] } = await db.query('SELECT pg_current_wal_insert_lsn() AS lsn');
    for (let i = 1; i <= WAL; i += 1) {
      const q = s.one(ROWS + i, at0 + ROWS + i);
      await db.query(q.sql, q.params);
    }
    const { rows: [after] } = await db.query('SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), $1) AS bytes', [before.lsn]);
    const per = (b: string) => (Number(b) / ROWS).toFixed(1);
    console.log(`${name.padEnd(8)} heap ${per(z.heap)} (tuple ${Number(z.tuple).toFixed(0)}), index ${per(z.idx)}, total ${per(String(Number(z.heap) + Number(z.idx)))} B; WAL ${(Number(after.bytes) / WAL).toFixed(0)} B per use`);
  }
  await db.end();

  // The wired schema: seed-one.ts's database, its own `uses`.
  execFileSync(process.execPath, [new URL('./seed-one.ts', import.meta.url).pathname, '--url', scratch.toString(), '--principals', '100'], { stdio: 'ignore' });
  const wired = new pg.Client({ connectionString: scratch.toString() });
  await wired.connect();
  const day = new Date().toISOString().slice(0, 10).replaceAll('-', '');
  await wired.query(`INSERT INTO uses SELECT 1000000 + i, $1::bigint + i * 50, (random() * 9e18)::bigint, $2::uuid, $3::uuid, substring(sha256(i::text::bytea) FROM 1 FOR 16)
    FROM generate_series(1, $4::bigint) i`, [String(Math.floor(Date.now() / 86_400_000) * 86_400_000), credentialId(0), secretId(0), String(Math.min(ROWS, 1_700_000))]);
  await wired.query(`VACUUM ANALYZE uses_${day}`);
  const { rows: [w] } = await wired.query(`SELECT pg_relation_size('uses_${day}') AS heap, pg_indexes_size('uses_${day}') AS idx,
    (SELECT count(*) FROM uses_${day}) AS n, (SELECT avg(pg_column_size(t.*)) FROM uses_${day} t) AS tuple`);
  const n = Number(w.n);
  const keys = keysFrom('w194-synthetic');
  const cap = limits();
  const walOf = async (covers?: Covers) => {
    const { rows: [before] } = await wired.query('SELECT pg_current_wal_insert_lsn() AS lsn');
    let covered = 0;
    for (let i = 0; i < WAL; i += 1) {
      const at = Date.now();
      const a = await use(wired, keys, { credential: credentialId(i % 100), secretId: secretId(0), requestId: newRequestId(), at }, at + 3000, cap, covers);
      if (a.ok && a.covered) covered += 1;
    }
    const { rows: [after] } = await wired.query('SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), $1) AS bytes', [before.lsn]);
    return { per: (Number(after.bytes) / WAL).toFixed(0), covered };
  };
  const plain = await walOf();
  const covers = await walOf({ window: 60_000, held: new Map() });
  console.log(`wired    heap ${(Number(w.heap) / n).toFixed(1)} (tuple ${Number(w.tuple).toFixed(0)}), index ${(Number(w.idx) / n).toFixed(1)}, total ${((Number(w.heap) + Number(w.idx)) / n).toFixed(1)} B over ${n} rows; WAL ${plain.per} B per use through use_credential; with covers ${covers.per} B per use (${covers.covered} of ${WAL} on a cover)`);
  await wired.end();
} finally {
  await admin.query('DROP DATABASE IF EXISTS w208_size WITH (FORCE)');
  await admin.end();
}
