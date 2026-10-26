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
//
//   node experiments/lanes/size-one.ts --url postgresql://… (a server where a scratch database may be made) [--rows 1000000]
import { randomBytes, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import pg from 'pg';

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
} finally {
  await admin.query('DROP DATABASE IF EXISTS w208_size WITH (FORCE)');
  await admin.end();
}
