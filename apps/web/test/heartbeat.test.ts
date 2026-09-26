import test from 'node:test';
import assert from 'node:assert/strict';

import {
  auditReadiness,
  HEARTBEAT_STALE_AFTER_SECONDS,
  writeAuditHeartbeat,
} from '../src/server/heartbeat.ts';

function heartbeatDatabase(options: { heartbeatRows?: number } = {}) {
  const statements: string[] = [];
  const client = {
    async query(sql: string) {
      statements.push(sql);
      if (sql.includes('SELECT next_seq, head_hash')) {
        return { rowCount: 1, rows: [{ next_seq: '0', head_hash: Buffer.alloc(32) }] };
      }
      if (sql.includes(`to_char(now()`)) {
        return { rowCount: 1, rows: [{ ts: '2026-01-01T00:00:00.000000Z' }] };
      }
      if (sql.includes('UPDATE audit_heartbeat')) {
        return { rowCount: options.heartbeatRows ?? 1, rows: [] };
      }
      return { rowCount: 1, rows: [] };
    },
    async release() {},
  };
  return {
    database: { connect: async () => client } as never,
    statements,
  };
}

test('the scheduled heartbeat updates the database-owned signal', async () => {
  const { database, statements } = heartbeatDatabase();
  const written = await writeAuditHeartbeat(
    database,
    Buffer.alloc(32, 1),
    { warn: () => assert.fail('successful heartbeat must not warn') },
  );

  assert.equal(written, true);
  assert.ok(statements.some((statement) => statement.includes('INSERT INTO audit_log')));
  assert.ok(statements.some((statement) => statement.includes('UPDATE audit_chain_head')));
  assert.ok(statements.some((statement) => statement.includes('UPDATE audit_heartbeat')));
  assert.equal(statements.at(-1), 'COMMIT');
});

test('the scheduled heartbeat rejects a missing singleton row', async () => {
  let warning = '';
  const { database, statements } = heartbeatDatabase({ heartbeatRows: 0 });
  const written = await writeAuditHeartbeat(
    database,
    Buffer.alloc(32, 1),
    { warn: (_value, message) => { warning = message; } },
  );

  assert.equal(written, false);
  assert.equal(warning, 'audit heartbeat singleton is missing');
  assert.equal(statements.at(-1), 'ROLLBACK');
});

test('readiness accepts a recent audit heartbeat and rejects a stale one', async () => {
  const recent = await auditReadiness(
    {
      query: async (sql: string) =>
        sql.includes('__drizzle_migrations')
          ? { rowCount: 1, rows: [{ ready: true }] }
          : { rowCount: 1, rows: [{ age: '12.5' }] },
    } as never,
  );
  assert.deepEqual(recent, { ok: true, auditHeartbeatAgeSeconds: 12.5 });

  // A Cron run that fires a few seconds late is not a logging failure.
  const late = await auditReadiness(
    {
      query: async (sql: string) =>
        sql.includes('__drizzle_migrations')
          ? { rowCount: 1, rows: [{ ready: true }] }
          : { rowCount: 1, rows: [{ age: '307' }] },
    } as never,
  );
  assert.equal(late.ok, true);

  const stale = await auditReadiness(
    {
      query: async (sql: string) =>
        sql.includes('__drizzle_migrations')
          ? { rowCount: 1, rows: [{ ready: true }] }
          : { rowCount: 1, rows: [{ age: String(HEARTBEAT_STALE_AFTER_SECONDS + 1) }] },
    } as never,
  );
  assert.deepEqual(stale, { ok: false, auditHeartbeatAgeSeconds: HEARTBEAT_STALE_AFTER_SECONDS + 1 });
});

test('readiness rejects a database without the expected Drizzle schema prefix', async () => {
  const readiness = await auditReadiness(
    { query: async () => ({ rowCount: 1, rows: [{ ready: false }] }) } as never,
  );
  assert.deepEqual(readiness, { ok: false, auditHeartbeatAgeSeconds: null });
});
