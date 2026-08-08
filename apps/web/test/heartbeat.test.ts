import test from 'node:test';
import assert from 'node:assert/strict';

import { auditReadiness, writeAuditHeartbeat } from '../src/server/heartbeat.ts';

test('the scheduled heartbeat updates the database-owned signal', async () => {
  let statement = '';
  const written = await writeAuditHeartbeat(
    {
      query: async (sql: string) => {
        statement = sql;
        return { rowCount: 1, rows: [] };
      },
    } as never,
    { warn: () => assert.fail('successful heartbeat must not warn') },
  );

  assert.equal(written, true);
  assert.match(statement, /UPDATE audit_heartbeat/);
  assert.match(statement, /audit_chain_head/);
});

test('the scheduled heartbeat rejects a missing singleton row', async () => {
  let warning = '';
  const written = await writeAuditHeartbeat(
    { query: async () => ({ rowCount: 0, rows: [] }) } as never,
    { warn: (_value, message) => { warning = message; } },
  );

  assert.equal(written, false);
  assert.equal(warning, 'audit heartbeat singleton is missing');
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

  const stale = await auditReadiness(
    {
      query: async (sql: string) =>
        sql.includes('__drizzle_migrations')
          ? { rowCount: 1, rows: [{ ready: true }] }
          : { rowCount: 1, rows: [{ age: '301' }] },
    } as never,
  );
  assert.deepEqual(stale, { ok: false, auditHeartbeatAgeSeconds: 301 });
});

test('readiness rejects a database without the expected Drizzle schema prefix', async () => {
  const readiness = await auditReadiness(
    { query: async () => ({ rowCount: 1, rows: [{ ready: false }] }) } as never,
  );
  assert.deepEqual(readiness, { ok: false, auditHeartbeatAgeSeconds: null });
});
