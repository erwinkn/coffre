import test from 'node:test';
import assert from 'node:assert/strict';

import { auditReadiness } from '../src/server/heartbeat.ts';

test('readiness fails closed when the audit writer has not completed its first beat', async () => {
  let queried = false;
  const readiness = await auditReadiness(
    {
      query: async () => {
        queried = true;
        return { rowCount: 1, rows: [{ age: '0' }] };
      },
    } as never,
    { firstBeat: Promise.resolve(false) },
  );

  assert.deepEqual(readiness, { ok: false, auditHeartbeatAgeSeconds: null });
  assert.equal(queried, false);
});

test('readiness accepts a recent audit heartbeat and rejects a stale one', async () => {
  const recent = await auditReadiness(
    {
      query: async (sql: string) =>
        sql.includes('__drizzle_migrations')
          ? { rowCount: 1, rows: [{ ready: true }] }
          : { rowCount: 1, rows: [{ age: '12.5' }] },
    } as never,
    { firstBeat: Promise.resolve(true) },
  );
  assert.deepEqual(recent, { ok: true, auditHeartbeatAgeSeconds: 12.5 });

  const stale = await auditReadiness(
    {
      query: async (sql: string) =>
        sql.includes('__drizzle_migrations')
          ? { rowCount: 1, rows: [{ ready: true }] }
          : { rowCount: 1, rows: [{ age: '301' }] },
    } as never,
    { firstBeat: Promise.resolve(true) },
  );
  assert.deepEqual(stale, { ok: false, auditHeartbeatAgeSeconds: 301 });
});

test('readiness rejects a database without the expected Drizzle schema prefix', async () => {
  const readiness = await auditReadiness(
    { query: async () => ({ rowCount: 1, rows: [{ ready: false }] }) } as never,
    { firstBeat: Promise.resolve(true) },
  );
  assert.deepEqual(readiness, { ok: false, auditHeartbeatAgeSeconds: null });
});
