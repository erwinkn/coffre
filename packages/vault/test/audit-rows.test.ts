// The audit projection's MAC inputs (audit-rows.ts): fixed vectors, so that a column reordered or dropped fails
// here rather than changing every MAC unseen; and every column of the tables covered, so that one added later and
// left out of its MAC, unprotected, fails here too.
import test from 'node:test';
import assert from 'node:assert/strict';

import { auditCursor, auditEvents } from '@coffre/db/schema';
import { getTableColumns } from 'drizzle-orm';

import { CURSOR_INTERIM_COLUMNS, CURSOR_MAC_COLUMNS, cursorColumns, cursorMac, cursorVouched, EVENT_MAC_COLUMNS, eventColumns, eventMac, type AuditCursor, type AuditEvent } from '../src/audit-rows.ts';
import type { Keyring } from '../src/keyring.ts';
import { logMacKey } from '../src/log-entry.ts';

const KEY = logMacKey(Buffer.alloc(32, 7));

const EVENT: Omit<AuditEvent, 'mac'> = {
  at: 1_794_000_000_000,
  number: 4_242n,
  log: 15,
  author: 'vault',
  action: 'secret.write',
  shown: true,
  allowed: false,
  code: 'no_grant',
  actor: 'user:ada@acme.example',
  subject: 'token:ci',
  credential: '11111111-1111-4111-8111-111111111111',
  project: '22222222-2222-4222-8222-222222222222',
  environment: '33333333-3333-4333-8333-333333333333',
  secret: '44444444-4444-4444-8444-444444444444',
  version: '55555555-5555-4555-8555-555555555555',
  places: ['22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444'],
  requestId: 'req-1',
  operationId: '66666666-6666-4666-8666-666666666666',
  related: 17n,
  sourceIp: '203.0.113.9',
  detail: '{"path":"market/dev","keys":["API_KEY"]}',
};

const CURSOR: Omit<AuditCursor, 'mac'> = { through: 900n, pair: 880n, at: 1_794_000_000_500, oldFloor: 10n, oldFrom: 400n, oldTop: 5_000n, oldHash: Buffer.alloc(32, 0xab) };

test('an event and the cursor have fixed MACs under a fixed key: a column moved, dropped or encoded otherwise fails here', () => {
  assert.equal(eventMac(KEY, EVENT).toString('hex'), '7e18085a811ae2070cb7e43abb3c8fe8');
  assert.equal(cursorMac(KEY, CURSOR).toString('hex'), 'fa7a68dd9c15a02c383d998d5c27f455');
});

/** Each field of a row with its value changed: a string or id other, a number one more, a flag flipped, a null set. */
function otherwise(value: unknown): unknown {
  if (typeof value === 'bigint') return value + 1n;
  if (typeof value === 'number') return value + 1;
  if (typeof value === 'boolean') return !value;
  if (Buffer.isBuffer(value)) return Buffer.alloc(value.length, value[0]! ^ 1);
  if (Array.isArray(value)) return value.slice(1);
  if (value === null) return 'set';
  return `${String(value)}x`;
}

const camel = (column: string) => column.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());

test("every column of audit_events but its MAC, and of audit_cursor but its MAC, retention's reads_from and the temporary old_floor and old_top, is under its MAC", () => {
  const names = (table: Parameters<typeof getTableColumns>[0]) => Object.values(getTableColumns(table)).map((column) => column.name).sort();
  assert.deepEqual([...EVENT_MAC_COLUMNS].sort(), names(auditEvents).filter((name) => name !== 'mac'));
  assert.deepEqual([...CURSOR_MAC_COLUMNS].sort(), names(auditCursor).filter((name) => !['only_row', 'mac', 'reads_from', ...CURSOR_INTERIM_COLUMNS].includes(name)));
  // And each listed column is one the MAC's input reads: changed alone, it changes the input.
  for (const column of EVENT_MAC_COLUMNS) {
    const field = camel(column) as keyof typeof EVENT;
    assert.ok(field in EVENT, column);
    assert.notEqual(eventColumns({ ...EVENT, [field]: otherwise(EVENT[field]) }), eventColumns(EVENT), `${column} is not in the event's MAC`);
  }
  for (const column of CURSOR_MAC_COLUMNS) {
    const field = camel(column) as keyof typeof CURSOR;
    assert.ok(field in CURSOR, column);
    assert.notEqual(cursorColumns({ ...CURSOR, [field]: otherwise(CURSOR[field]) }), cursorColumns(CURSOR), `${column} is not in the cursor's MAC`);
  }
  // And the two temporary columns are not: the MAC keeps its five when these two go.
  for (const column of CURSOR_INTERIM_COLUMNS) {
    const field = camel(column) as keyof typeof CURSOR;
    assert.equal(cursorColumns({ ...CURSOR, [field]: otherwise(CURSOR[field]) }), cursorColumns(CURSOR), `${column} is in the cursor's MAC`);
  }
});

test('a cursor whose old-log positions are out of order is refused, its MAC holding: the order is all that holds old_floor and old_top', () => {
  const ring = { current: { mac: KEY }, previous: [] } as unknown as Keyring;
  const vouched = (cursor: Omit<AuditCursor, 'mac'>) => cursorVouched(ring, { ...cursor, mac: cursorMac(KEY, cursor) });
  assert.equal(vouched(CURSOR), true);
  assert.equal(vouched({ ...CURSOR, oldFloor: CURSOR.oldFrom + 1n }), false, 'old_floor above old_from');
  assert.equal(vouched({ ...CURSOR, oldTop: CURSOR.oldFrom - 1n }), false, 'old_top below old_from');
  // In order, the two are the database writer's to move (the gap the PR states): the walk's hashes keep what is listed true.
  assert.equal(vouched({ ...CURSOR, oldFloor: CURSOR.oldFrom, oldTop: CURSOR.oldTop + 1n }), true);
});
