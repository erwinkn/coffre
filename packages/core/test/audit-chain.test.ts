import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import {
  chainHash,
  verifyChain,
  GENESIS_HASH,
  type ChainedAuditRow,
} from '../src/audit/chain.ts';

type StoredRow = ChainedAuditRow & { prevHash: Buffer; hash: Buffer };

function buildLog(chainKey: Buffer, count: number): StoredRow[] {
  const projectId = randomUUID();
  const environmentId = randomUUID();

  const rows: StoredRow[] = [];
  let prevHash = GENESIS_HASH;

  for (let i = 0; i < count; i++) {
    const row: ChainedAuditRow = {
      seq: BigInt(i),
      occurredAt: new Date(Date.UTC(2026, 6, 27, 12, 0, i)).toISOString(),
      actorType: 'user',
      actorId: 'erwin@equisafe.io',
      action: 'secret.read',
      decision: 'allow',
      projectId,
      environmentId,
      secretId: randomUUID(),
      bundleId: null,
      requestId: randomUUID(),
      sourceIp: '10.0.0.1',
      metadata: '{}',
    };

    const hash = chainHash(chainKey, prevHash, row);
    rows.push({ ...row, prevHash, hash });
    prevHash = hash;
  }

  return rows;
}

test('an untampered chain verifies', () => {
  const chainKey = randomBytes(32);
  const rows = buildLog(chainKey, 5);

  const result = verifyChain(chainKey, rows);
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.rows, 5);
});

test('mutating a row breaks the chain at that row', () => {
  const chainKey = randomBytes(32);
  const rows = buildLog(chainKey, 5);

  // Someone edits an audit entry to hide who read the secret.
  rows[2].actorId = 'someone-else@equisafe.io';

  const result = verifyChain(chainKey, rows);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.failedAtSeq, 2n);
  assert.match(result.ok === false ? result.reason : '', /does not match its contents/);
});

test('changing a decision from deny to allow is detected', () => {
  const chainKey = randomBytes(32);
  const rows = buildLog(chainKey, 3);

  rows[1].decision = 'deny';

  const result = verifyChain(chainKey, rows);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.failedAtSeq, 1n);
});

test('deleting a row from the middle is detected', () => {
  const chainKey = randomBytes(32);
  const rows = buildLog(chainKey, 5);

  const withHole = [...rows.slice(0, 2), ...rows.slice(3)];

  const result = verifyChain(chainKey, withHole);
  assert.equal(result.ok, false);
  // The row after the hole is where verification stops.
  assert.equal(result.ok === false && result.failedAtSeq, 3n);
  assert.match(result.ok === false ? result.reason : '', /sequence gap/);
});

test('truncating the log is detected when checked against a known head', () => {
  const chainKey = randomBytes(32);
  const rows = buildLog(chainKey, 5);

  const full = verifyChain(chainKey, rows);
  const truncated = verifyChain(chainKey, rows.slice(0, 3));

  assert.equal(full.ok, true);
  assert.equal(truncated.ok, true);

  // Truncation cannot be caught by looking at the rows alone -- a short chain
  // is internally consistent. It is caught by comparing the head against a
  // checkpoint published outside the database. This is why checkpoints matter.
  assert.notDeepEqual(
    full.ok ? full.head : null,
    truncated.ok ? truncated.head : null,
  );
});

test('reordering two rows is detected', () => {
  const chainKey = randomBytes(32);
  const rows = buildLog(chainKey, 5);

  const swapped = [...rows];
  [swapped[1], swapped[2]] = [swapped[2], swapped[1]];

  const result = verifyChain(chainKey, swapped);
  assert.equal(result.ok, false);
});

test('an attacker without the chain key cannot re-chain a forged row', () => {
  const chainKey = randomBytes(32);
  const attackerKey = randomBytes(32);
  const rows = buildLog(chainKey, 4);

  // Rewrite row 1 and recompute the rest of the chain -- but with the wrong
  // key, because the real one is not stored in the database.
  rows[1].actorId = 'attacker@example.com';
  let prevHash = rows[0].hash;
  for (let i = 1; i < rows.length; i++) {
    rows[i].prevHash = prevHash;
    rows[i].hash = chainHash(attackerKey, prevHash, rows[i]);
    prevHash = rows[i].hash;
  }

  const result = verifyChain(chainKey, rows);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.failedAtSeq, 1n);
});

test('null and empty string are distinguishable in the chain', () => {
  const chainKey = randomBytes(32);
  const base = buildLog(chainKey, 1)[0];

  const withNull = chainHash(chainKey, GENESIS_HASH, { ...base, sourceIp: null });
  const withEmpty = chainHash(chainKey, GENESIS_HASH, { ...base, sourceIp: '' });

  assert.notDeepEqual(withNull, withEmpty);
});

test('field values containing the separator cannot forge another row', () => {
  const chainKey = randomBytes(32);
  const base = buildLog(chainKey, 1)[0];

  // Length-prefixed encoding means a value cannot impersonate a field boundary.
  const a = chainHash(chainKey, GENESIS_HASH, {
    ...base,
    actorId: 'a|b',
    action: 'c',
  });
  const b = chainHash(chainKey, GENESIS_HASH, {
    ...base,
    actorId: 'a',
    action: 'b|c',
  });

  assert.notDeepEqual(a, b);
});
