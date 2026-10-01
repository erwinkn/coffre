import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  deriveLogKey,
  encodeFields,
  entryHash,
  entryMac,
  GENESIS_HASH,
  LOG_FORMAT,
  sealEntry,
  verifyEntries,
  type LogFields,
  type LogKey,
  type StoredEntry,
} from '../src/audit/chain.ts';

type VectorFields = Omit<LogFields, 'seq' | 'relatedSeq'> & { seq: string; relatedSeq: string | null };
type Vectors = {
  format: string;
  keys: Record<'app' | 'vault', { secret: string; keyId: string; key: string }>;
  entries: { fields: VectorFields; prevHash: string; mac: string; hash: string }[];
};

const vectors = JSON.parse(readFileSync(new URL('./vectors/audit-v2.json', import.meta.url), 'utf8')) as Vectors;
const fieldsOf = (fields: VectorFields): LogFields => ({
  ...fields,
  seq: BigInt(fields.seq),
  relatedSeq: fields.relatedSeq === null ? null : BigInt(fields.relatedSeq),
});

test('the test vectors still hold: keys, MACs and hashes, byte for byte', () => {
  assert.equal(vectors.format, LOG_FORMAT);
  for (const author of ['app', 'vault'] as const) {
    const key = deriveLogKey(author, Buffer.from(vectors.keys[author].secret, 'hex'));
    assert.equal(key.keyId, vectors.keys[author].keyId);
    assert.equal(key.key.toString('hex'), vectors.keys[author].key);
  }
  for (const vector of vectors.entries) {
    const fields = fieldsOf(vector.fields);
    const prevHash = Buffer.from(vector.prevHash, 'hex');
    const key = Buffer.from(vectors.keys[fields.author].key, 'hex');
    const mac = entryMac(key, prevHash, fields);
    assert.equal(mac.toString('hex'), vector.mac, `the MAC of entry ${fields.seq}`);
    assert.equal(entryHash(prevHash, fields, mac).toString('hex'), vector.hash, `the hash of entry ${fields.seq}`);
  }
});

test('the vectors chain from the genesis hash, and each author verifies its own', () => {
  const chained = vectors.entries.slice(0, 4).map((vector) => ({
    ...fieldsOf(vector.fields),
    prevHash: Buffer.from(vector.prevHash, 'hex'),
    mac: Buffer.from(vector.mac, 'hex'),
    hash: Buffer.from(vector.hash, 'hex'),
  }));
  for (const author of ['app', 'vault'] as const) {
    const key = { author, keyId: vectors.keys[author].keyId, key: Buffer.from(vectors.keys[author].key, 'hex') };
    const result = verifyEntries(chained, { keys: [key] });
    assert.deepEqual(result.ok && [result.entries, result.authenticated], [4, 2]);
  }
});

test('a null and an empty string encode differently', () => {
  const fields = entry(0n, deriveLogKey('app', randomBytes(32)));
  assert.notDeepEqual(encodeFields({ ...fields, code: null }), encodeFields({ ...fields, code: '' }));
});

function entry(seq: bigint, key: LogKey, change: Partial<LogFields> = {}): LogFields {
  return {
    seq,
    author: key.author,
    keyId: key.keyId,
    occurredAt: 1_790_841_600_000 + Number(seq),
    actor: 'user:ada@acme.example',
    action: 'secret.read',
    decision: 'allow',
    code: null,
    subjectPrincipal: null,
    projectId: randomUUID(),
    environmentId: randomUUID(),
    secretId: randomUUID(),
    secretVersionId: null,
    operationId: randomUUID(),
    requestId: randomUUID(),
    sourceIp: '192.0.2.10',
    relatedSeq: null,
    metadata: '{}',
    ...change,
  };
}

/** A log of entries by these keys, in turn. */
function buildLog(keys: LogKey[]): StoredEntry[] {
  const log: StoredEntry[] = [];
  let prevHash = GENESIS_HASH;
  keys.forEach((key, i) => {
    const fields = entry(BigInt(i), key);
    const { mac, hash } = sealEntry(key, prevHash, fields);
    log.push({ ...fields, prevHash, mac, hash });
    prevHash = hash;
  });
  return log;
}

/**
 * Entry `i` changed by whoever holds `key`, and the rest of the log chained
 * again as they would: their own entries sealed afresh, the other author's
 * linked to the new hashes with the MACs they cannot remake.
 */
function rewrite(log: StoredEntry[], i: number, key: LogKey, change: Partial<LogFields>): StoredEntry[] {
  const out = log.map((row) => ({ ...row }));
  out[i] = { ...out[i], ...change };
  for (let j = i; j < out.length; j++) {
    if (j > i) out[j].prevHash = out[j - 1].hash;
    if (out[j].author === key.author) Object.assign(out[j], sealEntry(key, out[j].prevHash, out[j]));
    else out[j].hash = entryHash(out[j].prevHash, out[j], out[j].mac);
  }
  return out;
}

const app = deriveLogKey('app', randomBytes(32));
const vault = deriveLogKey('vault', randomBytes(32));

test('an untouched log verifies, for each author with its key', () => {
  const log = buildLog([app, vault, app, app, vault]);
  assert.deepEqual(verifyEntries(log, { keys: [app] }), { ok: true, entries: 5, head: log[4].hash, nextSeq: 5n, authenticated: 3 });
  assert.equal(verifyEntries(log, { keys: [vault] }).ok, true);
});

test('a field edited in place breaks the entry, for anyone who reads the table', () => {
  const log = buildLog([app, app, app]);
  log[1].actor = 'user:someone-else@acme.example';
  const result = verifyEntries(log, { keys: [] });
  assert.deepEqual(result.ok ? null : [result.failedAtSeq, result.reason], [1n, 'hash does not match the entry']);
});

test('a MAC swapped for another breaks the public chain too', () => {
  const log = buildLog([app, app]);
  log[0].mac = Buffer.alloc(32, 7);
  assert.equal(verifyEntries(log, { keys: [] }).ok, false);
});

test('an entry rewritten by the app is caught at the next vault entry, which the app cannot seal again', () => {
  const log = rewrite(buildLog([app, vault, app]), 0, app, { decision: 'deny' });
  // The app's own check passes: it can make its MACs, and the chain re-links.
  assert.equal(verifyEntries(log, { keys: [app] }).ok, true);
  const result = verifyEntries(log, { keys: [vault] });
  assert.deepEqual(result.ok ? null : [result.failedAtSeq, result.reason], [1n, 'not written by the vault: its MAC does not match']);
});

test('an entry rewritten by the vault is caught at the next app entry', () => {
  const log = rewrite(buildLog([vault, app, vault]), 0, vault, { actor: 'user:mallory@acme.example' });
  assert.equal(verifyEntries(log, { keys: [vault] }).ok, true);
  const result = verifyEntries(log, { keys: [app] });
  assert.equal(result.ok ? null : result.failedAtSeq, 1n);
});

test("each author can rewrite its own entries since the other's last one: the accepted window", () => {
  const log = rewrite(buildLog([vault, app, app]), 1, app, { actor: 'user:mallory@acme.example' });
  assert.equal(verifyEntries(log, { keys: [app] }).ok, true);
  assert.equal(verifyEntries(log, { keys: [vault] }).ok, true);
});

test('an entry claiming the other author is refused by that author', () => {
  const log = buildLog([app, app]);
  const forged = { ...entry(2n, app), author: 'vault' as const };
  const mac = entryMac(app.key, log[1].hash, forged);
  log.push({ ...forged, prevHash: log[1].hash, mac, hash: entryHash(log[1].hash, forged, mac) });
  const result = verifyEntries(log, { keys: [vault] });
  assert.deepEqual(result.ok ? null : [result.failedAtSeq, result.reason], [2n, `written under ${app.keyId}, a key this verifier does not hold`]);
});

test('an old key verifies its entries beside a new one', () => {
  const rotated = deriveLogKey('app', randomBytes(32));
  const log = buildLog([app, rotated]);
  assert.equal(verifyEntries(log, { keys: [rotated] }).ok, false);
  assert.equal(verifyEntries(log, { keys: [rotated, app] }).ok, true);
});

test('a gap, a removed entry and a reordering are all caught', () => {
  const log = buildLog([app, app, app, app]);
  const gapped = verifyEntries([log[0], log[2]], { keys: [app] });
  assert.match(gapped.ok ? '' : gapped.reason, /sequence gap: expected seq 1, found 2/);
  const swapped = verifyEntries([log[0], log[2], log[1], log[3]], { keys: [app] });
  assert.equal(swapped.ok, false);
  const late = verifyEntries(log.slice(1), { keys: [app], startSeq: 0n });
  assert.equal(late.ok ? null : late.failedAtSeq, 1n);
});

test('a run in the middle verifies from the entry before it', () => {
  const log = buildLog([app, vault, app, app]);
  const result = verifyEntries(log.slice(2), { keys: [app], startSeq: 2n, startPrevHash: log[1].hash });
  assert.equal(result.ok && result.nextSeq, 4n);
});

test('sealing with a key that is not the entry\'s refuses', () => {
  assert.throws(() => sealEntry(vault, GENESIS_HASH, entry(0n, app)), /cannot be sealed/);
});
