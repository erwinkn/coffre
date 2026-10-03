import assert from 'node:assert/strict';
import test from 'node:test';
import { createPrivateKey, sign } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { deriveLogKey, entryHash, entryMac, GENESIS_HASH, sealEntry, verifyEntries, type LogFields, type StoredEntry } from '../src/audit/chain.ts';
import { checkpointMessage, verifyCheckpoint } from '../src/checkpoint.ts';
import type { Checkpoint } from '../src/vault.ts';
import { propertySettings } from './properties.ts';

const text = gs.text({ codec: 'utf-8', maxSize: 12 });
const nullable = gs.oneOf(gs.just(null), text);
const fields = gs.record({
  author: gs.sampledFrom(['app', 'vault'] as const),
  occurredAt: gs.integers({ minValue: 0, maxValue: 2_000_000_000_000 }),
  actor: text, action: text, decision: text,
  code: nullable, subjectPrincipal: nullable, projectId: nullable,
  environmentId: nullable, secretId: nullable, secretVersionId: nullable,
  operationId: nullable, requestId: nullable, sourceIp: nullable,
  relatedSeq: gs.oneOf(gs.just(null), gs.bigIntegers({ minValue: 0n, maxValue: 100n })),
  metadata: gs.record({ name: text, count: gs.integers(), values: gs.arrays(text, { maxSize: 3 }) }).map(JSON.stringify),
});
const settings = propertySettings(1, 64);

function broken(log: StoredEntry[], keys: ReturnType<typeof deriveLogKey>[], seq: bigint, kind: string) {
  const result = verifyEntries(log, { keys });
  assert.equal(result.ok, false, kind);
  if (!result.ok) assert.equal(result.failedAtSeq, seq, `${kind}: first broken retained entry`);
}

function edit(value: StoredEntry[keyof StoredEntry], byte: number, mask: number): typeof value {
  if (Buffer.isBuffer(value)) {
    const changed = Buffer.from(value);
    changed[byte % changed.length] ^= mask;
    return changed;
  }
  if (typeof value === 'bigint') return value + 1n;
  if (typeof value === 'number') return value + 1;
  if (value === null) return '';
  if (value === 'app') return 'vault';
  if (value === 'vault') return 'app';
  const changed = Buffer.from(value);
  if (!changed.length) return '\0';
  changed[byte % changed.length] ^= mask;
  // Stored fields are Unicode strings. A byte edit may decode to U+FFFD;
  // either way it changes the stored string and must invalidate its MAC.
  return changed.toString('utf8');
}

test(`audit chain mutations fail at the first broken entry, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const secret = tc.draw(gs.binary({ minSize: 32, maxSize: 32 }));
  const keys = [deriveLogKey('app', secret), deriveLogKey('vault', secret)];
  const drafts = tc.draw(gs.arrays(fields, { minSize: 2, maxSize: 12 }));
  // Every case includes both authors, followed by arbitrary author order.
  drafts[0].author = 'app';
  drafts[1].author = 'vault';
  const checkpointAfter = tc.draw(gs.integers({ minValue: 1, maxValue: drafts.length - 1 }));
  const seed = Buffer.from(secret);
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const publicKey = Buffer.from(privateKey.export({ format: 'jwk' }).x!, 'base64url').toString('base64');
  const log: StoredEntry[] = [];
  const checkpoints: { checkpoint: Checkpoint; entry: number }[] = [];
  function append(draft: Omit<LogFields, 'seq' | 'keyId'>) {
    const key = keys[draft.author === 'app' ? 0 : 1];
    const row = { ...draft, seq: BigInt(log.length), keyId: key.keyId };
    const prevHash = log.at(-1)?.hash ?? GENESIS_HASH;
    log.push({ ...row, prevHash, ...sealEntry(key, prevHash, row) });
  }
  for (const [i, draft] of drafts.entries()) {
    append(draft);
    if (i === checkpointAfter || i === drafts.length - 1) {
      const prefix = log.at(-1)!;
      const unsigned = { seq: Number(prefix.seq), hash: prefix.hash.toString('hex'), signedAt: new Date(draft.occurredAt).toISOString() };
      const checkpoint: Checkpoint = { ...unsigned, keyId: 'test-signing-key', signature: sign(null, checkpointMessage(unsigned), privateKey).toString('base64') };
      checkpoints.push({ checkpoint, entry: log.length });
      append({ ...draft, author: 'vault', action: 'audit.checkpoint', metadata: JSON.stringify(checkpoint) });
    }
  }
  const valid = verifyEntries(log, { keys });
  assert.ok(valid.ok);
  if (valid.ok) {
    assert.equal(valid.authenticated, log.length);
    assert.equal(valid.nextSeq, BigInt(log.length));
    assert.deepEqual(valid.head, log.at(-1)!.hash);
  }
  for (const { checkpoint, entry } of checkpoints) {
    assert.ok(await verifyCheckpoint(checkpoint, publicKey));
    for (const field of ['seq', 'hash', 'signedAt', 'signature'] as const) {
      const damaged = { ...checkpoint, [field]: edit(checkpoint[field], 0, 1) };
      assert.equal(await verifyCheckpoint(damaged, publicKey), false, `checkpoint ${field} edit`);
    }
    const prefix = verifyEntries(log.slice(0, checkpoint.seq + 1), { keys });
    assert.ok(prefix.ok);
    if (prefix.ok) assert.equal(prefix.head.toString('hex'), checkpoint.hash);
    const cut = tc.draw(gs.integers({ minValue: 0, maxValue: checkpoint.seq }));
    // Retain the signed checkpoint after cutting its prefix. No invented
    // verifier: the real chain detects the gap at the checkpoint itself.
    broken([...log.slice(0, cut), ...log.slice(entry)], keys, log[entry].seq, 'truncated before checkpoint');
  }
  const index = tc.draw(gs.integers({ minValue: 0, maxValue: log.length - 1 }));
  const byte = tc.draw(gs.integers({ minValue: 0, maxValue: 1024 }));
  const mask = tc.draw(gs.integers({ minValue: 1, maxValue: 255 }));
  const original = log[index];
  for (const name of Object.keys(original) as (keyof StoredEntry)[]) {
    const changed = { ...original, [name]: edit(original[name], byte, mask) };
    assert.notDeepEqual(changed[name], original[name], `edit changes ${name}`);
    const damaged = log.with(index, changed);
    broken(damaged, keys, changed.seq, `edited ${name}`);
  }
  const removed = tc.draw(gs.integers({ minValue: 0, maxValue: log.length - 2 }));
  broken(log.filter((_, i) => i !== removed), keys, log[removed + 1].seq, 'deleted before retained checkpoint');
  broken([...log.slice(0, index + 1), original, ...log.slice(index + 1)], keys, original.seq, 'duplicated');
  const left = tc.draw(gs.integers({ minValue: 0, maxValue: log.length - 2 }));
  const right = tc.draw(gs.integers({ minValue: left + 1, maxValue: log.length - 1 }));
  broken(log.with(left, log[right]).with(right, log[left]), keys, log[right].seq, 'swapped');
  const wrongKey = keys[original.author === 'app' ? 1 : 0];
  const mac = entryMac(wrongKey.key, original.prevHash, original);
  // Recompute the public hash as an attacker can. Only the author's MAC
  // check should reject this entry, even when it is the last in a run.
  broken(log.with(index, { ...original, mac, hash: entryHash(original.prevHash, original, mac) }), keys, original.seq, 're-signed with the other author key');
}, settings));
