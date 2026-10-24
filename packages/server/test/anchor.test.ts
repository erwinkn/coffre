import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { admits, anchorIsOwn, memoryAnchor, sealAnchor, type AnchorFields, type AnchorStore } from '../src/anchor.ts';
import { fileAnchor } from '../src/anchor-file.ts';
import { anchorObject, durableAnchor, type AnchorNamespace } from '../src/cloudflare-anchor.ts';

const chainKey = Buffer.alloc(32, 1);
const checkpoint = (seq: number) => ({ seq, hash: 'aa'.repeat(32), signedAt: new Date(0).toISOString(), keyId: 'k', signature: 's' });
const fields = (seq: number, verified = seq): AnchorFields => ({
  checkpoint: checkpoint(seq),
  verified: { seq: verified, hash: 'aa'.repeat(32) },
  finding: null,
  beat: seq,
  reanchor: null,
  epoch: 0,
  at: 1000 + seq,
});

/** The Durable Object as the runtime gives it a storage, and the binding that reaches it; its alarm, run by hand. */
function durableObject(walk: ((store: AnchorStore) => Promise<boolean>) | null = null) {
  const stored = new Map<string, unknown>();
  let alarm: number | null = null;
  const storage = {
    get: async <T>(key: string) => stored.get(key) as T | undefined,
    put: async <T>(key: string, value: T) => void stored.set(key, value),
    getAlarm: async () => alarm,
    setAlarm: async (at: number) => void (alarm = at),
  };
  const object = new (anchorObject<object>(() => walk))({ storage }, {});
  const namespace: AnchorNamespace = { idFromName: (name) => name, get: () => ({ fetch: (request) => object.fetch(request) }) };
  return { namespace, alarmSet: () => alarm !== null, ring: async () => ((alarm = null), object.alarm()) };
}

const scratch = mkdtempSync(join(tmpdir(), 'coffre-anchor-'));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

const stores: [string, () => AnchorStore][] = [
  ['in memory', memoryAnchor],
  ['in a file', () => fileAnchor(join(mkdtempSync(join(scratch, 'f-')), 'state', 'anchor.json'))],
  ['in a Durable Object', () => durableAnchor(durableObject().namespace)],
];

for (const [where, open] of stores) {
  test(`an anchor ${where}: compare-and-set, and never moved back`, async () => {
    const store = open();
    assert.equal(await store.read(), null);
    const first = sealAnchor(chainKey, fields(3));
    assert.equal(await store.write(null, first), true);
    assert.deepEqual(await store.read(), first);
    // A second write that names nothing stored loses.
    assert.equal(await store.write(null, sealAnchor(chainKey, fields(5))), false);
    const second = sealAnchor(chainKey, fields(5));
    assert.equal(await store.write(first, second), true);
    // Back to the older one, as whoever can call the store would: refused, by the checkpoint or by the app's progress.
    assert.equal(await store.write(second, first), false);
    assert.equal(await store.write(second, sealAnchor(chainKey, fields(6, 2))), false);
    assert.deepEqual(await store.read(), second);
    // As far as before, a finding added: allowed.
    const found = sealAnchor(chainKey, { ...fields(5), finding: { seq: 4, reason: 'edited', by: 'app', since: 1 } });
    assert.equal(await store.write(second, found), true);
    assert.deepEqual(await store.read(), found);
  });
}

test('a file anchor is written whole, readable by its owner only, and one write at a time', async () => {
  const path = join(mkdtempSync(join(scratch, 'm-')), 'anchor.json');
  const store = fileAnchor(path);
  const first = sealAnchor(chainKey, fields(1));
  // Two writes at once from one process: the second sees the first's record, not the one it named.
  const [a, b] = await Promise.all([store.write(null, first), store.write(null, sealAnchor(chainKey, fields(2)))]);
  assert.deepEqual([a, b], [true, false]);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  // Another process's store over the same file reads what this one wrote.
  assert.deepEqual(await fileAnchor(path).read(), first);
});

test('an anchor is the app\'s by its MAC: every field counts, and another key\'s is not', () => {
  const sealed = sealAnchor(chainKey, fields(3));
  assert.equal(anchorIsOwn(chainKey, sealed), true);
  assert.equal(anchorIsOwn(Buffer.alloc(32, 2), sealed), false);
  for (const changed of [{ at: 1 }, { beat: 4 }, { verified: null }, { epoch: 1 }, { reanchor: { since: 1 } }, { finding: { seq: 1, reason: 'x', by: 'app' as const, since: 0 } }, { checkpoint: checkpoint(4) }]) {
    assert.equal(anchorIsOwn(chainKey, { ...sealed, ...changed }), false, JSON.stringify(changed));
  }
  assert.equal(anchorIsOwn(chainKey, { ...sealed, mac: 'not hex' }), false);
});

test('admits: the first write needs nothing stored, every later one the record stored', () => {
  const one = sealAnchor(chainKey, fields(1));
  const two = sealAnchor(chainKey, fields(2));
  assert.equal(admits(null, null, one), true);
  assert.equal(admits(one, null, two), false);
  assert.equal(admits(null, one, two), false);
  assert.equal(admits(one, one, two), true);
  assert.equal(admits(two, two, one), false);
  // An Owner's acceptance of lost entries, in a new epoch: the one record that moves back.
  assert.equal(admits(two, two, sealAnchor(chainKey, { ...fields(1), epoch: 1 })), true);
  assert.equal(admits(two, two, sealAnchor(chainKey, { ...fields(1), epoch: 0 })), false);
});

test('the Durable Object sets its alarm while a backlog is left, and its alarm walks it over its own storage', async () => {
  const walked: (AnchorStore | null)[] = [];
  let left = 2;
  const object = durableObject(async (store) => {
    walked.push(store);
    return --left > 0;
  });
  const store = durableAnchor(object.namespace);
  // Caught up: no alarm.
  await store.write(null, sealAnchor(chainKey, fields(3)));
  assert.equal(object.alarmSet(), false);
  // Verified short of its checkpoint: an alarm, which walks until none is left.
  await store.write(await store.read(), sealAnchor(chainKey, fields(5, 3)));
  assert.equal(object.alarmSet(), true);
  await object.ring();
  assert.equal(object.alarmSet(), true);
  await object.ring();
  assert.equal(object.alarmSet(), false);
  assert.equal(walked.length, 2);
  // Over its own storage: what it reads is what the binding wrote.
  assert.deepEqual(await walked[0]!.read(), await store.read());
});
