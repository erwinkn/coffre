// The MAC of a 0.15 log entry (log-entry.ts; D162): 16 bytes, the key's public tag in the first four, then twelve of
// HMAC-SHA256 under the key. The tag names the key, so that a rotation of the vault's signing key (T168) can tell its
// keys' entries apart; it vouches for nothing by itself, which these hold.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { authentic, changeEntry, entryMac, logMacKey, MAC_BYTES, TAG_BYTES, useEntry } from '../src/log-entry.ts';

const row = () => ({ at: Date.now(), requestId: 7n, credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null });

test('a MAC is 16 bytes: its key\'s tag, then 12 bytes of HMAC; the tag is the seed\'s alone, and holds under its key', () => {
  assert.equal(TAG_BYTES, 4);
  const seed = randomBytes(32);
  const key = logMacKey(seed);
  assert.equal(key.tag.length, 4);
  assert.ok(logMacKey(seed).tag.equals(key.tag), 'one tag a seed');
  assert.ok(!logMacKey(randomBytes(32)).tag.equals(key.tag));
  assert.ok(!key.key.subarray(0, 4).equals(key.tag), 'the tag is no part of the key');
  const r = row();
  const mac = entryMac(key, { tree: 'uses', row: r });
  assert.equal(mac.length, MAC_BYTES);
  assert.ok(mac.subarray(0, TAG_BYTES).equals(key.tag));
  assert.ok(authentic(key)(useEntry({ number: 1n, ...r, mac })));
  const c = { at: Date.now(), requestId: 'c-1', object: randomUUID(), actor: 'vault', payload: '{}', seal: null };
  assert.ok(authentic(key)(changeEntry({ number: 2n, ...c, mac: entryMac(key, { tree: 'changes', row: c }) })));
});

test('fails closed: another key\'s MAC, either half swapped for another key\'s, a bit flipped in the tag, a MAC cut short or grown', () => {
  const [key, other] = [logMacKey(randomBytes(32)), logMacKey(randomBytes(32))];
  const r = row();
  const mine = entryMac(key, { tree: 'uses', row: r });
  const theirs = entryMac(other, { tree: 'uses', row: r });
  const flipped = Buffer.from(mine);
  flipped[0]! ^= 1;
  const refused: [string, Buffer][] = [
    ['another key\'s MAC', theirs],
    ['another key\'s tag over this key\'s HMAC', Buffer.concat([other.tag, mine.subarray(4)])],
    ['this key\'s tag over another key\'s HMAC', Buffer.concat([key.tag, theirs.subarray(4)])],
    ['a bit flipped in the tag', flipped],
    ['cut to 15 bytes', mine.subarray(0, 15)],
    ['grown to 17 bytes', Buffer.concat([mine, Buffer.alloc(1)])],
  ];
  for (const [what, mac] of refused) assert.ok(!authentic(key)(useEntry({ number: 1n, ...r, mac })), what);
  // The same MAC over another tree, or another row, holds for neither.
  assert.ok(!authentic(key)({ ...useEntry({ number: 1n, ...r, mac: mine }), tree: 'changes' }));
  assert.ok(!authentic(key)(useEntry({ number: 1n, ...r, purpose: 2, mac: mine })));
});
