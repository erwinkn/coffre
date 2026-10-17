import test from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient, SecretKey } from '@coffre/client';

import { saveSecrets } from '../src/lib/changes.ts';
import { liveGeneration } from '../src/lib/recipes.ts';

const PAIR = { recipe: 'ecdsa:p-256', pair: { private: 'JWT_PRIVATE_KEY', public: 'JWT_PUBLIC_KEY' } };

function listed(key: string, generated: SecretKey['generated'], more: Partial<SecretKey> = {}): SecretKey {
  return { key, reference: null, folder: null, archived: false, version: 1, updatedAt: null, updatedBy: null, generated, ...more };
}

const pair = () => [listed('JWT_PRIVATE_KEY', PAIR), listed('JWT_PUBLIC_KEY', PAIR), listed('TOKEN', { recipe: 'bytes:32:base62' })];

/** What the list shows the moment a save is made, before the server answers. */
function shownAfter(entries: SecretKey[], vars: Parameters<ReturnType<typeof saveSecrets>['apply']>[1]): SecretKey[] {
  return saveSecrets({} as CoffreClient, { project: 'market', environment: 'dev' }, 'ada@acme.example').apply(entries, vars);
}

const regenerable = (entries: SecretKey[]) =>
  Object.fromEntries(entries.map((entry) => [entry.key, liveGeneration(entry, entries)]));

test('a key pair is regenerable while both its halves are listed, alike', () => {
  assert.deepEqual(regenerable(pair()), { JWT_PRIVATE_KEY: PAIR, JWT_PUBLIC_KEY: PAIR, TOKEN: { recipe: 'bytes:32:base62' } });
  const [privateKey, publicKey, token] = pair();
  assert.equal(liveGeneration(privateKey!, [privateKey!, token!]), null, 'its other half is gone');
  assert.equal(liveGeneration(privateKey!, [privateKey!, { ...publicKey!, archived: true }]), null, 'its other half is archived');
  assert.equal(liveGeneration(privateKey!, [privateKey!, { ...publicKey!, generated: { ...PAIR, recipe: 'ecdsa:p-384' } }]), null, 'its other half is of another recipe');
  assert.equal(liveGeneration(token!, [token!]), token!.generated);
});

test('a rename shown at once renames the pair in both halves, so Regenerate writes the keys as they are', () => {
  const entries = pair();
  const shown = shownAfter(entries, {
    active: entries,
    drafts: [],
    changes: { JWT_PRIVATE_KEY: { key: 'SIGNING_KEY', value: null, archived: false } },
  });
  const renamed = { ...PAIR, pair: { private: 'SIGNING_KEY', public: 'JWT_PUBLIC_KEY' } };
  assert.deepEqual(regenerable(shown), { SIGNING_KEY: renamed, JWT_PUBLIC_KEY: renamed, TOKEN: { recipe: 'bytes:32:base62' } });
});

test('a value typed over one half, shown at once, leaves neither half regenerable', () => {
  const entries = pair();
  const shown = shownAfter(entries, {
    active: entries,
    drafts: [],
    changes: { JWT_PUBLIC_KEY: { key: 'JWT_PUBLIC_KEY', value: 'pasted', archived: false } },
  });
  assert.deepEqual(regenerable(shown), { JWT_PRIVATE_KEY: null, JWT_PUBLIC_KEY: null, TOKEN: { recipe: 'bytes:32:base62' } });
});
