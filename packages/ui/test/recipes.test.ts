import test from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient, SecretKey } from '@coffre/client';

import { regenerateSecret, saveSecrets } from '../src/lib/changes.ts';
import { liveGeneration, regenerateWaits } from '../src/lib/recipes.ts';

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

test("a pair's Regenerate waits while a save of either half is on its way, its rename included", () => {
  const entries = pair();
  const vars = { active: entries, drafts: [], changes: { JWT_PRIVATE_KEY: { key: 'SIGNING_KEY', value: null, archived: false } } };
  const shown = shownAfter(entries, vars);
  // What the save marks pending, as the page's status reads it: the key under both its names.
  const save = saveSecrets({} as CoffreClient, { project: 'market', environment: 'dev' }, 'ada@acme.example');
  const saving = new Set(save.targets(vars).map((target) => target.id));
  assert.deepEqual([...saving].sort(), ['JWT_PRIVATE_KEY', 'SIGNING_KEY']);
  const publicKey = shown.find((entry) => entry.key === 'JWT_PUBLIC_KEY')!;
  assert.equal(regenerateWaits(publicKey.key, liveGeneration(publicKey, shown)!, (key) => saving.has(key)), true, 'from the untouched half');
  assert.equal(regenerateWaits(publicKey.key, liveGeneration(publicKey, shown)!, () => false), false, 'once the rename has landed');
  // A key of its own waits only on its own save.
  const token = shown.find((entry) => entry.key === 'TOKEN')!;
  assert.equal(regenerateWaits('TOKEN', token.generated!, (key) => saving.has(key)), false);
  assert.equal(regenerateWaits('TOKEN', token.generated!, (key) => key === 'TOKEN'), true);
});

test("Regenerate is a save of every key it writes: both halves are pending until it lands, so neither is renamed meanwhile", async () => {
  const sent: unknown[] = [];
  const client = { secrets: { set: async (path: string, patch: unknown) => (sent.push([path, patch]), { operationId: 'op', keys: {} }) } } as unknown as CoffreClient;
  const change = regenerateSecret(client, { project: 'market', environment: 'dev' }, 'ada@acme.example');
  const vars = { key: 'JWT_PUBLIC_KEY', generated: PAIR, versions: { JWT_PRIVATE_KEY: 1, JWT_PUBLIC_KEY: 1 } };
  // The page's status marks each target pending, and a row with a save on its way takes no edit.
  assert.deepEqual(change.targets(vars).map(({ id, kind }) => [id, kind]), [['JWT_PRIVATE_KEY', 'saving'], ['JWT_PUBLIC_KEY', 'saving']]);
  const busy = new Set(change.targets(vars).map((target) => target.id));
  assert.equal(regenerateWaits('JWT_PRIVATE_KEY', PAIR, (key) => busy.has(key)), true, 'nor regenerated again');

  // Shown at once as the next versions, still a pair; nothing of the value.
  const shown = change.apply!(pair(), vars);
  assert.deepEqual(shown.map(({ key, version, generated }) => [key, version, generated]), [
    ['JWT_PRIVATE_KEY', 2, PAIR],
    ['JWT_PUBLIC_KEY', 2, PAIR],
    ['TOKEN', 1, { recipe: 'bytes:32:base62' }],
  ]);

  // The value is made as the change runs, and sent with its recipe, under the pair's names.
  await change.run(vars);
  const [[path, patch]] = sent as [[string, Record<string, { generated: unknown; replaces: number }>]];
  assert.equal(path, 'market/dev');
  assert.deepEqual(Object.keys(patch), ['JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY']);
  // Each replaces the version the page listed: the server refuses it if either has changed since.
  assert.deepEqual([patch.JWT_PUBLIC_KEY!.generated, patch.JWT_PRIVATE_KEY!.replaces, patch.JWT_PUBLIC_KEY!.replaces], [PAIR, 1, 1]);
});

test('Regenerate waits while either half is being edited, before any save is sent', () => {
  assert.equal(regenerateWaits('JWT_PUBLIC_KEY', PAIR, (key) => key === 'JWT_PRIVATE_KEY'), true);
  assert.equal(regenerateWaits('JWT_PUBLIC_KEY', PAIR, () => false), false);
});
