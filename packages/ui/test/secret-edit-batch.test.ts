import test from 'node:test';
import assert from 'node:assert/strict';

import {
  applySecretEditBatch,
  hasSecretEditConflict,
  type SecretChange,
  type SecretDraft,
} from '../src/lib/secret-edit-batch.ts';

const active = [{ key: 'A' }, { key: 'B' }, { key: 'C' }];

function change(key: string, value: string): SecretChange {
  return { key, value, archived: false };
}

test('one draft can append a version to an unchanged active key', () => {
  assert.equal(
    hasSecretEditConflict(
      [{ key: 'API_KEY' }],
      [{ id: 1, key: 'API_KEY', value: 'next' }],
      {},
    ),
    false,
  );
});

test('prototype property names do not create phantom changes', () => {
  assert.equal(hasSecretEditConflict([{ key: 'constructor' }], [], {}), false);
  assert.equal(hasSecretEditConflict([{ key: 'toString' }], [], {}), false);
  assert.equal(hasSecretEditConflict([{ key: '__proto__' }], [], {}), false);
});

test('competing drafts and value edits still conflict', () => {
  assert.equal(
    hasSecretEditConflict(
      [{ key: 'API_KEY' }],
      [
        { id: 1, key: 'NEW_KEY', value: 'one' },
        { id: 2, key: 'NEW_KEY', value: 'two' },
      ],
      {},
    ),
    true,
  );
  assert.equal(
    hasSecretEditConflict(
      [{ key: 'API_KEY' }],
      [{ id: 1, key: 'API_KEY', value: 'draft' }],
      { API_KEY: change('API_KEY', 'inline') },
    ),
    true,
  );
});

test('values, new keys and archives are saved as one patch', async () => {
  const patches: unknown[] = [];
  const result = await applySecretEditBatch({
    active,
    drafts: [{ id: 1, key: ' NEW ', value: 'fresh' }],
    changes: {
      A: change('A', 'one'),
      B: { key: 'B', value: null, archived: true },
    },
    operations: {
      rename: async () => assert.fail('nothing was renamed'),
      write: async (patch) => {
        patches.push(patch);
      },
    },
  });

  assert.deepEqual(patches, [{ A: 'one', B: null, NEW: 'fresh' }]);
  assert.equal(result.error, null);
  assert.equal(result.applied, 3);
  assert.deepEqual(result.drafts, []);
  assert.deepEqual(result.changes, {});
});

test('a refused patch keeps every edit, since none of it landed', async () => {
  const drafts: SecretDraft[] = [{ id: 1, key: 'NEW', value: 'fresh' }];
  const changes = { A: change('A', 'one'), C: change('C', 'three') };
  const result = await applySecretEditBatch({
    active,
    drafts,
    changes,
    operations: {
      rename: async () => {},
      write: async () => {
        throw new Error('C is archived');
      },
    },
  });

  assert.equal(result.applied, 0);
  assert.deepEqual(result.drafts, drafts);
  assert.deepEqual(result.changes, changes);
  assert.match(String(result.error), /C is archived/);
});

test('renames go first, and a value follows its new key when the patch fails', async () => {
  const calls: string[] = [];
  const result = await applySecretEditBatch({
    active: [{ key: 'OLD' }],
    drafts: [],
    changes: { OLD: change('NEW', 'pending-value') },
    operations: {
      rename: async (key, nextKey) => {
        calls.push(`rename ${key}->${nextKey}`);
      },
      write: async (patch) => {
        calls.push(`write ${Object.keys(patch).join(',')}`);
        throw new Error('write failed');
      },
    },
  });

  assert.deepEqual(calls, ['rename OLD->NEW', 'write NEW']);
  assert.equal(result.applied, 1);
  assert.deepEqual(result.changes, {
    NEW: { key: 'NEW', value: 'pending-value', archived: false },
  });
});

test('a failed rename stops the save before the patch', async () => {
  let wrote = false;
  const result = await applySecretEditBatch({
    active,
    drafts: [{ id: 1, key: 'NEW', value: 'fresh' }],
    changes: {
      A: { key: 'A2', value: null, archived: false },
      B: change('B', 'two'),
    },
    operations: {
      rename: async () => {
        throw new Error('A: taken');
      },
      write: async () => {
        wrote = true;
      },
    },
  });

  assert.equal(wrote, false);
  assert.equal(result.applied, 0);
  assert.deepEqual(Object.keys(result.changes), ['A', 'B']);
  assert.equal(result.drafts.length, 1);
});

test('a key named __proto__ is written like any other', async () => {
  const patches: Record<string, string | null>[] = [];
  await applySecretEditBatch({
    active: [],
    drafts: [{ id: 1, key: '__proto__', value: 'x' }],
    changes: {},
    operations: {
      rename: async () => {},
      write: async (patch) => {
        patches.push(patch);
      },
    },
  });

  assert.deepEqual(Object.keys(patches[0]), ['__proto__']);
  assert.equal(JSON.stringify(patches[0]), '{"__proto__":"x"}');
});

test('dependent renames free destinations before they are reused', async () => {
  const attempted: string[] = [];
  const result = await applySecretEditBatch({
    active: [{ key: 'A' }, { key: 'B' }],
    drafts: [],
    changes: {
      A: { key: 'B', value: null, archived: false },
      B: { key: 'C', value: null, archived: false },
    },
    operations: {
      rename: async (key, nextKey) => {
        attempted.push(`${key}->${nextKey}`);
      },
      write: async () => assert.fail('renames alone write no patch'),
    },
  });

  assert.deepEqual(attempted, ['B->C', 'A->B']);
  assert.equal(result.error, null);
  assert.deepEqual(result.changes, {});
});

test('cyclic renames fail before any mutation', async () => {
  let attempted = false;
  const result = await applySecretEditBatch({
    active: [{ key: 'A' }, { key: 'B' }],
    drafts: [],
    changes: {
      A: { key: 'B', value: null, archived: false },
      B: { key: 'A', value: null, archived: false },
    },
    operations: {
      rename: async () => { attempted = true; },
      write: async () => { attempted = true; },
    },
  });

  assert.equal(attempted, false);
  assert.match(String(result.error), /cycle/);
});

test('archive and rewrite of one key fails before any mutation', async () => {
  let attempted = false;
  const result = await applySecretEditBatch({
    active: [{ key: 'A' }],
    drafts: [{ id: 1, key: 'A', value: 'new' }],
    changes: { A: { key: 'A', value: null, archived: true } },
    operations: {
      rename: async () => { attempted = true; },
      write: async () => { attempted = true; },
    },
  });

  assert.equal(attempted, false);
  assert.match(String(result.error), /cannot archive and write/);
});
