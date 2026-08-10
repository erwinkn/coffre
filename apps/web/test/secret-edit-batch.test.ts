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

test('a failed edit keeps that edit and every untried edit', async () => {
  const attempted: string[] = [];
  const result = await applySecretEditBatch({
    active,
    drafts: [],
    changes: {
      A: change('A', 'one'),
      B: change('B', 'two'),
      C: change('C', 'three'),
    },
    operations: {
      archive: async () => {},
      rename: async () => {},
      save: async (key) => {
        attempted.push(key);
        if (key === 'B') throw new Error('B failed');
      },
    },
  });

  assert.deepEqual(attempted, ['A', 'B']);
  assert.equal(result.applied, 1);
  assert.deepEqual(Object.keys(result.changes), ['B', 'C']);
  assert.match(String(result.error), /B failed/);
});

test('a value follows its new key when rename succeeds and save fails', async () => {
  const result = await applySecretEditBatch({
    active: [{ key: 'OLD' }],
    drafts: [],
    changes: { OLD: change('NEW', 'pending-value') },
    operations: {
      archive: async () => {},
      rename: async () => {},
      save: async () => {
        throw new Error('save failed');
      },
    },
  });

  assert.equal(result.applied, 1);
  assert.deepEqual(result.changes, {
    NEW: { key: 'NEW', value: 'pending-value', archived: false },
  });
});

test('a failed draft keeps that draft and later drafts', async () => {
  const drafts: SecretDraft[] = [
    { id: 1, key: 'A', value: 'one' },
    { id: 2, key: 'B', value: 'two' },
    { id: 3, key: 'C', value: 'three' },
  ];
  const result = await applySecretEditBatch({
    active: [],
    drafts,
    changes: {},
    operations: {
      archive: async () => {},
      rename: async () => {},
      save: async (key) => {
        if (key === 'B') throw new Error('B failed');
      },
    },
  });

  assert.equal(result.applied, 1);
  assert.deepEqual(result.drafts.map((draft) => draft.id), [2, 3]);
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
      archive: async () => {},
      rename: async (key, nextKey) => attempted.push(`${key}->${nextKey}`),
      save: async () => {},
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
      archive: async () => { attempted = true; },
      rename: async () => { attempted = true; },
      save: async () => { attempted = true; },
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
      archive: async () => { attempted = true; },
      rename: async () => { attempted = true; },
      save: async () => { attempted = true; },
    },
  });

  assert.equal(attempted, false);
  assert.match(String(result.error), /cannot archive and write/);
});
