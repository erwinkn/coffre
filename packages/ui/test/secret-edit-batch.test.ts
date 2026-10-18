import test from 'node:test';
import assert from 'node:assert/strict';

import {
  applySecretEditBatch,
  companionsOf,
  generationsOf,
  hasSecretEditConflict,
  levelsOf,
  madeSensitive,
  valueEdit,
  type SecretChange,
  type SecretDraft,
} from '../src/lib/secret-edit-batch.ts';

const active = [{ key: 'A' }, { key: 'B' }, { key: 'C' }];

function change(key: string, value: string): SecretChange {
  return { key, value, archived: false };
}

/** A value as every write says it: with who sees it, a secret unless the row says otherwise. */
const secret = (value: string) => ({ value, sensitivity: 'secret' });

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

  assert.deepEqual(patches, [{ A: secret('one'), B: null, NEW: secret('fresh') }]);
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
  assert.equal(JSON.stringify(patches[0]), '{"__proto__":{"value":"x","sensitivity":"secret"}}');
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

test("a row's companion is written in the same patch as the row", async () => {
  const writes: Record<string, string | null>[] = [];
  const result = await applySecretEditBatch({
    active,
    drafts: [{ id: 1, key: 'JWT_PRIVATE_KEY', value: 'private', companion: { key: 'JWT_PUBLIC_KEY', value: 'public' } }],
    changes: { A: { ...change('A', 'a-private'), companion: { key: 'A_PUBLIC', value: 'a-public' } } },
    operations: {
      rename: async () => assert.fail('nothing is renamed'),
      write: async (patch) => {
        writes.push(patch);
      },
    },
  });
  assert.equal(result.error, null);
  assert.deepEqual(writes, [
    { A: secret('a-private'), JWT_PRIVATE_KEY: secret('private'), JWT_PUBLIC_KEY: secret('public'), A_PUBLIC: secret('a-public') },
  ]);
});

test('a generated value is written with its recipe, and a key pair names both keys as they are saved', async () => {
  const writes: unknown[] = [];
  const changes = {
    // Renamed in the same save: the pair names the private key's new name.
    A: { ...change('SIGNING_PRIVATE_KEY', 'private'), recipe: 'ecdsa:p-256', companion: { key: ' SIGNING_PUBLIC_KEY ', value: 'public' } },
    B: change('B', 'typed'),
  };
  const drafts: SecretDraft[] = [{ id: 1, key: 'TOKEN ', value: 'made', recipe: 'bytes:32:hex' }];
  const result = await applySecretEditBatch({
    active,
    drafts,
    changes,
    operations: {
      rename: async () => {},
      write: async (patch) => {
        writes.push(patch);
      },
    },
  });
  assert.equal(result.error, null);
  const pair = { recipe: 'ecdsa:p-256', pair: { private: 'SIGNING_PRIVATE_KEY', public: 'SIGNING_PUBLIC_KEY' } };
  assert.deepEqual(writes, [{
    SIGNING_PRIVATE_KEY: { value: 'private', generated: pair, sensitivity: 'secret' },
    SIGNING_PUBLIC_KEY: { value: 'public', generated: pair, sensitivity: 'secret' },
    B: secret('typed'),
    TOKEN: { value: 'made', generated: { recipe: 'bytes:32:hex' }, sensitivity: 'secret' },
  }]);
  // And what the list shows until it is read back.
  assert.deepEqual(generationsOf(active, drafts, changes), new Map([
    ['TOKEN', { recipe: 'bytes:32:hex' }],
    ['SIGNING_PRIVATE_KEY', pair],
    ['SIGNING_PUBLIC_KEY', pair],
  ]));
});

test('a companion stays with its row when the patch after a rename fails', async () => {
  const companion = { key: 'SIGNING_PUBLIC_KEY', value: 'public' };
  const result = await applySecretEditBatch({
    active,
    drafts: [],
    changes: { A: { ...change('SIGNING_PRIVATE_KEY', 'private'), companion } },
    operations: {
      rename: async () => {},
      write: async () => {
        throw new Error('refused');
      },
    },
  });
  // The rename is done; the retry writes the value and its companion together.
  assert.deepEqual(result.changes, {
    SIGNING_PRIVATE_KEY: { ...change('SIGNING_PRIVATE_KEY', 'private'), companion },
  });
});

test("an archive writes no companion, and a companion's name clashes like a new row's", () => {
  const companion = { key: 'A_PUBLIC', value: 'public' };
  assert.deepEqual(companionsOf(active, [], { A: { key: 'A', value: null, archived: true, companion } }), []);
  assert.deepEqual(companionsOf(active, [], { A: { ...change('A', 'private'), companion } }), [companion]);

  // Two rows' companions, or a companion and a new row, on one name.
  assert.equal(
    hasSecretEditConflict(active, [{ id: 1, key: 'A_PUBLIC', value: 'x' }], { A: { ...change('A', 'private'), companion } }),
    true,
  );
  // A row renamed onto its own companion's name.
  assert.equal(
    hasSecretEditConflict(active, [], { A: { ...change('A_PUBLIC', 'private'), companion } }),
    true,
  );
  // A companion onto a key being archived.
  assert.equal(
    hasSecretEditConflict(active, [{ id: 1, key: 'N', value: 'x', companion: { key: 'B', value: 'y' } }], {
      B: { key: 'B', value: null, archived: true },
    }),
    true,
  );
  assert.equal(hasSecretEditConflict(active, [], { A: { ...change('A', 'private'), companion } }), false);
});

test('a companion named __proto__ is a key like any other', async () => {
  const writes: Record<string, string | null>[] = [];
  await applySecretEditBatch({
    active,
    drafts: [{ id: 1, key: 'PRIVATE', value: 'private', companion: { key: '__proto__', value: 'public' } }],
    changes: {},
    operations: { rename: async () => {}, write: async (patch) => void writes.push(patch) },
  });
  assert.deepEqual(Object.keys(writes[0]!), ['PRIVATE', '__proto__']);
});

test("an edit whose key left the list on a refresh writes no companion either", async () => {
  // JWT_PRIVATE_KEY was edited here, then renamed or archived elsewhere: the
  // list read back no longer has it, and the edit is skipped, public key too.
  const companion = { key: 'JWT_PUBLIC_KEY', value: 'public' };
  const changes = { JWT_PRIVATE_KEY: { ...change('JWT_PRIVATE_KEY', 'private'), companion } };
  const drafts = [{ id: 1, key: 'OTHER', value: 'other' }];
  assert.deepEqual(companionsOf(active, drafts, changes), []);
  const writes: Record<string, string | null>[] = [];
  await applySecretEditBatch({
    active,
    drafts,
    changes,
    operations: { rename: async () => {}, write: async (patch) => void writes.push(patch) },
  });
  assert.deepEqual(writes, [{ OTHER: secret('other') }]);
});

test('each value is written with who sees it, a mark alone with its level, and a generated value never plain', async () => {
  const patches: unknown[] = [];
  await applySecretEditBatch({
    active: [...active, { key: 'D' }],
    drafts: [{ id: 1, key: 'ACCOUNT', value: 'acct_42', sensitivity: 'plain' }],
    changes: {
      A: { ...change('A', 'region-eu'), sensitivity: 'plain' },
      B: { key: 'B', value: null, archived: false, sensitivity: 'sensitive' },
      C: { ...change('C', 'secret-again'), sensitivity: 'secret' },
      D: { ...change('D', 'made'), recipe: 'bytes:32:hex', sensitivity: 'plain' },
    },
    operations: {
      rename: async () => assert.fail('nothing was renamed'),
      write: async (patch) => {
        patches.push(patch);
      },
    },
  });
  assert.deepEqual(patches, [{
    A: { value: 'region-eu', sensitivity: 'plain' },
    B: { sensitivity: 'sensitive' },
    C: secret('secret-again'),
    D: { value: 'made', generated: { recipe: 'bytes:32:hex' }, sensitivity: 'secret' },
    ACCOUNT: { value: 'acct_42', sensitivity: 'plain' },
  }]);
});

test('a mark follows its key through a rename refused after it, for the retry', async () => {
  const result = await applySecretEditBatch({
    active,
    drafts: [],
    changes: { A: { key: 'A2', value: null, archived: false, sensitivity: 'sensitive' } },
    operations: {
      rename: async () => {},
      write: async () => {
        throw new Error('refused');
      },
    },
  });
  assert.deepEqual(result.changes, { A2: { key: 'A2', value: null, archived: false, sensitivity: 'sensitive' } });
});

test('a level changed alone is a mark, looser waits for a value typed into an empty field, and back where it started is no change', () => {
  const opened = { start: 'sk_1', level: 'secret' as const };
  // Stricter, the value as it opened: a mark.
  assert.deepEqual(valueEdit(opened, { value: null, sensitivity: 'sensitive' }), { value: null, sensitivity: 'sensitive' });
  // Looser: the field opens empty, and the value is typed again, even as it was.
  assert.deepEqual(valueEdit(opened, { value: null, sensitivity: 'plain' }), { value: null, sensitivity: 'plain' });
  assert.deepEqual(valueEdit(opened, { value: '', sensitivity: 'plain' }), { value: null, sensitivity: 'plain' });
  assert.deepEqual(valueEdit(opened, { value: 'sk_1', sensitivity: 'plain' }), { value: 'sk_1', sensitivity: 'plain' });
  // A new value says its level, the row's included.
  assert.deepEqual(valueEdit(opened, { value: 'sk_2', sensitivity: 'secret' }), { value: 'sk_2', sensitivity: 'secret' });
  // Back where it started.
  assert.deepEqual(valueEdit(opened, { value: 'sk_1', sensitivity: 'secret' }), { value: null, sensitivity: undefined });
  // A key with no value of its own, a reference: written, it is a secret unless it says.
  assert.deepEqual(valueEdit({ start: '', level: null }, { value: null, sensitivity: 'secret' }), { value: null, sensitivity: undefined });
  // A sensitive one, never read: anything typed is a new value, and it stays sensitive.
  assert.deepEqual(valueEdit({ start: '', level: 'sensitive' }, { value: 'sk_3', sensitivity: 'sensitive' }), { value: 'sk_3', sensitivity: 'sensitive' });
});

test("a generated pair's public key is written at its own level, not its private key's", async () => {
  const pair = { recipe: 'ecdsa:p-256', pair: { private: 'PRIVATE_KEY', public: 'PUBLIC_KEY' } };
  const listed = [
    { key: 'PRIVATE_KEY', sensitivity: 'sensitive' as const },
    { key: 'PUBLIC_KEY', sensitivity: 'secret' as const },
    { key: 'SIGNING_PRIVATE', sensitivity: 'secret' as const },
    { key: 'SIGNING_PUBLIC', sensitivity: 'sensitive' as const },
  ];
  const changes: Record<string, SecretChange> = {
    // A sensitive private key regenerated: its public key stays a secret.
    PRIVATE_KEY: { ...change('PRIVATE_KEY', 'private'), recipe: 'ecdsa:p-256', sensitivity: 'sensitive', companion: { key: 'PUBLIC_KEY', value: 'public' } },
    // A public key someone made sensitive stays so.
    SIGNING_PRIVATE: { ...change('SIGNING_PRIVATE', 'private-2'), recipe: 'ecdsa:p-256', companion: { key: 'SIGNING_PUBLIC', value: 'public-2' } },
  };
  // A new pair's public key is a secret, its private key sensitive.
  const drafts: SecretDraft[] = [{ id: 1, key: 'NEW_PRIVATE', value: 'private-3', recipe: 'ecdsa:p-256', sensitivity: 'sensitive', companion: { key: 'NEW_PUBLIC', value: 'public-3' } }];
  const patches: unknown[] = [];
  await applySecretEditBatch({
    active: listed,
    drafts,
    changes,
    operations: {
      rename: async () => assert.fail('nothing is renamed'),
      write: async (patch) => {
        patches.push(patch);
      },
    },
  });
  const signing = { recipe: 'ecdsa:p-256', pair: { private: 'SIGNING_PRIVATE', public: 'SIGNING_PUBLIC' } };
  const made = { recipe: 'ecdsa:p-256', pair: { private: 'NEW_PRIVATE', public: 'NEW_PUBLIC' } };
  assert.deepEqual(patches, [{
    PRIVATE_KEY: { value: 'private', generated: pair, sensitivity: 'sensitive' },
    PUBLIC_KEY: { value: 'public', generated: pair, sensitivity: 'secret' },
    SIGNING_PRIVATE: { value: 'private-2', generated: signing, sensitivity: 'secret' },
    SIGNING_PUBLIC: { value: 'public-2', generated: signing, sensitivity: 'sensitive' },
    NEW_PRIVATE: { value: 'private-3', generated: made, sensitivity: 'sensitive' },
    NEW_PUBLIC: { value: 'public-3', generated: made, sensitivity: 'secret' },
  }]);
  // What the list shows until it is read back, and what the save asks to confirm: only the new private key.
  assert.equal(levelsOf(listed, drafts, changes).get('PUBLIC_KEY')?.sensitivity, 'secret');
  assert.equal(levelsOf(listed, drafts, changes).get('NEW_PUBLIC')?.sensitivity, 'secret');
  assert.deepEqual(madeSensitive(listed, drafts, changes), ['NEW_PRIVATE']);
});

test('a save asks to confirm every key it makes sensitive, a public key made so included', () => {
  const listed = [
    { key: 'PRIVATE_KEY', sensitivity: 'secret' as const },
    { key: 'PUBLIC_KEY', sensitivity: 'secret' as const },
    { key: 'TOKEN', sensitivity: 'secret' as const },
    { key: 'OLD', sensitivity: 'sensitive' as const },
  ];
  const changes: Record<string, SecretChange> = {
    PRIVATE_KEY: {
      ...change('PRIVATE_KEY', 'private'),
      recipe: 'ecdsa:p-256',
      sensitivity: 'sensitive',
      companion: { key: 'PUBLIC_KEY', value: 'public', sensitivity: 'sensitive' },
    },
    // A mark, named by the key's name after its rename.
    TOKEN: { key: 'API_TOKEN', value: null, archived: false, sensitivity: 'sensitive' },
    // Already sensitive: nothing to confirm.
    OLD: { ...change('OLD', 'next'), sensitivity: 'sensitive' },
  };
  assert.deepEqual(madeSensitive(listed, [], changes), ['PRIVATE_KEY', 'PUBLIC_KEY', 'API_TOKEN']);
  // Its public key at its own level: a secret, nothing more to confirm than the private key.
  const { sensitivity: _, ...secretPublic } = changes.PRIVATE_KEY!.companion!;
  assert.deepEqual(madeSensitive(listed, [], { PRIVATE_KEY: { ...changes.PRIVATE_KEY!, companion: secretPublic } }), ['PRIVATE_KEY']);
});
