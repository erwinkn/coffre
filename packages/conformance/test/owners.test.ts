import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { OWNER_VARS } from '../src/harness.ts';

test("the harness names the vault's Owners under every name a deployment's vault reads them by, the older ones included", () => {
  // As `coffre init` writes the vault today, and as deployments written before still read it until 0.7.
  const entries = ['../../../examples/node/src/vault.ts', '../../../examples/workers/vault/src/worker.ts'].map((path) => readFileSync(new URL(path, import.meta.url), 'utf8'));
  const read = entries.flatMap((source) => [...source.matchAll(/env(?:\('|\.)([A-Z_]*OWNERS)/g)].map((match) => match[1]!));
  assert.deepEqual([...new Set(read)], ['OWNERS']);
  for (const name of [...read, 'BOOTSTRAP_OWNERS', 'ROOT_ADMINS']) {
    assert.equal(OWNER_VARS[name as keyof typeof OWNER_VARS], 'root@conformance.example', name);
  }
});
