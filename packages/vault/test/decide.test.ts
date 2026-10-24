import test from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_POLICY, EVERYWHERE, type Holdings } from '@coffre/core/access';

import { keyRefusals, sensitiveRefusals, type Reader } from '../src/decide.ts';
import type { EnvironmentRow } from '../src/store.ts';

// The vault's per-key decision, which formal/lean holds to its model on
// generated cases (`pnpm formal:lean`); these are the cases it found.

const market = { projectId: 'market', environmentId: 'market-dev' };
const environments = new Map<string, EnvironmentRow>([
  ['market-dev', { projectId: 'market', slug: 'dev', owner: null, parentId: null, deleted: false, archived: false }],
]);
const holding = (role: Holdings['role']): Holdings => ({ role, scope: EVERYWHERE, grants: [], policy: DEFAULT_POLICY });
const reader = (live: Holdings): Reader => ({ status: 'active', live, all: live });

test('a key that needs any one of no permissions is refused, its own permission unchecked or not', () => {
  // Any one of none is none held. Before, `refused[0]` of none passed for no refusal, and released the key unchecked.
  const decide = (role: Holdings['role']) => keyRefusals(reader(holding(role)), {
    principal: 'user:ada@acme.example', permission: 'secret.read', secrets: [market], at: [market], environments, needs: [[]],
  });
  assert.deepEqual(decide('member'), ['no_grant']);
  assert.deepEqual(decide('owner'), ['no_grant']);
});

test('a person is never handed back a sensitive value, an Owner included, whatever else allowed it', () => {
  const owner = reader(holding('owner'));
  const read = (purpose: string, principal: string) => sensitiveRefusals([null], owner, {
    action: 'secret.read', principal, purpose, secrets: [{ projectId: 'market', sensitive: true }],
  });
  assert.deepEqual(read('reveal', 'user:ada@acme.example'), ['sensitive']);
  assert.deepEqual(read('use', 'user:ada@acme.example'), [null]);
  // A service on a credential no Owner of market issued reads none either.
  assert.deepEqual(read('reveal', 'token:ci'), ['not_owner_issued']);
});
