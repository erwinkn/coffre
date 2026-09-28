import { after, test } from 'node:test';
import assert from 'node:assert/strict';

import { loadCaller } from '../src/server/api/caller.ts';
import { me } from '../src/server/api/projects.ts';
import { displayName, principalId } from '../src/shared/schemas.ts';
import { contextFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';

const db = await openTestDatabase();
after(() => db.close());

test('shared nonblank schemas reject whitespace and canonicalize valid input', () => {
  for (const schema of [displayName, principalId]) {
    assert.equal(schema.safeParse('   ').success, false);
    assert.equal(schema.parse('  visible  '), 'visible');
  }
});

test('/me projects only browser-safe principal fields', async () => {
  const principal = {
    type: 'user' as const,
    id: 'person@example.com',
    email: 'person@example.com',
    subject: 'private-provider-subject',
  };
  await resetDatabase(db.owner);
  // The verified identity, with everything its provider said, loaded as a request loads it.
  const deps = testDeps(db.runtime, [principal.id]);
  const ctx = await contextFor(deps, principal.id);
  ctx.caller = await loadCaller(db.runtime, principal, deps.rootAdmins);
  const result = await me(ctx);

  assert.deepEqual(result.principal, {
    type: 'user',
    id: 'person@example.com',
  });
  assert.deepEqual(Object.keys(result.principal).sort(), ['id', 'type']);
});
