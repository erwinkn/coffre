import test from 'node:test';
import assert from 'node:assert/strict';

import { getMe } from '../src/server/queries/me.ts';
import { displayName, principalId } from '../src/shared/schemas.ts';

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
  const me = await getMe(
    {
      rootAdmins: [],
      secrets: { listAccessible: async () => [] },
      admin: { instanceRole: async () => 'user' as const },
      audit: { canRead: async () => false },
    } as never,
    { principal, requestId: 'request-id', sourceIp: null },
  );

  assert.deepEqual(me.principal, {
    type: 'user',
    id: 'person@example.com',
  });
  assert.deepEqual(Object.keys(me.principal).sort(), ['id', 'type']);
});
