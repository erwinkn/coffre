import test from 'node:test';
import assert from 'node:assert/strict';

import { EVERYWHERE } from '@coffre/core/access';

import { changeRole, invite } from '../src/lib/changes.ts';
import { scopeComplete } from '../src/lib/validation.ts';

test('a scope saves once each Only or All except names something; a Member has none to fill', () => {
  assert.equal(scopeComplete({ role: 'developer', scope: EVERYWHERE }), true);
  assert.equal(scopeComplete({ role: 'developer', scope: { projects: 'all', environments: { only: ['dev'] } } }), true);
  assert.equal(scopeComplete({ role: 'developer', scope: { projects: 'all', environments: { only: [] } } }), false);
  assert.equal(scopeComplete({ role: 'admin', scope: { projects: { except: [] }, environments: 'all' } }), false);
  assert.equal(scopeComplete({ role: 'member', scope: { projects: { only: [] }, environments: 'all' } }), true);
});

test('adding or changing a role sends the scope only when it narrows anything, and a service account none', async () => {
  const sent: [string, unknown][] = [];
  const client = {
    members: {
      list: async () => ({ members: [], removed: [] }),
      add: async (member: string, input: unknown) => {
        sent.push([member, input]);
        return { member, instanceRole: 'member', scope: EVERYWHERE, created: true };
      },
    },
  } as never;
  const dev = { projects: 'all', environments: { only: ['dev'] } } as const;
  await invite(client).run({ principalType: 'user', principalId: 'ada@acme.example', role: 'developer', scope: dev });
  await invite(client).run({ principalType: 'user', principalId: 'bo@acme.example', role: 'admin', scope: EVERYWHERE });
  await invite(client).run({ principalType: 'service', principalId: 'ci', role: 'owner', scope: dev });
  await changeRole(client).run({ principalId: 'ada@acme.example', role: 'member', scope: dev });
  assert.deepEqual(sent, [
    ['user:ada@acme.example', { role: 'developer', scope: dev }],
    ['user:bo@acme.example', { role: 'admin' }],
    ['token:ci', {}],
    ['user:ada@acme.example', { role: 'member' }],
  ]);
});
