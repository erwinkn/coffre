import test from 'node:test';
import assert from 'node:assert/strict';

import { assignableToEnvironment, EVERYWHERE, ROLES, type Permission } from '@coffre/core/access';

import { givable } from '../src/lib/service-setup.ts';
import type { ProjectSummary } from '../src/shared/models.ts';

const roles = Object.entries(ROLES).map(([id, role]) => ({ id, permissions: [...role.permissions], assignableToEnvironment: assignableToEnvironment(id) }));

function market(prodProtected: boolean): ProjectSummary {
  const environment = (slug: string, isProtected: boolean) => ({ slug, name: slug, accessible: true, parent: null, protected: isProtected, personal: false, details: null });
  return {
    slug: 'market',
    name: 'Market',
    archivedAt: null,
    folder: null,
    permissions: ['secret.read', 'secret.use', 'secret.write'],
    environments: [environment('dev', false), environment('prod', prodProtected)],
    secretCount: null,
  };
}

/** A Developer of market: all of it in dev, and in prod too unless protected, where they only use and write. */
function developer(prodProtected: boolean) {
  const prod: Permission[] = prodProtected ? ['secret.use', 'secret.write'] : ['secret.read', 'secret.use', 'secret.write'];
  return {
    roles,
    projects: [market(prodProtected)],
    environments: [
      { project: 'market', environment: 'dev', permissions: ['secret.read', 'secret.use', 'secret.write'] as Permission[] },
      { project: 'market', environment: 'prod', permissions: prod },
    ],
    serviceSetup: EVERYWHERE,
  };
}

test('a project gives a service account only what you hold in each of its protected environments, as the server does', () => {
  const shielded = developer(true);
  assert.deepEqual(givable(shielded, shielded.projects[0]!, null), ['contributor']);
  assert.deepEqual(givable(shielded, shielded.projects[0]!, 'dev'), ['viewer', 'contributor', 'developer']);
  assert.deepEqual(givable(shielded, shielded.projects[0]!, 'prod'), ['contributor']);
  const open = developer(false);
  assert.deepEqual(givable(open, open.projects[0]!, null), ['viewer', 'contributor', 'developer']);
});

test('a role that holds nothing is offered only where you manage access, as the server gives it', () => {
  const pending = { id: 'pending', permissions: [] as Permission[], assignableToEnvironment: true };
  const holder = { ...developer(false), roles: [...roles, pending] };
  assert.ok(!givable(holder, holder.projects[0]!, 'dev').includes('pending'));
  const manager = { ...holder, projects: [{ ...holder.projects[0]!, permissions: [...holder.projects[0]!.permissions, 'grant.manage'] as Permission[] }] };
  assert.ok(givable(manager, manager.projects[0]!, null).includes('pending'));
});
