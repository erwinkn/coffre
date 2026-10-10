import test from 'node:test';
import assert from 'node:assert/strict';

import { accessRows } from '../src/lib/project-access.ts';
import type { GrantRow, ProjectSummary } from '../src/shared/models';

const project = (slug: string): ProjectSummary => ({
  slug,
  name: slug,
  archivedAt: null,
  folder: null,
  permissions: ['grant.manage'],
  environments: [],
  secretCount: null,
});

const grant = (id: string): GrantRow => ({
  id,
  principalType: 'service',
  principalId: 'deploy-auth',
  role: 'viewer',
  roleName: 'Viewer',
  permissions: ['secret.read'],
  scope: 'project',
  environmentSlug: null,
  expiresAt: null,
});

test("a project whose grants could not be read keeps its row on someone's Access tab, saying why", () => {
  // What a service account's Access tab once showed as no row at all, for
  // the read Postgres refused a connection to (`auth`), between two that answered.
  const rows = accessRows([
    { project: project('aristotle'), grants: [grant('token:deploy-auth/aristotle')], grantsError: null },
    { project: project('auth'), grants: [], grantsError: 'coffre is unavailable. Nothing was read or written.' },
    { project: project('deploy'), grants: [grant('token:deploy-auth/deploy/prod'), grant('token:deploy-auth/deploy')], grantsError: null },
  ]);
  assert.deepEqual(
    rows.map((row) => [row.project.slug, row.grant?.id ?? null, row.error]),
    [
      ['aristotle', 'token:deploy-auth/aristotle', null],
      ['auth', null, 'coffre is unavailable. Nothing was read or written.'],
      ['deploy', 'token:deploy-auth/deploy/prod', null],
      ['deploy', 'token:deploy-auth/deploy', null],
    ],
  );
});

test('a project read that holds no grant of theirs has no row', () => {
  assert.deepEqual(accessRows([{ project: project('market'), grants: [], grantsError: null }]), []);
});
