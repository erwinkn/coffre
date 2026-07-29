import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement, Fragment } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import type { Me, Permission, ProjectSummary } from '../src/lib/api.ts';
import {
  canRevealSecrets,
  deriveUiCapabilities,
} from '../src/lib/capabilities.ts';
import {
  AdministrationNav,
  ProjectEmptyStateCopy,
  RootAdminOnly,
  SecretReadOnly,
} from '../src/components/affordances.ts';

type Persona = {
  root: boolean;
  instanceRole: Me['instanceRole'];
  projectPermissions: Permission[];
  environmentPermissions: Permission[];
  expected: {
    users: boolean;
    audit: boolean;
    newProject: boolean;
    revealSecret: boolean;
  };
};

const PERSONAS: Record<string, Persona> = {
  'root admin': {
    root: true,
    instanceRole: 'root-admin',
    projectPermissions: [],
    environmentPermissions: [
      'secret.read',
      'secret.write',
      'secret.archive',
      'audit.read',
      'environment.manage',
      'grant.manage',
      'project.manage',
    ],
    expected: { users: true, audit: true, newProject: true, revealSecret: true },
  },
  owner: {
    root: false,
    instanceRole: 'owner',
    projectPermissions: [],
    environmentPermissions: [],
    expected: { users: true, audit: true, newProject: true, revealSecret: false },
  },
  auditor: {
    root: false,
    instanceRole: 'user',
    projectPermissions: [],
    // Audit roles may be scoped to one environment, so /v1/me projects that
    // authority into canReadAudit even when no project-level permission exists.
    environmentPermissions: ['audit.read'],
    expected: { users: false, audit: true, newProject: false, revealSecret: false },
  },
  'access manager': {
    root: false,
    instanceRole: 'user',
    projectPermissions: ['grant.manage'],
    environmentPermissions: [],
    expected: { users: false, audit: false, newProject: false, revealSecret: false },
  },
  developer: {
    root: false,
    instanceRole: 'user',
    projectPermissions: [],
    environmentPermissions: ['secret.read', 'secret.write', 'secret.archive'],
    expected: { users: false, audit: false, newProject: false, revealSecret: true },
  },
  outsider: {
    root: false,
    instanceRole: 'user',
    projectPermissions: [],
    environmentPermissions: [],
    expected: { users: false, audit: false, newProject: false, revealSecret: false },
  },
};

for (const [name, persona] of Object.entries(PERSONAS)) {
  test(`${name} sees only permitted navigation and actions`, () => {
    const me: Me = {
      principal: { type: 'user', id: `${name.replaceAll(' ', '-')}@example.test` },
      instanceRole: persona.instanceRole,
      isRootAdmin: persona.root,
      canReadAudit:
        persona.instanceRole === 'owner' ||
        persona.root ||
        persona.projectPermissions.includes('audit.read') ||
        persona.environmentPermissions.includes('audit.read'),
      environments:
        persona.environmentPermissions.length === 0
          ? []
          : [
              {
                project: 'market',
                environment: 'prod',
                permissions: persona.environmentPermissions,
              },
            ],
    };
    const projects: ProjectSummary[] =
      persona.projectPermissions.length === 0 && name === 'outsider'
        ? []
        : [
            {
              slug: 'market',
              name: 'Market',
              archivedAt: null,
              permissions: persona.projectPermissions,
              environments: [],
            },
          ];

    const capabilities = deriveUiCapabilities(me, projects);
    const affordances = renderToStaticMarkup(
      createElement(
        Fragment,
        null,
        createElement(AdministrationNav, {
          capabilities,
          users: createElement('a', { href: '/access' }, 'Users'),
          audit: createElement('a', { href: '/audit' }, 'Audit log'),
        }),
        createElement(
          RootAdminOnly,
          { capabilities },
          createElement('button', null, 'New project'),
        ),
        createElement(
          SecretReadOnly,
          { canReveal: canRevealSecrets(persona.environmentPermissions) },
          createElement('button', null, 'Reveal secret'),
        ),
      ),
    );

    assert.deepEqual(
      {
        users: affordances.includes('Users'),
        audit: affordances.includes('Audit log'),
        newProject: affordances.includes('New project'),
        revealSecret: affordances.includes('Reveal secret'),
      },
      persona.expected,
    );
  });
}

test('a signed-out shell exposes no privileged affordances', () => {
  assert.deepEqual(deriveUiCapabilities(null, []), {
    canManageGrants: false,
    canReadAudit: false,
    canCreateProject: false,
  });
});

test('root project empty states distinguish empty from archived-only instances', () => {
  const capabilities = {
    canManageGrants: true,
    canReadAudit: true,
    canCreateProject: true,
  };
  const empty = renderToStaticMarkup(
    createElement(ProjectEmptyStateCopy, {
      capabilities,
      hasArchivedProjects: false,
    }),
  );
  const archivedOnly = renderToStaticMarkup(
    createElement(ProjectEmptyStateCopy, {
      capabilities,
      hasArchivedProjects: true,
    }),
  );

  assert.equal(empty, 'No projects exist yet. Create the first one below.');
  assert.equal(
    archivedOnly,
    'No active projects. Create another below or restore one from Archived.',
  );
});

test('non-root archived-only project states point to the visible archived list', () => {
  const capabilities = {
    canManageGrants: true,
    canReadAudit: false,
    canCreateProject: false,
  };
  const archivedOnly = renderToStaticMarkup(
    createElement(ProjectEmptyStateCopy, {
      capabilities,
      hasArchivedProjects: true,
    }),
  );

  assert.equal(
    archivedOnly,
    'No active projects. Your archived projects appear below.',
  );
});
