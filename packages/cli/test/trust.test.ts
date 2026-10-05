import test from 'node:test';
import assert from 'node:assert/strict';

import { checkBinding } from '@coffre/core/workloads';

import { bindingFrom, describeBindings, describePlan, type Lookup, runsOf, serviceMember, type TrustFlags } from '../src/trust.ts';

const SHA = 'b'.repeat(40);

/** What the server's lookup would find: public repositories and projects, by name. */
const lookup: Lookup = async (input) => {
  if (input.github === 'acme/api') return { github: 'acme/api', repositoryId: '41532', ownerId: '9919' };
  if (input.gitlab === 'acme/api' && input.gitlabUrl === undefined) return { gitlab: 'acme/api', projectId: '345', namespaceId: '12' };
  throw new Error('not found: a private one\'s IDs are typed in');
};

/** Each binding the flags build is one the server accepts. */
async function built(flags: TrustFlags) {
  const binding = await bindingFrom(flags, lookup);
  checkBinding(binding);
  return binding;
}

test('a workflow of the repository, on a branch, a tag or a release, with its IDs looked up', async () => {
  assert.deepEqual(await built({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main' }), {
    profile: 'github',
    issuer: null,
    claims: {
      repository_owner_id: '9919',
      repository_id: '41532',
      workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
      ref: 'refs/heads/main',
      event_name: 'push',
    },
  });
  const release = await built({ github: 'acme/api', workflow: '.github/workflows/ship.yml', tag: 'v2.0.0', event: 'release' });
  assert.deepEqual([release.claims.ref, release.claims.workflow_ref, release.claims.event_name], [
    'refs/tags/v2.0.0', 'acme/api/.github/workflows/ship.yml@refs/tags/v2.0.0', 'release',
  ]);
  // A private repository: its IDs are given, and nothing is looked up.
  const given = await built({ github: 'acme/secret', workflow: 'deploy.yml', branch: 'main', 'repository-id': '7', 'owner-id': '9919' });
  assert.equal(given.claims.repository_id, '7');
  await assert.rejects(bindingFrom({ github: 'acme/secret', workflow: 'deploy.yml', branch: 'main' }, lookup), /gh api repos\/acme\/secret/);
});

test('a reusable workflow is pinned to its commit and its caller\'s ref; the whole organization only by its ID', async () => {
  const reusable = await built({ github: 'acme/api', reusable: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA, branch: 'main' });
  assert.equal(reusable.profile, 'github-reusable');
  assert.deepEqual(reusable.claims, {
    repository_owner_id: '9919',
    repository_id: '41532',
    ref: 'refs/heads/main',
    event_name: 'push',
    job_workflow_ref: 'acme/deploy/.github/workflows/release.yml@refs/heads/main',
    job_workflow_sha: SHA,
  });
  const caller = await built({ github: 'acme/api', reusable: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA, branch: 'main', workflow: 'ship.yml' });
  assert.equal(caller.claims.workflow_ref, 'acme/api/.github/workflows/ship.yml@refs/heads/main');
  const organization = await built({ github: 'acme', reusable: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA, branch: 'main', 'any-repository': true, 'owner-id': '9919' });
  assert.equal(organization.profile, 'github-reusable-organization');
  assert.equal(organization.claims.repository_id, undefined);
  await assert.rejects(bindingFrom({ github: 'acme/api', reusable: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', branch: 'main' }, lookup), /--sha <commit>/);
  await assert.rejects(bindingFrom({ github: 'acme', reusable: 'x', sha: SHA, branch: 'main', 'any-repository': true }, lookup), /--owner-id/);
});

test('a GitLab project, by its namespace and project IDs, a branch or a tag, and its pipeline source', async () => {
  assert.deepEqual(await built({ gitlab: 'acme/api', branch: 'main' }), {
    profile: 'gitlab',
    issuer: null,
    claims: { namespace_id: '12', project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: 'push' },
  });
  const tag = await built({ gitlab: 'acme/api', tag: 'v1', source: 'web' });
  assert.deepEqual([tag.claims.ref_type, tag.claims.ref, tag.claims.pipeline_source], ['tag', 'v1', 'web']);
  const selfManaged = await built({ gitlab: 'acme/api', branch: 'main', 'gitlab-url': 'https://gitlab.acme.example', 'project-id': '5', 'namespace-id': '6' });
  assert.equal(selfManaged.issuer, 'https://gitlab.acme.example');
  await assert.rejects(bindingFrom({ gitlab: 'acme/private', branch: 'main' }, lookup), /glab api projects\/acme%2Fprivate/);
});

test('any other issuer, by its claims', async () => {
  assert.deepEqual(await built({ issuer: 'https://accounts.google.com', claim: ['sub=104000000000000000000'] }), {
    profile: 'custom',
    issuer: 'https://accounts.google.com',
    claims: { sub: '104000000000000000000' },
  });
  await assert.rejects(bindingFrom({ issuer: 'https://idp.acme.example', claim: ['sub'] }, lookup), /--claim takes <name>=<value>/);
});

test('the flags name one platform, and one of a branch or a tag', async () => {
  await assert.rejects(bindingFrom({}, lookup), /name one of --github, --gitlab or --issuer/);
  await assert.rejects(bindingFrom({ github: 'acme/api', gitlab: 'acme/api' }, lookup), /name one of --github, --gitlab or --issuer/);
  await assert.rejects(bindingFrom({ github: 'acme/api', workflow: 'deploy.yml' }, lookup), /name one of --branch or --tag/);
  await assert.rejects(bindingFrom({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main', tag: 'v1' }, lookup), /name one of --branch or --tag/);
  await assert.rejects(bindingFrom({ github: 'acme/api', branch: 'main' }, lookup), /--workflow deploy.yml/);
  assert.equal(serviceMember('api-deploy'), 'token:api-deploy');
  assert.equal(serviceMember('token:api-deploy'), 'token:api-deploy');
});

test('a plan and a list show every claim in full', () => {
  const plan = {
    profile: 'github' as const,
    issuer: 'https://token.actions.githubusercontent.com',
    jwksUri: 'https://token.actions.githubusercontent.com/.well-known/jwks',
    claims: { event_name: 'push', ref: 'refs/heads/main' },
    replaces: [{ id: 'old', why: 'keys_moved' as const }],
  };
  assert.equal(
    describePlan('token:api-deploy', plan, null),
    [
      'Would trust CI runs to sign in as token:api-deploy:',
      '  profile  github',
      '  issuer   https://token.actions.githubusercontent.com',
      '  keys     https://token.actions.githubusercontent.com/.well-known/jwks',
      '  claims   event_name  push',
      '           ref         refs/heads/main',
      '  replaces old: the issuer moved its keys',
      'Run it again with --apply to save it.',
      '',
    ].join('\n'),
  );
  assert.equal(describeBindings('token:api-deploy', []), 'token:api-deploy trusts no CI runs\n');
  const listed = describeBindings('token:api-deploy', [
    { ...plan, id: 'b1', label: 'prod', createdAt: '2026-10-03T22:00:00.000Z', createdBy: 'lead@acme.example', lastUsedAt: null },
  ]);
  assert.match(listed, /^b1  prod  \(added by lead@acme.example 2026-10-03, never used\)\n  profile  github\n/);
});

test('a binding says, in a sentence, which CI runs it lets sign in: platform, repository or project, workflow, ref', () => {
  const SHA = 'a'.repeat(40);
  assert.equal(
    runsOf({ profile: 'github', issuer: 'https://token.actions.githubusercontent.com', claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' } }),
    "GitHub Actions runs of acme/api's workflow deploy.yml, on branch main, by push",
  );
  assert.equal(
    runsOf({ profile: 'github-reusable', issuer: 'https://token.actions.githubusercontent.com', claims: { repository_owner_id: '9919', repository_id: '41532', ref: 'refs/tags/v2', event_name: 'release', job_workflow_ref: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', job_workflow_sha: SHA } }),
    'GitHub Actions runs of repository 41532 that call the reusable workflow acme/deploy/.github/workflows/release.yml@refs/heads/main at commit aaaaaaaaaaaa, on tag v2, by release',
  );
  assert.match(
    runsOf({ profile: 'github-reusable-organization', issuer: 'https://token.actions.githubusercontent.com', claims: { repository_owner_id: '9919', ref: 'refs/heads/main', job_workflow_ref: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', job_workflow_sha: SHA } }),
    /^GitHub Actions runs of any repository of owner 9919 that call the reusable workflow/,
  );
  assert.equal(
    runsOf({ profile: 'gitlab', issuer: 'https://gitlab.com', claims: { namespace_id: '12', project_id: '345', ref_type: 'tag', ref: 'v1', pipeline_source: 'web' } }),
    'GitLab pipelines of project 345 (namespace 12), on tag v1, by web',
  );
  assert.equal(
    runsOf({ profile: 'gitlab', issuer: 'https://gitlab.acme.example', claims: { namespace_id: '6', project_id: '5', ref_type: 'branch', ref: 'main', pipeline_source: 'push' } }),
    'GitLab pipelines of project 5 (namespace 6) on https://gitlab.acme.example, on branch main, by push',
  );
  assert.equal(
    runsOf({ profile: 'custom', issuer: 'https://accounts.google.com', claims: { sub: '1040' } }),
    'runs whose ID token, from https://accounts.google.com, says sub=1040',
  );
});
