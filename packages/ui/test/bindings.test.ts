import test from 'node:test';
import assert from 'node:assert/strict';

import { checkBinding } from '@coffre/core/workloads';

import { bindingOf, EMPTY_FORM, summary, type Form } from '../src/lib/bindings.ts';

const SHA = 'c'.repeat(40);
const form = (changes: Partial<Form>): Form => ({ ...EMPTY_FORM, ...changes });

test('the GitHub form fills in a workflow of the repository, or a reusable workflow at its commit', () => {
  const workflow = bindingOf(form({ repository: 'acme/api', repositoryId: '41532', ownerId: '9919', workflow: 'deploy.yml' }));
  assert.deepEqual(workflow, {
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
  checkBinding(workflow);

  const called = 'acme/deploy/.github/workflows/release.yml@refs/heads/main';
  const reusable = bindingOf(form({ reusable: true, repositoryId: '41532', ownerId: '9919', called, sha: SHA, refKind: 'tag', refName: 'v3', event: 'release' }));
  assert.equal(reusable.profile, 'github-reusable');
  assert.deepEqual([reusable.claims.ref, reusable.claims.event_name, reusable.claims.workflow_ref], ['refs/tags/v3', 'release', undefined]);
  checkBinding(reusable);
  const anywhere = bindingOf(form({ reusable: true, anyRepository: true, ownerId: '9919', called, sha: SHA }));
  assert.equal(anywhere.profile, 'github-reusable-organization');
  checkBinding(anywhere);

  assert.throws(() => bindingOf(form({ repository: 'acme/api', ownerId: '9919', workflow: 'deploy.yml' })), /The repository's ID is needed/);
  assert.throws(() => bindingOf(form({ reusable: true, repositoryId: '1', ownerId: '9919', called })), /The called workflow's commit is needed/);
});

test('the GitLab form names the namespace and the project, and the other issuer its subject and claims', () => {
  const gitlab = bindingOf(form({ platform: 'gitlab', projectId: '345', namespaceId: '12', refName: 'main' }));
  assert.deepEqual(gitlab, {
    profile: 'gitlab',
    issuer: null,
    claims: { namespace_id: '12', project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: 'push' },
  });
  checkBinding(gitlab);
  assert.equal(bindingOf(form({ platform: 'gitlab', gitlabUrl: 'https://gitlab.acme.example', projectId: '1', namespaceId: '2' })).issuer, 'https://gitlab.acme.example');

  const other = bindingOf(form({ platform: 'other', issuer: 'https://accounts.google.com', sub: '104', extra: 'email_verified=true\n\n  hd = acme.example ' }));
  assert.deepEqual(other, { profile: 'custom', issuer: 'https://accounts.google.com', claims: { sub: '104', email_verified: 'true', hd: 'acme.example' } });
  assert.throws(() => bindingOf(form({ platform: 'other', issuer: 'https://idp.acme.example', sub: 'x', extra: 'oops' })), /"oops" is not <claim>=<value>/);
});

test('a binding reads in a line: what it trusts, and at which ref', () => {
  const issuer = 'https://token.actions.githubusercontent.com';
  assert.deepEqual(
    summary({ profile: 'github', issuer, claims: bindingOf(form({ repository: 'acme/api', repositoryId: '1', ownerId: '2', workflow: 'deploy.yml' })).claims }),
    { title: 'acme/api · deploy.yml', detail: 'push at main' },
  );
  assert.deepEqual(
    summary({ profile: 'github-reusable', issuer, claims: { repository_id: '41532', ref: 'refs/heads/main', event_name: 'push', job_workflow_ref: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', job_workflow_sha: SHA } }),
    { title: 'acme/deploy · release.yml @ ccccccc', detail: 'push at main, from repository 41532' },
  );
  assert.deepEqual(
    summary({ profile: 'gitlab', issuer: 'https://gitlab.com', claims: { project_id: '345', pipeline_source: 'push', ref_type: 'tag', ref: 'v1' } }),
    { title: 'GitLab project 345', detail: 'push at tag v1' },
  );
  assert.deepEqual(summary({ profile: 'custom', issuer: 'https://accounts.google.com', claims: { sub: '104' } }), { title: 'accounts.google.com', detail: 'sub 104' });
});
