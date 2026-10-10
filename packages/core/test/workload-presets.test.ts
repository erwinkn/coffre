import test from 'node:test';
import assert from 'node:assert/strict';

import {
  BindingInvalid,
  checkBinding,
  differingClaims,
  githubReusable,
  githubWorkflow,
  gitlabProject,
} from '@coffre/core/workloads';

const SHA = 'b'.repeat(40);

// The calls 0.4.6 documented: one `event`, one `source`. Their claims are what
// 8c333fb made of them, a plain string, so a binding stored then and one made
// now are the same.
const workflow = { repository: 'acme/api', repositoryId: '41532', ownerId: '9919', workflow: 'deploy.yml', ref: 'refs/heads/main' };
const reusable = { repositoryId: '41532', ownerId: '9919', ref: 'refs/heads/main', called: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA };
const project = { namespaceId: '12', projectId: '345', refType: 'branch' as const, ref: 'main' };

test('0.4.6 call shapes: one event or source makes the claims it made, and a binding that checks', () => {
  const github = githubWorkflow({ ...workflow, event: 'push' });
  assert.deepEqual(github, {
    profile: 'github',
    claims: {
      repository_owner_id: '9919',
      repository_id: '41532',
      workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
      ref: 'refs/heads/main',
      event_name: 'push',
    },
  });
  assert.equal(checkBinding({ ...github, issuer: null }).claims.event_name, 'push');

  const called = githubReusable({ ...reusable, event: 'push' });
  assert.equal(called.profile, 'github-reusable');
  assert.equal(called.claims.event_name, 'push');
  assert.equal(checkBinding({ ...called, issuer: null }).claims.event_name, 'push');
  const organization = githubReusable({ ...reusable, repositoryId: null, event: 'workflow_dispatch' });
  assert.equal(organization.profile, 'github-reusable-organization');
  assert.equal(checkBinding({ ...organization, issuer: null }).claims.event_name, 'workflow_dispatch');

  const gitlab = gitlabProject({ ...project, source: 'push' });
  assert.deepEqual(gitlab.claims, { namespace_id: '12', project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: 'push' });
  assert.equal(checkBinding({ ...gitlab, issuer: null }).claims.pipeline_source, 'push');
});

test('0.4.6 call shapes: the binding they make matches the same tokens, and refuses the same ones', () => {
  const token = {
    repository_owner_id: '9919', repository_id: '41532', ref: 'refs/heads/main', base_ref: '', event_name: 'push',
    workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  };
  const old = checkBinding({ ...githubWorkflow({ ...workflow, event: 'push' }), issuer: null });
  const now = checkBinding({ ...githubWorkflow({ ...workflow, events: ['push'] }), issuer: null });
  assert.deepEqual(old, now);
  assert.deepEqual(differingClaims('github', old.claims, token), []);
  assert.deepEqual(differingClaims('github', old.claims, { ...token, event_name: 'workflow_dispatch' }), ['event_name']);
  assert.deepEqual(differingClaims('github', old.claims, { ...token, event_name: 'pull_request', ref: 'refs/pull/3/merge', base_ref: 'main', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/pull/3/merge' }), ['event_name']);

  const gitlab = checkBinding({ ...gitlabProject({ ...project, source: 'push' }), issuer: null });
  const gitlabToken = { namespace_id: '12', project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: 'push' };
  assert.deepEqual(differingClaims('gitlab', gitlab.claims, gitlabToken), []);
  assert.deepEqual(differingClaims('gitlab', gitlab.claims, { ...gitlabToken, pipeline_source: 'web' }), ['pipeline_source']);

  // Refusals are 0.4.6's too: an event it refused, and a release at a branch.
  assert.throws(() => checkBinding({ ...githubWorkflow({ ...workflow, event: 'pull_request_target' }), issuer: null }), BindingInvalid);
  assert.throws(() => checkBinding({ ...gitlabProject({ ...project, source: 'merge_request_event' }), issuer: null }), BindingInvalid);
  assert.throws(() => checkBinding({ ...githubWorkflow({ ...workflow, event: 'release' }), issuer: null }), /a release runs at its tag/);
});

test('the lists make one binding for several events', () => {
  const github = githubWorkflow({ ...workflow, events: ['pull_request', 'push'] });
  assert.deepEqual(checkBinding({ ...github, issuer: null }).claims.event_name, ['push', 'pull_request']);
  assert.deepEqual(githubReusable({ ...reusable, events: ['push', 'schedule'] }).claims.event_name, ['push', 'schedule']);
  assert.deepEqual(gitlabProject({ ...project, sources: ['web', 'push'] }).claims.pipeline_source, ['web', 'push']);
});

test('naming both the single value and the list, or neither, is refused, and the types say so', () => {
  const refuses = (call: () => unknown, pattern: RegExp) => assert.throws(call, (error) => error instanceof BindingInvalid && pattern.test(error.message));
  // @ts-expect-error both
  refuses(() => githubWorkflow({ ...workflow, event: 'push', events: ['push'] }), /event or events, not both/);
  // @ts-expect-error both
  refuses(() => githubReusable({ ...reusable, event: 'push', events: ['push'] }), /event or events, not both/);
  // @ts-expect-error both
  refuses(() => gitlabProject({ ...project, source: 'push', sources: ['push'] }), /source or sources, not both/);
  // @ts-expect-error neither
  refuses(() => githubWorkflow({ ...workflow }), /event or events/);
  // @ts-expect-error neither
  refuses(() => gitlabProject({ ...project }), /source or sources/);
});
