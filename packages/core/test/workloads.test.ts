import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalClaims,
  checkBinding,
  checkFetchUrl,
  differingClaims,
  githubEventsAt,
  GITHUB_ISSUER,
  GITLAB_ISSUER,
  MAX_CLAIMS,
  type BindingClaims,
} from '@coffre/core/identity';

const SHA = 'a'.repeat(40);

/** `deploy.yml`, pushed to `main` of `acme/api`. */
const GITHUB: BindingClaims = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};

/** `acme/deploy`'s release workflow at one commit, called from `main` of `acme/api`. */
const REUSABLE: BindingClaims = {
  repository_owner_id: '9919',
  repository_id: '41532',
  ref: 'refs/heads/main',
  event_name: 'push',
  job_workflow_ref: 'acme/deploy/.github/workflows/release.yml@refs/heads/main',
  job_workflow_sha: SHA,
};

const GITLAB: BindingClaims = { namespace_id: '12', project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: 'push' };

const refused = (input: Parameters<typeof checkBinding>[0], pattern: RegExp) => assert.throws(() => checkBinding(input), pattern);

test('a GitHub binding names the repository by ID, the workflow, the ref and a trusted event, and is stored sorted', () => {
  const checked = checkBinding({ profile: 'github', issuer: null, claims: { ...GITHUB } });
  assert.equal(checked.issuer, GITHUB_ISSUER);
  assert.deepEqual(Object.keys(checked.claims), ['event_name', 'ref', 'repository_id', 'repository_owner_id', 'workflow_ref']);
  assert.equal(canonicalClaims(GITHUB), canonicalClaims(checked.claims));

  for (const missing of Object.keys(GITHUB)) {
    const { [missing]: _, ...rest } = GITHUB;
    refused({ profile: 'github', issuer: null, claims: rest }, new RegExp(`requires ${missing}`));
  }
  // A name is not an ID: names can be registered again by someone else.
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, repository_id: 'acme/api' } }, /numeric ID/);
  // The workflow file at the binding's ref.
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/dev' } }, /at the binding's ref/);
});

test('GitHub events: those a writer starts, and pull_request and workflow_run when chosen; the ref fits each event', () => {
  for (const event of ['pull_request_target', 'issue_comment', 'dynamic']) {
    refused({ profile: 'github', issuer: null, claims: { ...GITHUB, event_name: event } }, /event_name must be one or more of push, workflow_dispatch, schedule, release, pull_request, workflow_run/);
    refused({ profile: 'github', issuer: null, claims: { ...GITHUB, event_name: ['push', event] } }, /event_name must be one or more of/);
  }
  for (const event of ['push', 'workflow_dispatch', 'schedule', 'pull_request', 'workflow_run']) {
    checkBinding({ profile: 'github', issuer: null, claims: { ...GITHUB, event_name: event } });
  }
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, event_name: [] } }, /one or more/);
  // A release runs at its tag, and a tag `main` is not the branch.
  const tag = { ...GITHUB, event_name: 'release', ref: 'refs/tags/v1.2.0', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/tags/v1.2.0' };
  checkBinding({ profile: 'github', issuer: null, claims: tag });
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, event_name: 'release' } }, /a release runs at its tag/);
  refused({ profile: 'github', issuer: null, claims: { ...tag, event_name: 'schedule' } }, /default branch/);
  // A pull request is matched by the branch it merges into; a workflow_run runs on the default branch.
  refused({ profile: 'github', issuer: null, claims: { ...tag, event_name: ['push', 'pull_request'] } }, /the branch it merges into/);
  refused({ profile: 'github', issuer: null, claims: { ...tag, event_name: 'workflow_run' } }, /default branch/);
  checkBinding({ profile: 'github', issuer: null, claims: { ...tag, event_name: ['push', 'release'] } });
  assert.deepEqual(githubEventsAt('tag'), ['push', 'workflow_dispatch', 'release']);
  assert.deepEqual(githubEventsAt('branch'), ['push', 'workflow_dispatch', 'schedule', 'pull_request', 'workflow_run']);
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, ref: 'main' } }, /ref is a full ref/);
});

test('a binding names several events, stored once each in GitHub\'s order, a single one as a plain value; no other claim lists', () => {
  const checked = checkBinding({ profile: 'github', issuer: null, claims: { ...GITHUB, event_name: ['pull_request', 'push', 'workflow_dispatch', 'push'] } });
  assert.deepEqual(checked.claims.event_name, ['push', 'workflow_dispatch', 'pull_request']);
  assert.equal(checkBinding({ profile: 'github', issuer: null, claims: { ...GITHUB, event_name: ['push'] } }).claims.event_name, 'push');
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, ref: ['refs/heads/main', 'refs/heads/dev'] } }, /claim ref must be a nonempty string: only event_name lists several/);
  assert.deepEqual(checkBinding({ profile: 'gitlab', issuer: null, claims: { ...GITLAB, pipeline_source: ['web', 'push'] } }).claims.pipeline_source, ['push', 'web']);
  refused({ profile: 'gitlab', issuer: null, claims: { ...GITLAB, pipeline_source: ['push', 'merge_request_event'] } }, /pipeline_source must be one or more of push, web, schedule/);
});

test('a token matches when it carries every claim, one of a list; a pull request at the branch it merges into', () => {
  const binding = checkBinding({ profile: 'github', issuer: null, claims: { ...GITHUB, workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main', event_name: ['push', 'pull_request'] } });
  const push = {
    repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main',
    ref: 'refs/heads/main', base_ref: '', event_name: 'push', sub: 'repo:acme/api:ref:refs/heads/main',
  };
  const pr = { ...push, event_name: 'pull_request', ref: 'refs/pull/12/merge', base_ref: 'main', head_ref: 'feature', workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/pull/12/merge' };
  const match = (token: Record<string, unknown>, claims: BindingClaims = binding.claims) => differingClaims('github', claims, token);
  assert.deepEqual(match(push), []);
  assert.deepEqual(match(pr), []);
  // Merged, its run is at the branch it went into.
  assert.deepEqual(match({ ...pr, ref: 'refs/heads/main', workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main' }), []);
  // Into another branch, or another workflow file.
  assert.deepEqual(match({ ...pr, base_ref: 'dev' }), ['ref', 'workflow_ref']);
  assert.deepEqual(match({ ...pr, workflow_ref: 'acme/api/.github/workflows/other.yml@refs/pull/12/merge' }), ['workflow_ref']);
  // A push to another branch is no pull request; an event not listed, at the same ref, is refused.
  assert.deepEqual(match({ ...push, ref: 'refs/heads/dev', workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/dev' }), ['ref', 'workflow_ref']);
  assert.deepEqual(match({ ...push, event_name: 'pull_request_target' }), ['event_name']);
  // A binding made before, for push alone, takes no pull request, whatever its base.
  assert.deepEqual(match(pr, { ...binding.claims, event_name: 'push' }), ['event_name']);
  // Only GitHub's profiles read a pull request at its base, and a claim that is no string never matches.
  assert.deepEqual(differingClaims('custom', { ref: 'refs/heads/main' }, pr), ['ref']);
  assert.deepEqual(match({ ...push, repository_id: 41532 }), ['repository_id']);
});

test('a reusable workflow is pinned to one commit and called from one ref; the whole organization is an explicit profile', () => {
  checkBinding({ profile: 'github-reusable', issuer: null, claims: { ...REUSABLE } });
  // The caller's ref is required: a feature branch's own caller cannot borrow production's binding (review R3).
  const { ref: _, ...noRef } = REUSABLE;
  refused({ profile: 'github-reusable', issuer: null, claims: noRef }, /requires ref/);
  const { job_workflow_sha: __, ...noSha } = REUSABLE;
  refused({ profile: 'github-reusable', issuer: null, claims: noSha }, /requires job_workflow_sha/);
  refused({ profile: 'github-reusable', issuer: null, claims: { ...REUSABLE, job_workflow_sha: 'main' } }, /full commit SHA/);
  // Without the repository, only as the explicit organization-wide profile.
  const { repository_id: ___, ...anyRepository } = REUSABLE;
  refused({ profile: 'github-reusable', issuer: null, claims: anyRepository }, /requires repository_id/);
  checkBinding({ profile: 'github-reusable-organization', issuer: null, claims: anyRepository });
  refused({ profile: 'github-reusable-organization', issuer: null, claims: { ...REUSABLE } }, /names no repository_id/);
  // `workflow_ref` may narrow it to one caller.
  checkBinding({ profile: 'github-reusable', issuer: null, claims: { ...REUSABLE, workflow_ref: 'acme/api/.github/workflows/ship.yml@refs/heads/main' } });
});

test('a GitLab binding names the namespace and the project by ID, the ref and its type, and a pipeline that is no merge request', () => {
  const checked = checkBinding({ profile: 'gitlab', issuer: null, claims: { ...GITLAB } });
  assert.equal(checked.issuer, GITLAB_ISSUER);
  // A transferred project keeps its ID: the namespace is required too (review R4).
  const { namespace_id: _, ...noNamespace } = GITLAB;
  refused({ profile: 'gitlab', issuer: null, claims: noNamespace }, /requires namespace_id/);
  refused({ profile: 'gitlab', issuer: null, claims: { ...GITLAB, pipeline_source: 'merge_request_event' } }, /pipeline_source must be one or more of push, web, schedule/);
  refused({ profile: 'gitlab', issuer: null, claims: { ...GITLAB, ref_type: 'commit' } }, /ref_type is branch or tag/);
  refused({ profile: 'gitlab', issuer: null, claims: { ...GITLAB, ref: 'refs/heads/main' } }, /without refs\//);
  refused({ profile: 'gitlab', issuer: null, claims: { ...GITLAB, project_id: 'acme/api' } }, /numeric ID/);
  // A self-managed GitLab names its own issuer, and still gets the profile's minimum.
  checkBinding({ profile: 'gitlab', issuer: 'https://gitlab.acme.example', claims: { ...GITLAB } });
});

test('a known issuer forces its profile; any other issuer is custom, by its subject, or a profile it chooses', () => {
  refused({ profile: 'custom', issuer: GITHUB_ISSUER, claims: { sub: 'repo:acme/api:ref:refs/heads/main' } }, /signs only for the github profiles/);
  refused({ profile: 'github', issuer: GITLAB_ISSUER, claims: { ...GITHUB } }, /signs only for the gitlab profile/);
  refused({ profile: 'custom', issuer: null, claims: { sub: 'x' } }, /names its issuer/);
  refused({ profile: 'custom', issuer: 'https://accounts.google.com', claims: { email: 'deploy@acme.iam.gserviceaccount.com' } }, /requires sub/);
  checkBinding({ profile: 'custom', issuer: 'https://accounts.google.com', claims: { sub: '104000000000000000000' } });
  // A GitHub Enterprise Server is checked as GitHub.
  refused({ profile: 'github', issuer: 'https://github.acme.example/_services/token', claims: { ...GITHUB, event_name: 'pull_request_target' } }, /event_name/);
  refused({ profile: 'nope', issuer: null, claims: {} }, /unknown profile "nope"/);
});

test('claims are bounded strings with names a binding may match, and never the exchange\'s own', () => {
  const many = Object.fromEntries(Array.from({ length: MAX_CLAIMS }, (_, i) => [`c${i}`, 'x']));
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { ...many, sub: 'x' } }, /at most 16 claims/);
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: 'é'.repeat(129) } }, /longer than 256 bytes/);
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: '' } }, /nonempty string/);
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: 'x', groups: ['a'] as unknown as string } }, /nonempty string/);
  for (const name of ['aud', 'iss', 'exp', 'iat', 'nbf', 'jti']) {
    refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: 'x', [name]: 'y' } }, /never names/);
  }
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: 'x', 'kubernetes.io serviceaccount': 'y' } }, /not a claim name/);
});

test('a URL coffre fetches is https on 443 at a public host name, with no credentials, and loopback only for a deployment that says so', () => {
  const at = (url: string, options: { allowLoopback?: boolean; path?: boolean; query?: boolean } = {}) =>
    checkFetchUrl(url, 'the issuer', { path: true, query: false, ...options });
  at('https://token.actions.githubusercontent.com');
  at('https://login.microsoftonline.com/0000/v2.0');
  for (const [url, why] of [
    ['http://token.actions.githubusercontent.com', /must use https/],
    ['https://token.actions.githubusercontent.com:8443', /port 443/],
    ['https://user:pw@idp.acme.example', /no user or password/],
    ['https://idp.acme.example?x=1', /no query or fragment/],
    ['https://idp.acme.example#x', /no query or fragment/],
    ['https://10.0.0.1', /not an IP address/],
    ['https://[fd00::1]', /not an IP address/],
    ['https://169.254.169.254', /not an IP address/],
    ['https://localhost', /public host name/],
    ['https://metadata', /public host name/],
    ['https://idp.internal', /public host name/],
    ['https://printer.local', /public host name/],
    ['https://IdP.Acme.Example', /plain URL/],
    ['not a url', /not a URL/],
  ] as const) {
    assert.throws(() => at(url), why, url);
  }
  assert.throws(() => at('http://127.0.0.1:8081'), /must use https/);
  at('http://127.0.0.1:8081', { allowLoopback: true });
  assert.throws(() => at('http://10.0.0.1:8081', { allowLoopback: true }), /must use https/);
  // A key set's URL may carry a query.
  at('https://idp.acme.example/keys?v=2', { query: true });
});
