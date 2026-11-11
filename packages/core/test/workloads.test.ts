import test from 'node:test';
import assert from 'node:assert/strict';

import {
  BindingInvalid,
  canonicalClaims,
  checkBinding,
  checkFetchUrl,
  checkRecord,
  claimAt,
  customExposure,
  differingClaims,
  githubEventsAt,
  githubReusable,
  githubWorkflow,
  GITHUB_ISSUER,
  GITLAB_ISSUER,
  MAX_ISSUER_BYTES,
  recordedNames,
  recordText,
  runClaims,
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
  // Only the ref at its end is read at the base, even an empty one: slice(0, -0) would have left nothing of the file.
  assert.deepEqual(differingClaims('github', { workflow_ref: 'refs/heads/main' }, { ...pr, ref: '', workflow_ref: 'acme/api/.github/workflows/ci.yml@' }), ['workflow_ref']);
});

test('a GitHub binding may name the environment its job runs in, matched whatever its case, whatever sub says', () => {
  const binding = checkBinding({ profile: 'github', issuer: null, claims: { ...GITHUB, environment: 'production' } });
  assert.equal(binding.claims.environment, 'production');
  // A job in an environment: GitHub names it in sub, which no GitHub binding reads; ref and workflow_ref are the same.
  const job = {
    repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
    ref: 'refs/heads/main', event_name: 'push', environment: 'production', sub: 'repo:acme/api:environment:production',
  };
  assert.deepEqual(differingClaims('github', binding.claims, job), []);
  // GitHub's environment names are case-insensitive: one environment, one set of protection rules.
  assert.deepEqual(differingClaims('github', binding.claims, { ...job, environment: 'Production' }), []);
  assert.deepEqual(differingClaims('github', binding.claims, { ...job, environment: 'staging', sub: 'repo:acme/api:environment:staging' }), ['environment']);
  // A job in no environment carries no claim, and is refused.
  const { environment: _, ...outside } = job;
  assert.deepEqual(differingClaims('github', binding.claims, { ...outside, sub: 'repo:acme/api:ref:refs/heads/main' }), ['environment']);
  // A binding without one takes the job either way, as before.
  assert.deepEqual(differingClaims('github', GITHUB, job), []);
  assert.deepEqual(differingClaims('github', GITHUB, outside), []);
  // A pull request's job in the environment, at the branch it merges into.
  const pr = { ...job, event_name: 'pull_request', ref: 'refs/pull/7/merge', base_ref: 'main', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/pull/7/merge' };
  assert.deepEqual(differingClaims('github', { ...binding.claims, event_name: ['push', 'pull_request'] }, pr), []);
  // Exact elsewhere: a custom binding's environment is the issuer's own claim.
  assert.deepEqual(differingClaims('custom', { environment: 'production' }, { environment: 'Production' }), ['environment']);

  // A reusable workflow's job names it too, its caller's ref and the called workflow unchanged.
  const reusable = checkBinding({ profile: 'github-reusable', issuer: null, claims: { ...REUSABLE, environment: 'prod/eu' } });
  assert.deepEqual(differingClaims('github-reusable', reusable.claims, { ...REUSABLE, environment: 'prod/eu', sub: 'repo:acme/api:environment:prod/eu' }), []);
  assert.deepEqual(differingClaims('github-reusable', reusable.claims, REUSABLE), ['environment']);

  for (const name of ['Staging EU', 'prod/eu:1', 'é'.repeat(100), 'x'.repeat(255)]) checkBinding({ profile: 'github', issuer: null, claims: { ...GITHUB, environment: name } });
  for (const name of [' production', 'production ', 'prod\nuction', 'x'.repeat(256)]) {
    refused({ profile: 'github', issuer: null, claims: { ...GITHUB, environment: name } }, /GitHub environment's name|longer than 256 bytes/);
  }
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, environment: '' } }, /nonempty string/);
  refused({ profile: 'github', issuer: null, claims: { ...GITHUB, environment: ['production', 'staging'] } }, /only event_name lists several/);
});

test('the presets name an environment only when given one', () => {
  const at = { repository: 'acme/api', repositoryId: '41532', ownerId: '9919', workflow: 'deploy.yml', ref: 'refs/heads/main', events: ['push'] };
  assert.equal(githubWorkflow(at).claims.environment, undefined);
  assert.equal(githubWorkflow({ ...at, environment: 'production' }).claims.environment, 'production');
  const called = { repositoryId: null, ownerId: '9919', ref: 'refs/heads/main', called: REUSABLE.job_workflow_ref as string, sha: SHA, events: ['push'] };
  assert.equal(githubReusable(called).claims.environment, undefined);
  const reusable = githubReusable({ ...called, environment: 'production' });
  assert.deepEqual({ profile: reusable.profile, environment: reusable.claims.environment }, { profile: 'github-reusable-organization', environment: 'production' });
  checkBinding({ ...reusable, issuer: null });
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
  checkBinding({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: '104000000000000000000' } });
  // A GitHub Enterprise Server is checked as GitHub.
  refused({ profile: 'github', issuer: 'https://github.acme.example/_services/token', claims: { ...GITHUB, event_name: 'pull_request_target' } }, /event_name/);
  refused({ profile: 'nope', issuer: null, claims: {} }, /unknown profile "nope"/);
});

test('claims are nonempty strings with names a binding may match, and never the exchange\'s own, as many and as long as the body holds', () => {
  // No count or length of their own (R70): the body's bounds hold them (`API_BODY_BYTES`, `MAX_BODY_NODES`).
  const many = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`c${i}`, 'é'.repeat(1000)]));
  assert.equal(Object.keys(checkBinding({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { ...many, sub: 'x' } }).claims).length, 201);
  // The issuer is held to what fits in its index entry beside its service, the one bound left that is storage's.
  assert.equal(MAX_ISSUER_BYTES, 1670);
  checkBinding({ profile: 'custom', issuer: 'i'.repeat(MAX_ISSUER_BYTES), claims: { sub: 'x' } }, { uploaded: true });
  assert.throws(() => checkBinding({ profile: 'custom', issuer: 'i'.repeat(MAX_ISSUER_BYTES + 1), claims: { sub: 'x' } }, { uploaded: true }), /longer than 1670 bytes/);
  refused({ profile: 'custom', issuer: `https://idp.acme.example/${'p'.repeat(MAX_ISSUER_BYTES)}`, claims: { sub: 'x' } }, /longer than 1670 bytes/);
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: '' } }, /nonempty string/);
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: 'x', groups: ['a'] as unknown as string } }, /nonempty string/);
  for (const name of ['aud', 'iss', 'exp', 'iat', 'nbf', 'jti']) {
    refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: 'x', [name]: 'y' } }, /never names/);
  }
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: 'x', 'kubernetes.io serviceaccount': 'y' } }, /not a claim name/);
  // As a JSON body has it: an own `__proto__`, which the stored binding would otherwise drop, matching more than it says.
  refused({ profile: 'custom', issuer: 'https://idp.acme.example', claims: JSON.parse('{"sub":"x","__proto__":"y"}') as Record<string, unknown> }, /not a claim name/);
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

test('a claim is named by its path through nested objects; a key may hold dots, and a path read two ways names nothing', () => {
  const token = {
    sub: 'system:serviceaccount:ci:deploy',
    'kubernetes.io': { namespace: 'ci', serviceaccount: { name: 'deploy', uid: '4f1c' } },
    'oidc.circleci.com/vcs-origin': 'github.com/acme/api',
  };
  assert.equal(claimAt(token, 'sub'), token.sub);
  assert.equal(claimAt(token, 'kubernetes.io.serviceaccount.uid'), '4f1c');
  assert.equal(claimAt(token, 'kubernetes.io.namespace'), 'ci');
  assert.equal(claimAt(token, 'oidc.circleci.com/vcs-origin'), 'github.com/acme/api', 'a top-level name with dots, as before');
  assert.equal(claimAt(token, 'kubernetes.io.pod.name'), undefined);
  assert.equal(claimAt(token, 'kubernetes'), undefined);
  assert.equal(claimAt({ list: ['a'] }, 'list.0'), undefined, 'arrays are not walked');
  // Two readings, each reaching a value: which one the binding meant cannot be told, so neither matches.
  assert.equal(claimAt({ 'a.b': 'top', a: { b: 'nested' } }, 'a.b'), undefined);
  assert.equal(claimAt({ 'a.b': 'top', a: { c: 'nested' } }, 'a.b'), 'top');

  const binding = checkBinding({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: token.sub, 'kubernetes.io.serviceaccount.uid': '4f1c' } });
  assert.deepEqual(differingClaims('custom', binding.claims, token), []);
  assert.deepEqual(differingClaims('custom', binding.claims, { ...token, 'kubernetes.io': { serviceaccount: { uid: 'other' } } }), ['kubernetes.io.serviceaccount.uid']);
  // An object where a string is expected matches nothing.
  assert.deepEqual(differingClaims('custom', { sub: token.sub, 'kubernetes.io.serviceaccount': 'deploy' }, token), ['kubernetes.io.serviceaccount']);
});

test('a binding that carries its keys names any issuer, exactly, but never one coffre fetches from', () => {
  const custom = (issuer: string) => checkBinding({ profile: 'custom', issuer, claims: { sub: 'x' } }, { uploaded: true });
  for (const issuer of ['https://kubernetes.default.svc.cluster.local', 'https://10.0.0.1:6443', 'kapsule:fr-par:5f2a', 'http://localhost']) {
    assert.equal(custom(issuer).issuer, issuer);
  }
  assert.throws(() => checkBinding({ profile: 'custom', issuer: 'https://kubernetes.default.svc.cluster.local', claims: { sub: 'x' } }), /public host name/);
  for (const issuer of ['', ' https://idp', 'https://idp\n', 'x'.repeat(MAX_ISSUER_BYTES + 1)]) assert.throws(() => custom(issuer), BindingInvalid);
  assert.throws(() => checkBinding({ profile: 'github', issuer: null, claims: {} }, { uploaded: true }), /publishes its keys/);
  assert.throws(() => checkBinding({ profile: 'gitlab', issuer: GITLAB_ISSUER, claims: {} }, { uploaded: true }), /publishes its keys/);
});

/** Capy's token for one thread of project p_7 (docs/design/oidc.md, section 9): its `sub` changes with every thread. */
const CAPY_ISSUER = 'https://api.capy.ai/oidc/orgs/o_123';
const capy = (thread: string, more: Record<string, unknown> = {}) => ({
  iss: CAPY_ISSUER, aud: 'https://secrets.acme.example', sub: `org/o_123/project/p_7/thread/${thread}`,
  org: 'o_123', project: 'p_7', thread, machine: 'm_9', user: 'u_4', jti: 'j', iat: 1, nbf: 0, exp: 3601, ...more,
});

test('a custom binding pins one or more claims of any name, each exact, and needs no sub (0.17)', () => {
  const binding = checkBinding({ profile: 'custom', issuer: CAPY_ISSUER, claims: { project: 'p_7', org: 'o_123' } });
  assert.deepEqual(binding.claims, { org: 'o_123', project: 'p_7' });
  // Every thread of the project matches, whatever its sub; every claim must, exactly.
  assert.deepEqual(differingClaims('custom', binding.claims, capy('ENG-142')), []);
  assert.deepEqual(differingClaims('custom', binding.claims, capy('ENG-143')), []);
  assert.deepEqual(differingClaims('custom', binding.claims, capy('ENG-142', { project: 'p_8' })), ['project']);
  assert.deepEqual(differingClaims('custom', binding.claims, capy('ENG-142', { project: 'p_7 ', org: 'O_123' })), ['org', 'project']);
  // No prefix, no pattern: a value is a value.
  assert.deepEqual(differingClaims('custom', binding.claims, capy('ENG-142', { project: 'p_70' })), ['project']);
  assert.deepEqual(differingClaims('custom', { sub: 'org/o_123/project/p_7/thread/*' }, capy('ENG-142')), ['sub']);
});

test('a claim the token lacks, or carries as another type, matches no custom binding', () => {
  const binding = checkBinding({ profile: 'custom', issuer: CAPY_ISSUER, claims: { project: 'p_7', tier: '7', verified: 'true' } }).claims;
  const token = capy('ENG-142', { tier: '7', verified: 'true' });
  assert.deepEqual(differingClaims('custom', binding, token), []);
  const { project: _, ...missing } = token;
  assert.deepEqual(differingClaims('custom', binding, missing), ['project']);
  // A number or a boolean is no string, however it would print.
  assert.deepEqual(differingClaims('custom', binding, { ...token, tier: 7 }), ['tier']);
  assert.deepEqual(differingClaims('custom', binding, { ...token, verified: true }), ['verified']);
  assert.deepEqual(differingClaims('custom', binding, { ...token, project: ['p_7'] }), ['project']);
  assert.deepEqual(differingClaims('custom', binding, { ...token, project: { id: 'p_7' } }), ['project']);
  assert.deepEqual(differingClaims('custom', binding, { ...token, project: null }), ['project']);
  // And a binding's own values are strings only.
  refused({ profile: 'custom', issuer: CAPY_ISSUER, claims: { tier: 7 as unknown as string } }, /nonempty string/);
  refused({ profile: 'custom', issuer: CAPY_ISSUER, claims: { verified: true as unknown as string } }, /nonempty string/);
});

test('a custom binding that pins no claim, or only claims that say how a token was issued, is refused', () => {
  refused({ profile: 'custom', issuer: CAPY_ISSUER, claims: {} }, /names one or more claims/);
  refused({ profile: 'custom', issuer: CAPY_ISSUER, claims: { email_verified: 'true' } }, /email_verified says how a token was issued, not to whom/);
  refused({ profile: 'custom', issuer: CAPY_ISSUER, claims: { acr: 'phr', azp: 'client' } }, /acr, azp say how a token was issued/);
  // Beside a claim that says who, they narrow.
  assert.deepEqual(checkBinding({ profile: 'custom', issuer: CAPY_ISSUER, claims: { email_verified: 'true', project: 'p_7' } }).claims, { email_verified: 'true', project: 'p_7' });
  // A workload's platform still names its own, and the claimless proofs none.
  refused({ profile: 'kubernetes', issuer: 'https://k8s.acme.example', claims: {} }, /requires sub/);
  refused({ profile: 'enrollment', issuer: null, claims: { sub: 'x' } }, /names no claims: its proof carries none/);
});

test('who a custom binding lets in, said in words', () => {
  assert.equal(
    customExposure(CAPY_ISSUER, { org: 'o_123', project: 'p_7' }),
    'Anyone holding a token from https://api.capy.ai/oidc/orgs/o_123 that says org=o_123 and project=p_7 signs in as this service account. ' +
      'Coffre cannot tell whether these claims name one workload: you vouch that this issuer gives such a token to nobody else.',
  );
  assert.match(customExposure(CAPY_ISSUER, { project: 'p_7' }), /that says project=p_7 signs in/);
  assert.match(customExposure(CAPY_ISSUER, { a: '1', b: '2', c: '3' }), /that says a=1, b=2 and c=3 signs in/);
});

test('a binding records claims by name: sorted, each once, at most eight, only where its proof is an ID token', () => {
  assert.deepEqual(checkRecord('custom', ['user', 'thread', 'machine', 'user']), ['machine', 'thread', 'user']);
  assert.equal(checkRecord('custom', []), null);
  assert.equal(checkRecord('custom', undefined), null);
  assert.equal(checkRecord('github', null), null);
  assert.deepEqual(checkRecord('kubernetes', ['kubernetes.io.pod.uid']), ['kubernetes.io.pod.uid']);
  assert.throws(() => checkRecord('custom', 'user'), /record lists claim names/);
  assert.throws(() => checkRecord('custom', [7]), /record lists claim names/);
  assert.throws(() => checkRecord('custom', ['a b']), /"a b" is not a claim name a binding can record/);
  assert.throws(() => checkRecord('custom', ['__proto__']), /not a claim name/);
  assert.throws(() => checkRecord('custom', Array.from({ length: 9 }, (_, i) => `c${i}`)), /at most 8 claims/);
  for (const profile of ['aws', 'enrollment', 'cloudflare'] as const) assert.throws(() => checkRecord(profile, ['user']), /records no claims: its proof carries none/);
  // One spelling, stored and read back.
  assert.equal(recordText(['machine', 'user']), '["machine","user"]');
  assert.equal(recordText(null), null);
  assert.deepEqual(recordedNames('["machine","user"]'), ['machine', 'user']);
  assert.deepEqual(recordedNames(null), []);
  assert.deepEqual(recordedNames('not json'), []);
});

test("a sign-in's record holds the run's claims and those its binding records, each bounded; recording refuses nothing", () => {
  const token = capy('ENG-142', { user: 'u_4', machine: 'm_9', score: 3, admin: true, groups: ['a'], long: 'x'.repeat(300) });
  // `sub` is a run claim already: the thread is in it.
  assert.deepEqual(runClaims(token), { sub: 'org/o_123/project/p_7/thread/ENG-142', jti: 'j' });
  assert.deepEqual(runClaims(token, ['machine', 'user', 'thread', 'score', 'admin', 'groups', 'long', 'absent']), {
    sub: 'org/o_123/project/p_7/thread/ENG-142', jti: 'j', machine: 'm_9', user: 'u_4', thread: 'ENG-142', score: 3, long: 'x'.repeat(256),
  });
});
