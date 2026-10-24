import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError } from '@coffre/client';
import { checkBinding } from '@coffre/core/workloads';

import {
  answered,
  askedScope,
  bindingOf,
  EMPTY_FORM,
  githubTarget,
  keySetOf,
  keysOf,
  lookupable,
  listedIds,
  listingGap,
  lookupFailure,
  lookupOf,
  planned,
  summary,
  type Form,
  type GitHubIds,
  type GitHubLookups,
  type ScopeChoice,
} from '../src/lib/bindings.ts';

const SHA = 'c'.repeat(40);
const form = (changes: Partial<Form>): Form => ({ ...EMPTY_FORM, ...changes });
/** `acme/api` as GitHub's lookup finds it, and its owner. */
const API: GitHubIds = { github: 'acme/api', repositoryId: '41532', ownerId: '9919' };
const ACME: GitHubIds = { github: 'acme', ownerId: '9919' };

test('the GitHub form fills in a workflow of the repository, or a reusable workflow at its commit', () => {
  const workflow = bindingOf(form({ repository: 'acme/api', workflow: 'deploy.yml' }), API);
  assert.deepEqual(workflow, {
    profile: 'github',
    issuer: null,
    claims: {
      repository_owner_id: '9919',
      repository_id: '41532',
      workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
      ref: 'refs/heads/main',
      event_name: ['push'],
    },
  });
  checkBinding(workflow);
  // Several events, one binding.
  const ci = bindingOf(form({ repository: 'acme/api', workflow: 'ci.yml', events: ['push', 'pull_request'] }), API);
  assert.deepEqual(checkBinding(ci).claims.event_name, ['push', 'pull_request']);
  assert.throws(() => bindingOf(form({ repository: 'acme/api', workflow: 'ci.yml', events: [] }), API), /Choose at least one event/);

  const called = 'acme/deploy/.github/workflows/release.yml@refs/heads/main';
  const reusable = bindingOf(form({ reusable: true, repository: 'acme/api', called, sha: SHA, refKind: 'tag', refName: 'v3', events: ['release'] }), API);
  assert.equal(reusable.profile, 'github-reusable');
  assert.deepEqual([reusable.claims.ref, reusable.claims.event_name, reusable.claims.workflow_ref], ['refs/tags/v3', ['release'], undefined]);
  checkBinding(reusable);
  // Called from any repository of the organization: the owner's ID alone, and no calling workflow, which would name one repository.
  const anywhere = bindingOf(form({ reusable: true, anyRepository: true, owner: 'acme', repository: 'acme/api', workflow: 'ship.yml', called, sha: SHA }), ACME);
  assert.equal(anywhere.profile, 'github-reusable-organization');
  assert.deepEqual([anywhere.claims.repository_owner_id, anywhere.claims.workflow_ref], ['9919', undefined]);
  checkBinding(anywhere);

  assert.throws(() => bindingOf(form({ reusable: true, repository: 'acme/api', called }), API), /The called workflow's commit is needed/);
});

test('the GitHub form takes the IDs GitHub found for the name in the field, or those typed in for a private repository', () => {
  // Typed in another case: the workflow is named as GitHub names it, as its tokens do.
  assert.equal(bindingOf(form({ repository: 'Acme/API', workflow: 'deploy.yml' }), API).claims.workflow_ref, 'acme/api/.github/workflows/deploy.yml@refs/heads/main');
  // Not found yet, or found for a name since changed: no IDs.
  assert.throws(() => bindingOf(form({ repository: 'acme/api', workflow: 'deploy.yml' })), /The repository's IDs are needed: wait for GitHub to find acme\/api, or enter them/);
  assert.throws(() => bindingOf(form({ repository: 'acme/web', workflow: 'deploy.yml' }), API), /wait for GitHub to find acme\/web/);
  assert.throws(() => bindingOf(form({ repository: '', workflow: 'deploy.yml' }), API), /The repository is needed/);
  assert.throws(() => bindingOf(form({ reusable: true, anyRepository: true, owner: 'acme' }), API), /The organization's IDs are needed/);

  // Typed in: they win over any lookup, and a repository needs both.
  const typed = bindingOf(form({ repository: 'acme/secret', typedIds: true, repositoryId: '7', ownerId: '9919', workflow: 'deploy.yml' }), null);
  assert.deepEqual([typed.claims.repository_id, typed.claims.workflow_ref], ['7', 'acme/secret/.github/workflows/deploy.yml@refs/heads/main']);
  assert.throws(() => bindingOf(form({ repository: 'acme/secret', typedIds: true, ownerId: '9919', workflow: 'deploy.yml' })), /The repository's ID is needed/);
  const organization = bindingOf(form({ reusable: true, anyRepository: true, owner: 'acme', typedIds: true, ownerId: '9919', called: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA }));
  assert.equal(organization.claims.repository_owner_id, '9919');

  // What the dialog looks up: the repository, or the organization; only once it reads as one.
  assert.deepEqual(githubTarget(form({ repository: ' acme/api ', owner: 'acme' })), { kind: 'repository', name: 'acme/api' });
  assert.deepEqual(githubTarget(form({ reusable: true, anyRepository: true, repository: 'acme/api', owner: 'acme' })), { kind: 'owner', name: 'acme' });
  for (const name of ['acme/api', 'Acme-Inc/api.js', 'a/b_c']) assert.equal(lookupable({ kind: 'repository', name }), true, name);
  for (const name of ['', 'acme', 'acme/', '/api', 'acme/api/x', '../users', 'acme/a b']) assert.equal(lookupable({ kind: 'repository', name }), false, name);
  assert.equal(lookupable({ kind: 'owner', name: 'acme' }), true);
  assert.equal(lookupable({ kind: 'owner', name: 'acme/api' }), false);
});

test('a GitHub environment narrows the binding, left out when empty', () => {
  assert.equal(bindingOf(form({ repository: 'acme/api', workflow: 'deploy.yml' }), API).claims.environment, undefined);
  const deploy = bindingOf(form({ repository: 'acme/api', workflow: 'deploy.yml', environment: ' production ' }), API);
  assert.equal(deploy.claims.environment, 'production');
  checkBinding(deploy);
  const reusable = bindingOf(form({ reusable: true, repository: 'acme/api', called: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA, environment: 'prod/eu' }), API);
  assert.equal(checkBinding(reusable).claims.environment, 'prod/eu');
});

test('the page keeps each lookup by name: IDs found stand, and a late failure replaces only its own lookup', () => {
  const owner = { kind: 'owner' as const, name: 'acme' };
  let known: GitHubLookups = new Map();
  // An owner named like an object's own property is a name like any other: not known before it is asked.
  assert.equal(lookupOf(known, { kind: 'owner', name: 'constructor' }), null);
  assert.equal(lookupOf(known, { kind: 'owner', name: '__proto__' }), null);
  known = answered(known, 'acme', { state: 'looking' });
  // The repository's answer names its owner while the owner's own lookup is under way.
  known = answered(known, 'acme/api', { state: 'found', ids: API });
  known = answered(known, 'acme', { state: 'found', ids: ACME });
  // Then the owner's lookup fails, the hour's spent: the IDs found stand.
  known = answered(known, 'ACME', { state: 'failed', message: 'spent' });
  assert.deepEqual(lookupOf(known, owner), { state: 'found', ids: ACME });
  // A failure over its own lookup is recorded, under the name in any case.
  known = answered(known, 'acme/web', { state: 'looking' });
  known = answered(known, 'Acme/Web', { state: 'missing', message: 'nothing' });
  assert.deepEqual(lookupOf(known, { kind: 'repository', name: 'acme/web' }), { state: 'missing', message: 'nothing' });
  // A name that does not read as one is never looked up, whatever the page knows.
  assert.equal(lookupOf(known, { kind: 'repository', name: 'acme' }), null);
});

test("a lookup that fails says why: nothing public there, final; the hour's lookups spent, or no answer, worth asking again", () => {
  assert.deepEqual(lookupFailure('acme/secret', new CoffreError(404, 'not_found', 'api.github.com did not find it')), {
    state: 'missing',
    message: 'GitHub shows nothing public at acme/secret.',
  });
  const notInstalled = 'GitHub did not find it, and the GitHub App is not installed on it: install it on globex, or type its IDs';
  assert.deepEqual(lookupFailure('globex/secret', new CoffreError(404, 'not_found', notInstalled, 'not_installed')), { state: 'missing', message: notInstalled });
  assert.deepEqual(lookupFailure('acme/api', new CoffreError(429, 'too_many_requests', "this hour's are spent")), {
    state: 'failed',
    message: "GitHub's hourly limit on lookups without signing in is spent. Enter the IDs, or try again later.",
  });
  assert.deepEqual(lookupFailure('acme/api', new CoffreError(503, 'unavailable', 'api.github.com did not answer')), { state: 'failed', message: 'api.github.com did not answer' });
  assert.deepEqual(lookupFailure('acme/api', 'boom'), { state: 'failed', message: 'GitHub could not be asked.' });
});

test('the GitLab form names the namespace and the project, and the other issuer its subject and claims', () => {
  const gitlab = bindingOf(form({ platform: 'gitlab', projectId: '345', namespaceId: '12', refName: 'main' }));
  assert.deepEqual(gitlab, {
    profile: 'gitlab',
    issuer: null,
    claims: { namespace_id: '12', project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: ['push'] },
  });
  checkBinding(gitlab);
  assert.equal(bindingOf(form({ platform: 'gitlab', gitlabUrl: 'https://gitlab.acme.example', projectId: '1', namespaceId: '2' })).issuer, 'https://gitlab.acme.example');

  const other = bindingOf(form({ platform: 'other', issuer: 'https://idp.acme.example', sub: '104', extra: 'email_verified=true\n\n  hd = acme.example ' }));
  assert.deepEqual(other, { profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: '104', email_verified: 'true', hd: 'acme.example' } });
  assert.throws(() => bindingOf(form({ platform: 'other', issuer: 'https://idp.acme.example', sub: 'x', extra: 'oops' })), /"oops" is not <claim>=<value>/);

  // A private cluster's keys, pasted: sent with it, for the server to check.
  const cluster = 'https://kubernetes.default.svc.cluster.local';
  const keys = { keys: [{ kty: 'RSA', kid: 'k8s', n: 'AQAB', e: 'AQAB' }] };
  const pasted = bindingOf(form({ platform: 'other', issuer: cluster, sub: 'system:serviceaccount:ci:deploy', extra: 'kubernetes.io.serviceaccount.uid=4f1c', jwks: JSON.stringify(keys) }));
  assert.deepEqual(pasted, { profile: 'custom', issuer: cluster, claims: { sub: 'system:serviceaccount:ci:deploy', 'kubernetes.io.serviceaccount.uid': '4f1c' }, jwks: keys });
  assert.throws(() => bindingOf(form({ platform: 'other', issuer: cluster, sub: 'x', jwks: '{ keys' })), /not JSON/);
  assert.throws(() => bindingOf(form({ platform: 'other', issuer: cluster, sub: 'x', jwks: '{"kty":"RSA"}' })), /a key set/);
  assert.equal(keySetOf('  '), undefined);
});

test('a binding reads in a line: what it trusts, and at which ref', () => {
  const issuer = 'https://token.actions.githubusercontent.com';
  assert.deepEqual(
    summary({ profile: 'github', issuer, claims: bindingOf(form({ repository: 'acme/api', workflow: 'deploy.yml' }), API).claims }),
    { title: 'acme/api · deploy.yml', detail: 'push at main' },
  );
  assert.deepEqual(
    summary({ profile: 'github', issuer, claims: { workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', event_name: 'push', environment: 'production' } }),
    { title: 'acme/api · deploy.yml', detail: 'push at main, in environment production' },
  );
  assert.deepEqual(
    summary({ profile: 'github', issuer, claims: { workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main', event_name: ['push', 'pull_request'] } }),
    { title: 'acme/api · ci.yml', detail: 'push, pull_request at main' },
  );
  assert.deepEqual(
    summary({ profile: 'github-reusable', issuer, claims: { repository_id: '41532', ref: 'refs/heads/main', event_name: 'push', job_workflow_ref: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', job_workflow_sha: SHA } }),
    { title: 'acme/deploy · release.yml @ ccccccc', detail: 'push at main, from repository 41532' },
  );
  assert.deepEqual(
    summary({ profile: 'gitlab', issuer: 'https://gitlab.com', claims: { project_id: '345', pipeline_source: 'push', ref_type: 'tag', ref: 'v1' } }),
    { title: 'GitLab project 345', detail: 'push at tag v1' },
  );
  assert.deepEqual(summary({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: '104' } }), { title: 'idp.acme.example', detail: 'sub 104' });
  // A binding that carries its keys may name any issuer, a URL or not.
  assert.deepEqual(summary({ profile: 'custom', issuer: 'kapsule:fr-par', claims: { sub: 'x' } }), { title: 'kapsule:fr-par', detail: 'sub x' });
  assert.equal(keysOf({ jwksUri: 'https://idp.acme.example/keys', keys: null }), 'https://idp.acme.example/keys');
  assert.equal(keysOf({ jwksUri: 'sha256:00', keys: [{ kid: 'k8s', alg: 'RS256', thumbprint: 't1' }, { kid: null, alg: 'ES256', thumbprint: 't2' }] }), 'Uploaded: k8s (RS256), t2 (ES256)');
});

test("the Trust dialog leaves a binding's scope to the server until the person chooses: one that replaces others reaches what they did, and the picker says so", () => {
  const whole: ScopeChoice = { scope: { market: 'developer', 'billing/dev': 'viewer' }, chosen: false };
  assert.deepEqual(askedScope(whole), {}, 'the server decides: what the bindings it replaces reached, or all the account holds');
  // The plan replaces a binding that reached market/dev: the picker shows that, still the server's.
  const inherited = planned(whole, { scope: { 'market/dev': 'viewer' } });
  assert.deepEqual(inherited, { scope: { 'market/dev': 'viewer' }, chosen: false });
  assert.deepEqual(askedScope(inherited), {});
  // Chosen in the picker, it is asked for, and no plan changes it.
  const chosen: ScopeChoice = { scope: { market: 'viewer' }, chosen: true };
  assert.deepEqual(askedScope(chosen), { scope: { market: 'viewer' } });
  assert.equal(planned(chosen, { scope: { 'market/dev': 'viewer' } }), chosen);
});

test("a GitHub App's listing tells each repository's IDs, and each owner's once, so that picking either asks GitHub nothing", () => {
  const listed = [
    { github: 'acme/api', repositoryId: '41532', ownerId: '9919', private: false },
    { github: 'acme/infra', repositoryId: '41540', ownerId: '9919', private: true },
    { github: 'octo-dev/dotfiles', repositoryId: '70001', ownerId: '583231', private: true },
  ];
  assert.deepEqual(listedIds(listed), [
    { github: 'acme/api', repositoryId: '41532', ownerId: '9919' },
    { github: 'acme/infra', repositoryId: '41540', ownerId: '9919' },
    { github: 'octo-dev/dotfiles', repositoryId: '70001', ownerId: '583231' },
    { github: 'acme', ownerId: '9919' },
    { github: 'octo-dev', ownerId: '583231' },
  ]);
  // What the form then binds: the picked repository's IDs, found without a lookup.
  const known = listedIds(listed).reduce((map, ids) => answered(map, ids.github, { state: 'found', ids }), new Map() as GitHubLookups);
  assert.deepEqual(lookupOf(known, { kind: 'repository', name: 'ACME/infra' }), { state: 'found', ids: { github: 'acme/infra', repositoryId: '41540', ownerId: '9919' } });
  assert.deepEqual(lookupOf(known, { kind: 'owner', name: 'octo-dev' }), { state: 'found', ids: { github: 'octo-dev', ownerId: '583231' } });
});

test('a listing that stopped short says so before saying the app is installed nowhere or reaches nothing', () => {
  const repo = { github: 'acme/api' };
  // GitHub's first 100 installations suspended, an active one past them: nothing listed, and partial.
  assert.equal(listingGap({ installations: [], repositories: [], truncated: true }, false), 'partial');
  assert.equal(listingGap({ installations: Array(20).fill('org'), repositories: [], truncated: true }, false), 'partial');
  assert.equal(listingGap({ installations: [], repositories: [], truncated: false }, false), 'not_installed');
  assert.equal(listingGap({ installations: [], repositories: [], truncated: false }, true), 'not_installed');
  assert.equal(listingGap({ installations: ['acme'], repositories: [], truncated: false }, false), 'no_repositories');
  // The organization field offers accounts, which it has.
  assert.equal(listingGap({ installations: ['acme'], repositories: [], truncated: false }, true), null);
  assert.equal(listingGap({ installations: ['acme'], repositories: [repo], truncated: false }, false), null);
});
