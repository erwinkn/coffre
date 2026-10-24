import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError, type BindingView } from '@coffre/client';
import { checkBinding, checkPolicy } from '@coffre/core/workloads';

import {
  bindingFrom,
  describeBindings,
  describeEvents,
  describeKeys,
  describePlan,
  keySetFrom,
  keysLine,
  readsFrom,
  runsOf,
  serviceMember,
  type Lookup,
  type PlatformLookup,
  type TrustFlags,
} from '../src/trust.ts';

const SHA = 'b'.repeat(40);

/** What the server's lookup would find: public repositories and projects, by name. */
const lookup: Lookup = async (input) => {
  // GitHub spells a repository as its tokens do, whatever the case it was asked in.
  if (input.github?.toLowerCase() === 'acme/api') return { github: 'acme/api', repositoryId: '41532', ownerId: '9919' };
  if (input.github === 'acme') return { github: 'acme', ownerId: '9919' };
  if (input.gitlab === 'acme/api' && input.gitlabUrl === undefined) return { gitlab: 'acme/api', projectId: '345', namespaceId: '12' };
  // As the server answers, through a client that hands a 404 back to the command.
  throw new CoffreError(404, 'not_found', 'api.github.com did not find it: a private one\'s IDs are typed in');
};

/** Each binding the flags build is one the server accepts: here as it stores it. */
async function built(flags: TrustFlags) {
  const binding = await bindingFrom(flags, lookup);
  return { ...binding, claims: checkBinding(binding).claims };
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
  const release = await built({ github: 'acme/api', workflow: '.github/workflows/ship.yml', tag: 'v2.0.0', event: ['release'] });
  assert.deepEqual([release.claims.ref, release.claims.workflow_ref, release.claims.event_name], [
    'refs/tags/v2.0.0', 'acme/api/.github/workflows/ship.yml@refs/tags/v2.0.0', 'release',
  ]);
  // A private repository: its IDs are given, and nothing is looked up.
  const given = await built({ github: 'acme/secret', workflow: 'deploy.yml', branch: 'main', 'repository-id': '7', 'owner-id': '9919' });
  assert.equal(given.claims.repository_id, '7');
  await assert.rejects(bindingFrom({ github: 'acme/secret', workflow: 'deploy.yml', branch: 'main' }, lookup), /gh api repos\/acme\/secret/);
  // Typed in another case, the workflow is named as GitHub names it, or no run's workflow_ref would match.
  const typed = await built({ github: 'Acme/API', workflow: 'deploy.yml', branch: 'main' });
  assert.equal(typed.claims.workflow_ref, 'acme/api/.github/workflows/deploy.yml@refs/heads/main');
});

test('a GitHub environment narrows a binding to the jobs that run in it', async () => {
  const deploy = await built({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main', 'github-environment': 'production' });
  assert.equal(deploy.claims.environment, 'production');
  const reusable = await built({ github: 'acme', reusable: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA, branch: 'main', 'any-repository': true, 'github-environment': 'production' });
  assert.equal(reusable.claims.environment, 'production');
  assert.equal((await built({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main' })).claims.environment, undefined);
  await assert.rejects(bindingFrom({ gitlab: 'acme/api', branch: 'main', 'github-environment': 'production' }, lookup), /--github-environment narrows a GitHub binding/);
  await assert.rejects(built({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main', 'github-environment': 'production ' }), /GitHub environment's name/);
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
  // The organization's ID looked up when not given, from its name or any of its repositories'.
  for (const github of ['acme', 'acme/api']) {
    const looked = await built({ github, reusable: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', sha: SHA, branch: 'main', 'any-repository': true });
    assert.deepEqual([looked.profile, looked.claims.repository_owner_id], ['github-reusable-organization', '9919']);
  }
  await assert.rejects(
    bindingFrom({ github: 'hidden', reusable: 'x', sha: SHA, branch: 'main', 'any-repository': true }, lookup),
    /gh api users\/hidden --jq '"--owner-id \\\(\.id\)"'\nand add the flag it prints, --owner-id <n>, to this coffre trust/,
  );
});

test('a GitLab project, by its namespace and project IDs, a branch or a tag, and its pipeline source', async () => {
  assert.deepEqual(await built({ gitlab: 'acme/api', branch: 'main' }), {
    profile: 'gitlab',
    issuer: null,
    claims: { namespace_id: '12', project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: 'push' },
  });
  const tag = await built({ gitlab: 'acme/api', tag: 'v1', source: ['web'] });
  assert.deepEqual([tag.claims.ref_type, tag.claims.ref, tag.claims.pipeline_source], ['tag', 'v1', 'web']);
  const selfManaged = await built({ gitlab: 'acme/api', branch: 'main', 'gitlab-url': 'https://gitlab.acme.example', 'project-id': '5', 'namespace-id': '6' });
  assert.equal(selfManaged.issuer, 'https://gitlab.acme.example');
  await assert.rejects(bindingFrom({ gitlab: 'acme/private', branch: 'main' }, lookup), /glab api projects\/acme%2Fprivate/);
});

test('any other issuer, by its claims', async () => {
  assert.deepEqual(await built({ issuer: 'https://idp.acme.example', claim: ['sub=104000000000000000000'] }), {
    profile: 'custom',
    issuer: 'https://idp.acme.example',
    claims: { sub: '104000000000000000000' },
  });
  await assert.rejects(bindingFrom({ issuer: 'https://idp.acme.example', claim: ['sub'] }, lookup), /--claim takes <name>=<value>/);
});

test('the flags name one platform, and one of a branch or a tag', async () => {
  await assert.rejects(bindingFrom({}, lookup), /name one of --github, --gitlab or --issuer, or a workload's platform: --aws, --kubernetes/);
  await assert.rejects(bindingFrom({ github: 'acme/api', gitlab: 'acme/api' }, lookup), /name one platform, not --github and --gitlab/);
  await assert.rejects(bindingFrom({ github: 'acme/api', issuer: 'https://idp.acme.example' }, lookup), /--github names its own/);
  await assert.rejects(bindingFrom({ github: 'acme/api', workflow: 'deploy.yml' }, lookup), /name one of --branch or --tag/);
  await assert.rejects(bindingFrom({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main', tag: 'v1' }, lookup), /name one of --branch or --tag/);
  await assert.rejects(bindingFrom({ github: 'acme/api', branch: 'main' }, lookup), /--workflow deploy.yml/);
  assert.equal(serviceMember('api-deploy'), 'token:api-deploy');
  assert.equal(serviceMember('token:api-deploy'), 'token:api-deploy');
  // As people write it now: the API keeps token:<name>.
  assert.equal(serviceMember('service:api-deploy'), 'token:api-deploy');
});

test('a plan and a list show every claim in full', () => {
  const plan = {
    profile: 'github' as const,
    issuer: 'https://token.actions.githubusercontent.com',
    jwksUri: 'https://token.actions.githubusercontent.com/.well-known/jwks',
    claims: { event_name: 'push', ref: 'refs/heads/main' },
    keys: null,
    scope: { 'market/dev': 'developer' as const, 'market/prod': 'viewer' as const, 'api/dev': 'developer' as const },
    withheld: [] as string[],
    replaces: [{ id: 'old', why: 'keys_moved' as const }],
  };
  assert.equal(
    describePlan('token:api-deploy', plan, null),
    [
      'Would trust CI runs to sign in as service:api-deploy, by OIDC:',
      '  profile  github',
      '  issuer   https://token.actions.githubusercontent.com',
      '  keys     https://token.actions.githubusercontent.com/.well-known/jwks',
      '  claims   event_name  push',
      '           ref         refs/heads/main',
      '  reaches  developer on market/dev, api/dev; viewer on market/prod',
      '  replaces old: the issuer moved its keys',
      '',
    ].join('\n'),
  );
  // A Developer's binding, where market/prod holds sensitive values: told before it is saved (R32).
  assert.match(
    describePlan('token:api-deploy', { ...plan, withheld: ['market/prod'] }, null),
    /\n  reads no sensitive value of market\/prod: only one an Owner of its project issues does\n$/,
  );
  assert.equal(describeBindings('token:api-deploy', []), "service:api-deploy trusts no CI runs or workloads: none signs in as it by OIDC or a platform's proof\n");
  const listed = describeBindings('token:api-deploy', [
    { ...plan, id: 'b1', label: 'prod', createdAt: '2026-10-03T22:00:00.000Z', createdBy: 'lead@acme.example', lastUsedAt: null },
    { ...plan, scope: null, id: 'b0', label: null, createdAt: '2026-09-03T22:00:00.000Z', createdBy: 'lead@acme.example', lastUsedAt: null },
  ]);
  assert.match(listed, /^b1  prod  \(added by lead@acme.example 2026-10-03, never used\)\n  profile  github\n/);
  assert.match(listed, /\n  reaches  all its account holds\n$/, 'one of 0.4 the app has not sealed yet');
});

test('uploaded keys show by kid, or by thumbprint without one; replacing them names each binding replaced', () => {
  const ISSUER = 'https://kubernetes.default.svc.cluster.local';
  const keys = [
    { kid: 'k8s-2026', alg: 'RS256' as const, thumbprint: 'tp1' },
    { kid: null, alg: 'ES256' as const, thumbprint: 'tp2' },
  ];
  assert.equal(keysLine({ jwksUri: `sha256:${'a'.repeat(64)}`, keys }), 'uploaded: k8s-2026 (RS256), thumbprint tp2 (ES256)');
  assert.equal(keysLine({ jwksUri: 'https://idp.acme.example/keys', keys: null }), 'https://idp.acme.example/keys');
  const plan = { issuer: ISSUER, jwksUri: `sha256:${'b'.repeat(64)}`, keys: keys.slice(0, 1), replaces: ['old-1', 'old-2'], withheld: [] };
  assert.equal(
    describeKeys('token:api', plan, null),
    [
      "Would give service:api's 2 bindings on https://kubernetes.default.svc.cluster.local these keys, each replaced by a binding the same but for them:",
      '  keys     uploaded: k8s-2026 (RS256)',
      '  replaces old-1',
      '  replaces old-2',
      'Credentials those bindings issued, five minutes each at most, would end at once.',
      '',
    ].join('\n'),
  );
  assert.match(describeKeys('token:api', plan, { bindings: [{ id: 'new-1' }, { id: 'new-2' }] as BindingView[], replaced: ['old-1', 'old-2'] }), /\n  new-1 replaces old-1\n  new-2 replaces old-2\n/);
  // Bindings an Owner made, re-keyed by someone else: told what the new ones will not read.
  assert.match(describeKeys('token:api', { ...plan, withheld: ['market/prod'] }, null), /\n  replaces old-2\n  reads no sensitive value of market\/prod: only one an Owner of its project issues does\nCredentials/);
  // One of those planned was removed before the save: what the server answered, not the plan.
  const raced = describeKeys('token:api', plan, { bindings: [{ id: 'new-1' }] as BindingView[], replaced: ['old-1'] });
  assert.match(raced, /^Gave service:api's binding on .*\n  keys .*\n  new-1 replaces old-1\nCredentials/);
});

test('--jwks-file takes a key set, as kubectl prints it', () => {
  assert.deepEqual(keySetFrom('{"keys":[{"kty":"RSA","kid":"a"}]}', 'jwks.json'), { keys: [{ kty: 'RSA', kid: 'a' }] });
  assert.throws(() => keySetFrom('nope', 'jwks.json'), /jwks.json is not JSON/);
  assert.throws(() => keySetFrom('{"kty":"RSA"}', 'jwks.json'), /jwks.json is no key set/);
});

test('a binding says, in a sentence, which CI runs it lets sign in: platform, repository or project, workflow, ref', () => {
  const SHA = 'a'.repeat(40);
  assert.equal(
    runsOf({ profile: 'github', issuer: 'https://token.actions.githubusercontent.com', claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' } }),
    "GitHub Actions runs of acme/api's workflow deploy.yml, on branch main, by push",
  );
  assert.equal(
    runsOf({ profile: 'github', issuer: 'https://token.actions.githubusercontent.com', claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main', ref: 'refs/heads/main', event_name: ['push', 'pull_request'] } }),
    "GitHub Actions runs of acme/api's workflow ci.yml, on branch main or a pull request into it, by push or pull_request",
  );
  assert.equal(
    runsOf({ profile: 'github', issuer: 'https://token.actions.githubusercontent.com', claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push', environment: 'production' } }),
    "GitHub Actions runs of acme/api's workflow deploy.yml, on branch main, by push, in environment production",
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
    runsOf({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { sub: '1040' } }),
    'runs whose ID token, from https://idp.acme.example, says sub=1040',
  );
});

test('a private repository or project: said in a line, then the command that gets its IDs, then the flags to add', async () => {
  await assert.rejects(bindingFrom({ github: 'erwinkn/website', workflow: 'deploy.yml', branch: 'main' }, lookup), {
    message:
      'GitHub shows coffre nothing of erwinkn/website: it is private, or not there. Get its IDs with\n' +
      '  gh api repos/erwinkn/website --jq \'"--repository-id \\(.id) --owner-id \\(.owner.id)"\'\n' +
      'and add the two flags it prints, --repository-id <n> --owner-id <n>, to this coffre trust.',
  });
  await assert.rejects(
    bindingFrom({ gitlab: 'acme/private', branch: 'main', 'gitlab-url': 'https://gitlab.acme.example' }, lookup),
    /^Error: GitLab shows coffre nothing of acme\/private: it is private, or not there\. Get its IDs with\n  glab api --hostname gitlab\.acme\.example projects\/acme%2Fprivate \| jq -r '"--project-id \\\(\.id\) --namespace-id \\\(\.namespace\.id\)"'\n/,
  );
  // Any other refusal is said as it is, with no hint that would not help.
  const malformed: Lookup = async () => { throw new CoffreError(400, 'bad_request', 'a GitHub repository is <owner>/<name>'); };
  await assert.rejects(bindingFrom({ github: 'nope', workflow: 'deploy.yml', branch: 'main' }, malformed), { message: 'a GitHub repository is <owner>/<name>' });
});

test('one binding for every event or pipeline source named, push unless told', async () => {
  const three = await built({ github: 'acme/api', workflow: 'ci.yml', branch: 'main', event: ['schedule,push', 'workflow_dispatch', 'push'] });
  // Stored once each, in GitHub's order.
  assert.deepEqual(three.claims.event_name, ['push', 'workflow_dispatch', 'schedule']);
  assert.equal((await built({ github: 'acme/api', workflow: 'ci.yml', branch: 'main' })).claims.event_name, 'push');
  assert.deepEqual((await built({ gitlab: 'acme/api', branch: 'main', source: ['web', 'schedule'] })).claims.pipeline_source, ['web', 'schedule']);
  // Pull requests, by the branch they merge into, and workflow_run.
  const ci = await built({ github: 'acme/api', workflow: 'ci.yml', branch: 'main', event: ['push,pull_request,workflow_run'] });
  assert.deepEqual(ci.claims.event_name, ['push', 'pull_request', 'workflow_run']);
  await assert.rejects(bindingFrom({ github: 'acme/api', workflow: 'ci.yml', branch: 'main', event: ['pull_request_target'] }, lookup), /--event takes push, workflow_dispatch, schedule, release, pull_request, workflow_run, not pull_request_target/);
  await assert.rejects(bindingFrom({ gitlab: 'acme/api', branch: 'main', event: ['push'] }, lookup), /--event is a GitHub run's/);
});

test('the preview says which events the binding accepts, the flag that adds those the ref allows, and what a pull request exposes', async () => {
  const push = await built({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main' });
  assert.equal(
    describeEvents(push),
    'Accepts runs started by push. Not by workflow_dispatch or schedule: add them with --event, as --event push,workflow_dispatch,schedule.',
  );
  // At a tag, a release runs, and a schedule never does.
  const tag = await built({ github: 'acme/api', workflow: 'ship.yml', tag: 'v1', event: ['push', 'release'] });
  assert.equal(describeEvents(tag), 'Accepts runs started by push and release. Not by workflow_dispatch: add them with --event, as --event push,release,workflow_dispatch.');
  const all = await built({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main', event: ['push,workflow_dispatch,schedule'] });
  assert.equal(describeEvents(all), 'Accepts runs started by push, workflow_dispatch and schedule.');
  // Never suggested; said what it exposes once chosen.
  const ci = await built({ github: 'acme/api', workflow: 'ci.yml', branch: 'main', event: ['push,workflow_dispatch,schedule,pull_request'] });
  assert.match(describeEvents(ci)!, /^Accepts runs started by push, workflow_dispatch, schedule and pull_request\.\npull_request: Anyone who can push a branch to the repository/);
  assert.equal(
    describeEvents(await built({ gitlab: 'acme/api', branch: 'main' })),
    'Accepts pipelines started by push. Not by web or schedule: add them with --source, as --source push,web,schedule.',
  );
  assert.equal(describeEvents(await built({ issuer: 'https://idp.acme.example', claim: ['sub=1'] })), null);
});

test('the CLI hands a refused lookup back to trust, which says how to give the IDs, rather than ending on "not found"', async (t) => {
  const { createServer } = await import('node:http');
  const { once } = await import('node:events');
  const { spawn } = await import('node:child_process');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { signedInWithToken } = await import('./fakes.ts');
  const server = createServer((request, response) =>
    response.writeHead(request.url!.startsWith('/api/workloads/lookup') ? 404 : 500, { 'content-type': 'application/json' })
      .end(JSON.stringify({ error: 'not_found', message: "api.github.com did not find it: for a private one, type its IDs" })),
  );
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const home = mkdtempSync(join(tmpdir(), 'coffre-trust-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  signedInWithToken(home, origin, 'coffre_cli_owner');
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
  const main = new URL('../src/main.ts', import.meta.url).pathname;
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'trust', 'website-deploy', '--github', 'erwinkn/website', '--workflow', 'deploy.yml', '--branch', 'main'], {
    env: { ...env, HOME: home },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  const [code] = (await once(child, 'close')) as [number];
  assert.equal(code, 1);
  assert.equal(
    stderr,
    'coffre: GitHub shows coffre nothing of erwinkn/website: it is private, or not there. Get its IDs with\n' +
      '  gh api repos/erwinkn/website --jq \'"--repository-id \\(.id) --owner-id \\(.owner.id)"\'\n' +
      'and add the two flags it prints, --repository-id <n> --owner-id <n>, to this coffre trust.\n',
  );
});

const ACCOUNT = '671742253563';
const ROLE_ID = 'AROAZ3EXAMPLE7QXYZAB';
const SA_UID = '8f2d6a1e-5b3c-4e7f-9a0b-1c2d3e4f5a6b';
const TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const OBJECT = '4c1d3b2a-9f8e-4d7c-b6a5-0123456789ab';

/** What the platforms' CLIs say, as the person running coffre trust is signed in to them; what each was asked. */
let asked: string[];
const platforms: PlatformLookup = {
  awsRole: async (name) => {
    asked.push(`aws ${name}`);
    if (name !== 'ingest-task') throw new Error('aws iam get-role failed: NoSuchEntity; add --role-id <AROA…>');
    return { roleId: ROLE_ID, arn: `arn:aws:iam::${ACCOUNT}:role/ingest-task` };
  },
  kubernetesIssuer: async () => {
    asked.push('kubectl issuer');
    return 'https://oidc.prod.acme.example';
  },
  kubernetesUid: async (namespace, name) => {
    asked.push(`kubectl ${namespace}/${name}`);
    return SA_UID;
  },
  gcpUniqueId: async (email) => {
    asked.push(`gcloud ${email}`);
    return '104729384756102938475';
  },
};

/** A workload's binding as the flags build it, and as the server would check it: its claims, then its policy, `reads` aside. */
async function workload(flags: TrustFlags) {
  asked = [];
  const binding = await bindingFrom(flags, lookup, { service: 'token:ingest', platforms });
  const checked = checkBinding(binding);
  checkPolicy(binding.profile, { ...binding.policy, reads: undefined }, { service: 'token:ingest' });
  return { ...binding, claims: checked.claims };
}

test("each workload platform's flag binds it by the IDs its platform never reuses, looked up with its CLI where one has them", async () => {
  assert.deepEqual(await workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task` }), {
    profile: 'aws', issuer: null, claims: { account: ACCOUNT, role_id: ROLE_ID }, policy: {},
  });
  assert.deepEqual(asked, ['aws ingest-task']);
  // A role under a path is looked up by its name; --role-id asks nothing.
  assert.deepEqual((await workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, 'role-id': 'AROAZ3EXAMPLE7QXYZAC' })).claims, { account: ACCOUNT, role_id: 'AROAZ3EXAMPLE7QXYZAC' });
  assert.deepEqual(asked, []);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/teams/ingest-task` }), /aws iam get-role finds arn:aws:iam::671742253563:role\/ingest-task, not arn:aws:iam::671742253563:role\/teams\/ingest-task/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/other` }), /NoSuchEntity; add --role-id/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:user/ada` }), /--aws takes a role's ARN/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, claim: ['session=x'] }), /names the role alone/);

  assert.deepEqual(await workload({ kubernetes: 'ingest/api' }), {
    profile: 'kubernetes',
    issuer: 'https://oidc.prod.acme.example',
    claims: { 'kubernetes.io.serviceaccount.uid': SA_UID, sub: 'system:serviceaccount:ingest:api' },
    policy: {},
  });
  assert.deepEqual(asked, ['kubectl issuer', 'kubectl ingest/api']);
  const given = await workload({ kubernetes: 'ingest/api', issuer: 'https://container.googleapis.com/v1/projects/acme/locations/europe-west1/clusters/prod', uid: SA_UID, claim: ['kubernetes.io.namespace=ingest'] });
  assert.equal(given.issuer, 'https://container.googleapis.com/v1/projects/acme/locations/europe-west1/clusters/prod');
  assert.equal(given.claims['kubernetes.io.namespace'], 'ingest');
  assert.deepEqual(asked, []);
  await assert.rejects(workload({ kubernetes: 'api' }), /--kubernetes takes <namespace>\/<service-account>/);

  assert.deepEqual((await workload({ gcp: 'web@acme-prod.iam.gserviceaccount.com' })).claims, { sub: '104729384756102938475' });
  assert.deepEqual(asked, ['gcloud web@acme-prod.iam.gserviceaccount.com']);
  assert.deepEqual(await workload({ gcp: '104729384756102938476' }), { profile: 'gcp', issuer: 'https://accounts.google.com', claims: { sub: '104729384756102938476' }, policy: {} });
  await assert.rejects(workload({ gcp: 'web' }), /email or unique ID/);

  assert.deepEqual(await workload({ azure: true, tenant: TENANT, object: OBJECT, audience: 'api://coffre-acme' }), {
    profile: 'azure', issuer: `https://sts.windows.net/${TENANT}/`, claims: { oid: OBJECT, tid: TENANT }, policy: { audience: 'api://coffre-acme' },
  });
  assert.equal((await workload({ azure: true, tenant: TENANT, object: OBJECT, audience: 'api://coffre-acme', issuer: `https://login.microsoftonline.com/${TENANT}/v2.0` })).issuer, `https://login.microsoftonline.com/${TENANT}/v2.0`);
  await assert.rejects(workload({ azure: true, tenant: TENANT, object: OBJECT }), /--audience/);
  await assert.rejects(workload({ azure: true, object: OBJECT, audience: 'api://coffre-acme' }), /--tenant/);

  assert.deepEqual(await workload({ fly: 'acme', 'org-id': '29873298', 'app-id': '3671581' }), {
    profile: 'fly', issuer: 'https://oidc.fly.io/acme', claims: { app_id: '3671581', org_id: '29873298' }, policy: {},
  });
  await assert.rejects(workload({ fly: 'acme', 'org-id': '29873298' }), /--app-id/);

  assert.deepEqual(await workload({ vercel: 'acme', 'owner-id': 'team_7Gw5ZMBpQA8h9GF832KGp7nw', 'project-id': 'prj_8bFh2nVq3eDcJ7tY5mWx' }), {
    profile: 'vercel',
    issuer: 'https://oidc.vercel.com/acme',
    claims: { environment: 'production', owner_id: 'team_7Gw5ZMBpQA8h9GF832KGp7nw', project_id: 'prj_8bFh2nVq3eDcJ7tY5mWx' },
    policy: {},
  });
  const preview = await workload({ vercel: 'acme', 'owner-id': 'team_7Gw5ZMBpQA8h9GF832KGp7nw', 'project-id': 'prj_8bFh2nVq3eDcJ7tY5mWx', 'vercel-environment': 'preview', issuer: 'https://oidc.vercel.com' });
  assert.deepEqual([preview.issuer, preview.claims.environment], ['https://oidc.vercel.com', 'preview']);
  await assert.rejects(workload({ vercel: 'acme', 'owner-id': 'team_7Gw5ZMBpQA8h9GF832KGp7nw', 'project-id': 'prj_8bFh2nVq3eDcJ7tY5mWx', audience: 'https://vercel.com/acme' }), /--audience is --azure's/);

  assert.deepEqual(await workload({ enrollment: true, replicas: '2', source: ['162.220.232.0/24'], 'minted-by': 'deploy' }), {
    profile: 'enrollment', issuer: null, claims: {}, policy: { replicas: 2, sources: ['162.220.232.0/24'], mintedBy: 'token:deploy' },
  });
  assert.deepEqual(await workload({ cloudflare: true }), { profile: 'cloudflare', issuer: null, claims: {}, policy: {} });
});

test("a workload binding's policy, from its flags: each one its profile takes, checked as the server checks it", async () => {
  const enrolled = await workload({
    enrollment: true, replicas: '3', approve: true, 'session-days': '14', 'overlap-minutes': '30', 'on-contention': 'alert', 'minted-by': 'service:deploy',
    reads: ['market/prod=STRIPE_WEBHOOK_SECRET,DATABASE_URL,STRIPE_WEBHOOK_SECRET', 'market/dev=*'], 'unsigned-uploads': true,
  });
  assert.deepEqual(enrolled.policy, {
    reads: { 'market/prod': ['DATABASE_URL', 'STRIPE_WEBHOOK_SECRET'], 'market/dev': '*' },
    replicas: 3, sessionDays: 14, overlapMinutes: 30, mintedBy: 'token:deploy', approve: true, unsignedUploads: true, onContention: 'alert',
  });
  assert.deepEqual((await workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, 'session-hours': '4', source: ['10.0.0.0/8,2001:db8::/32'] })).policy, { sessionHours: 4, sources: ['10.0.0.0/8', '2001:db8::/32'] });

  await assert.rejects(workload({ enrollment: true }), /replicas/);
  await assert.rejects(workload({ enrollment: true, replicas: 'two' }), /--replicas takes a whole number/);
  await assert.rejects(workload({ enrollment: true, replicas: '2', 'minted-by': 'ingest' }), /mintedBy names another service than service:ingest/);
  await assert.rejects(workload({ enrollment: true, replicas: '2', 'on-contention': 'ignore' }), /freeze or alert/);
  await assert.rejects(workload({ enrollment: true, replicas: '2', 'session-hours': '4' }), /an enrollment binding takes --reads, --source, --unsigned-uploads, --replicas, --minted-by, --approve, --session-days, --overlap-minutes, --on-contention, not --session-hours/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, replicas: '2' }), /an aws binding takes --reads, --source, --session-hours, --unsigned-uploads, not --replicas/);
  await assert.rejects(workload({ cloudflare: true, source: ['10.0.0.0/8'] }), /a cloudflare binding takes --reads, not --source/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, 'session-hours': '169' }), /sessionHours is a whole number from 1 to 168/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, source: ['10.0.0.1/8'] }), /--source takes CIDRs, such as 162.220.232.0\/24 or 2001:db8::\/32: 10.0.0.1\/8 is none/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, source: ['push'] }), /--source takes CIDRs, such as 162.220.232.0\/24: push is none/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, workload: true }), /--workload is for --github, --gitlab and --issuer/);
  await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, gcp: '1' }), /name one platform, not --aws and --gcp/);
  await assert.rejects(workload({ gcp: '1', tenant: TENANT }), /--tenant is --azure's/);
  // A claim the platform's flags set is theirs: a --claim of it would be dropped, so it is refused.
  await assert.rejects(workload({ kubernetes: 'ingest/api', claim: ['sub=system:serviceaccount:other:x'] }), /--kubernetes sets sub from its own flags/);
  await assert.rejects(workload({ vercel: 'acme', 'owner-id': 'team_7Gw5ZMBpQA8h9GF832KGp7nw', 'project-id': 'prj_8bFh2nVq3eDcJ7tY5mWx', claim: ['environment=preview'] }), /--vercel sets environment from its own flags/);
  // What narrows a CI run's binding narrows no workload's: refused, never dropped.
  for (const flag of ['branch', 'event', 'github-environment', 'workflow', 'namespace-id'] as const) {
    await assert.rejects(workload({ aws: `arn:aws:iam::${ACCOUNT}:role/ingest-task`, [flag]: flag === 'event' ? ['push'] : 'x' }), new RegExp(`--${flag} says which CI runs a --github or --gitlab binding takes: --aws has none`));
  }

  for (const bad of ['market=A', 'market/prod', 'market/prod=', 'market/prod/eu=A', 'market/prod=*,A']) assert.throws(() => readsFrom([bad]), /--reads takes|name keys, or \*/, bad);
  assert.throws(() => readsFrom(['market/prod=A', 'market/prod=B']), /names market\/prod twice/);
});

test("a CI run's binding is for a key-bound session with --workload, and a bearer one without, which takes no policy", async () => {
  const flags = { github: 'acme/api', workflow: 'deploy.yml', branch: 'main' };
  assert.equal((await bindingFrom(flags, lookup)).policy, undefined);
  const keyed = await bindingFrom({ ...flags, workload: true, reads: ['market/ci=NPM_TOKEN'] }, lookup, { service: 'token:ci' });
  assert.deepEqual(keyed.policy, { reads: { 'market/ci': ['NPM_TOKEN'] } });
  assert.equal(keyed.profile, 'github');
  await assert.rejects(bindingFrom({ ...flags, reads: ['market/ci=NPM_TOKEN'] }, lookup), /--reads is a key-bound session's: add --workload/);
  await assert.rejects(bindingFrom({ ...flags, source: ['10.0.0.0/8'] }, lookup), /--source is a key-bound session's: add --workload/);
  // On GitLab, a pipeline source is a word and a session's source a CIDR: both, apart.
  const gitlab = await bindingFrom({ gitlab: 'acme/api', branch: 'main', workload: true, source: ['push,web', '10.0.0.0/8'] }, lookup, { service: 'token:ci' });
  assert.deepEqual([gitlab.claims.pipeline_source, gitlab.policy], [['push', 'web'], { sources: ['10.0.0.0/8'] }]);
  await assert.rejects(bindingFrom({ github: 'acme/api', workflow: 'deploy.yml', branch: 'main', source: ['push'] }, lookup), /--source is a GitLab pipeline's, or a CIDR: push is neither/);
  const custom = await bindingFrom({ issuer: 'https://idp.acme.example', claim: ['sub=svc'], workload: true, 'session-hours': '2' }, lookup, { service: 'token:ci' });
  assert.deepEqual(custom.policy, { sessionHours: 2 });
});

test("a workload's plan says what it trusts, how its sessions live, and what each listed key exposes", () => {
  const plan = {
    profile: 'aws' as const,
    issuer: 'urn:coffre:aws',
    jwksUri: '',
    claims: { account: ACCOUNT, role_id: ROLE_ID },
    keys: null,
    scope: { 'market/prod': 'viewer' as const },
    withheld: [] as string[],
    replaces: [],
    policy: { reads: { 'market/prod': ['STRIPE_WEBHOOK_SECRET'] }, sources: ['10.0.0.0/8'], sessionHours: 4 },
  };
  assert.equal(describePlan('token:ingest', plan, null), [
    `Would trust AWS workloads running as role ${ROLE_ID} of account ${ACCOUNT} to sign in as service:ingest, for key-bound sessions:`,
    '  profile  aws',
    `  claims   account  ${ACCOUNT}`,
    `           role_id  ${ROLE_ID}`,
    '  reaches  viewer on market/prod',
    '  sessions key-bound, at most 4 h from each proof',
    '  reads    market/prod: STRIPE_WEBHOOK_SECRET, exposed if aws is breached',
    '  from     10.0.0.0/8',
    '',
  ].join('\n'));
  // A workload's plan says nothing of a CI run's events.
  assert.equal(describeEvents(plan), null);
  const enrollment = { ...plan, profile: 'enrollment' as const, issuer: 'urn:coffre:enrollment', claims: {}, policy: { replicas: 2, mintedBy: 'token:deploy' } };
  assert.equal(describePlan('token:api-prod', enrollment, null), [
    'Would trust workloads enrolled with a code minted for this binding to sign in as service:api-prod, for key-bound sessions:',
    '  profile  enrollment',
    '  reaches  viewer on market/prod',
    "  sessions key-bound, each renewed every 30 s and ended at its code's expiry, 30 days after minting",
    '  reads    nothing: every secret value is used through coffre, never read',
    '  codes    minted by its managers and service:deploy, 30 days each; up to 4 sessions of 2 replicas',
    '           freezes when a copy contends past 15 minutes of overlap',
    '',
  ].join('\n'));
  // A Worker's call through a service binding is no session.
  const cloudflare = { ...plan, profile: 'cloudflare' as const, issuer: 'urn:coffre:cloudflare', claims: {}, policy: {} };
  assert.doesNotMatch(describePlan('token:api-prod', cloudflare, null), /\n  sessions/);
  const gcp = { ...plan, profile: 'gcp' as const, issuer: 'https://accounts.google.com', jwksUri: 'https://www.googleapis.com/oauth2/v3/certs', claims: { sub: '104729384756102938475' }, policy: { keyAudience: true as const } };
  assert.match(describePlan('token:web', gcp, null), /\n  keys     https:\/\/www.googleapis.com\/oauth2\/v3\/certs\n.*\n  audience names the session's key: <publicUrl>#jkt=<thumbprint>\n/s);
  for (const [binding, says] of [
    [{ profile: 'kubernetes', issuer: 'https://oidc.prod.acme.example', claims: { sub: 'system:serviceaccount:ingest:api', 'kubernetes.io.serviceaccount.uid': SA_UID } }, `pods of service account ingest/api (UID ${SA_UID}) of the cluster https://oidc.prod.acme.example`],
    [{ profile: 'azure', issuer: `https://sts.windows.net/${TENANT}/`, claims: { tid: TENANT, oid: OBJECT } }, `Azure workloads of managed identity ${OBJECT} in tenant ${TENANT}`],
    [{ profile: 'vercel', issuer: 'https://oidc.vercel.com/acme', claims: { owner_id: 'team_1', project_id: 'prj_1', environment: 'production' } }, 'Vercel functions of project prj_1 of team team_1, in production'],
    [{ profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', claims: {} }, "Workers that call it through a service binding's props"],
  ] as const) {
    assert.equal(runsOf(binding as Parameters<typeof runsOf>[0]), says);
  }
});
