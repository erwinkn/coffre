// What a trust binding names, looked up over HTTP on the 0.16 table: a
// repository's, owner's or project's IDs, and the repositories the
// deployment's GitHub App is installed on, each for whoever sets up a
// service account, and asked of GitHub or GitLab by the app, never the
// vault. 0.14.7's assertions (its test/workload-bindings.test.ts), and what
// each costs; request-cost.test.ts holds the budgets.
import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';

import { PERMISSIONS } from '@coffre/core/access';
import { github, GitHubApp, githubApp, pkcs8Of, signin } from '@coffre/core/identity';
import { DevIdp, fakeInstallations } from '@coffre/conformance/idp';
import { credential, emptyDatabase, environment, grant, identity, instance, principal, project, role, rows, user, write } from '@coffre/vault/testing';

import { asApp, GITHUB_DEADLINE_MS } from '../src/api/routes/workloads.ts';
import { ApiError } from '../src/api/errors.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp, SESSION } from './app-fixture.ts';

const idp = new DevIdp();
await idp.start();

/** What the public APIs answer, by URL: a document, or a status; every URL asked, in order. */
const documents = new Map<string, unknown>();
const fetched: string[] = [];
const transport: WorkloadTransport = {
  async json(url) {
    fetched.push(url.href);
    const answer = documents.get(url.href);
    if (answer === undefined) throw FetchRefused.answered(url, 404);
    if (typeof answer === 'number') throw FetchRefused.answered(url, answer);
    return answer;
  },
};

const providers = [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })];
const app = await openApp({ auth: signin({ providers, workloads: { limits: processLimits(), github: githubApp(idp.githubApp.options) } }), transport, workloads: {} });
const { world } = app;
after(async () => {
  await app.close();
  await idp.stop();
});

const [root, ada, bo, dee, al, ivy] = [user('root'), user('ada'), user('bo'), user('dee'), user('al'), user('ivy')];

/**
 * Root owns the instance. Ada owns market by a grant, so manages its
 * access; Bo is a Developer of market/dev, inside the instance's setting,
 * so gives a service account what he holds there; Dee holds nothing, and
 * `ci` is a service account. Al and Ivy hold no grant, which the vault
 * names no role of: Al is an Admin scoped to market, so manages its
 * access; Ivy a Developer of the instance, so gives developer anywhere. `ada-token` is Ada's personal token, scoped
 * to market, and `ada-web` her browser's session. The policy row lets people set service accounts up anywhere;
 * `archived`, market is archived.
 */
async function seed(setting = '{"projects":"all","environments":"all"}', archived = false): Promise<void> {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market', archived ? { archivedAt: new Date(Date.UTC(2026, 10, 1)) } : {});
  const dev = environment(market, 'dev');
  const adas = identity(ada);
  await write(
    world,
    ...rows('roles', role(true, 'owner', [...PERMISSIONS]), role(true, 'member', []), role(true, 'admin', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage']),
      role(true, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'owner', [...PERMISSIONS]), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(dee), principal('token:ci'),
      principal(al, { role: 'admin', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }), principal(ivy, { role: 'developer' })),
    ...rows('projects', market),
    ...rows('environments', dev),
    ...rows('grants', grant(ada, 'owner', { project: market }), grant(bo, 'developer', { environment: dev }), grant('token:ci', 'developer', { environment: dev })),
    ...rows('policy', instance({ serviceAccounts: setting })),
    ...rows('identities', adas),
    ...rows('credentials', credential('root-cli', root), credential('ada-cli', ada), credential('bo-cli', bo), credential('dee-cli', dee), credential('ci-cli', 'token:ci'), credential('al-cli', al), credential('ivy-cli', ivy),
      credential('ada-web', ada, { kind: 'browser', identityId: adas.id }),
      credential('ada-token', ada, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'owner' }]) })),
  );
  // The schema's check, made once: no request below pays it.
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
}

before(() => seed());
beforeEach(() => {
  documents.clear();
  fetched.length = 0;
  idp.githubApp.installations = fakeInstallations();
  idp.githubApp.down = false;
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
/** A GET as `label`, with what it cost: the vault's calls and the app's statements. */
async function get(label: string, path: string): Promise<{ status: number; body: Body; calls: string[]; statements: number }> {
  const [calls, statements] = [app.calls.length, app.statements];
  const got = await app.request(`/api${path}`, { headers: { authorization: `Bearer ${label}` } });
  return { status: got.status, body: (await got.json()) as Body, calls: app.calls.slice(calls), statements: app.statements - statements };
}
const lookup = (input: Record<string, string>, label = 'root-cli') => get(label, `/workloads/lookup?${new URLSearchParams(input)}`);
const ids = async (input: Record<string, string>, label?: string) => {
  const { status, body } = await lookup(input, label);
  assert.equal(status, 200, JSON.stringify(body));
  return body;
};
const refused = async (input: Record<string, string>) => {
  const { status, body } = await lookup(input);
  return [status, body.error, body.message] as const;
};

test("a public repository's, owner's or project's IDs, under the host's names; a private one is not found, and its IDs are typed in", async () => {
  documents.set('https://api.github.com/users/ACME', { id: 9919, login: 'acme', type: 'Organization' });
  documents.set('https://api.github.com/repos/torvalds/linux', { id: 2325298, full_name: 'torvalds/linux', owner: { id: 1024025 } });
  documents.set('https://api.github.com/repos/Torvalds/Linux', { id: 2325298, full_name: 'torvalds/linux', owner: { id: 1024025 } });
  documents.set('https://gitlab.com/api/v4/projects/acme%2Fapi', { id: 345, path_with_namespace: 'acme/api', namespace: { id: 12 } });
  documents.set('https://gitlab.acme.example/api/v4/projects/infra%2Fdeploy', { id: 7, namespace: { id: 3 } });
  // Outside the GitHub App, through GitHub's public API.
  assert.deepEqual(await ids({ github: 'torvalds/linux' }), { github: 'torvalds/linux', repositoryId: '2325298', ownerId: '1024025' });
  // As GitHub names it, which its tokens' workflow_ref spells: a name typed in another case is the same repository.
  assert.deepEqual(await ids({ github: 'Torvalds/Linux' }), { github: 'torvalds/linux', repositoryId: '2325298', ownerId: '1024025' });
  // An owner alone, for a reusable workflow called from any of its repositories.
  assert.deepEqual(await ids({ github: 'ACME' }), { github: 'acme', ownerId: '9919' });
  assert.deepEqual(await ids({ gitlab: 'acme/api' }), { gitlab: 'acme/api', projectId: '345', namespaceId: '12' });
  // A project its host does not name back keeps the name asked.
  assert.deepEqual(await ids({ gitlab: 'infra/deploy', gitlabUrl: 'https://gitlab.acme.example' }), { gitlab: 'infra/deploy', projectId: '7', namespaceId: '3' });
  // A public one the App is not installed on, nor GitHub knows: not installed, in words the pages show.
  const missing = await lookup({ github: 'globex/secret' });
  assert.deepEqual([missing.status, missing.body.reason], [404, 'not_installed']);
  assert.match(String(missing.body.message), /the GitHub App is not installed on it: install it on globex, or type its IDs/);
  assert.deepEqual(await refused({ github: 'nobody-here' }), [404, 'not_found', 'api.github.com did not find it: for a private one, type its IDs']);
  // An answer without the IDs is a host that does not know it.
  documents.set('https://gitlab.com/api/v4/projects/acme%2Fodd', { id: '345' });
  assert.deepEqual(await refused({ gitlab: 'acme/odd' }), [404, 'not_found', 'GitLab does not know acme/odd']);
});

test("GitHub's hourly limit without signing in is said as such; a host that fails is a 503 that says so", async () => {
  documents.set('https://api.github.com/repos/globex/busy', 403);
  documents.set('https://api.github.com/users/busy', 429);
  documents.set('https://api.github.com/repos/globex/down', 502);
  for (const name of ['globex/busy', 'busy']) {
    const [status, error, message] = await refused({ github: name });
    assert.deepEqual([status, error], [429, 'too_many_requests']);
    assert.match(String(message), /this hour's are spent/);
  }
  const [status, error, message] = await refused({ github: 'globex/down' });
  assert.deepEqual([status, error], [503, 'unavailable']);
  assert.match(String(message), /api\.github\.com did not answer .*answered 502/);
});

test('what is asked is held first: a name of no shape, a GitLab URL a binding could not name, or nothing, a 400 with nothing fetched', async () => {
  for (const [input, words] of [
    [{ github: '../../users' }, /a GitHub repository is <owner>\/<name>, and an owner <owner>/],
    [{ github: 'acme/..' }, /a GitHub repository is <owner>\/<name>/],
    [{ gitlab: 'api' }, /a GitLab project is <group>\/<name>/],
    [{ gitlab: 'acme/api', gitlabUrl: 'http://10.0.0.1' }, /must use https/],
    [{ gitlab: 'acme/api', gitlabUrl: 'https://gitlab.internal' }, /must be a public host name/],
    [{}, /look up a GitHub repository or a GitLab project/],
  ] as const) {
    const [status, error, message] = await refused(input);
    assert.deepEqual([status, error], [400, 'bad_request'], JSON.stringify(input));
    assert.match(String(message), words);
  }
  assert.equal((await lookup({ github: 'acme', extra: 'x' })).status, 400);
  assert.deepEqual(fetched, []);
});

test('the App lists the repositories it is installed on, private ones too, and resolves one of them by name, private or not', async () => {
  const listed = await get('root-cli', '/workloads/repositories');
  assert.equal(listed.status, 200, JSON.stringify(listed.body));
  const answer = listed.body as unknown as { app: unknown; installations: string[]; repositories: { github: string }[]; truncated: boolean };
  assert.deepEqual(answer.app, { name: 'Coffre (dev)', installUrl: `${idp.origin}/github/apps/coffre-dev/installations/new` });
  // The suspended installation is left out.
  assert.deepEqual(answer.installations, ['acme', 'octo-dev']);
  assert.deepEqual(answer.repositories.find((each) => each.github === 'acme/infra'), { github: 'acme/infra', repositoryId: '41540', ownerId: '9919', private: true });
  assert.deepEqual([answer.repositories.length, answer.truncated], [6, false]);
  // Nothing public was asked, and the vault only who is calling.
  assert.deepEqual([listed.calls, listed.statements, fetched], [['caller'], 0, []]);

  assert.deepEqual(await ids({ github: 'acme/payments' }), { github: 'acme/payments', repositoryId: '41541', ownerId: '9919' });
  assert.deepEqual(fetched, []);
});

test('GitHub down is a 503 that says so, and to type the IDs; nothing the App holds reaches an answer', async () => {
  idp.githubApp.down = true;
  for (const path of ['/workloads/repositories', '/workloads/lookup?github=acme%2Finfra']) {
    const { status, body } = await get('root-cli', path);
    assert.deepEqual([status, body.error], [503, 'unavailable'], path);
    assert.match(String(body.message), /^GitHub answered \/[a-z/-]+ with 503; type its IDs meanwhile$/);
    assert.ok(!JSON.stringify(body).includes('ghs_') && !JSON.stringify(body).includes('PRIVATE KEY'));
  }
});

test("past the deadline, all of a call's requests to the App end, and it is 503 `deadline`", async () => {
  /** An App whose every request hangs until it is ended. */
  const ended: string[] = [];
  const hangs = new GitHubApp({ appId: idp.githubApp.appId, apiUrl: 'https://api.github.example', pkcs8: pkcs8Of(idp.githubApp.privateKey) }, {
    fetch: (input, init) =>
      new Promise((_, reject) => {
        init?.signal?.addEventListener('abort', () => {
          ended.push(String(input));
          reject(init.signal!.reason);
        });
      }),
  });
  const started = Date.now();
  await assert.rejects(asApp((signal) => hangs.repositories({ signal }), 50), (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.deepEqual([error.code, error.reason], ['unavailable', 'deadline']);
    assert.match(error.message, /^GitHub did not answer within 0\.05 s; type its IDs meanwhile$/);
    return true;
  });
  assert.ok(Date.now() - started < 5_000);
  assert.deepEqual(ended, ['https://api.github.example/app']);
  assert.equal(GITHUB_DEADLINE_MS, 20_000);
});

test('only those who set up service accounts may: whoever runs the instance, for one call to the vault; a person who gives one a grant somewhere, for two statements more', async () => {
  documents.set('https://api.github.com/users/acme', { id: 9919, login: 'acme' });
  // Al and Ivy by their instance roles alone, holding no grant.
  for (const [label, statements] of [['root-cli', 0], ['ada-cli', 2], ['bo-cli', 2], ['al-cli', 2], ['ivy-cli', 2]] as const) {
    for (const path of ['/workloads/lookup?github=acme', '/workloads/repositories']) {
      const got = await get(label, path);
      assert.deepEqual([got.status, got.calls, got.statements], [200, ['caller'], statements], `${label} ${path}`);
    }
  }
  const before = fetched.length;
  // Anyone else asks nothing outside: someone who holds nothing, a service account, a credential with a scope.
  for (const [label, statements] of [['dee-cli', 2], ['ci-cli', 0], ['ada-token', 0]] as const) {
    for (const path of ['/workloads/lookup?github=acme', '/workloads/repositories']) {
      const got = await get(label, path);
      assert.deepEqual([got.status, got.body.error, got.body.message, got.calls, got.statements], [403, 'forbidden', 'only those who set up service accounts may trust workloads', ['caller'], statements], `${label} ${path}`);
    }
  }
  assert.equal(fetched.length, before);
});

test("the instance's setting decides for whoever does not manage access: outside it, a Developer sets nothing up", async () => {
  await seed('{"projects":{"only":[]},"environments":"all"}');
  try {
    assert.equal((await get('bo-cli', '/workloads/repositories')).status, 403);
    assert.equal((await get('ivy-cli', '/workloads/repositories')).status, 403);
    // Ada manages market's access, which the setting does not narrow; Al too, by his instance role.
    assert.equal((await get('ada-cli', '/workloads/repositories')).status, 200);
    assert.equal((await get('al-cli', '/workloads/repositories')).status, 200);
  } finally {
    await seed();
  }
});

test('asked with the cookie from another site\'s page, both are refused before the vault or GitHub is asked; from coffre\'s own, answered', async () => {
  documents.set('https://api.github.com/users/acme', { id: 9919, login: 'acme' });
  for (const path of ['/workloads/lookup?github=acme', '/workloads/repositories']) {
    for (const site of [{ 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'same-site', origin: 'https://evil.acme.example' }, {}] as Record<string, string>[]) {
      const [calls, statements] = [app.calls.length, app.statements];
      const got = await app.request(`/api${path}`, { headers: { cookie: `${SESSION}=ada-web`, ...site } });
      assert.deepEqual([got.status, ((await got.json()) as Body).error, app.calls.slice(calls), app.statements - statements], [403, 'cross_origin', [], 0], `${path} ${JSON.stringify(site)}`);
    }
    const own = await app.request(`/api${path}`, { headers: { cookie: `${SESSION}=ada-web`, 'sec-fetch-site': 'same-origin' } });
    assert.equal(own.status, 200, path);
  }
  // Only the own page's lookup reached GitHub.
  assert.deepEqual(fetched, ['https://api.github.com/users/acme']);
});

test("an archived project's Owner still sets service accounts up there, as the vault admits one: archived places count", async () => {
  await seed(undefined, true);
  try {
    assert.equal((await get('ada-cli', '/workloads/repositories')).status, 200);
    assert.equal((await get('bo-cli', '/workloads/repositories')).status, 200);
    assert.equal((await get('dee-cli', '/workloads/repositories')).status, 403);
  } finally {
    await seed();
  }
});

test('without a GitHub App the pages are told there is none; with workloads off, each route says how to turn them on, and asks nothing', async () => {
  const bare = await openApp({ auth: signin({ providers, workloads: { limits: processLimits() } }), transport, workloads: {} });
  try {
    const got = await bare.request('/api/workloads/repositories', { headers: { authorization: 'Bearer root-cli' } });
    assert.deepEqual([got.status, await got.json()], [200, { app: null }]);
  } finally {
    await bare.close();
  }
  const off = await openApp();
  try {
    for (const path of ['/workloads/lookup?github=acme', '/workloads/repositories']) {
      const got = await off.request(`/api${path}`, { headers: { authorization: 'Bearer root-cli' } });
      const answer = (await got.json()) as Body;
      assert.deepEqual([got.status, answer.error, off.calls], [404, 'not_found', []], path);
      assert.match(String(answer.message), /signin\(\{ workloads/);
    }
  } finally {
    await off.close();
  }
});
