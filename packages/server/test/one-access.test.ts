// One call to the vault for each request: checking a coffre credential asks
// the vault who its member is, and that answer is the caller, rather than
// a second call; and a page's render, which makes several API calls in
// process, checks its credential once for all of them. Every vault call
// costs a round trip to the vault Worker, and on Cloudflare the page that
// made seven of them was the slowest, and the likeliest to meet a hang.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';

import { SigninService } from '../src/api/signin.ts';
import { fetchApi, pageClient } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(ORIGIN);

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
/** Each principal the vault was asked about, in order. */
let asked: string[];
let runtime: CoffreRuntime;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  const vault: Vault = {
    ...deps.vault,
    access: (principal: string) => {
      asked.push(principal);
      return deps.vault.access(principal);
    },
  };
  if (auth.mode !== 'signin') throw new Error('unreachable');
  const service = new SigninService({ ...deps, vault, signin: auth.signin });
  runtime = {
    db: deps.db,
    vault,
    chainKey: deps.chainKey,

    signin: service,
    workloads: null,
    mcp: null,
    auth,
    publicUrl: ORIGIN,
    verifier: service,
    waitUntil,
  };
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Development' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  asked = [];
});

/** A CLI session for `email`, from an approved device login. */
async function cliToken(email: string): Promise<string> {
  const service = runtime.signin!;
  const started = await service.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await service.decideDevice(await contextFor(deps, email), started.userCode, true);
  const polled = await service.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  return polled.credential.token;
}

test('an API request with a coffre credential asks the vault once', async () => {
  const token = await cliToken(DEV);
  asked = [];
  for (const path of ['/api/me', '/api/projects', '/api/secrets/market/dev']) {
    const response = await fetchApi(new Request(`${ORIGIN}${path}`, { headers: { authorization: `Bearer ${token}` } }), runtime, { sourceIp: null });
    assert.equal(response.status, 200, path);
  }
  assert.deepEqual(asked, [`user:${DEV}`, `user:${DEV}`, `user:${DEV}`], 'one vault call for each request');
});

test("a page's render, its loaders calling the API at once, asks the vault once for all of them", async () => {
  const token = await cliToken(DEV);
  asked = [];
  // The browser's session cookie, as the page was asked for with it; a CLI token works the same as a cookie value here.
  const page = new Request(`${ORIGIN}/projects`, { headers: { cookie: `__Host-coffre_session=${token}` } });
  const client = pageClient(page, runtime, null);
  // As the shell and the projects page load: who is looking, how one signs in, the projects, and each environment's keys.
  const [me, , { projects }, { keys }] = await Promise.all([
    client.me(),
    client.auth(),
    client.projects.list(),
    client.secrets.list('market/dev'),
  ]);
  assert.equal(me.principal.id, DEV);
  assert.deepEqual([projects.map(({ slug }) => slug), keys], [['market'], []]);
  await client.me();
  assert.deepEqual(asked, [`user:${DEV}`], 'one vault call for the whole render');

  // A refusal is answered to every call of the render, each its own response.
  const signedOut = pageClient(new Request(`${ORIGIN}/projects`, { headers: { cookie: '__Host-coffre_session=coffre_cli_unknown' } }), runtime, null);
  const refused = await Promise.allSettled([signedOut.me(), signedOut.projects.list()]);
  assert.deepEqual(
    refused.map((outcome) => outcome.status === 'rejected' && (outcome.reason as { status: number }).status),
    [401, 401],
  );
});
