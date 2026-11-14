// The app in workerd, as it runs on Cloudflare (docs/design/0.16.md, "The
// server"): a request to the app Worker, its token hashed, the vault
// Worker called over the service binding, the vault's signer told over
// another, each Worker on a Hyperdrive binding of its own. app.test.ts
// holds what each route answers; this holds that a request goes all the
// way, and what it costs in connections.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import test, { after, before } from 'node:test';
import { fileURLToPath } from 'node:url';

import { bodyDigest, createProof, generateProofKey, thumbprint } from '@coffre/client/dpop';
import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { amend, APP_URL, binding, credential, emptyDatabase, environment, grant, identity, instance, openConfiguredVault, principal, project, role, rows, secret, session, slowPostgres, user, value, VAULT_URL, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { appClient, tunnelListener } from './tunnel-listener.ts';

const VAULT_KEY = randomBytes(32).toString('base64');
// The instance's rows are written here as the Worker's vault would write them: under its keys.
const { world } = await openConfiguredVault({ kek: { id: 'app-workers-test', key: VAULT_KEY }, owners: ['root@acme.example'] });

const [ada, bo] = [user('ada'), user('bo')];
const BROWSER = `coffre_web_${'b'.repeat(43)}`;
const SESSION = '__Host-coffre_session';
/** A workload's session of `token:deploy`, bound to `KEY`. */
const DEPLOY = 'token:deploy';
const WORKLOAD = generateToken('workload');
const KEY = await generateProofKey();
/** A handle of ada's, for market/apis, which the proxy takes in place of `API_KEY`. */
const HANDLE = generateToken('handle');
const API_KEY = 'sk_workers_0123456789';
/** What the upstream answers for a request with `API_KEY` in: its `authorization`, reversed (test/workers/app-worker.ts). */
const ECHOED = { path: '/v1/ping', reversed: [...`Bearer ${API_KEY}`].reverse().join('') };
/** A handle of ada's, for market/data, whose `TUNNEL_URL` is the suite's database, as the app's login: the tunnel `db` reaches it. */
const TUNNEL_HANDLE = generateToken('handle');
let tunnelHandleId: string;

let worker: Unstable_DevWorker;
let dir: string;
/** Each Worker's Postgres, a few milliseconds away as Hyperdrive's is, counting the connections made to it. */
let app: Awaited<ReturnType<typeof slowPostgres>>;
let vault: Awaited<ReturnType<typeof slowPostgres>>;

before(async () => {
  await emptyDatabase(world.owner);
  const market = project('market');
  const [prod, staging, apis, data] = [environment(market, 'prod'), environment(market, 'staging', { protected: true }), environment(market, 'apis'), environment(market, 'data')];
  const url = await value(world, secret(prod, 'DATABASE_URL'), 'postgres://märkt');
  const apiKey = await value(world, secret(apis, 'API_KEY'), API_KEY);
  // A plain value no credential covers: what `coffre run`'s plan hands the app as it is.
  const region = await value(world, secret(apis, 'REGION'), 'eu-west-3', { plain: true });
  const tunnelUrl = await value(world, secret(data, 'TUNNEL_URL'), `${APP_URL}?sslmode=disable`, { sensitive: true });
  const tunnelHandle = credential(TUNNEL_HANDLE, ada, { kind: 'handle', scope: JSON.stringify([{ projectId: market.id, environmentId: data.id, role: 'viewer' }]), places: JSON.stringify([{ environmentId: data.id, personal: false }]) });
  tunnelHandleId = tunnelHandle.id;
  // Bo's alone: three values he marks, a key service giving out partway through.
  const lab = project('lab');
  const labProd = environment(lab, 'prod');
  const marked = await Promise.all(['K1', 'K2', 'K3'].map((key) => value(world, secret(labProd, key), key.toLowerCase())));
  const used = { lastUsedAt: new Date() };
  const github = identity(bo);
  const deploy = binding(DEPLOY, { policy: '{}', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]) });
  await write(
    world,
    ...rows('projects', market, lab),
    ...rows('environments', prod, staging, apis, data, labProd),
    ...rows('secrets', url, apiKey, region, tunnelUrl, ...marked),
    ...rows('roles', role(false, 'viewer', ['secret.read', 'secret.use'], []), role(false, 'developer', ['secret.read', 'secret.write']), role(true, 'member', [])),
    ...rows('policy', instance()),
    ...rows('principals', principal(ada), principal(bo), principal(DEPLOY)),
    ...rows('identities', github),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'developer', { project: market }), grant(bo, 'developer', { project: lab }), grant(DEPLOY, 'viewer', { project: market })),
    ...rows('bindings', deploy),
    ...rows('credentials', credential('ada-cli', ada, used), credential('bo-cli', bo, used), credential(BROWSER, bo, { ...used, kind: 'browser', identityId: github.id }), session(WORKLOAD, deploy, { jkt: await thumbprint(KEY.jwk), places: JSON.stringify([{ environmentId: apis.id }]) }),
      credential(HANDLE, ada, { kind: 'handle', scope: JSON.stringify([{ projectId: market.id, environmentId: apis.id, role: 'viewer' }]), places: JSON.stringify([{ environmentId: apis.id, personal: false }]) }), tunnelHandle),
  );

  [app, vault] = await Promise.all([slowPostgres(3, APP_URL), slowPostgres(3, VAULT_URL)]);
  dir = mkdtempSync(join(tmpdir(), 'coffre-app-worker-'));
  const name = 'coffre-app-workers-test';
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { VAULT_KEY, APP_KEY: randomBytes(32).toString('base64') },
      hyperdrive: [
        { binding: 'HYPERDRIVE', id: 'app-workers-test', localConnectionString: app.url },
        { binding: 'VAULT_HYPERDRIVE', id: 'app-workers-test-vault', localConnectionString: vault.url },
      ],
      // As a deployment's two Workers: the app binds the vault's entrypoint, and the vault its signer.
      services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
      durable_objects: { bindings: [{ name: 'SIGNER', class_name: 'CoffreSigner' }, { name: 'GATES', class_name: 'CoffreGates' }, { name: 'SOCKETS', class_name: 'CoffreSockets' }] },
      migrations: [{ tag: 'signer', new_sqlite_classes: ['CoffreSigner'] }, { tag: 'gates', new_sqlite_classes: ['CoffreGates'] }, { tag: 'sockets', new_sqlite_classes: ['CoffreSockets'] }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/app-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
}, { timeout: 120_000 });

after(async () => {
  await worker?.stop();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  await Promise.all([app?.close(), vault?.close(), world.close()]);
});

type Answer = { status: number; body: Record<string, unknown>; headers: Headers };
async function ask(path: string, init: RequestInit = {}): Promise<Answer> {
  const response = await worker.fetch(path, { ...init, signal: AbortSignal.timeout(20_000) } as never);
  return { status: response.status, body: (await response.json()) as Record<string, unknown>, headers: response.headers as unknown as Headers };
}
const bearer = (label: string, init: RequestInit = {}) => ({ ...init, headers: { authorization: `Bearer ${label}`, ...(init.headers as Record<string, string> | undefined) } });
/** What a request opened: the app's connections to Postgres, and the vault Worker's. */
async function opened<T>(run: () => Promise<T>): Promise<[T, number, number]> {
  const [mine, theirs] = [app.opened, vault.opened];
  const result = await run();
  return [result, app.opened - mine, vault.opened - theirs];
}
const count = async (table: 'log_pending') => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;

// First, while the signer has never been told of an entry and runs nothing of its own: every connection counted is a request's.
test("a page's read: the vault asked once who is asking, on one connection, the app's query on another; nothing more within the vault's memory", { timeout: 120_000 }, async () => {
  // The app's first request asks whether its database is migrated, once an isolate; the vault's first call, whether the
  // database is adopted, of the signer, which signs what the instance was written with on a connection of its own.
  assert.equal((await ask('/api/me')).status, 401);
  assert.equal((await ask('/api/me', bearer('nobody'))).status, 401);
  const [me, mine, theirs] = await opened(() => ask('/api/me', bearer('ada-cli')));
  assert.equal(me.status, 200, JSON.stringify(me.body));
  assert.deepEqual([(me.body.principal as { id: string }).id, me.body.environments], ['ada@acme.example', ['apis', 'data', 'prod'].map((environment) => ({ project: 'market', environment, permissions: ['secret.read', 'secret.use'] }))]);
  assert.deepEqual([mine, theirs], [1, 1]);
  assert.ok(me.headers.has('content-security-policy'));
  // Asked again at once: the vault remembers its rows, and opens no connection; the app lists again.
  assert.deepEqual((await opened(() => ask('/api/me', bearer('ada-cli')))).slice(1), [1, 0]);

  // A page's render, two loaders side by side on the browser's session: one ask of the vault, and one connection of the app's.
  const [page, pages, asks] = await opened(() => ask('/page', { headers: { cookie: `${SESSION}=${BROWSER}` } }));
  assert.deepEqual([page.status, page.body], [200, { who: 'bo@acme.example', same: true }]);
  assert.deepEqual([pages, asks], [1, 1]);

  // No credential, and one the vault does not know: neither reaches the app's database, and only the second the vault's.
  assert.deepEqual((await opened(() => ask('/api/reveals', { method: 'POST', body: '{"path":"market/prod"}' }))).slice(1), [0, 0]);
  const [nobody, none, one] = await opened(() => ask('/api/me', bearer('nobody')));
  assert.deepEqual([nobody.status, nobody.body.error, none, one], [401, 'unauthenticated', 0, 1]);
});

test('a reveal and a write go all the way: the app opens no connection, the vault decides, and the signer signs their entries', { timeout: 120_000 }, async () => {
  const [read, mine] = await opened(() => ask('/api/reveals', bearer('ada-cli', { method: 'POST', body: JSON.stringify({ path: 'market/prod/DATABASE_URL' }) })));
  assert.deepEqual([read.status, read.body.values, mine], [200, { DATABASE_URL: 'postgres://märkt' }, 0], JSON.stringify(read.body));

  // Ada views: her write is refused. Bo's, from coffre's own page on his browser's session, is made.
  const patch = (headers: Record<string, string>) => ask('/api/secrets/market/prod', { method: 'PATCH', headers, body: JSON.stringify({ DATABASE_URL: 'postgres://next', API_KEY: 'a new këy' }) });
  const refused = await patch({ authorization: 'Bearer ada-cli' });
  assert.deepEqual([refused.status, refused.body.error, refused.body.reason], [403, 'vault_refused', 'no_access']);
  const forged = await patch({ cookie: `${SESSION}=${BROWSER}`, 'sec-fetch-site': 'cross-site' });
  assert.deepEqual([forged.status, forged.body.error], [403, 'cross_origin']);
  const [written, wrote] = await opened(() => patch({ cookie: `${SESSION}=${BROWSER}`, 'sec-fetch-site': 'same-origin' }));
  assert.deepEqual([written.status, written.body.keys, wrote], [200, { DATABASE_URL: { version: 2, sensitivity: 'secret' }, API_KEY: { version: 1, sensitivity: 'secret' } }, 0], JSON.stringify(written.body));

  // Read back once the vault's memory of the first read has run out.
  await sleep(2100);
  const again = await ask('/api/reveals', bearer('ada-cli', { method: 'POST', body: JSON.stringify({ path: 'market/prod' }) }));
  assert.deepEqual([again.status, again.body.values], [200, { API_KEY: 'a new këy', DATABASE_URL: 'postgres://next' }]);

  // Two reads, the write and Ada's refused write: each entry signed, nothing left waiting.
  for (let waited = 0; (await count('log_pending')) > 0; waited += 250) {
    assert.ok(waited < 15_000, 'the signer has taken every entry');
    await sleep(250);
  }
  const entries = (await rowsOf<{ kept: boolean; body: string }>(world.owner, sql`SELECT kept, body FROM log ORDER BY seq`)).map(({ kept, body }) => [kept, (JSON.parse(body) as { action: string }).action, (JSON.parse(body) as { actor: string | null }).actor]);
  // After the instance's own writing: Ada's read, her refused write, which ages out as reads do, Bo's write, kept for good, and her second read.
  assert.deepEqual(entries.slice(-4), [[false, 'secret.read', ada], [false, 'secret.write', ada], [true, 'secret.write', bo], [false, 'secret.read', ada]]);
});

test("a person reads back what they just wrote: get, set, get on one CLI session within the vault's memory, at one more read of the vault's", { timeout: 120_000 }, async () => {
  const get = (path: string) => ask('/api/reveals', bearer('bo-cli', { method: 'POST', body: JSON.stringify({ path }) }));
  // `coffre get`, of one key and of the whole environment.
  assert.deepEqual((await get('market/prod/DATABASE_URL')).body.values, { DATABASE_URL: 'postgres://next' });
  assert.equal((await get('market/prod')).status, 200);
  // `coffre set`, at once.
  const set = await ask('/api/secrets/market/prod', bearer('bo-cli', { method: 'PATCH', body: JSON.stringify({ DATABASE_URL: 'postgres://third' }) }));
  assert.equal(set.status, 200, JSON.stringify(set.body));
  // `coffre get` again, within the memory: the value just written, each read the vault's own, on a connection of its own.
  const [one, , oneRead] = await opened(() => get('market/prod/DATABASE_URL'));
  const [whole, , wholeRead] = await opened(() => get('market/prod'));
  assert.deepEqual([one.body.values, (whole.body.values as Record<string, string>).DATABASE_URL, oneRead, wholeRead], [{ DATABASE_URL: 'postgres://third' }, 'postgres://third', 1, 1]);
});

test("a workload's session on Workers: its service's gate, a Durable Object, gives the nonce and takes each proof once, before the vault is asked", { timeout: 120_000 }, async () => {
  const URL_ME = 'https://secrets.acme.example/api/me';
  const asSession = async (nonce?: string, proof?: string) => ({
    headers: { authorization: `DPoP ${WORKLOAD}`, dpop: proof ?? (await createProof(KEY, { method: 'GET', url: URL_ME, token: WORKLOAD, ...(nonce === undefined ? {} : { nonce }) })) },
  });
  const [first, , none] = await opened(async () => ask('/api/me', await asSession()));
  assert.deepEqual([first.status, first.body.reason, none], [401, 'use_dpop_nonce', 0]);
  const nonce = first.headers.get('dpop-nonce');
  assert.ok(nonce !== null);
  const proof = await createProof(KEY, { method: 'GET', url: URL_ME, token: WORKLOAD, nonce });
  const me = await ask('/api/me', await asSession(nonce, proof));
  assert.equal(me.status, 200, JSON.stringify(me.body));
  assert.deepEqual(me.body.principal, { type: 'service', id: 'deploy' });
  assert.ok(me.headers.get('dpop-nonce') !== null);
  const [replayed, , asked] = await opened(async () => ask('/api/me', await asSession(nonce, proof)));
  assert.deepEqual([replayed.status, replayed.body.reason, asked], [401, 'replayed', 0]);
});

test('a request through the credential proxy on Workers: one use of the vault, by a handle or by a session its gate took, and the value in, never kept', { timeout: 120_000 }, async () => {
  // A handle, where `echo` takes its key: the app reads its row for the place, one connection; the vault one.
  const [byHandle, appOpened, vaultOpened] = await opened(() => ask('/use/echo/ping', bearer(HANDLE)));
  assert.equal(byHandle.status, 200, JSON.stringify(byHandle.body));
  assert.deepEqual(byHandle.body, ECHOED);
  assert.deepEqual([appOpened, vaultOpened], [1, 1]);

  // A session: its proof signs the request whole, under its gate's nonce.
  const url = 'https://secrets.acme.example/use/echo/ping';
  const asSession = async (nonce?: string) => {
    const content = { headers: { 'x-request': 'one' }, body: await bodyDigest(new Uint8Array()) };
    const dpop = await createProof(KEY, { method: 'GET', url, token: WORKLOAD, content, ...(nonce === undefined ? {} : { nonce }) });
    return { headers: { authorization: `DPoP ${WORKLOAD}`, dpop, ...content.headers } };
  };
  const first = await ask('/use/echo/ping', await asSession());
  assert.deepEqual([first.status, first.body.reason], [401, 'use_dpop_nonce']);
  const [bySession, , vaultAsked] = await opened(async () => ask('/use/echo/ping', await asSession(first.headers.get('dpop-nonce')!)));
  assert.equal(bySession.status, 200, JSON.stringify(bySession.body));
  assert.deepEqual(bySession.body, ECHOED);
  assert.ok(bySession.headers.get('dpop-nonce') !== null);
  assert.equal(vaultAsked, 1);

  // `coffre run`'s plan through the handle: the peek, each key's nature through the binding, then one use of what the app
  // is handed, each its own connection; none of the app's.
  const [plan, planApp, planVault] = await opened(() => ask('/use/market/apis', bearer(HANDLE)));
  assert.equal(plan.status, 200, JSON.stringify(plan.body));
  assert.deepEqual(plan.body, { environment: 'market/apis', env: { API_KEY: HANDLE, REGION: 'eu-west-3' }, credentials: { echo: 'https://secrets.acme.example/use/market/apis/echo' }, tunnels: {}, left: [] });
  assert.deepEqual([planApp, planVault], [0, 2]);
});

test("a tunnel on Workers: `coffre.upgrade` sends the WebSocket to its object, which the vault admits with one use, and a revocation ends at its next check", { timeout: 120_000 }, async () => {
  const listener = await tunnelListener(`ws://${worker.address}:${worker.port}/use/market/data/db`, TUNNEL_HANDLE);
  try {
    const client = appClient(listener.port, TUNNEL_HANDLE);
    // The object's first WebSocket: the migration door and the handle's row on one connection of the app's; the vault's
    // use at admission and its peek before the login, each a connection of the vault's.
    const [rows, appOpened, vaultOpened] = await opened(async () => [...(await client.unsafe('SELECT current_user AS who'))]);
    assert.deepEqual(rows, [{ who: 'coffre_runtime' }]);
    assert.deepEqual([appOpened, vaultOpened], [1, 2]);
    const revoked = Date.now();
    await amend(world, 'credentials', sql`id = ${tunnelHandleId}`, { revokedAt: new Date(), revokedBy: ada });
    // A check a second, ten to answer at most: the next one ends it.
    const ended = await client.ended;
    assert.ok(ended - revoked < 4000, `${ended - revoked} ms`);
    await client.end();
    const another = appClient(listener.port, TUNNEL_HANDLE);
    await assert.rejects(another.unsafe('SELECT 1'), 'nor is a new one let in');
    await another.end();
  } finally {
    listener.close();
  }
});

test("a key service that gives out partway through a mark, behind the vault's RPC: 503 unavailable with when to ask again, nothing written, and the same request made whole once it answers", { timeout: 120_000 }, async () => {
  const mark = () => ask('/api/secrets/lab/prod', bearer('bo-cli', { method: 'PATCH', body: JSON.stringify({ K1: { sensitivity: 'sensitive' }, K2: { sensitivity: 'sensitive' }, K3: { sensitivity: 'sensitive' } }) }));
  const versions = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM secret_versions`))[0]!.n;
  const before = await versions();
  // Three keys, each opened then sealed again: six calls of the key service's, the fifth failing.
  await worker.fetch('/key-service', { method: 'POST', body: '4' } as never);
  const failed = await mark();
  const { calls } = (await (await worker.fetch('/key-service')).json()) as { calls: number };
  assert.deepEqual([failed.status, failed.headers.get('retry-after'), failed.body.error, calls], [503, '5', 'unavailable', 5], JSON.stringify(failed.body));
  assert.equal(await versions(), before);
  // Asked again, the key service answering: all three marked.
  const again = await mark();
  assert.deepEqual([again.status, again.body.keys], [200, { K1: { version: 2, sensitivity: 'sensitive' }, K2: { version: 2, sensitivity: 'sensitive' }, K3: { version: 2, sensitivity: 'sensitive' } }], JSON.stringify(again.body));
  assert.equal(await versions(), before + 3);
});
