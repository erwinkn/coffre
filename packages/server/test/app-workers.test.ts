// The app in workerd, as it runs on Cloudflare (docs/design/0.16.md, "The
// server"): a request to the app Worker, its token hashed, the vault
// Worker called over the service binding, the vault's signer told over
// another, each Worker on a Hyperdrive binding of its own. app.test.ts
// holds what each route answers; this holds that a request goes all the
// way, and what it costs in connections.
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomBytes, verify as verifySignature } from 'node:crypto';
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
const { world } = await openConfiguredVault({ kek: { id: 'app-workers-test', key: VAULT_KEY }, owners: ['root@acme.example'], workloads: null });

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
/** `token:edge`, a Worker's service: a viewer of market, its `cloudflare` binding scoped to market/apis. */
const EDGE = 'token:edge';
let edgeBindingId: string;
/** `token:keys`, another Worker's service: a viewer of market, its `cloudflare` binding scoped to market/keys, which holds its signers' keys. */
const KEYS = 'token:keys';
let keysBindingId: string;
const MAC_KEY = 'a mac secrét';
const HOOK_SECRET = 'whsec_hook';
const SIGNING = generateKeyPairSync('ed25519');
const AWS_SECRET = 'aws/secret+0123456789';

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
  // What `keys` signs, checks and presigns with, over RPC.
  const keysEnv = environment(market, 'keys');
  const keyed = await Promise.all(Object.entries({
    MAC_KEY, HOOK_SECRET, SIGNING_KEY: SIGNING.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, AWS_ACCESS_KEY_ID: 'AKIAKEYS', AWS_SECRET_ACCESS_KEY: AWS_SECRET,
  }).map(([key, text]) => value(world, secret(keysEnv, key), text)));
  const tunnelHandle = credential(TUNNEL_HANDLE, ada, { kind: 'handle', scope: JSON.stringify([{ projectId: market.id, environmentId: data.id, role: 'viewer' }]), places: JSON.stringify([{ environmentId: data.id, personal: false }]) });
  tunnelHandleId = tunnelHandle.id;
  // Bo's alone: three values he marks, a key service giving out partway through.
  const lab = project('lab');
  const labProd = environment(lab, 'prod');
  const marked = await Promise.all(['K1', 'K2', 'K3'].map((key) => value(world, secret(labProd, key), key.toLowerCase())));
  const used = { lastUsedAt: new Date() };
  const github = identity(bo);
  const deploy = binding(DEPLOY, { policy: '{}', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]) });
  const edge = binding(EDGE, { profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', jwksUri: 'urn:coffre:cloudflare', policy: '{}', scope: JSON.stringify([{ projectId: market.id, environmentId: apis.id, role: 'viewer' }]) });
  edgeBindingId = edge.id;
  const keys = binding(KEYS, { profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', jwksUri: 'urn:coffre:cloudflare', policy: '{}', scope: JSON.stringify([{ projectId: market.id, environmentId: keysEnv.id, role: 'viewer' }]) });
  keysBindingId = keys.id;
  await write(
    world,
    ...rows('projects', market, lab),
    ...rows('environments', prod, staging, apis, data, keysEnv, labProd),
    ...rows('secrets', url, apiKey, region, tunnelUrl, ...keyed, ...marked),
    ...rows('roles', role(false, 'viewer', ['secret.read', 'secret.use'], []), role(false, 'developer', ['secret.read', 'secret.write']), role(true, 'member', [])),
    ...rows('policy', instance()),
    ...rows('principals', principal(ada), principal(bo), principal(DEPLOY), principal(EDGE), principal(KEYS), principal('token:ghost')),
    ...rows('identities', github),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'developer', { project: market }), grant(bo, 'developer', { project: lab }), grant(DEPLOY, 'viewer', { project: market }), grant(EDGE, 'viewer', { project: market }), grant(KEYS, 'viewer', { project: market }), grant('token:ghost', 'viewer', { project: market })),
    ...rows('bindings', deploy, edge, keys),
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
      services: [
        { binding: 'VAULT', service: name, entrypoint: 'Vault' },
        // As another Worker of the account binds coffre: the entrypoint, with props naming its service.
        { binding: 'COFFRE_EDGE', service: name, entrypoint: 'CoffreWorkload', props: { service: 'edge' } },
        { binding: 'COFFRE_TOKEN_EDGE', service: name, entrypoint: 'CoffreWorkload', props: { service: 'token:edge' } },
        { binding: 'COFFRE_KEYS', service: name, entrypoint: 'CoffreWorkload', props: { service: 'keys' } },
        { binding: 'COFFRE_GHOST', service: name, entrypoint: 'CoffreWorkload', props: { service: 'ghost' } },
        { binding: 'COFFRE_NO_PROPS', service: name, entrypoint: 'CoffreWorkload' },
      ],
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
  assert.deepEqual([(me.body.principal as { id: string }).id, me.body.environments], ['ada@acme.example', ['apis', 'data', 'keys', 'prod'].map((environment) => ({ project: 'market', environment, permissions: ['secret.read', 'secret.use'] }))]);
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
  assert.deepEqual(plan.body, { environment: 'market/apis', env: { API_KEY: HANDLE, REGION: 'eu-west-3' }, credentials: { echo: 'https://secrets.acme.example/use/market/apis/echo', ruled: 'https://secrets.acme.example/use/market/apis/ruled', once: 'https://secrets.acme.example/use/market/apis/once' }, tunnels: {}, left: [] });
  assert.deepEqual([planApp, planVault], [0, 2]);
});

test("a Worker bound to coffre: its props name its service, which uses a credential within its binding's scope and rules, never handed its value nor another's", { timeout: 120_000 }, async () => {
  // The stable URL, the binding naming one environment; and that environment by name. The Worker sends no token.
  for (const via of ['COFFRE_EDGE', 'COFFRE_TOKEN_EDGE']) {
    const used = await ask(`/as/${via}/use/echo/ping`);
    assert.equal(used.status, 200, JSON.stringify(used.body));
    assert.deepEqual(used.body, ECHOED);
  }
  const [named, , vaultAsked] = await opened(() => ask('/as/COFFRE_EDGE/use/market/apis/echo/ping', { headers: { 'x-request': 'one' } }));
  assert.equal(named.status, 200, JSON.stringify(named.body));
  assert.deepEqual(named.body, ECHOED);
  assert.ok(vaultAsked <= 1);

  // Where its grants reach and its binding does not: market/prod. A handle of ada's for market/apis, sent along, changes
  // nothing: the call is edge's whatever it carries.
  for (const init of [{}, bearer(HANDLE), { headers: { authorization: `DPoP ${WORKLOAD}` } }]) {
    const outside = await ask('/as/COFFRE_EDGE/use/market/prod/echo/ping', init);
    assert.equal(outside.status, 403, JSON.stringify(outside.body));
  }
  // A service with grants and no `cloudflare` binding, and a binding with no props: nobody.
  assert.equal((await ask('/as/COFFRE_GHOST/use/echo/ping')).status, 401);
  const none = await ask('/as/COFFRE_NO_PROPS/use/echo/ping');
  assert.deepEqual([none.status, none.body.reason], [403, 'props']);

  // Its credential's rules, default deny: `ruled` takes GET /ping alone.
  assert.equal((await ask('/as/COFFRE_EDGE/use/ruled/ping')).status, 200);
  assert.equal((await ask('/as/COFFRE_EDGE/use/ruled/pong')).status, 403);
  assert.equal((await ask('/as/COFFRE_EDGE/use/ruled/ping', { method: 'POST', body: '{}' })).status, 403);
  // Its limit, by its service's gate: one a minute.
  assert.equal((await ask('/as/COFFRE_EDGE/use/once/ping')).status, 200);
  const past = await ask('/as/COFFRE_EDGE/use/once/ping');
  assert.deepEqual([past.status, past.body.reason], [429, 'limit']);

  // Never a value: no plan, nothing but coffre's plugins, and the API refused.
  const plan = await ask('/as/COFFRE_EDGE/use/market/apis');
  assert.deepEqual([plan.status, plan.body.reason], [403, 'bound']);
  assert.equal((await ask('/as/COFFRE_EDGE/api/me')).status, 404);
  // A plugin that takes a token, vault-kv's, refuses a bound call as such: 403, not a fault.
  const kv = await ask('/as/COFFRE_EDGE/v1/secret/data/market/apis', { headers: { 'x-vault-token': HANDLE } });
  assert.deepEqual([kv.status, kv.body.reason], [403, 'bound']);
  // A coffre token the Worker sends along goes no further than coffre, wherever it is: a header, the URL or the body.
  for (const init of [{ headers: { 'x-forwarded': HANDLE } }, { headers: { 'x-forwarded': `DPoP ${WORKLOAD}` } }, { method: 'POST', body: `token=${HANDLE}` }]) {
    const sent = await ask('/as/COFFRE_EDGE/use/echo/ping', init);
    assert.equal(sent.status, 400, JSON.stringify(sent.body));
  }
  assert.equal((await ask(`/as/COFFRE_EDGE/use/echo/ping?token=${HANDLE}`)).status, 400);

  // A use logged as the service's, naming its binding and no credential.
  const entries = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending UNION ALL SELECT body FROM log`);
  const mine = entries.map((row) => JSON.parse(row.body) as { action: string; actor: string; credential: string | null; objects: string[] }).filter((entry) => entry.actor === EDGE);
  assert.ok(mine.length > 0);
  for (const entry of mine) assert.deepEqual([entry.action, entry.credential, entry.objects.includes(`binding:${edgeBindingId}`)], ['secret.read', null, true]);

  // Frozen, then revoked: the next call is refused, once the vault's memory is past.
  await amend(world, 'bindings', sql`id = ${edgeBindingId}`, { frozenAt: new Date() });
  await sleep(2100);
  const frozen = await ask('/as/COFFRE_EDGE/use/echo/ping');
  assert.deepEqual([frozen.status, frozen.body.reason], [403, 'frozen']);
  await amend(world, 'bindings', sql`id = ${edgeBindingId}`, { frozenAt: null, revokedAt: new Date(), revokedBy: 'root@acme.example' });
  await sleep(2100);
  assert.equal((await ask('/as/COFFRE_EDGE/use/echo/ping')).status, 401);
});

/** A method of coffre's, called over `binding` as a bound Worker calls it: what it answered, or what it threw. */
async function call(binding: string, method: 'sign' | 'verify' | 'presign', ...args: unknown[]): Promise<{ value?: unknown; thrown?: { name: string; message: string; status: number; code: string; reason?: string } }> {
  const response = await worker.fetch(`/rpc/${binding}`, { method: 'POST', body: JSON.stringify({ method, args }), signal: AbortSignal.timeout(20_000) } as never);
  return (await response.json()) as never;
}
/** Bytes as `/rpc` carries them to the Worker, which hands the method a Uint8Array. */
const bytes = (of: Uint8Array | string) => ({ bytes: Buffer.from(of).toString('base64') });
const mac = (message: Uint8Array | string) => createHmac('sha256', MAC_KEY).update(message).digest('hex');

test("a Worker bound to coffre calls sign, verify and presign over RPC: each the HTTP form's operation, as its service, answering what it made and refusing as it does", { timeout: 120_000 }, async () => {
  // An HMAC signer's signature of a string, its UTF-8, and of bytes: one use of the vault, then within its memory.
  const [signed, , vaultAsked] = await opened(() => call('COFFRE_KEYS', 'sign', 'mac', 'héllo'));
  assert.deepEqual([signed, vaultAsked], [{ value: mac('héllo') }, 1]);
  const binary = randomBytes(64);
  assert.deepEqual(await call('COFFRE_KEYS', 'sign', 'mac', bytes(binary)), { value: mac(binary) });
  // The environment by name gives the same; one past JSON's 1 MiB goes raw, as the SDK sends it.
  assert.deepEqual(await call('COFFRE_KEYS', 'sign', 'mac', 'héllo', { place: 'market/keys' }), { value: mac('héllo') });
  const long = randomBytes(1024 * 1024 + 7);
  assert.deepEqual(await call('COFFRE_KEYS', 'sign', 'mac', bytes(long)), { value: mac(long) });
  // A private key's, base64url, which its public key checks.
  const challenge = 'a dfns challenge';
  const byKey = await call('COFFRE_KEYS', 'sign', 'ed25519', challenge);
  assert.equal(typeof byKey.value, 'string', JSON.stringify(byKey));
  assert.ok(verifySignature(null, Buffer.from(challenge), SIGNING.publicKey, Buffer.from(byKey.value as string, 'base64url')));

  // A verifier's yes and no, and a signer's HMAC checks its own: a no is an answer, not a refusal.
  const body = '{"event":"paid"}';
  const header = `sha256=${createHmac('sha256', HOOK_SECRET).update(body).digest('hex')}`;
  assert.deepEqual(await call('COFFRE_KEYS', 'verify', 'hook', body, header), { value: true });
  assert.deepEqual(await call('COFFRE_KEYS', 'verify', 'hook', bytes(body), header), { value: true });
  assert.deepEqual(await call('COFFRE_KEYS', 'verify', 'hook', '{"event":"refunded"}', header), { value: false });
  assert.deepEqual(await call('COFFRE_KEYS', 'verify', 'mac', 'héllo', mac('héllo')), { value: true });

  // A presigned GET of the bucket's object: the access key's ID and a signature, never the secret, for as long as asked.
  const before = Date.now();
  const presigned = await call('COFFRE_KEYS', 'presign', 's3', '/reports/q3.pdf', { expiresIn: 600, query: { 'response-content-disposition': 'attachment' } });
  const { url, expiresAt } = presigned.value as { url: string; expiresAt: string };
  const signedUrl = new URL(url);
  assert.equal(`${signedUrl.origin}${signedUrl.pathname}`, 'https://bucket.s3.eu-west-3.amazonaws.com/reports/q3.pdf', JSON.stringify(presigned));
  assert.deepEqual([signedUrl.searchParams.get('X-Amz-Expires'), signedUrl.searchParams.get('X-Amz-Credential')?.split('/')[0], signedUrl.searchParams.get('response-content-disposition')], ['600', 'AKIAKEYS', 'attachment']);
  assert.ok(!url.includes(encodeURIComponent(AWS_SECRET)) && !url.includes(AWS_SECRET));
  assert.ok(Math.abs(Date.parse(expiresAt) - (before + 600_000)) < 5000, expiresAt);

  // Each refusal the HTTP form makes, thrown with its status, code and reason.
  const refused = async (binding: string, method: 'sign' | 'verify' | 'presign', args: unknown[], status: number, reason?: string) => {
    const { thrown } = await call(binding, method, ...args);
    assert.equal(thrown?.name, 'CoffreError', `${method} ${JSON.stringify(args)}: ${JSON.stringify(thrown)}`);
    assert.equal(thrown.status, status, `${method} ${JSON.stringify(args)}: ${JSON.stringify(thrown)}`);
    if (reason !== undefined) assert.equal(thrown.reason, reason, JSON.stringify(thrown));
    return thrown;
  };
  // What the deployment does not name, or names for another operation.
  await refused('COFFRE_KEYS', 'sign', ['nope', 'm'], 404);
  await refused('COFFRE_KEYS', 'sign', ['hook', 'm'], 404);
  await refused('COFFRE_KEYS', 'verify', ['ed25519', 'm', 'sig'], 404);
  await refused('COFFRE_KEYS', 'presign', ['echo', '/ping'], 404);
  // What the operation refuses: an upload, an hour past, a path out of the bucket, a message past the verifier's.
  await refused('COFFRE_KEYS', 'presign', ['s3', '/a', { method: 'PUT' }], 400);
  await refused('COFFRE_KEYS', 'presign', ['s3', '/a', { expiresIn: 7200 }], 400);
  await refused('COFFRE_KEYS', 'presign', ['s3', '/../other/a'], 400);
  await refused('COFFRE_KEYS', 'verify', ['hook', bytes(randomBytes(64 * 1024 + 1)), header], 413);
  // What RPC carries that the operation could not read.
  for (const [method, args] of [['sign', [42, 'm']], ['sign', ['mac', 42]], ['sign', ['mac', 'm', { place: 'market' }]], ['sign', ['mac', 'm', 'market/keys']], ['verify', ['hook', body, 42]], ['presign', ['s3', 42]], ['presign', ['s3', '/a', { query: { a: 1 } }]], ['presign', ['s3', '/a', { expiresIn: '600' }]]] as const) {
    const thrown = await refused('COFFRE_KEYS', method, [...args], 400);
    assert.equal(thrown.code, 'bad_request');
  }
  // Where its grants reach and its binding does not; a service with no `cloudflare` binding; a binding with no props.
  await refused('COFFRE_KEYS', 'sign', ['mac', 'm', { place: 'market/prod' }], 403);
  await refused('COFFRE_GHOST', 'sign', ['mac', 'm'], 401);
  await refused('COFFRE_NO_PROPS', 'sign', ['mac', 'm'], 403, 'props');
  // A signer's limit, by the service's gate.
  assert.deepEqual(await call('COFFRE_KEYS', 'sign', 'mac-once', 'm'), { value: mac('m') });
  await refused('COFFRE_KEYS', 'sign', ['mac-once', 'm'], 429, 'limit');

  // Each use logged as the service's, naming its binding and no credential.
  const entries = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending UNION ALL SELECT body FROM log`);
  const mine = entries.map((row) => JSON.parse(row.body) as { action: string; credential: string | null; actor: string; objects: string[] }).filter((entry) => entry.actor === KEYS);
  assert.ok(mine.length > 0);
  for (const entry of mine) assert.deepEqual([entry.action, entry.credential, entry.objects.includes(`binding:${keysBindingId}`)], ['secret.read', null, true]);

  // Frozen, once the vault's memory is past: refused as fetch is.
  await amend(world, 'bindings', sql`id = ${keysBindingId}`, { frozenAt: new Date() });
  await sleep(2100);
  await refused('COFFRE_KEYS', 'sign', ['mac', 'm'], 403, 'frozen');
  await refused('COFFRE_KEYS', 'presign', ['s3', '/a'], 403, 'frozen');
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
