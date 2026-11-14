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

import { createProof, generateProofKey, thumbprint } from '@coffre/client/dpop';
import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { APP_URL, binding, credential, emptyDatabase, environment, grant, identity, instance, openConfiguredVault, principal, project, role, rows, secret, session, slowPostgres, user, value, VAULT_URL, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

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

let worker: Unstable_DevWorker;
let dir: string;
/** Each Worker's Postgres, a few milliseconds away as Hyperdrive's is, counting the connections made to it. */
let app: Awaited<ReturnType<typeof slowPostgres>>;
let vault: Awaited<ReturnType<typeof slowPostgres>>;

before(async () => {
  await emptyDatabase(world.owner);
  const market = project('market');
  const [prod, staging] = [environment(market, 'prod'), environment(market, 'staging', { protected: true })];
  const url = await value(world, secret(prod, 'DATABASE_URL'), 'postgres://märkt');
  const used = { lastUsedAt: new Date() };
  const github = identity(bo);
  const deploy = binding(DEPLOY, { policy: '{}', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]) });
  await write(
    world,
    ...rows('projects', market),
    ...rows('environments', prod, staging),
    ...rows('secrets', url),
    ...rows('roles', role(false, 'viewer', ['secret.read'], []), role(false, 'developer', ['secret.read', 'secret.write']), role(true, 'member', [])),
    ...rows('policy', instance()),
    ...rows('principals', principal(ada), principal(bo), principal(DEPLOY)),
    ...rows('identities', github),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'developer', { project: market }), grant(DEPLOY, 'viewer', { project: market })),
    ...rows('bindings', deploy),
    ...rows('credentials', credential('ada-cli', ada, used), credential('bo-cli', bo, used), credential(BROWSER, bo, { ...used, kind: 'browser', identityId: github.id }), session(WORKLOAD, deploy, { jkt: await thumbprint(KEY.jwk), places: JSON.stringify([{ environmentId: prod.id }]) })),
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
      durable_objects: { bindings: [{ name: 'SIGNER', class_name: 'CoffreSigner' }, { name: 'GATES', class_name: 'CoffreGates' }] },
      migrations: [{ tag: 'signer', new_sqlite_classes: ['CoffreSigner'] }, { tag: 'gates', new_sqlite_classes: ['CoffreGates'] }],
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
  // The app's first request asks whether its database is migrated, once an isolate.
  assert.equal((await ask('/api/me')).status, 401);
  const [me, mine, theirs] = await opened(() => ask('/api/me', bearer('ada-cli')));
  assert.equal(me.status, 200, JSON.stringify(me.body));
  assert.deepEqual([(me.body.principal as { id: string }).id, me.body.environments], ['ada@acme.example', [{ project: 'market', environment: 'prod', permissions: ['secret.read'] }]]);
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
