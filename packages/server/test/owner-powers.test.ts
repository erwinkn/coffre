// What an Owner of a place does there that nobody else does (R30,
// docs/design/roles.md): make a sensitive value a secret in place, its
// value kept and never shown by it, and take an environment's protection
// off. An Owner of the whole instance, an Owner of the project by a grant,
// or one whose instance role is scoped to it; as a person, on no
// credential's scope. An Owner reads any value there anyway, through a
// service account they give read (break-glass): retyping protects nothing
// from them. Everyone else writes the value again, and leaves prod
// protected.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { defineSignin, github } from '@coffre/core/identity';
import { asc, eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const OLGA = 'user:olga@acme.example';
const LENA = 'user:lena@acme.example';
const BILL = 'user:bill@acme.example';
const PAT = 'user:pat@acme.example';
const MAYA = 'user:maya@acme.example';
const OPS = 'token:ops';
const SIGNIN = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })] });
const VALUE = 'sk_live_sensitive_0123456789';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
/** An Owner of the whole instance. */
let root: CoffreClient;
/** An Owner of market, by a grant on it. */
let olga: CoffreClient;
/** An Owner of market, as her instance role scoped to it. */
let lena: CoffreClient;
/** An Owner of billing, another project. */
let bill: CoffreClient;
/** An Owner of every prod: her instance role is scoped to environments, so she owns no project. */
let pat: CoffreClient;
/** A Maintainer of market, who manages its environments and protects them. */
let maya: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
  runtime = {
    db: deps.db,
    vault: deps.vault,
    chainKey: deps.chainKey,
    signin,
    workloads: null,
    mcp: null,
    auth: { mode: 'signin', signin: SIGNIN },
    publicUrl: ORIGIN,
    verifier: signin,
    waitUntil,
    schema: { migrated: true },
    rotateAfterDays: 365,
    plugins: [],
  } as CoffreRuntime;
  root = clientFor(deps, ROOT);
  await root.projects.create('market');
  await root.projects.create('billing');
  for (const environment of ['dev', 'prod']) await root.environments.create(`market/${environment}`);
  await root.secrets.set('market/prod', Object.fromEntries(['API_KEY', 'ROOT_KEY', 'OLGA_KEY', 'LENA_KEY'].map((key) => [key, { value: VALUE, sensitivity: 'sensitive' }])));
  await root.members.add(OLGA);
  await root.access.set(OLGA, { market: 'owner' });
  await root.members.add(LENA, { role: 'owner', scope: { projects: { only: ['market'] } } });
  await root.members.add(BILL, { role: 'owner', scope: { projects: { only: ['billing'] } } });
  await root.members.add(PAT, { role: 'owner', scope: { projects: 'all', environments: { only: ['prod'] } } });
  await root.members.add(MAYA);
  await root.access.set(MAYA, { market: 'maintainer' });
  await root.members.add(OPS);
  await root.access.set(OPS, { market: 'developer' });
  [olga, lena, bill, pat, maya] = [OLGA, LENA, BILL, PAT, MAYA].map((member) => clientFor(deps, member.slice('user:'.length)));
});

/** The API as a request with this bearer token sees it, through the app's front door. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });
}

/** The status a call answers with, or 200. */
async function status(call: Promise<unknown>): Promise<number> {
  try {
    await call;
    return 200;
  } catch (error) {
    return (error as { status: number }).status;
  }
}

async function entries(action: string) {
  const rows = await db.owner.select().from(auditLog).where(eq(auditLog.action, action)).orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

const levels = async (path: string) => Object.fromEntries((await root.secrets.list(path)).keys.map((entry) => [entry.key, entry.sensitivity]));
const environmentOf = async (client: CoffreClient, path: string) => {
  const [project, environment] = path.split('/');
  return (await client.projects.list()).projects.find((each) => each.slug === project)!.environments.find((each) => each.slug === environment)!;
};

test('an Owner of the project, or of the whole instance, makes a sensitive value a secret in place: its value kept, never in the answer, its own entry in the log', async () => {
  const reads = (await entries('secret.read')).length;
  for (const [client, key] of [[root, 'ROOT_KEY'], [olga, 'OLGA_KEY'], [lena, 'LENA_KEY']] as const) {
    assert.equal((await client.secrets.list('market/prod')).loosenable, true, key);
    const result = await client.secrets.set('market/prod', { [key]: { sensitivity: 'secret' } });
    assert.deepEqual(result.keys[key], { version: 2, sensitivity: 'secret' });
    assert.ok(!JSON.stringify(result).includes(VALUE), 'the answer carries no value');
    assert.deepEqual((await root.secrets.history(`market/prod/${key}`)).versions.map(({ version, sensitivity }) => [version, sensitivity]), [[2, 'secret'], [1, 'sensitive']]);
    // A secret now, read by whoever reads secrets there: its Owner, as anyone's reveal, logged as one.
    assert.deepEqual((await client.secrets.reveal(`market/prod/${key}`)).values, { [key]: VALUE });
  }
  assert.equal((await entries('secret.read')).length, reads + 3, 'the loosening opened nothing: each read is the reveal after it');
  assert.deepEqual(await levels('market/prod'), { API_KEY: 'sensitive', LENA_KEY: 'secret', OLGA_KEY: 'secret', ROOT_KEY: 'secret' });

  // Its own entry, saying both levels and the version whose value it kept, naming the vault's rewrap, which says it too.
  const [loosened] = (await entries('secret.loosen')).filter((entry) => entry.metadata.key === 'OLGA_KEY');
  assert.deepEqual([loosened!.decision, loosened!.actor, loosened!.metadata], ['allow', OLGA, { key: 'OLGA_KEY', version: 2, from: 'sensitive', to: 'secret', kept: 1 }]);
  const [rewrap] = (await entries('key.rewrap')).filter((entry) => entry.seq === loosened!.relatedSeq);
  assert.deepEqual([rewrap!.author, rewrap!.decision, rewrap!.metadata.was, rewrap!.metadata.from], ['vault', 'allow', 'sensitive', 1]);
  // No `secret.write` says it: nobody wrote a value, and nobody saw one (the offboarding report reads writes as seen).
  assert.equal((await entries('secret.write')).filter((entry) => entry.metadata.key === 'OLGA_KEY' && entry.metadata.version === 2).length, 0);
  const page = await root.audit.list({ limit: 50 });
  assert.ok(page.entries.some((entry) => entry.action === 'secret.loosen' && !entry.detail && entry.key === 'OLGA_KEY'));
});

test('everyone else writes the value again: a Maintainer, an Owner of another project or of every prod, a personal token and a service token', async () => {
  const personal = await root.tokens.issue(`user:${ROOT}`, { label: 'agent', expiresInMinutes: 60, scope: { market: 'maintainer' } });
  const service = await root.tokens.issue(OPS, { label: 'deploy', expiresInDays: 30 });
  for (const [who, client, code] of [
    ['a Maintainer', maya, 409],
    ['an Owner of every prod', pat, 409],
    ["an Owner's personal token", bearer(personal.token), 409],
    ['a service token', bearer(service.token), 409],
    // Billing's Owner writes nothing in market at all.
    ['an Owner of billing', bill, 403],
  ] as const) {
    if (code === 409) assert.equal((await client.secrets.list('market/prod')).loosenable, false, who);
    assert.equal(await status(client.secrets.set('market/prod', { API_KEY: { sensitivity: 'secret' } })), code, who);
  }
  const refused = await maya.secrets.set('market/prod', { API_KEY: { sensitivity: 'secret' } }).catch((error: Error) => error);
  assert.match((refused as Error).message, /API_KEY is sensitive: making it secret takes its value written again, unless an Owner of market makes it one in place/);
  // Nor in a dry run, which an Owner's says changes it.
  assert.equal(await status(maya.secrets.dryRun('market/prod', { API_KEY: { sensitivity: 'secret' } })), 409);
  assert.deepEqual({ ...(await olga.secrets.dryRun('market/prod', { API_KEY: { sensitivity: 'secret' } })).keys }, { API_KEY: 'changed' });
  assert.equal((await levels('market/prod')).API_KEY, 'sensitive');
  assert.equal((await entries('secret.loosen')).filter((entry) => entry.decision === 'allow').length, 0);
  assert.ok((await entries('secret.loosen')).some((entry) => entry.decision === 'deny' && entry.actor === MAYA && entry.metadata.reason === 'not_owner'));
  // Plain is never made in place, by anyone: a secret's or a sensitive value's.
  assert.equal(await status(root.secrets.set('market/prod', { API_KEY: { sensitivity: 'plain' } })), 409);
});

test('a reference reads its source loosened, live; the reference itself, or an inherited key, is loosened where it is held', async () => {
  await root.secrets.set('market/dev', { FROM_PROD: { ref: 'market/prod/API_KEY' } });
  await root.environments.create('market/prod-next', { from: 'prod', inherit: true });
  assert.equal((await levels('market/dev')).FROM_PROD, 'sensitive');
  assert.equal(await status(olga.secrets.set('market/dev', { FROM_PROD: { sensitivity: 'secret' } })), 409);
  assert.equal(await status(olga.secrets.set('market/prod-next', { API_KEY: { sensitivity: 'secret' } })), 409);
  await olga.secrets.set('market/prod', { API_KEY: { sensitivity: 'secret' } });
  assert.equal((await levels('market/dev')).FROM_PROD, 'secret');
  assert.equal((await levels('market/prod-next')).API_KEY, 'secret');
  assert.deepEqual((await olga.secrets.reveal('market/dev/FROM_PROD')).values, { FROM_PROD: VALUE });
});

test('an Owner of the project, or of the whole instance, unprotects its environments, as the server says; nobody else does', async () => {
  const personal = await root.tokens.issue(`user:${ROOT}`, { label: 'agent', expiresInMinutes: 60, scope: { market: 'maintainer' } });
  for (const client of [olga, lena, root]) {
    assert.equal((await maya.environments.protect('market/prod')).environment.protected, true);
    assert.equal((await environmentOf(client, 'market/prod')).unprotectable, true);
    assert.equal((await client.secrets.list('market/prod')).unprotectable, true);
    assert.equal((await client.environments.protect('market/prod', false)).environment.protected, false);
  }
  await maya.environments.protect('market/prod');
  for (const [who, client] of [['a Maintainer', maya], ['an Owner of every prod', pat], ["an Owner's personal token", bearer(personal.token)], ['an Owner of billing', bill]] as const) {
    if (client !== bill) assert.equal((await client.secrets.list('market/prod')).unprotectable, false, who);
    assert.equal(await status(client.environments.protect('market/prod', false)), 403, who);
  }
  assert.equal((await environmentOf(maya, 'market/prod')).unprotectable, false);
  assert.equal((await environmentOf(root, 'market/prod')).protected, true);
  // A personal config is protected as its environment is, and unprotected there: no flag of its own.
  await olga.environments.create('market/prod@me');
  assert.equal((await environmentOf(olga, 'market/prod@me')).unprotectable, false);
  // The vault's own entry names who did it.
  const unprotected = (await entries('policy.change')).filter((entry) => entry.decision === 'allow' && (entry.metadata.change as { protected?: boolean }).protected === false);
  assert.deepEqual(unprotected.map((entry) => entry.actor), [OLGA, LENA, `user:${ROOT}`]);
});
