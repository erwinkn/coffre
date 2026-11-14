// `coffre run`'s plan of an environment, `GET /use/<project>/<env>`, on the
// 0.16 contract (docs/design/0.16.md, "The proxy"): a peek, which says what
// the handle may use and each key's nature and opens nothing, then one use
// that opens and logs only what the app is handed. 0.14.7's assertions
// (packages/server/test/credential-proxy.test.ts, "the plan: …" and the
// handle tests after it), ported: placeholders for what the proxy covers, a
// plain value its rule leaves a slot for the handle beside, the secrets its
// person reads that no credential covers, never a sensitive one, and `left`
// for the rest; a fork's inherited values to a reader of its parent; a
// personal config; a protected prod its person only uses. Then what 0.16
// adds: a covered secret is never opened, each value is placed by the
// nature the use opened it under, and what a plan costs.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { bodyDigest, createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { binding, credential, emptyDatabase, environment, grant, instance, principal, project, rewrite, role, rows, secret, session, value, write, type TestVault } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processGates, type Gates } from '../src/gate.ts';
import { basic, credentialProxy, header, hmac, jwt, postgres, prefix, privateKey, sigv4 } from '../src/plugins/credential-proxy.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
const FORKER = 'user:fred';
const OLGA = 'user:olga';
const DEPLOY = 'token:deploy';

const SID = 'AC0123456789';
const KEY_ID = 'AKIAEXAMPLE0123';
const WEBHOOK = 'whsec_0123456789';
const APP_NAME = 'market-dev';
const b64 = (claims: object) => Buffer.from(JSON.stringify(claims)).toString('base64url');
const SUPA = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'anon', ref: 'abcdef', iss: 'supabase' })}.c2lnbmF0dXJl`;
/** Every value a covered key holds that is no plain one: none of them may be opened by a plan, nor reach its answer. */
const COVERED = { TWILIO_TOKEN: 'twilio-auth-token-0123', AWS_SECRET: 'aws-secret-0123456789', STRIPE_KEY: 'sk_live_0123456789', SIGNING_KEY: 'signing-key-0123456789', DATABASE_URL: 'postgres://db.internal/market', HOOK_SECRET: 'hook-secret-plain', CACHE_URL: 'redis://cache.internal' };

const proxy = credentialProxy({
  credentials: {
    twilio: { upstream: 'https://api.twilio.example/2010-04-01', inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}') },
    s3: { upstream: 'https://s3.eu-west-3.example', inject: sigv4({ accessKeyId: '{AWS_KEY_ID}', secretAccessKey: '{AWS_SECRET}', region: 'eu-west-3', service: 's3' }) },
    stripe: { upstream: 'https://api.stripe.example/v1', inject: header('authorization', 'Bearer {STRIPE_KEY}'), placeholder: prefix('sk_test_') },
    supa: { upstream: 'https://abcdef.supabase.example', inject: header('apikey', '{SUPA_KEY}'), placeholder: jwt({ claims: ['role'] }) },
    maps: { upstream: 'https://maps.example/v1', inject: header('x-maps-key', '{MAPS_KEY}') },
  },
  signers: { signer: privateKey('SIGNING_KEY') },
  // A verifier's key written plain, by mistake: it is the handle all the same, and never leaves coffre.
  verifiers: { hook: hmac('HOOK_SECRET', { encoding: 'hex' }) },
  // A local cache's URL, plain: a tunnel's key is the listener's URL whatever it holds.
  tunnels: { db: postgres('DATABASE_URL'), cache: postgres('CACHE_URL') },
  generate: { 'market/generated': 'all' },
});

let held = processGates();
const gates: Gates = (service) => held(service);
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates, plugins: [proxy] });
const { world } = app;
after(() => app.close());

const market = project('market');
const dev = environment(market, 'dev');
const fork = environment(market, 'dev-eu', { parentId: dev.id });
const mine = environment(market, 'dev-ada', { parentId: dev.id, owner: ADA });
const prod = environment(market, 'prod', { protected: true });
const staging = environment(market, 'staging');
const generated = environment(market, 'generated');
const PLACES = [dev, fork, prod, staging, generated];

/** A handle's scope: it reads and uses where its person does, a protected place included, as `POST /handles` makes it. */
const SCOPE = JSON.stringify(PLACES.map((each) => ({ projectId: market.id, environmentId: each.id, role: 'viewer', permissions: { normal: ['secret.read', 'secret.use'], protected: ['secret.read', 'secret.use'] } })));

/** A handle of `who`'s for `place`, a viewer where they read, as `POST /handles` makes one. */
const handles = new Map<string, string>();
const handleOf = (who: string, place: { id: string }, personal = false) => handles.get(`${who} ${place.id} ${personal}`)!;

let ids: Record<string, string>;
let deploy: { token: string; key: ProofKey };

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.memory.seconds = 2;
  held = processGates();
  handles.clear();
  const made = [];
  for (const [who, place, personal] of [[ADA, dev, false], [ADA, fork, false], [ADA, dev, true], [FORKER, fork, false], [ADA, prod, false], [OLGA, prod, false], [ADA, staging, false], [OLGA, staging, false], [ADA, generated, false]] as const) {
    const token = generateToken('handle');
    handles.set(`${who} ${place.id} ${personal}`, token);
    made.push(credential(token, who, { kind: 'handle', scope: SCOPE, places: JSON.stringify([{ environmentId: place.id, personal }]), expiresAt: new Date(Date.now() + 3_600_000) }));
  }
  const s = {
    TWILIO_SID: value(world, secret(dev, 'TWILIO_SID'), SID, { plain: true }),
    TWILIO_TOKEN: value(world, secret(dev, 'TWILIO_TOKEN'), COVERED.TWILIO_TOKEN),
    AWS_KEY_ID: value(world, secret(dev, 'AWS_KEY_ID'), KEY_ID, { plain: true }),
    AWS_SECRET: value(world, secret(dev, 'AWS_SECRET'), COVERED.AWS_SECRET),
    STRIPE_KEY: value(world, secret(dev, 'STRIPE_KEY'), COVERED.STRIPE_KEY, { sensitive: true }),
    SUPA_KEY: value(world, secret(dev, 'SUPA_KEY'), SUPA),
    SIGNING_KEY: value(world, secret(dev, 'SIGNING_KEY'), COVERED.SIGNING_KEY),
    DATABASE_URL: value(world, secret(dev, 'DATABASE_URL'), COVERED.DATABASE_URL),
    WEBHOOK_SECRET: value(world, secret(dev, 'WEBHOOK_SECRET'), WEBHOOK),
    APP_NAME: value(world, secret(dev, 'APP_NAME'), APP_NAME, { plain: true }),
    U_PASS: value(world, secret(dev, 'U_PASS'), 'u-pass-0123456789', { sensitive: true }),
    HOOK_SECRET: value(world, secret(dev, 'HOOK_SECRET'), COVERED.HOOK_SECRET, { plain: true }),
    CACHE_URL: value(world, secret(dev, 'CACHE_URL'), COVERED.CACHE_URL, { plain: true }),
    // A key with no value yet: held, and given to nobody.
    EMPTY: secret(dev, 'EMPTY'),
  };
  ids = Object.fromEntries(Object.entries(s).map(([key, row]) => [key, row.id]));
  const key = await generateProofKey();
  const token = generateToken('workload');
  // The deploy service reads WEBHOOK_SECRET where it is held, and only uses the rest.
  const onDev = JSON.stringify([{ projectId: market.id, environmentId: dev.id, role: 'viewer' }]);
  const deployBinding = binding(DEPLOY, { policy: JSON.stringify({ reads: { [dev.id]: { keys: [s.WEBHOOK_SECRET.id] } } }), scope: onDev });
  made.push(session(token, deployBinding, { jkt: await thumbprint(key.jwk), scope: onDev, places: JSON.stringify([{ environmentId: dev.id }]), expiresAt: new Date(Date.now() + 3_600_000) }));
  deploy = { token, key };
  await write(
    world,
    ...rows('policy', instance()),
    // A Developer only uses a protected place; a Maintainer reads it too.
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'], ['secret.use']), role(false, 'maintainer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'viewer', ['secret.read', 'secret.use'])),
    ...rows('projects', market),
    ...rows('environments', dev, fork, mine, prod, staging, generated),
    ...rows('principals', principal(ADA), principal(FORKER), principal(OLGA), principal(DEPLOY)),
    ...rows('grants', grant(ADA, 'developer', { project: market }), grant(OLGA, 'maintainer', { project: market }), grant(FORKER, 'viewer', { environment: fork }), grant(DEPLOY, 'developer', { project: market })),
    ...rows(
      'secrets',
      ...Object.values(s),
      value(world, secret(fork, 'APP_NAME'), 'market-dev-eu', { plain: true }),
      value(world, secret(mine, 'WEBHOOK_SECRET'), 'whsec_ada_own', {}),
      value(world, secret(mine, 'LOCAL_ONLY'), 'x', {}),
      value(world, secret(prod, 'WEBHOOK_SECRET'), 'whsec_prod_0123456789'),
      value(world, secret(prod, 'TWILIO_SID'), SID, { plain: true }),
      value(world, secret(prod, 'TWILIO_TOKEN'), 'twilio-prod-token'),
      value(world, secret(staging, 'TWILIO_SID'), SID, { plain: true }),
      value(world, secret(staging, 'TWILIO_TOKEN'), 'twilio-staging-token'),
      value(world, secret(staging, 'WEBHOOK_SECRET'), 'whsec_staging'),
      value(world, secret(generated, 'WEBHOOK_SECRET'), 'whsec_generated'),
    ),
    ...rows('bindings', deployBinding),
    ...rows('credentials', ...made),
  );
  await world.owner.execute(sql`DELETE FROM log_pending`);
  await app.request('/livez');
  // The app's first request reads whether it is migrated: no plan's cost.
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
  app.inputs.length = 0;
});

type Plan = { environment: string; env: Record<string, string>; credentials: Record<string, string>; tunnels: Record<string, { key: string; url: string }>; left: string[] };

/** The plan `handle` gets for `path`, what it cost (the vault's calls, the app's statements) and what the vault's own connection ran. */
async function planOf(path: string, handle: string): Promise<{ plan: Plan; calls: string[]; statements: number; vault: string[]; response: Response }> {
  const [calls, statements] = [app.calls.length, app.statements];
  const vault: string[] = [];
  const restore = counting(world, (what) => vault.push(what));
  try {
    const response = await app.request(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
    const plan = (response.status === 200 ? await response.clone().json() : null) as Plan;
    return { plan, calls: app.calls.slice(calls), statements: app.statements - statements, vault, response };
  } finally {
    restore();
  }
}

/** Names each statement and transaction the vault runs on its own connection, until put back: a use's read, its write (the log entry and the exposures, in one transaction), or the credential's last use. */
function counting(vault: TestVault, count: (what: string) => void): () => void {
  const db = vault.db as unknown as Record<'execute' | 'transaction', (...args: unknown[]) => unknown>;
  const was = { execute: db.execute, transaction: db.transaction };
  for (const name of ['execute', 'transaction'] as const) {
    db[name] = (...args: unknown[]) => {
      const text = String(JSON.stringify(args[0]));
      count(name === 'transaction' ? 'write' : text.includes('WITH RECURSIVE') ? 'read' : text.includes('last_used_at') ? 'last use' : text.slice(0, 160));
      return was[name].apply(vault.db, args);
    };
  }
  return () => Object.assign(db, was);
}

/** The vault's log entries not yet signed in: each one's purpose, the credential it names, and the keys it logs. */
async function logged(): Promise<{ purpose: string; credential?: string; keys: string[] }[]> {
  const bodies = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`);
  return bodies.map(({ body }) => {
    const { detail } = JSON.parse(body) as { detail: { purpose?: string; credential?: string; keys?: { key: string }[] } };
    if (detail.purpose === undefined) return [];
    return [{ purpose: detail.purpose, ...(detail.credential === undefined ? {} : { credential: detail.credential }), keys: detail.keys!.map((key) => key.key) }];
  }).flat();
}

const exposedKeys = async () => (await rowsOf<{ secret_id: string }>(world.owner, sql`SELECT secret_id FROM exposures`)).map((row) => Object.keys(ids).find((key) => ids[key] === row.secret_id) ?? row.secret_id).sort();

test('the plan: placeholders for what the proxy covers, and as they are the values its person reads where they are held, never a sensitive one', async () => {
  const handle = handleOf(ADA, dev);
  const { plan, calls, statements } = await planOf('market/dev', handle);
  assert.equal(plan.environment, 'market/dev');
  assert.equal(plan.env.WEBHOOK_SECRET, WEBHOOK, 'a secret its person reads, and no credential');
  assert.equal(plan.env.APP_NAME, APP_NAME, 'a plain value, and no credential');
  assert.equal(plan.env.TWILIO_SID, SID, 'a plain value its credential names, beside the key that carries the handle');
  assert.equal(plan.env.TWILIO_TOKEN, handle, "a credential's secret is the handle");
  assert.equal(plan.env.STRIPE_KEY, `sk_test_${handle}`, "and a credential's sensitive one, in the shape its client checks");
  assert.equal(plan.env.AWS_KEY_ID, handle, "a plain key where giving it would leave the handle nowhere: S3's access key id, which the SDK signs with");
  assert.equal(plan.env.AWS_SECRET, handle);
  assert.equal(plan.env.SIGNING_KEY, handle, "a signer's key, which never leaves coffre");
  assert.equal(plan.env.HOOK_SECRET, handle, "a verifier's, plain or not");
  const [head, claims, tail] = plan.env.SUPA_KEY!.split('.');
  assert.deepEqual([JSON.parse(Buffer.from(head!, 'base64url').toString()), tail], [{ alg: 'none', typ: 'JWT' }, handle]);
  const { role: claimed, exp, ...rest } = JSON.parse(Buffer.from(claims!, 'base64url').toString()) as { role: string; exp: number };
  assert.deepEqual([claimed, rest], ['anon', {}], 'the named claims of the real token, and no other');
  assert.ok(Math.abs(exp * 1000 - (Date.now() + 3_600_000)) < 60_000, 'it ends with the handle');
  assert.equal(Object.hasOwn(plan.env, 'DATABASE_URL') || Object.hasOwn(plan.env, 'CACHE_URL'), false, "a tunnel's URL is coffre run's listener's to make, a plain one's too");
  const ws = PUBLIC_URL.replace(/^http/, 'ws');
  assert.deepEqual(plan.tunnels, { db: { key: 'DATABASE_URL', url: `${ws}/use/market/dev/db` }, cache: { key: 'CACHE_URL', url: `${ws}/use/market/dev/cache` } });
  assert.deepEqual(plan.credentials, Object.fromEntries(['twilio', 's3', 'stripe', 'supa', 'signer', 'hook'].map((name) => [name, `${PUBLIC_URL}/use/market/dev/${name}`])), 'never maps, whose key dev lacks');
  assert.deepEqual(plan.left, ['EMPTY', 'U_PASS'], 'sensitive, or no value yet, and no credential: the app does without');
  for (const real of Object.values(COVERED)) assert.equal(JSON.stringify(plan).includes(real), false);

  // A peek, the one use that hands values back, and the JWT placeholder's use of its credential with the handle's row for its end.
  assert.deepEqual([calls, statements], [['peek', 'use', 'use'], 1]);
  const [peeked, exposed, claimed2] = app.inputs.slice(-3) as { keys: string[] | null; purpose: string; upstream: string | null }[];
  assert.deepEqual([peeked!.keys, peeked!.purpose, peeked!.upstream], [null, 'use', null]);
  assert.deepEqual([exposed!.keys, exposed!.purpose, exposed!.upstream], [['APP_NAME', 'TWILIO_SID', 'WEBHOOK_SECRET'], 'expose', null]);
  assert.deepEqual([claimed2!.keys, claimed2!.purpose, claimed2!.upstream], [['SUPA_KEY'], 'use', 'supa']);
});

test('a covered secret is never opened: no log entry and no exposure names it, and the values handed back are logged as exposed, as 0.14.7 logged them', async () => {
  await planOf('market/dev', handleOf(ADA, dev));
  assert.deepEqual(await logged(), [{ purpose: 'expose', keys: ['APP_NAME', 'TWILIO_SID', 'WEBHOOK_SECRET'] }, { purpose: 'use', credential: 'supa', keys: ['SUPA_KEY'] }]);
  const exposed = await exposedKeys();
  for (const key of [...Object.keys(COVERED), 'U_PASS', 'AWS_KEY_ID', 'EMPTY']) assert.equal(exposed.includes(key), false, `${key} is no exposure`);
  // What the vault says its person has seen, of all it opened: the JWT placeholder's use counts too, as every use does.
  assert.deepEqual(exposed, ['APP_NAME', 'SUPA_KEY', 'TWILIO_SID', 'WEBHOOK_SECRET']);
});

test("a key is placed by the nature its use opened it under, not the peek's: one turned secret between the two stays its credential's placeholder, its value dropped", async () => {
  const handle = handleOf(ADA, dev);
  const peek = app.vault.peek.bind(app.vault);
  app.vault.peek = async (input) => {
    const answer = await peek(input);
    // Between the peek and the use, TWILIO_SID is written again, a secret now.
    await rewrite(world, { id: ids.TWILIO_SID! }, 'AC-now-a-secret');
    return answer;
  };
  try {
    const { plan } = await planOf('market/dev', handle);
    assert.equal(plan.env.TWILIO_SID, handle);
    assert.equal(JSON.stringify(plan).includes('AC-now-a-secret'), false);
    // The use opened it, as asked, and says so: what the log says is what happened.
    assert.deepEqual((await logged())[0], { purpose: 'expose', keys: ['APP_NAME', 'TWILIO_SID', 'WEBHOOK_SECRET'] });
  } finally {
    app.vault.peek = peek;
  }
});

test('a plan with no JWT placeholder is two calls to the vault and no statement; the vault reads twice and writes once, its memory on or off, and logs it once a minute', async () => {
  // Each a handle of its own: one never used before, whose plan's first is the one measured.
  for (const [seconds, who] of [[2, ADA], [0, OLGA]] as const) {
    world.memory.seconds = seconds;
    const { plan, calls, statements, vault } = await planOf('market/staging', handleOf(who, staging));
    assert.deepEqual(plan, { environment: 'market/staging', env: { TWILIO_SID: SID, TWILIO_TOKEN: handleOf(who, staging), WEBHOOK_SECRET: 'whsec_staging' }, credentials: { twilio: `${PUBLIC_URL}/use/market/staging/twilio` }, tunnels: {}, left: [] });
    // The peek's read, the use's own (it names its keys, so it is no ask the peek's rows answer), and the use's one write.
    // The peek's read; the use's own, since it names its keys and no ask the peek's rows answer; its one write; and the handle's last use, once a minute.
    assert.deepEqual([calls, statements, vault], [['peek', 'use'], 0, ['read', 'read', 'write', 'last use']], `memory ${seconds}s`);
  }
  // Again within the minute: with no memory, both reads again and no write; within it, nothing at all.
  assert.deepEqual((await planOf('market/staging', handleOf(OLGA, staging))).vault, ['read', 'read']);
  world.memory.seconds = 2;
  await planOf('market/staging', handleOf(ADA, staging));
  assert.deepEqual((await planOf('market/staging', handleOf(ADA, staging))).vault, []);
});

test("a fork's inherited values reach the app of whoever reads them where they are held; a reader of the fork alone does without them", async () => {
  const { plan } = await planOf('market/dev-eu', handleOf(ADA, fork));
  assert.equal(plan.env.WEBHOOK_SECRET, WEBHOOK);
  assert.equal(plan.env.APP_NAME, 'market-dev-eu', "the fork's own");
  assert.equal(plan.env.STRIPE_KEY, `sk_test_${handleOf(ADA, fork)}`, 'its inherited keys are still placeholders');
  assert.deepEqual(plan.left, ['EMPTY', 'U_PASS']);
  const forker = await planOf('market/dev-eu', handleOf(FORKER, fork));
  assert.equal(forker.response.status, 200, await forker.response.clone().text());
  assert.deepEqual(forker.plan.env, { APP_NAME: 'market-dev-eu' }, 'a reader of the fork alone, never of dev');
  assert.deepEqual(forker.plan.credentials, {});
  assert.ok(forker.plan.left.includes('WEBHOOK_SECRET') && forker.plan.left.includes('TWILIO_TOKEN'));
});

test("a handle for dev@me stands in for the personal config: its own values, and dev's, which its owner reads through dev", async () => {
  const { plan } = await planOf('market/dev@me', handleOf(ADA, dev, true));
  assert.equal(plan.environment, 'market/dev@me');
  assert.equal(plan.env.WEBHOOK_SECRET, 'whsec_ada_own', "the personal config's own value, not dev's");
  assert.equal(plan.env.LOCAL_ONLY, 'x');
  assert.equal(plan.env.TWILIO_SID, SID, "dev's plain value");
  assert.equal(plan.credentials.twilio, `${PUBLIC_URL}/use/market/dev@me/twilio`);
  assert.deepEqual(plan.left, ['EMPTY', 'U_PASS']);
});

test("a handle reads a protected prod as its person does: a Maintainer's is handed its secrets, a Developer's only uses them, and its plan says so", async () => {
  const olga = await planOf('market/prod', handleOf(OLGA, prod));
  assert.equal(olga.plan.env.WEBHOOK_SECRET, 'whsec_prod_0123456789');
  const ada = await planOf('market/prod', handleOf(ADA, prod));
  assert.equal(ada.response.status, 200, await ada.response.clone().text());
  assert.deepEqual(ada.plan.env, { TWILIO_SID: handleOf(ADA, prod), TWILIO_TOKEN: handleOf(ADA, prod) }, 'the placeholders of what she uses, its plain key too, and no value');
  assert.deepEqual(ada.plan.left, ['WEBHOOK_SECRET']);
  assert.deepEqual(ada.calls, ['peek', 'use']);
});

test('a plan is a handle\'s alone, and refused as the vault refuses the handle; one of an environment the deployment generates for is not served yet', async () => {
  const status = async (path: string, authorization?: string) => {
    const before = app.calls.length;
    const response = await app.request(`/use/${path}`, authorization === undefined ? {} : { headers: { authorization } });
    return [response.status, ((await response.json()) as { reason?: string }).reason, app.calls.slice(before)];
  };
  assert.deepEqual(await status('market/dev'), [401, undefined, []]);
  // A person's own session reads their values through the API, never as a plan.
  const cli = generateToken('cli');
  await write(world, ...rows('credentials', credential(cli, ADA)));
  assert.deepEqual(await status('market/dev', `Bearer ${cli}`), [401, undefined, []]);
  assert.deepEqual(await status('market/dev', `Bearer ${generateToken('handle')}`), [401, 'unauthenticated', ['peek']]);
  assert.deepEqual(await status('market/nowhere', `Bearer ${handleOf(ADA, dev)}`), [403, 'no_access', ['peek']]);
  assert.deepEqual(await status('market/generated', `Bearer ${handleOf(ADA, generated)}`), [501, 'not_implemented', []]);
  assert.deepEqual((await status('market/dev', `Bearer ${handleOf(ADA, dev)}`))[0], 200);
});

test("a workload's plan: after its gate, one use of every key, handing back the plain values and those its binding reads, naming what it only uses", async () => {
  const url = `${PUBLIC_URL}/use/market/dev`;
  const proof = await createProof(deploy.key, { method: 'GET', url, token: deploy.token, nonce: await held(DEPLOY).nonce(), content: { headers: {}, body: await bodyDigest(new Uint8Array()) } });
  const [calls, statements] = [app.calls.length, app.statements];
  const response = await app.request('/use/market/dev', { headers: { authorization: `DPoP ${deploy.token}`, dpop: proof } });
  assert.equal(response.status, 200, await response.clone().text());
  assert.ok(response.headers.get('dpop-nonce'));
  const plan = (await response.json()) as { environment: string; values: Record<string, string>; credentials: string[]; tunnels: Record<string, unknown>; useOnly: string[]; mints: unknown[] };
  // A plain value is no secret, to a workload too, whatever uses it: as 0.14.7 handed them.
  assert.deepEqual(plan.values, { APP_NAME, AWS_KEY_ID: KEY_ID, CACHE_URL: COVERED.CACHE_URL, HOOK_SECRET: COVERED.HOOK_SECRET, TWILIO_SID: SID, WEBHOOK_SECRET: WEBHOOK });
  assert.deepEqual(plan.credentials, ['twilio', 's3', 'stripe', 'supa', 'signer', 'hook']);
  const ws = PUBLIC_URL.replace(/^http/, 'ws');
  assert.deepEqual(plan.tunnels, { db: { key: 'DATABASE_URL', url: `${ws}/use/market/dev/db` }, cache: { key: 'CACHE_URL', url: `${ws}/use/market/dev/cache` } });
  // Every key it holds and is not handed: those it only uses, and one with no value yet.
  assert.deepEqual(plan.useOnly, ['AWS_SECRET', 'DATABASE_URL', 'EMPTY', 'SIGNING_KEY', 'STRIPE_KEY', 'SUPA_KEY', 'TWILIO_TOKEN', 'U_PASS']);
  assert.deepEqual([plan.environment, plan.mints], ['market/dev', []]);
  // The session's row, by its token's hash, then one use.
  assert.deepEqual([app.calls.slice(calls), app.statements - statements], [['use'], 1]);
});
