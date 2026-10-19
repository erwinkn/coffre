// Sensitive values (docs/design/credential-proxy.md, section 2): each key's
// current version says who sees it. `plain`, whoever lists its environment;
// `secret`, the default, whoever's role reads it; `sensitive`, no person,
// Owners included, on any credential of theirs, while their apps use it
// through the credential proxy and service accounts read it. A key is made
// stricter at any time, its value kept as a new version; looser only by
// writing a value again. The vault binds `sensitive` into the wrap of each
// version's data key, so a column flipped around coffre opens nothing.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient, type CoffreClient } from '@coffre/client';
import { eq } from 'drizzle-orm';

import { clientFor, testVault } from './api-fixture.ts';
import { withTriggersLifted } from './db/engine.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { secretVersions } from './db/tables.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { basic, credentialProxy, header } from '../src/plugins/credential-proxy.ts';

const API_KEY = 'sk_live_real_0123456789abcdef';
const DB_PASSWORD = 'db_password_0123456789';
const WEBHOOK = 'whsec_0123456789abcdef';

/** A fake API that says whether it got the real key. */
let upstream: Server;
let upstreamUrl: string;

before(async () => {
  upstream = createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ real: request.headers['x-api-key'] === API_KEY }));
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

let root: CoffreClient;
let ci: CoffreClient;

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy({
    credentials: { api: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{API_KEY}') } },
    insecureUpstreams: true,
  })]);
  root = clientFor(deps, ROOT);
  ci = clientFor(deps, 'ci', 'service');
  await root.members.add(`user:${DEV}`);
  await root.members.add('token:ci');
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', {
    API_KEY: { value: API_KEY, sensitivity: 'sensitive' },
    DB_PASSWORD: { value: DB_PASSWORD, sensitivity: 'sensitive' },
    WEBHOOK,
    REGION: { value: 'eu-west-3', plain: true },
  });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  await root.access.set('token:ci', { 'market/dev': 'viewer' });
});

/** The API as whoever `token` is, over coffre's own routes. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

async function refusal(promise: Promise<unknown>): Promise<{ status: number; reason: string | null; message: string }> {
  try {
    await promise;
  } catch (error) {
    const { status, reason, message } = error as { status: number; reason?: string; message: string };
    return { status, reason: reason ?? null, message };
  }
  throw new Error('it was not refused');
}

const levels = async (path: string, as = root) => Object.fromEntries((await as.secrets.list(path)).keys.map((entry) => [entry.key, entry.sensitivity]));
const history = async (path: string) => (await root.secrets.history(path)).versions.map(({ version, sensitivity }) => [version, sensitivity]);
/** The metadata of each `secret.write` of `key`, oldest first. */
const writesOf = async (key: string) => (await entries('secret.write')).filter((entry) => entry.decision === 'allow' && entry.metadata.key === key).map((entry) => entry.metadata);

test('each key lists who sees its current value, and each version its own', async () => {
  assert.deepEqual(await levels('market/dev'), { API_KEY: 'sensitive', DB_PASSWORD: 'sensitive', REGION: 'plain', WEBHOOK: 'secret' });
  // A person who reads the environment is told the levels too, and no sensitive value.
  const dev = (await clientFor(deps, DEV).secrets.list('market/dev')).keys.find((entry) => entry.key === 'API_KEY')!;
  assert.deepEqual([dev.sensitivity, dev.value], ['sensitive', null]);
  assert.deepEqual(await history('market/dev/API_KEY'), [[1, 'sensitive']]);
  assert.deepEqual((await root.secrets.history('market/dev/REGION')).versions.map(({ plain, sensitivity }) => [plain, sensitivity]), [[true, 'plain']]);
  assert.deepEqual((await writesOf('API_KEY'))[0], { key: 'API_KEY', version: 1, sensitive: true });
});

test('a write that names no sensitivity keeps a sensitive key sensitive and makes a plain one secret; its log says what it was', async () => {
  await root.secrets.set('market/dev', { API_KEY: 'sk_live_rotated_0123456789', REGION: 'eu-west-1', WEBHOOK: { value: 'whsec_new_0123456789', sensitivity: 'sensitive' } });
  assert.deepEqual(await levels('market/dev'), { API_KEY: 'sensitive', DB_PASSWORD: 'sensitive', REGION: 'secret', WEBHOOK: 'sensitive' });
  assert.deepEqual((await ci.secrets.reveal('market/dev/API_KEY')).values, { API_KEY: 'sk_live_rotated_0123456789' });
  // `was` only where the level changed.
  assert.deepEqual((await writesOf('API_KEY'))[1], { key: 'API_KEY', version: 2, sensitive: true });
  assert.deepEqual((await writesOf('REGION'))[1], { key: 'REGION', version: 2, was: 'plain' });
  assert.deepEqual((await writesOf('WEBHOOK'))[1], { key: 'WEBHOOK', version: 2, sensitive: true, was: 'secret' });
  // Looser takes a value written again, saying so.
  await root.secrets.set('market/dev', { WEBHOOK: { value: 'whsec_back_0123456789', sensitivity: 'secret' } });
  assert.equal((await levels('market/dev')).WEBHOOK, 'secret');
  assert.deepEqual((await writesOf('WEBHOOK'))[2], { key: 'WEBHOOK', version: 3, was: 'sensitive' });
});

test('marking a key stricter keeps its value as a new version; as strict already is unchanged, and looser is refused', async () => {
  const marked = await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' }, REGION: { sensitivity: 'secret' }, API_KEY: { sensitivity: 'sensitive' } });
  assert.deepEqual({ ...marked.keys }, { WEBHOOK: { version: 2 }, REGION: { version: 2 }, API_KEY: { version: 1 } });
  assert.deepEqual(await levels('market/dev'), { API_KEY: 'sensitive', DB_PASSWORD: 'sensitive', REGION: 'secret', WEBHOOK: 'sensitive' });
  assert.equal((await root.secrets.list('market/dev')).keys.find((entry) => entry.key === 'REGION')!.value, null, 'a secret lists no value');
  // The same values, which a service account reads as before.
  assert.deepEqual((await ci.secrets.reveal('market/dev')).values, { API_KEY, DB_PASSWORD, REGION: 'eu-west-3', WEBHOOK });
  assert.deepEqual(await history('market/dev/WEBHOOK'), [[2, 'sensitive'], [1, 'secret']]);
  assert.deepEqual(await history('market/dev/API_KEY'), [[1, 'sensitive']], 'as strict already: no new version');
  assert.deepEqual((await writesOf('WEBHOOK'))[1], { key: 'WEBHOOK', version: 2, sensitive: true, was: 'secret', kept: 1 });
  assert.deepEqual((await writesOf('REGION'))[1], { key: 'REGION', version: 2, was: 'plain', kept: 1 });

  for (const to of ['secret', 'plain'] as const) {
    const looser = await refusal(root.secrets.set('market/dev', { WEBHOOK: { sensitivity: to } }));
    assert.equal(looser.status, 409);
    assert.match(looser.message, /WEBHOOK is sensitive: making it .* takes its value written again/);
  }
  const [denied] = (await entries('secret.write')).filter((entry) => entry.decision === 'deny');
  assert.deepEqual(denied!.metadata, { key: 'WEBHOOK', sensitivity: 'secret', was: 'sensitive', reason: 'looser' });
  assert.equal((await refusal(root.secrets.set('market/dev', { NOTHING: { sensitivity: 'sensitive' } }))).status, 409, 'no value to mark');
  assert.deepEqual(await history('market/dev/WEBHOOK'), [[2, 'sensitive'], [1, 'secret']]);
});

test('a person reads every value of an environment but its sensitive ones, which it names; one is refused on any credential, an Owner included', async () => {
  const session = await sessionFor(DEV);
  const pat = (await bearer(session).tokens.issue(`user:${DEV}`, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } })).token;
  for (const person of [bearer(session), bearer(pat), bearer(await sessionFor(ROOT))]) {
    const read = await person.secrets.reveal('market/dev');
    assert.deepEqual(read.values, { REGION: 'eu-west-3', WEBHOOK });
    assert.deepEqual([...read.sensitive].sort(), ['API_KEY', 'DB_PASSWORD']);
    assert.deepEqual(await refusal(person.secrets.reveal('market/dev/API_KEY')), {
      status: 403,
      reason: 'sensitive',
      message: 'a sensitive value is never shown to anyone, Owners included: `coffre run` gives your app a placeholder for it through the credential proxy, and a service account reads it',
    });
  }
  // The vault refused each read of one, and logged it, by the person and the version.
  const refused = (await entries('secret.read')).filter((entry) => entry.author === 'vault' && entry.decision === 'deny');
  assert.deepEqual(refused.map((entry) => [entry.actor, entry.code]), [[`user:${DEV}`, 'sensitive'], [`user:${DEV}`, 'sensitive'], [`user:${ROOT}`, 'sensitive']]);
  assert.ok(refused.every((entry) => entry.secretVersionId !== null));

  const read = await ci.secrets.reveal('market/dev');
  assert.deepEqual(read.values, { API_KEY, DB_PASSWORD, REGION: 'eu-west-3', WEBHOOK });
  assert.deepEqual(read.sensitive, []);
});

test('a dry run never tells a person whether they guessed a sensitive value, and a change of level is a change', async () => {
  const dev = clientFor(deps, DEV);
  assert.deepEqual({ ...(await dev.secrets.dryRun('market/dev', { API_KEY })).keys }, { API_KEY: 'changed' }, 'the right value, told nothing');
  assert.deepEqual({ ...(await ci.secrets.dryRun('market/dev', { API_KEY })).keys }, { API_KEY: 'unchanged' }, 'a service account reads it, and is told');
  assert.deepEqual({ ...(await dev.secrets.dryRun('market/dev', { WEBHOOK })).keys }, { WEBHOOK: 'unchanged' });
  assert.deepEqual({ ...(await root.secrets.dryRun('market/dev', { WEBHOOK: { value: WEBHOOK, sensitivity: 'sensitive' }, REGION: 'eu-west-3' })).keys }, { WEBHOOK: 'changed', REGION: 'changed' });
  // A mark compares levels, as the write would.
  assert.deepEqual({ ...(await root.secrets.dryRun('market/dev', { API_KEY: { sensitivity: 'sensitive' }, WEBHOOK: { sensitivity: 'sensitive' } })).keys }, { API_KEY: 'unchanged', WEBHOOK: 'changed' });
  assert.equal((await refusal(root.secrets.dryRun('market/dev', { API_KEY: { sensitivity: 'secret' } }))).status, 409);
  // None of it reads a sensitive value for a person: the vault refused nothing.
  assert.deepEqual((await entries('secret.read')).filter((entry) => entry.decision === 'deny'), []);
});

test('a rollback brings an old value back as it was held, and sensitive while the key is: never looser', async () => {
  // REGION: v1 plain, v2 a secret, v3 sensitive.
  await root.secrets.set('market/dev', { REGION: { sensitivity: 'secret' } });
  await root.secrets.set('market/dev', { REGION: { sensitivity: 'sensitive' } });
  await root.secrets.restore('market/dev/REGION', 1);
  assert.deepEqual((await history('market/dev/REGION'))[0], [4, 'sensitive']);
  assert.deepEqual((await ci.secrets.reveal('market/dev/REGION')).values, { REGION: 'eu-west-3' });
  const [restored] = (await entries('secret.restore')).filter((entry) => entry.decision === 'allow');
  assert.deepEqual(restored!.metadata, { key: 'REGION', version: 4, from: 1, sensitive: true });

  // Written again as a secret, the key takes back the plain value as plain, and the sensitive one as sensitive.
  await root.secrets.set('market/dev', { REGION: { value: 'eu-west-1', sensitivity: 'secret' } });
  await root.secrets.restore('market/dev/REGION', 1);
  assert.equal((await root.secrets.list('market/dev')).keys.find((entry) => entry.key === 'REGION')!.value, 'eu-west-3');
  await root.secrets.restore('market/dev/REGION', 3);
  assert.deepEqual((await history('market/dev/REGION')).slice(0, 3), [[7, 'sensitive'], [6, 'plain'], [5, 'secret']]);
  assert.deepEqual((await ci.secrets.reveal('market/dev/REGION')).values, { REGION: 'eu-west-3' });
});

test("a fork's copy keeps a sensitive value sensitive; an inheriting fork writes over one as sensitive, and marks only its own", async () => {
  await root.environments.create('market/copy', { from: 'dev' });
  assert.deepEqual(await levels('market/copy'), { API_KEY: 'sensitive', DB_PASSWORD: 'sensitive', REGION: 'plain', WEBHOOK: 'secret' });
  assert.equal((await refusal(root.secrets.reveal('market/copy/API_KEY'))).reason, 'sensitive');

  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  assert.equal((await levels('market/dev-eu')).API_KEY, 'sensitive', 'inherited, as its parent holds it');
  await root.secrets.set('market/dev-eu', { API_KEY: 'sk_live_eu_0123456789' });
  assert.equal((await levels('market/dev-eu')).API_KEY, 'sensitive');
  const inherited = await refusal(root.secrets.set('market/dev-eu', { DB_PASSWORD: { sensitivity: 'sensitive' } }));
  assert.equal(inherited.status, 409);
  assert.match(inherited.message, /DB_PASSWORD is inherited: mark it where it is held/);
  assert.equal((await refusal(root.secrets.set('market/dev-eu', { WEBHOOK: { sensitivity: 'sensitive' } }))).status, 409);
});

test("an override that takes its level from the parent is prepared again when the parent is marked sensitive meanwhile", async (t) => {
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  const wrap = deps.vault.wrap;
  let compete = true;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    if (compete) {
      compete = false;
      await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' } });
    }
    return result;
  });
  await root.secrets.set('market/dev-eu', { WEBHOOK: 'whsec_eu_0123456789abcdef' });
  assert.equal((await levels('market/dev-eu')).WEBHOOK, 'sensitive', 'written over the parent as it is now');
  assert.equal((await refusal(root.secrets.reveal('market/dev-eu/WEBHOOK'))).reason, 'sensitive');
});

test("a reference lists as its source reads: sensitive, or a secret, a plain source's included", async () => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { API_KEY: { ref: 'market/dev/API_KEY' }, WEBHOOK: { ref: 'market/dev/WEBHOOK' }, REGION: { ref: 'market/dev/REGION' } });
  assert.deepEqual(await levels('market/prod'), { API_KEY: 'sensitive', REGION: 'secret', WEBHOOK: 'secret' });
  assert.equal((await refusal(root.secrets.reveal('market/prod/API_KEY'))).reason, 'sensitive');
});

test("a fork's copy of a key marked sensitive while it was opened is refused, never written as the secret it was", async (t) => {
  const unwrap = deps.vault.unwrap;
  let compete = true;
  t.mock.method(deps.vault, 'unwrap', async (input: Parameters<typeof unwrap>[0]) => {
    const result = await unwrap(input);
    if (compete && input.purpose === 'copy') {
      compete = false;
      await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' } });
    }
    return result;
  });
  const refused = await refusal(root.environments.create('market/copy', { from: 'dev' }));
  assert.equal(refused.status, 409);
  assert.match(refused.message, /market\/dev\/WEBHOOK changed while it was forked: fork again/);
  // Nothing was copied, and the same fork again fills the environment it made, as the source is now.
  assert.deepEqual((await root.secrets.list('market/copy')).keys, []);
  await root.environments.create('market/copy', { from: 'dev' });
  assert.equal((await levels('market/copy')).WEBHOOK, 'sensitive');
});

/** Fork `from` into market/copy, running `meanwhile` once as the copy's values are opened. */
async function forkedWhile(t: test.TestContext, from: string, meanwhile: () => Promise<unknown>) {
  const unwrap = deps.vault.unwrap;
  let compete = true;
  t.mock.method(deps.vault, 'unwrap', async (input: Parameters<typeof unwrap>[0]) => {
    const result = await unwrap(input);
    if (compete && input.purpose === 'copy') {
      compete = false;
      await meanwhile();
    }
    return result;
  });
  return refusal(root.environments.create('market/copy', { from }));
}

test("a fork's copy of a reference retargeted to a sensitive source while it was opened is refused", async (t) => {
  await root.environments.create('market/base');
  await root.secrets.set('market/base', { OPEN: 'open_0123456789', HIDDEN: { value: 'hidden_0123456789', sensitivity: 'sensitive' } });
  await root.secrets.set('market/dev', { LINKED: { ref: 'market/base/OPEN' } });
  const refused = await forkedWhile(t, 'dev', () => root.secrets.set('market/dev', { LINKED: { ref: 'market/base/HIDDEN' } }));
  assert.equal(refused.status, 409);
  assert.match(refused.message, /market\/dev\/LINKED changed while it was forked: fork again/);
  assert.deepEqual((await root.secrets.list('market/copy')).keys, []);
  await root.environments.create('market/copy', { from: 'dev' });
  assert.equal((await levels('market/copy')).LINKED, 'sensitive');
});

test("a fork's copy of an inherited key overridden as sensitive while it was opened is refused", async (t) => {
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  const refused = await forkedWhile(t, 'dev-eu', () => root.secrets.set('market/dev-eu', { WEBHOOK: { value: 'whsec_eu_0123456789', sensitivity: 'sensitive' } }));
  assert.equal(refused.status, 409);
  assert.match(refused.message, /market\/dev-eu\/WEBHOOK changed while it was forked: fork again/);
  assert.deepEqual((await root.secrets.list('market/copy')).keys, []);
  await root.environments.create('market/copy', { from: 'dev-eu' });
  assert.equal((await levels('market/copy')).WEBHOOK, 'sensitive');
});

test("a value written over a reference to a sensitive source, saying nothing, is sensitive; a mark of a reference is refused", async () => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { API_KEY: { ref: 'market/dev/API_KEY' } });
  const mark = await refusal(root.secrets.set('market/prod', { API_KEY: { sensitivity: 'sensitive' } }));
  assert.match(mark.message, /API_KEY is a reference: mark its source/);
  await root.secrets.set('market/prod', { API_KEY: 'sk_live_prod_0123456789abcdef' });
  assert.equal((await levels('market/prod')).API_KEY, 'sensitive');
  // A dry run marks no key that has no value here, as the write would refuse it.
  assert.equal((await refusal(root.secrets.dryRun('market/prod', { MISSING: { sensitivity: 'sensitive' } }))).status, 409);
});

test("a write over a sensitive reference, prepared again after its source moved, stays sensitive", async (t) => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { API_KEY: { ref: 'market/dev/API_KEY' } });
  const wrap = deps.vault.wrap;
  let compete = true;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/prod/API_KEY')) {
      compete = false;
      await root.secrets.set('market/dev', { API_KEY: { value: 'sk_live_rotated_0123456789', sensitivity: 'sensitive' } });
    }
    return result;
  });
  await root.secrets.set('market/prod', { API_KEY: 'sk_live_prod_0123456789abcdef' });
  assert.equal((await levels('market/prod')).API_KEY, 'sensitive');
});

test("an override, saying nothing, over a parent's reference retargeted to a sensitive source meanwhile, is sensitive", async (t) => {
  await root.environments.create('market/base');
  await root.secrets.set('market/base', { OPEN: 'open_0123456789', HIDDEN: { value: 'hidden_0123456789', sensitivity: 'sensitive' } });
  await root.secrets.set('market/dev', { LINKED: { ref: 'market/base/OPEN' } });
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  const wrap = deps.vault.wrap;
  let compete = true;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/dev-eu/LINKED')) {
      compete = false;
      await root.secrets.set('market/dev', { LINKED: { ref: 'market/base/HIDDEN' } });
    }
    return result;
  });
  await root.secrets.set('market/dev-eu', { LINKED: 'mine_0123456789' });
  assert.equal((await levels('market/dev-eu')).LINKED, 'sensitive');
});

test("a write over a reference whose source is marked sensitive while it is wrapped is sensitive: the reference it ended still says so", async (t) => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK: { ref: 'market/dev/WEBHOOK' } });
  const wrap = deps.vault.wrap;
  let compete = true;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/prod/WEBHOOK')) {
      compete = false;
      await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' } });
    }
    return result;
  });
  await root.secrets.set('market/prod', { WEBHOOK: 'whsec_prod_0123456789abcdef' });
  assert.equal((await levels('market/prod')).WEBHOOK, 'sensitive');
  assert.equal((await refusal(root.secrets.reveal('market/prod/WEBHOOK'))).reason, 'sensitive');
});

test("a rollback over a reference whose source is marked sensitive while it is rewrapped brings the old value back sensitive", async (t) => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK: 'whsec_old_0123456789abcdef' });
  await root.secrets.set('market/prod', { WEBHOOK: { ref: 'market/dev/WEBHOOK' } });
  const rewrap = deps.vault.rewrap;
  let compete = true;
  t.mock.method(deps.vault, 'rewrap', async (input: Parameters<typeof rewrap>[0]) => {
    const result = await rewrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/prod/WEBHOOK')) {
      compete = false;
      await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' } });
    }
    return result;
  });
  await root.secrets.restore('market/prod/WEBHOOK', 1);
  assert.equal((await levels('market/prod')).WEBHOOK, 'sensitive');
  assert.equal((await refusal(root.secrets.reveal('market/prod/WEBHOOK'))).reason, 'sensitive');
});

/**
 * Once, as the write's first attempt is told to prepare again: `then`, before the next attempt reads anything.
 * PrepareAgain is the transaction's own, not exported, so it is told by name.
 */
function betweenAttempts(t: { mock: { method: typeof test.mock.method } }, then: () => Promise<unknown>): void {
  const transaction = db.runtime.transaction.bind(db.runtime);
  let armed = true;
  t.mock.method(db.runtime, 'transaction', (async (work: Parameters<typeof transaction>[0]) => {
    try {
      return await transaction(work);
    } catch (error) {
      if (armed && error instanceof Error && error.constructor.name === 'PrepareAgain') {
        armed = false;
        await then();
      }
      throw error;
    }
  }) as typeof db.runtime.transaction);
}

test("a write over a reference found sensitive under the head stays sensitive when its source is a secret again by the next attempt", async (t) => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK: { ref: 'market/dev/WEBHOOK' } });
  const wrap = deps.vault.wrap;
  let compete = true;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/prod/WEBHOOK')) {
      compete = false;
      await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' } });
    }
    return result;
  });
  betweenAttempts(t, () => root.secrets.set('market/dev', { WEBHOOK: { value: 'whsec_back_0123456789', sensitivity: 'secret' } }));
  await root.secrets.set('market/prod', { WEBHOOK: 'whsec_prod_0123456789abcdef' });
  assert.equal((await levels('market/dev')).WEBHOOK, 'secret');
  assert.equal((await levels('market/prod')).WEBHOOK, 'sensitive');
  assert.equal((await refusal(root.secrets.reveal('market/prod/WEBHOOK'))).reason, 'sensitive');
});

test("a rollback over a reference found sensitive under the head stays sensitive when its source is a secret again by the next attempt", async (t) => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK: 'whsec_old_0123456789abcdef' });
  await root.secrets.set('market/prod', { WEBHOOK: { ref: 'market/dev/WEBHOOK' } });
  const rewrap = deps.vault.rewrap;
  let compete = true;
  t.mock.method(deps.vault, 'rewrap', async (input: Parameters<typeof rewrap>[0]) => {
    const result = await rewrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/prod/WEBHOOK')) {
      compete = false;
      await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' } });
    }
    return result;
  });
  betweenAttempts(t, () => root.secrets.set('market/dev', { WEBHOOK: { value: 'whsec_back_0123456789', sensitivity: 'secret' } }));
  await root.secrets.restore('market/prod/WEBHOOK', 1);
  assert.equal((await levels('market/dev')).WEBHOOK, 'secret');
  assert.equal((await levels('market/prod')).WEBHOOK, 'sensitive');
  assert.equal((await refusal(root.secrets.reveal('market/prod/WEBHOOK'))).reason, 'sensitive');
});

test('a rollback over a reference to a sensitive source brings the old value back sensitive', async () => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { API_KEY: 'sk_live_old_0123456789abcdef' });
  await root.secrets.set('market/prod', { API_KEY: { ref: 'market/dev/API_KEY' } });
  await root.secrets.restore('market/prod/API_KEY', 1);
  assert.equal((await levels('market/prod')).API_KEY, 'sensitive');
  assert.equal((await refusal(root.secrets.reveal('market/prod/API_KEY'))).reason, 'sensitive');
});

test("a rollback of a key made sensitive, then a reference to a secret, brings the old value back sensitive: never looser than its newest version", async () => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK: 'whsec_old_0123456789abcdef' });
  await root.secrets.set('market/prod', { WEBHOOK: { sensitivity: 'sensitive' } });
  await root.secrets.set('market/prod', { WEBHOOK: { ref: 'market/dev/WEBHOOK' } });
  assert.equal((await levels('market/prod')).WEBHOOK, 'secret', 'as its source reads');
  await root.secrets.restore('market/prod/WEBHOOK', 1);
  assert.deepEqual((await history('market/prod/WEBHOOK'))[0], [3, 'sensitive']);
  assert.equal((await refusal(root.secrets.reveal('market/prod/WEBHOOK'))).reason, 'sensitive');
  const [restored] = (await entries('secret.restore')).filter((entry) => entry.decision === 'allow');
  assert.deepEqual(restored!.metadata, { key: 'WEBHOOK', version: 3, from: 1, sensitive: true, was: 'secret' });
});

test("a write's entry says what the key was as it commits: a reference's source marked sensitive while the value is wrapped", async (t) => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { WEBHOOK: { ref: 'market/dev/WEBHOOK' } });
  const wrap = deps.vault.wrap;
  let compete = true;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/prod/WEBHOOK')) {
      compete = false;
      await root.secrets.set('market/dev', { WEBHOOK: { sensitivity: 'sensitive' } });
    }
    return result;
  });
  await root.secrets.set('market/prod', { WEBHOOK: { value: 'whsec_prod_0123456789abcdef', sensitivity: 'secret' } });
  assert.equal((await levels('market/prod')).WEBHOOK, 'secret', 'said so');
  // The source's mark committed first: the newest is the write over the reference.
  assert.deepEqual((await writesOf('WEBHOOK')).at(-1), { key: 'WEBHOOK', version: 1, was: 'sensitive' });
});

test("a rollback's entry says what the key was as it commits: a reference's source written again as a secret while it is rewrapped", async (t) => {
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { API_KEY: 'sk_live_old_0123456789abcdef' });
  await root.secrets.set('market/prod', { API_KEY: { ref: 'market/dev/API_KEY' } });
  const rewrap = deps.vault.rewrap;
  let compete = true;
  t.mock.method(deps.vault, 'rewrap', async (input: Parameters<typeof rewrap>[0]) => {
    const result = await rewrap(input);
    if (compete && input.items.some((item) => item.secret.path === 'market/prod/API_KEY')) {
      compete = false;
      await root.secrets.set('market/dev', { API_KEY: { value: 'sk_live_back_0123456789', sensitivity: 'secret' } });
    }
    return result;
  });
  await root.secrets.restore('market/prod/API_KEY', 1);
  assert.equal((await levels('market/prod')).API_KEY, 'sensitive', 'found sensitive as it was prepared: never looser');
  const [restored] = (await entries('secret.restore')).filter((entry) => entry.decision === 'allow');
  assert.deepEqual(restored!.metadata, { key: 'API_KEY', version: 2, from: 1, sensitive: true, was: 'secret' });
});

test("an app before 0.10 copies no sensitive value for a fork: the vault opens one to copy only for an app that keeps it sensitive", async () => {
  const version = (await root.secrets.list('market/dev')).keys.find((entry) => entry.key === 'API_KEY')!.versionId!;
  const asked = (keepsSensitive?: boolean) => deps.vault.unwrap({ principal: `user:${ROOT}`, purpose: 'copy', ...(keepsSensitive === undefined ? {} : { keepsSensitive }), items: [{ secretVersionId: version }] });
  const old = await asked();
  assert.equal(!old.ok && old.refusal.code, 'sensitive');
  assert.equal((await asked(true)).ok, true);
});

/**
 * `local@me` (R18), its parent a fork of dev, as Equisafe's `backend/local@me`: its owner, whatever their role, overrides
 * every key; their own value is read as its own level says, plain and secret by them alone, sensitive by nobody; and what
 * it inherits is read as on the parent.
 */
async function personalOfFork(email: string, role: 'owner' | 'developer' | 'contributor') {
  await root.environments.create('market/local', { from: 'dev', inherit: true });
  if (role !== 'owner') {
    if (email !== DEV) await root.members.add(`user:${email}`);
    await root.access.set(`user:${email}`, { market: role });
  }
  const person = clientFor(deps, email);
  await person.environments.create('market/local@me');
  return person;
}

const readable = async (client: CoffreClient, path: string) =>
  Object.fromEntries((await client.secrets.list(path)).keys.map((entry) => [entry.key, [entry.parent?.state ?? 'own', entry.sensitivity, entry.readable]]));

for (const [email, role] of [[ROOT, 'owner'], [DEV, 'developer'], ['contributor@acme.example', 'contributor']] as const) {
  test(`in local@me, its ${role} overrides every key, at its level or one they say, and reads their own values but the sensitive ones; what it inherits, as on dev`, async () => {
    const person = await personalOfFork(email, role);
    const reads = role !== 'contributor';
    assert.ok((await person.secrets.list('market/local@me')).permissions.includes('secret.write'));
    assert.deepEqual(await readable(person, 'market/local@me'), {
      API_KEY: ['inherited', 'sensitive', false],
      DB_PASSWORD: ['inherited', 'sensitive', false],
      REGION: ['inherited', 'plain', true],
      WEBHOOK: ['inherited', 'secret', reads],
    });
    // Over a sensitive key and a plain one, as `coffre set` writes them, saying nothing: the person's own values, at the
    // level of the key each overrides (decision 27); as the page writes each, at the level they choose: a secret over a
    // sensitive key, which their app is given, and plain over a secret, which nobody else sees either.
    await person.secrets.set('market/local@me', {
      API_KEY: `sk_test_${role}_0123456789`,
      DB_PASSWORD: { value: `db_${role}_0123456789`, sensitivity: 'secret' },
      REGION: `${role}-region`,
      WEBHOOK: { value: `whsec_${role}_0123456789`, sensitivity: 'plain' },
      MINE: { value: `mine_${role}_0123456789`, sensitivity: 'sensitive' },
    });
    assert.deepEqual(await readable(person, 'market/local@me'), {
      API_KEY: ['overridden', 'sensitive', false],
      DB_PASSWORD: ['overridden', 'secret', true],
      MINE: ['own', 'sensitive', false],
      REGION: ['overridden', 'plain', true],
      WEBHOOK: ['overridden', 'plain', true],
    });
    const listed = Object.fromEntries((await person.secrets.list('market/local@me')).keys.map((entry) => [entry.key, entry.value]));
    assert.deepEqual([listed.REGION, listed.WEBHOOK, listed.DB_PASSWORD], [`${role}-region`, `whsec_${role}_0123456789`, null]);
    assert.deepEqual((await person.secrets.reveal('market/local@me/DB_PASSWORD')).values, { DB_PASSWORD: `db_${role}_0123456789` });
    assert.deepEqual((await person.secrets.reveal('market/local@me/WEBHOOK')).values, { WEBHOOK: `whsec_${role}_0123456789` });
    assert.deepEqual((await person.secrets.reveal('market/local@me/REGION')).values, { REGION: `${role}-region` });
    // Their own sensitive values are used, never read: by the app and by the vault.
    for (const key of ['API_KEY', 'MINE']) {
      const refused = await refusal(person.secrets.reveal(`market/local@me/${key}`));
      assert.deepEqual([refused.status, refused.reason], [403, 'sensitive'], key);
    }
    // One of their own stays sensitive, written again saying nothing; looser only by saying so, as anywhere.
    await person.secrets.set('market/local@me', { MINE: `mine_${role}_again_0123456789` });
    assert.equal((await levels('market/local@me', person)).MINE, 'sensitive');
    await person.secrets.set('market/local@me', { MINE: { value: `mine_${role}_read_0123456789`, sensitivity: 'secret' } });
    assert.deepEqual((await person.secrets.reveal('market/local@me/MINE')).values, { MINE: `mine_${role}_read_0123456789` });
    // dev itself is untouched.
    assert.deepEqual(await levels('market/dev'), { API_KEY: 'sensitive', DB_PASSWORD: 'sensitive', REGION: 'plain', WEBHOOK: 'secret' });
  });
}

test("an owner's sensitive value in local@me is their app's through the proxy: a placeholder, filled with their value, never dev's", async () => {
  const dev = await personalOfFork(DEV, 'developer');
  // dev's own key changes; the person's override holds the one the upstream takes.
  await root.secrets.set('market/dev', { API_KEY: 'sk_live_dev_rotated_0123456789' });
  await dev.secrets.set('market/local@me', { API_KEY: { value: API_KEY, sensitivity: 'sensitive' } });
  assert.equal((await levels('market/local@me', dev)).API_KEY, 'sensitive');
  const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre run market/local@me', paths: ['market/local@me'] })).token;
  const response = await route('/use/market/local@me', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(response.status, 200, await response.clone().text());
  const plan = (await response.json()) as { env: Record<string, string>; left: string[] };
  assert.equal(plan.env.API_KEY, handle);
  assert.equal(JSON.stringify(plan).includes(API_KEY), false);
  const answer = await route('/use/market/local@me/api/thing', { headers: { 'x-api-key': handle } });
  assert.deepEqual(await answer.json(), { real: true });
});

test("an environment's version is of what the caller's read opens: a sensitive value's change moves a service account's alone", async () => {
  const dev = clientFor(deps, DEV);
  const [person, service] = [(await dev.environments.version('market/dev')).version, (await ci.environments.version('market/dev')).version];
  assert.notEqual(person, service);
  // A watch compares the version a read answered with the next: the same, for the same read.
  assert.equal((await dev.secrets.reveal('market/dev')).version, person);
  await root.secrets.set('market/dev', { API_KEY: 'sk_live_rotated_0123456789' });
  assert.equal((await dev.environments.version('market/dev')).version, person);
  assert.notEqual((await ci.environments.version('market/dev')).version, service);
  await root.secrets.set('market/dev', { WEBHOOK: 'whsec_rotated_0123456789' });
  assert.notEqual((await dev.environments.version('market/dev')).version, person);
});

test("a person granted only a fork reads and versions it, a sensitive key it inherits from a parent they do not read left out of both", async () => {
  await root.environments.create('market/base');
  await root.secrets.set('market/base', { HIDDEN: { value: 'hidden_0123456789', sensitivity: 'sensitive' } });
  await root.environments.create('market/base-eu', { from: 'base', inherit: true });
  await root.secrets.set('market/base-eu', { OWN: 'own_0123456789' });
  const email = 'viewer@acme.example';
  await root.members.add(`user:${email}`);
  await root.access.set(`user:${email}`, { 'market/base-eu': 'viewer' });
  const viewer = clientFor(deps, email);
  const read = await viewer.secrets.reveal('market/base-eu');
  assert.deepEqual([read.values, read.sensitive], [{ OWN: 'own_0123456789' }, ['HIDDEN']]);
  const { version } = await viewer.environments.version('market/base-eu');
  // What a watch compares: the version the read answered with.
  assert.equal(read.version, version);
  await root.secrets.set('market/base', { HIDDEN: 'hidden_rotated_0123456789' });
  assert.equal((await viewer.environments.version('market/base-eu')).version, version);
  await root.secrets.set('market/base-eu', { OWN: 'own_rotated_0123456789' });
  assert.notEqual((await viewer.environments.version('market/base-eu')).version, version);
});

test("the plan gives a credential's sensitive key as a placeholder, filled upstream; a sensitive key no credential uses is left out, and a secret given", async () => {
  const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] })).token;
  const response = await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(response.status, 200, await response.clone().text());
  const plan = (await response.json()) as { env: Record<string, string>; left: string[] };
  assert.deepEqual(plan.env, { API_KEY: handle, REGION: 'eu-west-3', WEBHOOK });
  assert.deepEqual(plan.left, ['DB_PASSWORD']);
  assert.equal(JSON.stringify(plan).includes(API_KEY), false);
  const answer = await route('/use/market/dev/api/thing', { headers: { 'x-api-key': handle } });
  assert.equal(answer.status, 200);
  assert.deepEqual(await answer.json(), { real: true });
});

test("a fork's plan gives what it inherits as dev's would: each secret its person reads, a credential's placeholder, and only a sensitive key no credential uses left out", async () => {
  // As Equisafe's `backend/local`, a fork of dev, whose 0.9 export left 11 keys out under `people: 'stand-ins'`.
  await root.environments.create('market/local', { from: 'dev', inherit: true });
  const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre export market/local', paths: ['market/local'] })).token;
  const response = await route('/use/market/local', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(response.status, 200, await response.clone().text());
  const plan = (await response.json()) as { env: Record<string, string>; left: string[] };
  assert.deepEqual(plan.env, { API_KEY: handle, REGION: 'eu-west-3', WEBHOOK });
  assert.deepEqual(plan.left, ['DB_PASSWORD']);
});

test('0.9\'s people, expose and identifiers are refused at configuration, saying what to do instead', async () => {
  // @ts-expect-error -- the type says each key says who sees it now
  assert.throws(() => credentialProxy({ credentials: {}, expose: { 'market/dev': 'all' } }), /expose is gone in 0\.10.*coffre mark <env> sensitive/);
  assert.throws(
    // @ts-expect-error -- the type says to mark the key plain
    () => credentialProxy({ credentials: { twilio: { upstream: 'https://api.twilio.com', inject: basic('{SID}', '{TOKEN}'), identifiers: ['SID'] } } }),
    /twilio's identifiers are gone in 0\.10: mark each key plain instead/,
  );
  const vault = testVault([ROOT], { people: 'stand-ins' } as never);
  await assert.rejects(vault.about(), /people is gone in 0\.10 \(it was "stand-ins"\).*mark the keys no person may read sensitive/);
});

test('a sensitive column flipped around coffre opens nothing: the wrap of its key binds it, so a read fails as bad_claim', async () => {
  const id = (key: string) => root.secrets.list('market/dev').then(({ keys }) => keys.find((entry) => entry.key === key)!.versionId!);
  const [apiKey, webhook] = [await id('API_KEY'), await id('WEBHOOK')];
  // The database keeps a version's sensitivity as it keeps its value.
  await assert.rejects(db.owner.update(secretVersions).set({ sensitive: false }).where(eq(secretVersions.id, apiKey)), (error: Error) => /only ever erased/.test(`${error.message} ${String(error.cause)}`));
  // As the owner, with that guard lifted, as only someone around coffre could: sensitive made a secret, and a secret sensitive.
  await withTriggersLifted(db.owner, 'secret_versions', async (owner) => {
    await owner.update(secretVersions).set({ sensitive: false }).where(eq(secretVersions.id, apiKey));
    await owner.update(secretVersions).set({ sensitive: true }).where(eq(secretVersions.id, webhook));
  });
  assert.equal((await levels('market/dev')).API_KEY, 'secret', 'the listing believes the column');
  for (const reader of [clientFor(deps, DEV), ci]) {
    const refused = await refusal(reader.secrets.reveal('market/dev/API_KEY'));
    assert.deepEqual([refused.status, refused.reason], [403, 'bad_claim']);
    assert.equal(refused.message.includes(API_KEY), false);
  }
  assert.equal((await refusal(ci.secrets.reveal('market/dev/WEBHOOK'))).reason, 'bad_claim');
});
