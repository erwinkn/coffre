// A personal config is an overlay of its environment (docs/design/forking.md,
// R8, R18, decision 27): each key its owner sets is theirs, over dev's key or
// beside it, and every other key falls through to dev's, live. Its own
// values may be plain, secret or sensitive, as anywhere; one written saying
// nothing takes the level of the value the key reads now, dev's or the
// owner's own. Whatever its level, nobody but its owner sees one of its
// values, plain ones included, by any path: an instance Owner, the project's
// Maintainer and every other member see its key names at most.
import test from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { eq } from 'drizzle-orm';

import { clientFor } from './api-fixture.ts';
import { callRaw, connect, db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { auditLog, environments } from './db/tables.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy } from '../src/plugins/credential-proxy.ts';

const MAINTAINER = 'maintainer@acme.example';
const OTHER = 'other@acme.example';

/** dev's keys: three that fall through, and four the owner overrides. */
const DEV_VALUES = {
  HOST: 'db.dev.internal',
  TOKEN: 'token_dev_0123456789',
  SEAL: 'seal_dev_0123456789',
  REGION: 'eu-west-3',
  WEBHOOK: 'whsec_dev_0123456789',
  API_KEY: 'sk_dev_0123456789',
  DATABASE_URL: 'postgres://dev.internal/market',
};

/** The owner's own values in dev@me: four overrides and three new keys, one of each level. */
const MINE = {
  REGION: 'eu-west-1-mine',
  WEBHOOK: 'whsec_mine_0123456789',
  API_KEY: 'sk_mine_0123456789',
  DATABASE_URL: 'postgres://localhost/mine',
  NEW_PLAIN: 'new-plain-mine',
  NEW_SECRET: 'new_secret_mine_0123456789',
  NEW_SENSITIVE: 'new_sensitive_mine_0123456789',
};

let root: CoffreClient;
let dev: CoffreClient;

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {} })]);
  root = clientFor(deps, ROOT);
  dev = clientFor(deps, DEV);
  for (const email of [DEV, MAINTAINER, OTHER]) await root.members.add(`user:${email}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', {
    HOST: { value: DEV_VALUES.HOST, sensitivity: 'plain' },
    TOKEN: DEV_VALUES.TOKEN,
    SEAL: { value: DEV_VALUES.SEAL, sensitivity: 'sensitive' },
    REGION: { value: DEV_VALUES.REGION, sensitivity: 'plain' },
    WEBHOOK: DEV_VALUES.WEBHOOK,
    API_KEY: { value: DEV_VALUES.API_KEY, sensitivity: 'sensitive' },
    DATABASE_URL: { value: DEV_VALUES.DATABASE_URL, sensitivity: 'sensitive' },
  });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  await root.access.set(`user:${MAINTAINER}`, { market: 'maintainer' });
  await root.access.set(`user:${OTHER}`, { market: 'developer' });
  // Over each level of dev's, saying nothing, as `coffre set` writes: at dev's level. DATABASE_URL said a secret, a local
  // database their app is given; and a new key of each level.
  await dev.secrets.set('market/dev@me', {
    REGION: MINE.REGION,
    WEBHOOK: MINE.WEBHOOK,
    API_KEY: MINE.API_KEY,
    DATABASE_URL: { value: MINE.DATABASE_URL, sensitivity: 'secret' },
    NEW_PLAIN: { value: MINE.NEW_PLAIN, sensitivity: 'plain' },
    NEW_SECRET: MINE.NEW_SECRET,
    NEW_SENSITIVE: { value: MINE.NEW_SENSITIVE, sensitivity: 'sensitive' },
  });
});

function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

/** Each key as listed: where it stands to dev, who sees it, whether the caller reads it, and its plain value. */
const listed = async (client: CoffreClient, path: string) =>
  Object.fromEntries((await client.secrets.list(path)).keys.map((entry) => [entry.key, [entry.parent?.state ?? 'own', entry.sensitivity, entry.readable, entry.value]]));

/** The personal config's own slug, which only its owner's `dev@me` names, and an API that lists it for deletion shows. */
async function slugOf(): Promise<string> {
  const [row] = await db.owner.select({ slug: environments.slug }).from(environments).where(eq(environments.owner, `user:${DEV}`));
  return row!.slug;
}

/** Whether `text` holds any of the owner's own values. */
const leaks = (text: string) => Object.values(MINE).filter((value) => text.includes(value));

test('each key the owner sets is theirs, at the level of the key it overrides unless they say; every other key falls through to dev', async () => {
  assert.deepEqual(await listed(dev, 'market/dev@me'), {
    API_KEY: ['overridden', 'sensitive', false, null],
    DATABASE_URL: ['overridden', 'secret', true, null],
    HOST: ['inherited', 'plain', true, DEV_VALUES.HOST],
    NEW_PLAIN: ['own', 'plain', true, MINE.NEW_PLAIN],
    NEW_SECRET: ['own', 'secret', true, null],
    NEW_SENSITIVE: ['own', 'sensitive', false, null],
    REGION: ['overridden', 'plain', true, MINE.REGION],
    SEAL: ['inherited', 'sensitive', false, null],
    TOKEN: ['inherited', 'secret', true, null],
    WEBHOOK: ['overridden', 'secret', true, null],
  });
  // `coffre export` and `coffre get`: every value but the sensitive ones, theirs and dev's alike, which are left out by name.
  const all = await dev.secrets.reveal('market/dev@me');
  assert.deepEqual({ ...all.values }, {
    DATABASE_URL: MINE.DATABASE_URL,
    HOST: DEV_VALUES.HOST,
    NEW_PLAIN: MINE.NEW_PLAIN,
    NEW_SECRET: MINE.NEW_SECRET,
    REGION: MINE.REGION,
    TOKEN: DEV_VALUES.TOKEN,
    WEBHOOK: MINE.WEBHOOK,
  });
  assert.deepEqual([...all.sensitive].sort(), ['API_KEY', 'NEW_SENSITIVE', 'SEAL']);
  for (const key of ['API_KEY', 'NEW_SENSITIVE', 'SEAL']) {
    await assert.rejects(dev.secrets.reveal(`market/dev@me/${key}`), { status: 403, reason: 'sensitive' });
  }
  assert.deepEqual({ ...(await dev.secrets.reveal('market/dev@me/NEW_PLAIN')).values }, { NEW_PLAIN: MINE.NEW_PLAIN });
  // Each version says how it is held, a plain one's as any plain version's.
  assert.deepEqual((await dev.secrets.history('market/dev@me/REGION')).versions.map(({ plain, sensitivity }) => [plain, sensitivity]), [[true, 'plain']]);
  // A dry run compares as the write would hold it: plain with no read, a secret through the vault.
  const reads = (await entries('secret.read')).length;
  assert.deepEqual({ ...(await dev.secrets.dryRun('market/dev@me', { REGION: MINE.REGION, NEW_PLAIN: MINE.NEW_PLAIN })).keys }, { REGION: 'unchanged', NEW_PLAIN: 'unchanged' });
  assert.equal((await entries('secret.read')).length, reads);
  assert.deepEqual({ ...(await dev.secrets.dryRun('market/dev@me', { WEBHOOK: MINE.WEBHOOK, NEW_SECRET: 'guess_0123456789' })).keys }, { WEBHOOK: 'unchanged', NEW_SECRET: 'changed' });
  // dev itself is untouched.
  assert.deepEqual(Object.fromEntries((await root.secrets.list('market/dev')).keys.map((entry) => [entry.key, entry.value])).REGION, DEV_VALUES.REGION);
});

test("the owner's app gets their plain and secret values, theirs over dev's, and goes without the sensitive ones no credential uses", async () => {
  const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre run market/dev@me', paths: ['market/dev@me'] })).token;
  const response = await route('/use/market/dev@me', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(response.status, 200, await response.clone().text());
  const plan = (await response.json()) as { environment: string; env: Record<string, string>; left: string[] };
  assert.equal(plan.environment, 'market/dev@me');
  assert.deepEqual({ ...plan.env }, {
    DATABASE_URL: MINE.DATABASE_URL,
    HOST: DEV_VALUES.HOST,
    NEW_PLAIN: MINE.NEW_PLAIN,
    NEW_SECRET: MINE.NEW_SECRET,
    REGION: MINE.REGION,
    TOKEN: DEV_VALUES.TOKEN,
    WEBHOOK: MINE.WEBHOOK,
  });
  assert.deepEqual([...plan.left].sort(), ['API_KEY', 'NEW_SENSITIVE', 'SEAL']);
  // Through MCP too, as the person's own reads: a plain value listed, and every readable one revealed.
  const token = await connect(DEV, 'read reveal');
  const keys = (await callRaw(token, 'list_secrets', { environment: 'market/dev@me' })).body.result!.structuredContent!.keys as { key: string; value: string | null }[];
  assert.equal(keys.find((entry) => entry.key === 'NEW_PLAIN')!.value, MINE.NEW_PLAIN);
  const revealed = (await callRaw(token, 'reveal_secret_values', { path: 'market/dev@me' })).body.result!.structuredContent!;
  assert.equal((revealed.values as Record<string, string>).REGION, MINE.REGION);
});

for (const [who, email] of [['an instance Owner', ROOT], ["the project's Maintainer", MAINTAINER], ['another member', OTHER]] as const) {
  test(`${who} sees no value of the owner's dev@me, plain ones included, by any path: their own dev@me is dev`, async () => {
    const client = clientFor(deps, email);
    const slug = await slugOf();
    const path = `market/${slug}`;
    // Their `dev@me` is theirs, dev while they have none: dev's REGION, and no key of the owner's.
    const theirs = await listed(client, 'market/dev@me');
    assert.equal(theirs.REGION![3], DEV_VALUES.REGION);
    assert.equal(theirs.NEW_PLAIN, undefined);
    assert.equal((await client.secrets.reveal('market/dev@me')).values.REGION, DEV_VALUES.REGION);
    // The owner's, by its own slug: no list, read, export, history, version or dry run.
    for (const [what, attempt] of [
      ['list', () => client.secrets.list(path)],
      ['export', () => client.secrets.reveal(path)],
      ['get', () => client.secrets.reveal(`${path}/NEW_PLAIN`)],
      ['history', () => client.secrets.history(`${path}/REGION`)],
      ['version', () => client.environments.version(path)],
      ['dry run', () => client.secrets.dryRun(path, { NEW_PLAIN: MINE.NEW_PLAIN })],
      ['write', () => client.secrets.set(path, { NEW_PLAIN: { value: 'overwritten', sensitivity: 'plain' } })],
    ] as const) {
      await assert.rejects(attempt(), { status: 403 }, what);
    }
    // A handle may name it, and its plan opens nothing.
    const handle = (await bearer(await sessionFor(email)).handles.create({ label: 'coffre run', paths: [path] })).token;
    const plan = await route(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
    assert.equal(plan.status, 403);
    assert.deepEqual(leaks(await plan.text()), []);
    // Nor does MCP.
    const token = await connect(email, 'read reveal');
    for (const [name, args] of [['list_secrets', { environment: path }], ['reveal_secret_values', { path }]] as const) {
      const answered = await callRaw(token, name, args);
      assert.equal(answered.body.result!.isError, true, name);
      assert.deepEqual(leaks(JSON.stringify(answered.body)), [], name);
    }
    // What a maintainer is shown of personal configs, and the log, which they read: key names, never a value.
    if (email !== OTHER) {
      const { configs } = await client.environments.personal('market');
      assert.deepEqual(configs.map((config) => config.keys), [['API_KEY', 'DATABASE_URL', 'NEW_PLAIN', 'NEW_SECRET', 'NEW_SENSITIVE', 'REGION', 'WEBHOOK']]);
      assert.deepEqual(leaks(JSON.stringify(configs)), []);
      assert.deepEqual(leaks(JSON.stringify(await client.environments.previewDelete(path))), []);
    }
    if (email === ROOT) assert.deepEqual(leaks(JSON.stringify(await client.audit.list({ detail: '1', limit: 200 }))), []);
    // The owner's values stand.
    assert.equal((await listed(dev, 'market/dev@me')).NEW_PLAIN![3], MINE.NEW_PLAIN);
  });
}

test('no audit entry holds a value of a personal config, plain ones included', async () => {
  await dev.secrets.reveal('market/dev@me');
  const rows = await db.owner.select().from(auditLog);
  assert.ok(rows.length > 0);
  assert.deepEqual(leaks(JSON.stringify(rows, (_key, value: unknown) => (typeof value === 'bigint' ? value.toString() : value))), []);
});

test('a write saying nothing over a value of the owner\'s own keeps its level; one said changes it, and only stricter by a mark', async () => {
  await dev.secrets.set('market/dev@me', { REGION: 'eu-west-2-mine', WEBHOOK: 'whsec_mine_again_0123', API_KEY: 'sk_mine_again_0123', NEW_PLAIN: 'new-plain-again' });
  const levels = async () => Object.fromEntries((await dev.secrets.list('market/dev@me')).keys.map((entry) => [entry.key, entry.sensitivity]));
  assert.deepEqual(
    [(await levels()).REGION, (await levels()).WEBHOOK, (await levels()).API_KEY, (await levels()).NEW_PLAIN],
    ['plain', 'secret', 'sensitive', 'plain'],
  );
  // Their own level, once said, is the one kept: a secret REGION stays a secret, whatever dev's is.
  await dev.secrets.set('market/dev@me', { REGION: { value: 'eu-west-2-secret', sensitivity: 'secret' } });
  await dev.secrets.set('market/dev@me', { REGION: 'eu-west-2-secret-again' });
  assert.equal((await levels()).REGION, 'secret');
  // A generated value is never plain: over a plain one, saying nothing, a secret.
  await dev.secrets.set('market/dev@me', { NEW_PLAIN: { value: 'a'.repeat(32), generated: { recipe: 'bytes:16:hex' } } });
  assert.equal((await levels()).NEW_PLAIN, 'secret');
  // Marks: stricter keeps the value, looser takes it typed again, as anywhere.
  await dev.secrets.set('market/dev@me', { WEBHOOK: { sensitivity: 'sensitive' } });
  assert.equal((await levels()).WEBHOOK, 'sensitive');
  await assert.rejects(dev.secrets.set('market/dev@me', { WEBHOOK: { sensitivity: 'plain' } }), { status: 409 });
  // A key it only inherits has no value of its own to mark: dev's level is dev's.
  await assert.rejects(dev.secrets.set('market/dev@me', { TOKEN: { sensitivity: 'sensitive' } }), { status: 409 });
  // What falls through follows dev, live: dev's TOKEN made sensitive is sensitive here too.
  await root.secrets.set('market/dev', { TOKEN: { sensitivity: 'sensitive' } });
  assert.equal((await levels()).TOKEN, 'sensitive');
});
