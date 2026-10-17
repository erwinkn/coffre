import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog, secrets, secretVersions } from './db/tables.ts';
import { withTriggersLifted } from './db/engine.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

/**
 * Generated values (`@coffre/core/recipe`): a client makes the value and
 * sends it with its recipe; the server checks the recipe's shape, keeps it
 * with the version, and says it back in the listing, so Regenerate makes
 * the next one alike. It makes no value itself.
 */

const ROOT = 'admin@acme.example';
const PAIR = { recipe: 'ecdsa:p-256', pair: { private: 'JWT_PRIVATE_KEY', public: 'JWT_PUBLIC_KEY' } };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let firstSeq: bigint;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Dev' });
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  firstSeq = head.nextSeq;
});

async function generatedIn(path: string): Promise<Record<string, unknown>> {
  return Object.fromEntries((await root.secrets.list(path)).keys.map((entry) => [entry.key, entry.generated]));
}

function pairWrite(names = PAIR.pair, recipe = PAIR.recipe) {
  const generated = { recipe, pair: names };
  return { [names.private]: { value: 'private-key', generated }, [names.public]: { value: 'public-key', generated } };
}

test('a generated value keeps its recipe, written canonical, until a value is written by hand', async () => {
  const written = await root.secrets.set('market/dev', { TOKEN: { value: 'made-in-the-client', generated: { recipe: 'BYTES:32' } } });
  assert.deepEqual(written.keys, { TOKEN: { version: 1 } });
  assert.deepEqual(await generatedIn('market/dev'), { TOKEN: { recipe: 'bytes:32:base62' } });
  // The value is the one sent: the server made nothing.
  assert.deepEqual((await root.secrets.reveal('market/dev/TOKEN')).values, { TOKEN: 'made-in-the-client' });

  await root.secrets.set('market/dev', { TOKEN: 'typed' });
  assert.deepEqual(await generatedIn('market/dev'), { TOKEN: null });
  await root.secrets.set('market/dev', { TOKEN: { value: 'made-again', generated: { recipe: 'bytes:16:hex' } } });
  assert.deepEqual(await generatedIn('market/dev'), { TOKEN: { recipe: 'bytes:16:hex' } });

  // Each version says how it was made, and so does its write's audit entry, without the value.
  const history = await root.secrets.history('market/dev/TOKEN');
  assert.deepEqual(history.versions.map(({ version, recipe }) => [version, recipe]), [[3, 'bytes:16:hex'], [2, null], [1, 'bytes:32:base62']]);
  const entries = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog)
    .where(and(eq(auditLog.action, 'secret.write'), gte(auditLog.seq, firstSeq))).orderBy(asc(auditLog.seq));
  assert.deepEqual(entries.map(({ metadata }) => JSON.parse(metadata).recipe ?? null), ['bytes:32:base62', null, 'bytes:16:hex']);
  assert.equal(JSON.stringify(entries).includes('made-'), false);
});

test("a key pair's halves each name both, while both are of the same pair", async () => {
  await root.secrets.set('market/dev', { ...pairWrite(), OTHER: 'x' });
  assert.deepEqual(await generatedIn('market/dev'), { JWT_PRIVATE_KEY: PAIR, JWT_PUBLIC_KEY: PAIR, OTHER: null });

  // A rename moves no value: the pair names the halves as they are now.
  await root.secrets.rename('market/dev/JWT_PUBLIC_KEY', 'JWT_VERIFY_KEY');
  const renamed = { ...PAIR, pair: { private: 'JWT_PRIVATE_KEY', public: 'JWT_VERIFY_KEY' } };
  assert.deepEqual(await generatedIn('market/dev'), { JWT_PRIVATE_KEY: renamed, JWT_VERIFY_KEY: renamed, OTHER: null });

  // Typing over either half breaks the pair: neither has a recipe until the pair is made again.
  await root.secrets.set('market/dev', { JWT_VERIFY_KEY: 'pasted' });
  assert.deepEqual(await generatedIn('market/dev'), { JWT_PRIVATE_KEY: null, JWT_VERIFY_KEY: null, OTHER: null });
  await root.secrets.set('market/dev', pairWrite(renamed.pair));
  assert.deepEqual(await generatedIn('market/dev'), { JWT_PRIVATE_KEY: renamed, JWT_VERIFY_KEY: renamed, OTHER: null });

  // So does archiving one.
  await root.secrets.set('market/dev', { JWT_VERIFY_KEY: null });
  assert.equal((await generatedIn('market/dev')).JWT_PRIVATE_KEY, null);
});

test('rolling back brings an old value back with its recipe, and a pair only whole', async () => {
  await root.secrets.set('market/dev', { TOKEN: { value: 'one', generated: { recipe: 'aes:256' } } });
  await root.secrets.set('market/dev', { TOKEN: 'typed' });
  await root.secrets.restore('market/dev/TOKEN', 1);
  assert.deepEqual((await generatedIn('market/dev')).TOKEN, { recipe: 'aes:256' });

  await root.secrets.set('market/dev', pairWrite());
  await root.secrets.set('market/dev', pairWrite());
  // One half back to the first pair, beside the other half of the second: no pair.
  await root.secrets.restore('market/dev/JWT_PRIVATE_KEY', 1);
  assert.equal((await generatedIn('market/dev')).JWT_PRIVATE_KEY, null);
  assert.equal((await generatedIn('market/dev')).JWT_PUBLIC_KEY, null);
  // Both back to the first pair: a pair again.
  await root.secrets.restore('market/dev/JWT_PUBLIC_KEY', 1);
  assert.deepEqual((await generatedIn('market/dev')).JWT_PRIVATE_KEY, PAIR);
});

test('a recipe the server cannot read, or a key pair not written whole, is refused and writes nothing', async () => {
  const one = (generated: object) => ({ TOKEN: { value: 'v', generated } }) as never;
  const refused: [string, object][] = [
    ['no recipe', one({ recipe: 'bytes:0' })],
    ['an unknown recipe', one({ recipe: 'rsa:2048' })],
    ['one value named as a pair', one({ recipe: 'bytes:32', pair: PAIR.pair })],
    ['a pair named nowhere', one({ recipe: 'ecdsa:p-256' })],
    ['a pair it is no half of', one(PAIR)],
    ['half a pair', { JWT_PRIVATE_KEY: pairWrite().JWT_PRIVATE_KEY }],
    ['the other half typed', { ...pairWrite(), JWT_PUBLIC_KEY: 'typed' }],
    ['halves of two recipes', { ...pairWrite(), JWT_PUBLIC_KEY: { value: 'p', generated: { ...PAIR, recipe: 'ecdsa:p-384' } } }],
    ['halves naming two pairs', { ...pairWrite(), JWT_PUBLIC_KEY: { value: 'p', generated: { ...PAIR, pair: { ...PAIR.pair, private: 'OTHER' } } } }],
    ['one key as both halves', one({ recipe: 'ecdh:p-384', pair: { private: 'TOKEN', public: 'TOKEN' } })],
    ['an unknown field', one({ recipe: 'bytes:32', length: 3 })],
  ];
  for (const [what, patch] of refused) {
    await assert.rejects(root.secrets.set('market/dev', patch as never), { status: 400 }, what);
  }
  assert.equal((await db.owner.select().from(secrets)).length, 0);
});

/** What a regenerate of `keys` sends, from `path`'s listing now: each value with the id of the version it replaces. */
async function regenerateOf(path: string, keys: string[], names = PAIR.pair, generated: object = PAIR) {
  const listed = new Map((await root.secrets.list(path)).keys.map((entry) => [entry.key, entry.versionId]));
  const write = () => Object.fromEntries(keys.map((key) => [key, {
    value: `${key}-made`, generated: { ...generated, ...(keys.length === 2 ? { pair: names } : {}) }, replaces: listed.get(key)!,
  }])) as never;
  return { listed, send: () => root.secrets.set(path, write()) };
}

test('a regenerate replaces the versions it was listed with, by their ids, or writes nothing', async () => {
  await root.secrets.set('market/dev', pairWrite());
  const keys = ['JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY'];
  const first = await regenerateOf('market/dev', keys);
  assert.deepEqual((await first.send()).keys, { JWT_PRIVATE_KEY: { version: 2 }, JWT_PUBLIC_KEY: { version: 2 } });
  // The same listing again: both have moved on since.
  await assert.rejects(first.send(), { status: 409, message: /JWT_PRIVATE_KEY changed since it was listed/ });

  // One half renamed since it was listed: its old name is no half of the pair, even made again under that name.
  const stale = await regenerateOf('market/dev', keys);
  await root.secrets.rename('market/dev/JWT_PRIVATE_KEY', 'SIGNING_KEY');
  await assert.rejects(stale.send(), { status: 409, message: /JWT_PRIVATE_KEY has no value to regenerate now: it was renamed/ });
  await root.secrets.set('market/dev', { JWT_PRIVATE_KEY: 'a new key under the old name' });
  await assert.rejects(stale.send(), { status: 409, message: /JWT_PRIVATE_KEY changed since it was listed/ });

  // Typed over, or archived, since.
  const renamed = { private: 'SIGNING_KEY', public: 'JWT_PUBLIC_KEY' };
  const typed = await regenerateOf('market/dev', ['SIGNING_KEY', 'JWT_PUBLIC_KEY'], renamed);
  await root.secrets.set('market/dev', { JWT_PUBLIC_KEY: 'typed' });
  await assert.rejects(typed.send(), { status: 409, message: /JWT_PUBLIC_KEY changed/ });
  const archived = await regenerateOf('market/dev', ['SIGNING_KEY', 'JWT_PUBLIC_KEY'], renamed);
  await root.secrets.set('market/dev', { SIGNING_KEY: null });
  await assert.rejects(archived.send(), { status: 409, message: /SIGNING_KEY has no value to regenerate now/ });

  // Nothing of those refused was written.
  const listed = (await root.secrets.list('market/dev')).keys.map(({ key, version, archived }) => [key, version, archived]);
  assert.deepEqual(listed, [['JWT_PRIVATE_KEY', 1, false], ['JWT_PUBLIC_KEY', 3, false], ['SIGNING_KEY', 2, true]]);
});

test('in a fork, an inherited key keeps its recipe, and regenerating it overrides it there, never in the parent', async () => {
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.secrets.set('market/prod', { ...pairWrite(), TOKEN: { value: 'parent-token', generated: { recipe: 'bytes:32:hex' } } });
  await root.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  const listed = async () => Object.fromEntries((await root.secrets.list('market/prod-eu')).keys.map((entry) => [entry.key, [entry.generated, entry.version, entry.parent?.state]]));
  assert.deepEqual(await listed(), {
    JWT_PRIVATE_KEY: [PAIR, 1, 'inherited'],
    JWT_PUBLIC_KEY: [PAIR, 1, 'inherited'],
    TOKEN: [{ recipe: 'bytes:32:hex' }, 1, 'inherited'],
  });
  const parentBefore = (await root.secrets.list('market/prod')).keys.map(({ key, versionId }) => [key, versionId]);

  // Regenerating replaces the version it inherits, by its id, written as the fork's own.
  const written = await (await regenerateOf('market/prod-eu', ['JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY'])).send();
  assert.deepEqual(written.keys, { JWT_PRIVATE_KEY: { version: 1 }, JWT_PUBLIC_KEY: { version: 1 } });
  assert.deepEqual((await listed()).JWT_PUBLIC_KEY, [PAIR, 1, 'overridden']);
  // The parent is as it was.
  assert.deepEqual((await root.secrets.list('market/prod')).keys.map(({ key, versionId }) => [key, versionId]), parentBefore);

  // The parent rotated since the fork listed its key: refused.
  const token = await regenerateOf('market/prod-eu', ['TOKEN'], PAIR.pair, { recipe: 'bytes:32:hex' });
  await root.secrets.set('market/prod', { TOKEN: { value: 'rotated', generated: { recipe: 'bytes:32:hex' } } });
  await assert.rejects(token.send(), { status: 409, message: /TOKEN changed since it was listed/ });
  // Overridden by hand in the fork since: its own version 1 is not the inherited version it was listed with.
  const inherited = await regenerateOf('market/prod-eu', ['TOKEN'], PAIR.pair, { recipe: 'bytes:32:hex' });
  await root.secrets.set('market/prod-eu', { TOKEN: 'typed in the fork' });
  assert.equal((await root.secrets.list('market/prod-eu')).keys.find((entry) => entry.key === 'TOKEN')!.version, 1);
  await assert.rejects(inherited.send(), { status: 409, message: /TOKEN changed since it was listed/ });

  // One half overridden by hand in the fork: neither half pairs there.
  await root.secrets.set('market/prod-eu', { JWT_PUBLIC_KEY: 'typed' });
  assert.deepEqual([(await listed()).JWT_PRIVATE_KEY![0], (await listed()).JWT_PUBLIC_KEY![0]], [null, null]);
});

test("a parent's key renamed while a fork's regenerate of it is wrapped: checked again under the head, and refused", async (t) => {
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.secrets.set('market/prod', pairWrite());
  await root.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  const regenerate = await regenerateOf('market/prod-eu', ['JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY']);
  const wrap = deps.vault.wrap;
  let renamed = false;
  t.mock.method(deps.vault, 'wrap', async (input: Parameters<typeof wrap>[0]) => {
    const result = await wrap(input);
    // Once, after the write was prepared and before it takes the head.
    if (!renamed) {
      renamed = true;
      await root.secrets.rename('market/prod/JWT_PRIVATE_KEY', 'SIGNING_KEY');
    }
    return result;
  });
  await assert.rejects(regenerate.send(), { status: 409, message: /JWT_PRIVATE_KEY has no value to regenerate now/ });
  // No override under the old name beside the renamed inherited key.
  const forked = (await root.secrets.list('market/prod-eu')).keys.map(({ key, parent }) => [key, parent?.state]);
  assert.deepEqual(forked, [['JWT_PUBLIC_KEY', 'inherited'], ['SIGNING_KEY', 'inherited']]);
});

test('a recipe the database holds and no client could send makes no Regenerate', async () => {
  await root.secrets.set('market/dev', { TOKEN: { value: 'v', generated: { recipe: 'bytes:32' } } });
  // As the owner, with the erase-only guard lifted, as only someone around coffre could.
  await withTriggersLifted(db.owner, 'secret_versions', (owner) => owner.update(secretVersions).set({ recipe: 'bytes:9999' }));
  assert.deepEqual(await generatedIn('market/dev'), { TOKEN: null });
});

test('a version keeps its recipe as it keeps its value: the database refuses to change it', async () => {
  await root.secrets.set('market/dev', { TOKEN: { value: 'v', generated: { recipe: 'bytes:32' } } });
  for (const change of [{ recipe: 'bytes:1:hex' }, { pairId: '00000000-0000-4000-8000-000000000000' }, { pairHalf: 'public' }]) {
    // The driver's error wraps the database's.
    await assert.rejects(db.owner.update(secretVersions).set(change), (error: Error) => /only ever erased/.test(`${error.message} ${String(error.cause)}`), JSON.stringify(change));
  }
  assert.deepEqual(await generatedIn('market/dev'), { TOKEN: { recipe: 'bytes:32:base62' } });
});
