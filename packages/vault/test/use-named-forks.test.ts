// 0.15's use by name at a fork and at `dev@me` (T165, B2; migration 0050; formal/Probing.tla, Where): the vault's one
// call reads the place a fork's path names, or the caller's personal config of dev (dev while they have none), decides
// the caller's standing there first, then resolves the key through what the place inherits, its own first, then each
// parent's unless the place removed it, and decides it where it is held too. A chain cut (a parent archived) reads
// nothing. Every refusal is one call, whatever the key; a caller who does not stand at the place has nothing of the
// key read.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { NamedUseInput, NamedUseOutcome } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';

import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { bufferedBy, keyBlocksOf, namedWorld, slowed as slowedVault, weighed, weighingSession } from './named-world.ts';
import { emptyLog, isolate, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

const named = (options: Parameters<typeof world>[0] = {}) => namedWorld(db, options);
const uses = async () => Number((await rows<{ n: number | string }>(db.owner, sql`SELECT count(*) AS n FROM log_uses`))[0]!.n);
const served = (outcome: NamedUseOutcome) => {
  assert.equal(outcome.served, true);
  return outcome as Extract<NamedUseOutcome, { served: true }>;
};
const byName = (outcome: NamedUseOutcome) => {
  assert.equal(served(outcome).route, 'name');
  return outcome as Extract<NamedUseOutcome, { route: 'name' }>;
};
const codeOf = (outcome: NamedUseOutcome) => {
  const { outcome: used } = served(outcome);
  return used.ok ? 'ok' : 'busy' in used ? `busy:${used.busy}` : used.code;
};

/** A world with a fork of dev, `fork`, the caller's grant on both, and a key of its own, one of dev's, one dev's it removed. */
async function forked(options: Parameters<typeof world>[0] = {}) {
  const w = await named(options);
  const fork = await w.fork('fork');
  await w.grantAt(fork, options.role ?? 'viewer');
  const own = await w.key('fork-own', false, fork);
  const inherited = await w.key('dev-inherited');
  const removed = await w.key('dev-removed');
  await w.dismiss(fork, await w.nameOf(removed));
  const at = (key: string, extra: Partial<NamedUseInput> = {}) => w.ask(key, { place: { project: w.slug, environment: 'fork' }, forks: true, ...extra });
  return { ...w, fork, own, inherited, removed, at };
}

test("a fork's own key, and one it inherits from dev, are each one call by name; one it removed, and one never made, are keys it does not hold", async () => {
  const w = await forked();
  const { vault, cache } = await isolate();
  const own = byName(await vault.useNamed!(w.at(await w.nameOf(w.own))));
  assert.equal(own.outcome.ok, true);
  assert.equal(own.secretId, w.own);
  assert.deepEqual(own.at, { projectId: w.project, environmentId: w.fork }, 'decided at the fork');
  const inherited = byName(await vault.useNamed!(w.at(await w.nameOf(w.inherited))));
  assert.equal(inherited.outcome.ok, true, "dev's key, read through the fork");
  assert.equal(inherited.secretId, w.inherited);
  assert.deepEqual(inherited.at, { projectId: w.project, environmentId: w.dev }, 'logged, if refused, where it is held (review r5 of D153)');
  // The map keeps it as read through the fork: the next use is made by those ids, in its one call.
  assert.deepEqual(cache.keyed(w.fork, await w.nameOf(w.inherited)), { id: w.inherited, through: true });
  assert.deepEqual(cache.keyed(w.fork, await w.nameOf(w.own)), { id: w.own, through: false });
  assert.equal(await uses(), 2, 'each use its entry');
  assert.equal(codeOf(await vault.useNamed!(w.at(await w.nameOf(w.removed)))), 'missing', 'removed in the fork: none there');
  assert.equal(codeOf(await vault.useNamed!(w.at('NEVER_MADE'))), 'missing');
  assert.equal(await uses(), 2, 'a key the fork does not hold: no entry');
  // Its value is dev's, in dev itself, as ever: the removal is the fork's alone.
  assert.equal(codeOf(await vault.useNamed!(w.ask(await w.nameOf(w.removed), { forks: true }))), 'ok');
  if (ENGINE === 'postgres') {
    const app = JSON.parse(inherited.app!) as { environment: { id: string }; parent: string | null; secrets: { secret: { id: string } }[] };
    assert.equal(app.environment.id, w.fork, "the app's place: the fork");
    assert.equal(app.parent, 'dev', 'and its parent, by slug, as `app_read` names it');
    assert.deepEqual(app.secrets.map((row) => row.secret.id), [w.inherited]);
  }
});

test('a key a fork inherits takes the standing where it is held: without a grant on dev, refused as a key never made, in one call, nothing written', async () => {
  const w = await forked();
  // Their grants: the fork's alone.
  await w.revoke();
  await w.grantAt(w.fork, 'viewer');
  const hot = await slowedVault(db);
  try {
    const counted = async (key: string) => {
      const before = hot.statements();
      const code = codeOf(await hot.vault.useNamed!(w.at(key)));
      return { code, calls: hot.statements() - before };
    };
    assert.equal((await counted(await w.nameOf(w.own))).code, 'ok', "the fork's own: theirs");
    const inherited = await counted(await w.nameOf(w.inherited));
    const never = await counted('NEVER_MADE');
    assert.equal(inherited.code, 'no_grant', "dev's, which they do not read");
    assert.equal(never.code, 'missing', 'one the fork does not hold: they stand there, and may know it (R6)');
    assert.equal(inherited.calls, never.calls, 'one call each, no lock asked for');
    assert.equal(await uses(), 1, 'the refusal wrote nothing');
  } finally {
    await hot.end();
  }
});

test("without standing at the fork, its call reads nothing of the key: every key, held, inherited, removed or never made, refused alike, in one call, on the place alone (Probing.tla, StandingFirst)", async () => {
  const w = await forked();
  await w.revoke();
  // A grant on dev alone: they read dev's keys there, and stand nowhere in the fork.
  await w.grantAt(w.dev, 'viewer');
  const hot = await slowedVault(db);
  const session = ENGINE === 'postgres' ? weighingSession() : null;
  try {
    const answers: { code: string; calls: number }[] = [];
    const work: number[] = [];
    for (const name of [await w.nameOf(w.own), await w.nameOf(w.inherited), await w.nameOf(w.removed), 'NEVER_MADE']) {
      const before = hot.statements();
      const outcome = byName(await hot.vault.useNamed!(w.at(name)));
      answers.push({ code: codeOf(outcome), calls: hot.statements() - before });
      const read = await weighed(hot.last(), session ?? undefined);
      if (read !== null) work.push(keyBlocksOf(read.blocks));
    }
    assert.ok(answers.every((answer) => answer.code === 'no_grant' && answer.calls === answers[0]!.calls), JSON.stringify(answers));
    if (ENGINE === 'postgres') assert.ok(work.every((blocks) => blocks === work[0]), `no key's rows read: ${JSON.stringify(work)}`);
    assert.equal(await uses(), 0);
  } finally {
    await hot.end();
    await session?.end();
  }
});

test("a fork whose parent is archived reads nothing: every key refused on the place, `archived`, its own included, as the app's read refuses it whole (Probing.tla, CutByPlace)", async () => {
  const w = await forked();
  await w.archive(w.dev, false);
  const { vault } = await isolate();
  for (const name of [await w.nameOf(w.own), await w.nameOf(w.inherited), 'NEVER_MADE']) {
    assert.equal(codeOf(await vault.useNamed!(w.at(name))), 'archived', name);
  }
  assert.equal(await uses(), 0);
});

test('a fork of a fork inherits through both, the nearest that settles a key first; a removal in the middle stops it', async () => {
  const w = await forked();
  const deeper = await w.environment('deeper', false, { parentId: w.fork });
  await w.grantAt(deeper, 'viewer');
  // A key of the middle fork's own, of the name of one dev holds: the nearer settles it.
  const twin = await w.key('dev-twin');
  const shadow = await w.key('fork-twin', false, w.fork);
  await run(db.owner, sql`UPDATE secrets SET key = ${await w.nameOf(twin)} WHERE id = ${shadow}`);
  const at = (key: string) => w.ask(key, { place: { project: w.slug, environment: 'deeper' }, forks: true });
  const { vault } = await isolate();
  // dev's, through two forks; the middle fork's own over dev's; one the middle fork removed.
  assert.equal(byName(await vault.useNamed!(at(await w.nameOf(w.inherited)))).secretId, w.inherited);
  assert.equal(byName(await vault.useNamed!(at(await w.nameOf(twin)))).secretId, shadow);
  assert.equal(codeOf(await vault.useNamed!(at(await w.nameOf(w.removed)))), 'missing');
});

test("`dev@me`: the caller's personal config, their own value first, then dev's; while they have none, dev (T165; R20)", async () => {
  const w = await named({ caller: 'person' });
  const mine = (key: string, extra: Partial<NamedUseInput> = {}) => w.ask(key, { place: { project: w.slug, environment: 'dev@me' }, forks: true, ...extra });
  const devKey = await w.key('dev-value');
  const { vault, cache } = await isolate();
  // None of theirs yet: dev, read as dev.
  const fallback = byName(await vault.useNamed!(mine(await w.nameOf(devKey))));
  assert.equal(fallback.secretId, devKey);
  assert.deepEqual(fallback.at, { projectId: w.project, environmentId: w.dev });
  assert.deepEqual(fallback.place, { project: w.slug, environment: 'dev@me' }, 'the place as named');
  const config = await w.personal();
  const own = await w.key('my-own', false, config, w.principal);
  // Theirs now: the map, which held dev for `dev@me`, is out of date, and the names read again.
  const overridden = byName(await vault.useNamed!(mine(await w.nameOf(own))));
  assert.equal(overridden.outcome.ok, true);
  assert.equal(overridden.secretId, own);
  assert.deepEqual(overridden.at, { projectId: w.project, environmentId: config });
  const inherited = byName(await vault.useNamed!(mine(await w.nameOf(devKey))));
  assert.equal(inherited.secretId, devKey, "dev's, read through their config");
  assert.deepEqual(cache.keyed(config, await w.nameOf(devKey)), { id: devKey, through: true });
  assert.equal(codeOf(await vault.useNamed!(mine('NEVER_MADE'))), 'missing');
  if (ENGINE === 'postgres') {
    const app = JSON.parse(overridden.app!) as { environment: { id: string; owner: string }; parent: string };
    assert.deepEqual([app.environment.id, app.environment.owner, app.parent], [config, w.principal, 'dev']);
  }
});

test("at `dev@me`, a Contributor reads their own value, which use of dev allows, and not dev's, which takes read; revoked at dev, nothing of the key is read (Probing.tla, GateWeighsParent)", async () => {
  const w = await named({ caller: 'person', role: 'contributor' });
  const config = await w.personal();
  const own = await w.key('my-own', false, config, w.principal);
  const devKey = await w.key('dev-value');
  const mine = (key: string) => w.ask(key, { place: { project: w.slug, environment: 'dev@me' }, forks: true, purpose: 'reveal' });
  const { vault } = await isolate();
  assert.equal(codeOf(await vault.useNamed!(mine(await w.nameOf(own)))), 'ok', 'their own: use of dev is enough');
  assert.equal(codeOf(await vault.useNamed!(mine(await w.nameOf(devKey)))), 'no_grant', "dev's: read of dev");
  await w.revoke();
  const hot = await slowedVault(db);
  try {
    const answers: { code: string; calls: number; buffers: number | null }[] = [];
    for (const name of [await w.nameOf(own), await w.nameOf(devKey), 'NEVER_MADE']) {
      const before = hot.statements();
      const outcome = await hot.vault.useNamed!(mine(name));
      answers.push({ code: codeOf(outcome), calls: hot.statements() - before, buffers: await bufferedBy(hot.last()) });
    }
    assert.ok(answers.every((answer) => answer.code === 'no_grant' && answer.calls === answers[0]!.calls), JSON.stringify(answers));
  } finally {
    await hot.end();
  }
});

test('without `forks`, as an app of 0.15.0 asks: a fork and `dev@me` are not served by name, and read as ever', async () => {
  const w = await forked({ caller: 'person' });
  await w.personal();
  const { vault } = await isolate();
  assert.deepEqual(await vault.useNamed!(w.at('ANY', { forks: false })), { served: false });
  assert.deepEqual(await vault.useNamed!(w.ask('ANY', { place: { project: w.slug, environment: 'dev@me' } })), { served: false });
  // A personal config by its own slug: never, whatever the app reads.
  const [config] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM environments WHERE owner = ${w.principal}`);
  assert.deepEqual(await vault.useNamed!(w.ask('ANY', { place: { project: w.slug, environment: config!.slug }, forks: true })), { served: false });
});
