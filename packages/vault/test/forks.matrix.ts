// use.matrix.ts at a fork and at `dev@me` (T165, B2; migration 0050; formal/Probing.tla, Where): no key a caller may
// not know of shows through the use by name there either. The vault's one call reads the place (a fork; a fork of a
// fork; the caller's personal config of dev; or dev, for `dev@me` while they have none), decides their standing there
// first, then resolves the key through what the place inherits, and decides it where it is held too.
//
// A row is the place, how they lost their standing or not (their grant at the place revoked, or ended, which no change
// records; a Contributor asking to read; their grant on dev, which the place inherits from, revoked), what the
// isolate's map holds for the names (their asking's: never, while they stood, after; or set as it should never be: a
// key dev holds mapped as the place's own, or an id no key has) and the cap's window. A cell is one of the key's states
// at the place: its own, inherited from dev, inherited and made since, removed at the place (dev's, a dismissal), its own
// deleted since, never made, inherited and its reference ended since, inherited and its row put back since. Every cell
// of a row they may not have must answer the same, in as many of the vault's calls, writing no row of the cap's: on
// Postgres with the principal's lock held and every statement slow, so that a lock waited for, or a statement more,
// shows as busy. Without standing at the place, no cell's call reads anything of its key: the blocks of the key's own
// relations it fetches are the same for every key (W268, NoKeyBeforeStanding).
//
// Admission, the floor of `at`, a place archived and the credential's own dimensions are use.matrix.ts's: decided
// before the place is read, or on it alone, the same at a fork as anywhere.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type { NamedUseInput, NamedUseOutcome } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';

import { shardOf } from '../../../scripts/matrix-shard.ts';
import { refreshMs } from '../src/bulk.ts';
import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { holding, namedWorld, principalLock, slowed, weighed, weighingSession, type HotCall } from './named-world.ts';
import { emptyLog, useDatabases } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyLog();
  if (ENGINE === 'postgres') {
    await run(db.owner, sql.raw(`DO $$ DECLARE t record; BEGIN
      FOR t IN SELECT c.oid::regclass AS name FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' LOOP
        EXECUTE format('ALTER TABLE %s SET (autovacuum_enabled = off)', t.name);
      END LOOP; END $$`));
  }
});
after(() => db.close());

const WHERE = ['fork', 'fork of a fork', 'mine', 'mine, none of theirs'] as const;
const LOST = ['revoked', 'lapsed', 'may not read', 'parent not read', 'they stand'] as const;
const MAPS = ['never', 'while standing', 'after', "dev's key, mapped as the place's own", 'a key never made'] as const;
const WINDOWS = ['open', 'passed'] as const;
const KEYS = [
  'its own', 'inherited', 'inherited, made since', 'removed here', 'its own, deleted since', 'never made',
  'inherited, a reference ended since', 'inherited, its row put back since',
] as const;
type Row = { where: (typeof WHERE)[number]; lost: (typeof LOST)[number]; map: (typeof MAPS)[number]; window: (typeof WINDOWS)[number] };
type Key = (typeof KEYS)[number];

/** `dev@me` with none of theirs is dev: nothing it inherits, and a grant on dev is the place's. */
const inheriting = (row: Row) => row.where !== 'mine, none of theirs';
/**
 * Whether they stand at the place, for what they ask (the gate): at a fork, their grant there; at their personal config,
 * reading or using dev, whatever they ask; at dev, their grant there.
 */
const stands = (row: Row) => {
  if (row.lost === 'revoked' || row.lost === 'lapsed') return false;
  if (row.lost === 'may not read') return row.where === 'mine';
  if (row.lost === 'parent not read') return row.where !== 'mine' && row.where !== 'mine, none of theirs';
  return true;
};
/** Whether a cell's key is one they may have: they stand, it is held with its value, its own or dev's they read too. */
const usable = (row: Row, key: Key) => {
  if (!stands(row)) return false;
  // At dev itself (`dev@me`, none of theirs), every key of dev's is the place's own, and none is removed there.
  const own = key === 'its own' || (!inheriting(row) && (key === 'inherited' || key === 'inherited, made since' || key === 'removed here'));
  const inherited = key === 'inherited' || key === 'inherited, made since';
  // A Contributor reads their own value at their personal config (use of dev), never one of dev's (read of dev).
  if (row.lost === 'may not read') return own;
  // Their grant on dev gone: the place's own keys only.
  if (row.lost === 'parent not read') return own;
  return own || inherited;
};
const labelOf = (row: Row) => `${row.where} / ${row.lost} / ${row.map} / window ${row.window}`;
const told = (code: string) => (code === 'ok' || code === 'not served' || code === 'credential' || code === 'bulk_limit' || code.startsWith('busy') ? code : 'no');
const codeOf = (answer: NamedUseOutcome) => !answer.served ? 'not served' : answer.outcome.ok ? 'ok' : 'busy' in answer.outcome ? `busy:${answer.outcome.busy}` : answer.outcome.code;
const routeOf = (answer: NamedUseOutcome) => (answer.served ? answer.route : 'not served');
const count = async (query: ReturnType<typeof sql>) => Number((await rows<{ n: number | string }>(db.owner, query))[0]!.n);
const delayOf = () => (ENGINE !== 'postgres' ? 0 : 1600);
const LAPSES_MS = ENGINE === 'postgres' ? 2500 : 300;

async function inPeriod(ms: number): Promise<void> {
  const period = refreshMs({ count: 1000, windowMs: 15 * 60_000 });
  const left = period - (Date.now() % period);
  if (left < ms) await sleep(left + 50);
}

/** One cell, in its own world and isolate: everything up to its request, then the request, measured. */
async function cell(row: Row, key: Key) {
  const reads = row.lost === 'may not read';
  const mine = row.where === 'mine' || row.where === 'mine, none of theirs';
  const w = await namedWorld(db, { role: reads ? 'contributor' : 'developer', caller: mine ? 'person' : 'bearer' });
  const name = `K_${key.replaceAll(/[^a-z]+/g, '_').toUpperCase()}`;
  const keyOf = async (id: string) => {
    await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${id}`);
    return id;
  };
  // The place, and the environment its keys are inherited from: dev, through a fork between for a fork of a fork.
  let place = w.dev;
  let middle: string | null = null;
  if (row.where === 'fork' || row.where === 'fork of a fork') {
    middle = row.where === 'fork of a fork' ? await w.fork('mid') : null;
    place = await w.environment('named', false, { parentId: middle ?? w.dev });
    for (const at of [place, ...(middle === null ? [] : [middle])]) await w.grantAt(at, reads ? 'contributor' : 'developer');
  }
  if (row.where === 'mine') place = await w.personal();
  const slug = row.where === 'fork' || row.where === 'fork of a fork' ? 'named' : mine ? 'dev@me' : 'dev';
  const owner = row.where === 'mine' ? w.principal : null;
  const own = async () => keyOf(await w.key('own', false, place, owner));
  const ofDev = async () => keyOf(await w.key('dev'));
  const id = key === 'its own' || key === 'its own, deleted since' ? await own()
    : key === 'inherited' || key === 'removed here' || key === 'inherited, its row put back since' ? await ofDev() : null;
  if (key === 'removed here' && inheriting(row)) await w.dismiss(place, name);
  const reference = key === 'inherited, a reference ended since' ? await w.reference(name) : null;
  // A key of dev's, for a map that holds it as the place's own.
  const devKey = row.map === "dev's key, mapped as the place's own" && id === null ? await w.key('mapped') : id;
  const measured = await slowed(db, { connections: 1 });
  const purpose = reads ? 'reveal' : 'use';
  const ask = (purpose: NamedUseInput['purpose'], extra: Partial<NamedUseInput> = {}) => w.ask(name, { place: { project: w.slug, environment: slug }, forks: true, purpose, ...extra });
  if (row.map === 'while standing') await measured.vault.useNamed!(ask('use'));
  // Their standing goes, or a part of it.
  const ends = Date.now() + LAPSES_MS;
  const at = mine ? w.dev : place;
  if (row.lost === 'revoked') await w.revokeAt(at);
  if (row.lost === 'lapsed') {
    await w.revokeAt(at, ends);
    await sleep(Math.max(0, ends - Date.now()) + 50);
  }
  if (row.lost === 'parent not read') await w.revokeAt(w.dev);
  if (row.map === 'after') await measured.vault.useNamed!(ask(purpose));
  if (key === 'inherited, made since') await ofDev();
  if (key === 'its own, deleted since') await w.remove(id!);
  if (key === 'inherited, a reference ended since') await w.end(reference!);
  if (key === 'inherited, its row put back since') await w.putBack(id!);
  return {
    key,
    measure: async () => {
      // The map set as it should never be: the place named, with dev's key as its own, or an id no key has.
      if (row.map === "dev's key, mapped as the place's own" || row.map === 'a key never made') {
        measured.cache.name(`${w.tokenHash.toString('base64')}\n${w.slug}\n${slug}`, { credential: w.credentialId, environment: place, slugs: { project: w.slug, environment: slug } });
        measured.cache.key(place, name, { id: row.map === 'a key never made' ? randomUUID() : devKey!, through: false });
      }
      const entries = () => count(sql`SELECT count(*) AS n FROM log_uses WHERE credential = ${w.credentialId}`);
      const capRows = () => count(sql`SELECT count(*) AS n FROM log_bulk WHERE principal = ${w.principal}`);
      if (row.window === 'passed') await run(db.owner, sql`DELETE FROM log_bulk WHERE principal = ${w.principal}`);
      const [beforeEntries, beforeCap] = [await entries(), await capRows()];
      measured.slow(delayOf());
      const before = measured.statements();
      const now = Date.now();
      const work = () => measured.vault.useNamed!(ask(purpose, { at: now, deadline: now + 3000 }));
      const answer = ENGINE === 'postgres' ? await holding(db, principalLock(w.principal), work) : await work();
      measured.slow(0);
      const last = measured.statements() > before ? measured.last() : null;
      const result = {
        code: codeOf(answer), route: routeOf(answer), calls: measured.statements() - before,
        entries: (await entries()) - beforeEntries, capRows: (await capRows()) - beforeCap,
        cached: last !== null && last.args[11] != null, sent: last as HotCall | null, keyBlocks: null as number | null,
      };
      await measured.end();
      return result;
    },
  };
}

async function each<T, R>(items: readonly T[], work: (item: T) => Promise<R>): Promise<R[]> {
  if (ENGINE === 'postgres') return Promise.all(items.map(work));
  const done: R[] = [];
  for (const item of items) done.push(await work(item));
  return done;
}

/**
 * Every row, generated: each place, each way of losing standing or keeping it, each map, each window; `parent not read`
 * where the place inherits from a dev it is not (a fork's). CI runs them in shards, a slice each (`shardOf`).
 */
const ROWS: Row[] = shardOf(import.meta.url, WHERE.flatMap((where) => LOST
  .filter((lost) => lost !== 'parent not read' || where === 'fork' || where === 'fork of a fork')
  .flatMap((lost) => MAPS.flatMap((map) => WINDOWS.map((window) => ({ where, lost, map, window }))))), labelOf);

test(`at a fork and at \`dev@me\`, a caller learns nothing of a key they may not have, in any of ${ROWS.length} rows of ${KEYS.length} key states (T165, D153)`, { timeout: 7_200_000 }, async () => {
  const differing: string[] = [];
  await namedWorld(db);
  for (const row of ROWS) {
    await inPeriod(20_000);
    const made = await each(KEYS, (key) => cell(row, key));
    const results = await each(made, async (c) => ({ key: c.key, ...(await c.measure()) }));
    const label = labelOf(row);
    // The keys they may not have: each answered alike (D153).
    const refused = results.filter((r) => !usable(row, r.key));
    const [first] = refused;
    for (const r of refused) {
      if (r.capRows !== 0) differing.push(`${label}: ${r.key} wrote a row of the cap's`);
      if (!stands(row) && r.entries !== 0) differing.push(`${label}: ${r.key} wrote ${r.entries} entries, standing nowhere`);
    }
    if (refused.some((r) => told(r.code) !== told(first!.code) || r.route !== first!.route || r.calls !== first!.calls)) {
      differing.push(`${label}: ${refused.map((r) => `${r.key} ${r.code} by ${r.route} in ${r.calls}`).join(', ')}`);
    }
    if (refused.some((r) => r.code.startsWith('busy'))) differing.push(`${label}: busy, ${refused.filter((r) => r.code.startsWith('busy')).map((r) => r.key).join(', ')}`);
    if (refused.some((r) => r.cached)) differing.push(`${label}: the cached form for ${refused.filter((r) => r.cached).map((r) => r.key).join(', ')}`);
    // A key they may have, as asked, is theirs.
    for (const r of results.filter((r) => usable(row, r.key))) {
      if (r.code !== 'ok') differing.push(`${label}: ${r.key}, which they may have, ${r.code}`);
    }
    // Without standing at the place, no call reads anything of its key: as many blocks of the key's relations for each.
    if (ENGINE === 'postgres' && !stands(row)) {
      await run(db.owner, sql`ANALYZE`);
      const session = weighingSession();
      try {
        for (const r of refused) r.keyBlocks = (await weighed(r.sent, session))?.keyBlocks ?? null;
      } finally {
        await session.end();
      }
      const blocks = new Set(refused.flatMap((r) => (r.keyBlocks === null ? [] : [r.keyBlocks])));
      if (blocks.size > 1) differing.push(`${label}: blocks of the key's tables ${refused.map((r) => `${r.key} ${r.keyBlocks}`).join(', ')}`);
    }
  }
  assert.deepEqual(differing, []);
});
