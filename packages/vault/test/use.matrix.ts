// No key a caller may not know of shows through the use by name (T158; formal/Probing.tla, SameAnswer; reviews r1 to
// r4 of #412 and d1 to d4 of #416, each of which found a path the tests before it left out): the matrix of what a
// caller without standing at a place can make the vault do, generated, every cell its own world and isolate.
//
// A row is what the caller sees and shapes: what the isolate's map holds for the request's names (D150: anything at
// all; Probing.tla's `Maps`), how they lost their standing (a grant revoked; a grant's end passed, which no change
// records; their credential revoked by 0.14's code mid-upgrade, around the log; a Contributor, who may use and not
// read, asking to read), the place (live, its environment archived, its project archived) and the request's admission
// (as asked; the checkpointer's floor of `at` past it; its deadline past). The map is what their asking left it (never
// asked; asked while they stood, which leaves the isolate a standing; asked after; asked while they stood at a place
// whose slug another took since, their grant left on the old one), or one set as it should never be: another place,
// where they stand and a key of that name is held, with that key or none; an archived place of theirs, with its key;
// a place never made; the place named, with a key deleted since, another place's key, or a key never made; another
// credential. A cell is one of the key's states in that row, which the caller may not know: held, made since, used
// before (fresh in the principal's set of the cap), deleted since, never made. Every cell of a row must answer the
// same, in as many of the vault's calls, writing no row of the cap's: on Postgres with the principal's lock held and
// every statement slow (`delayOf`), so that a lock waited for, or a statement more, shows as busy; and with the cap's
// window passed since the requests before, or not, so that a key's use would take that lock, or not.
//
// No decision is kept for a later use to take the principal's lock on (D153, review r1): a row that would end one
// another way than by a change of the log's (a grant's end, a write around the log, another permission) holds a use
// to deciding again, as every other does.
//
// A use of a key fresh in the set writes its request's entry, refused, in the statement that reads it (R53): that row
// differs, which no caller sees, and costs no wait.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type { NamedUseInput, NamedUseOutcome } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';

import { shardOf } from '../../../scripts/matrix-shard.ts';
import { refreshMs } from '../src/bulk.ts';
import type { Input } from '../src/inputs.ts';
import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { holding, keyBlocksOf, namedWorld, principalLock, slowed, weighed, weighingSession, type HotCall, type Weighed } from './named-world.ts';
import { change, emptyLog, seal, useDatabases } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
  await emptyLog();
  // No autovacuum on this database's tables: the cells' buffers are weighed on statistics only `weigh` refreshes, between
  // batches, never while one is weighed.
  if (ENGINE === 'postgres') {
    await run(db.owner, sql.raw(`DO $$ DECLARE t record; BEGIN
      FOR t IN SELECT c.oid::regclass AS name FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' LOOP
        EXECUTE format('ALTER TABLE %s SET (autovacuum_enabled = off)', t.name);
      END LOOP; END $$`));
  }
});
after(() => db.close());

const KEYS = [
  'held', 'made since', 'used before', 'deleted', 'never made',
  // Used before, as above, then its value gone, or its row put back: what the use decides of the key's own rows comes
  // after the standing (review d5 of #416; `standingRefusal`, Lean's `refused_by_standing`).
  'a reference, its source deleted since', 'a reference, ended since', 'its row put back since',
  // Its source pointed elsewhere by a writer around the log, no change of the log's: its rows not as sealed, nor as the
  // isolate's seals of them say (review r2 of D153): refused by name, never routed to the app's path.
  'a reference repointed around the log',
  // Its source's environment archived since: the key reads nothing until it is back, the vault's refusal by name, never
  // the app's path (review r4 of D153).
  'a reference, its source archived since',
] as const;
/** The keys a use of theirs, while they stood, left fresh in their set: a use of one in its period writes its request's entry. */
const USED = new Set<Key>(['used before', 'a reference, its source deleted since', 'a reference, ended since', 'its row put back since', 'a reference repointed around the log', 'a reference, its source archived since']);
/** What their asking left the map: the names' ids as a read of them found them then. */
const ASKED = ['never', 'while standing', 'after', 'renamed, its slug reused'] as const;
/** The map set as it should never be (D150), whatever their asking would have left it. */
const SET = ['another place', 'another place, no key', 'an archived place', 'a place never made', 'a key gone', "another place's key", 'a key never made', 'another credential'] as const;
/** How they lost their standing, or not: then the keys they may not have are the ones to answer alike (D153). */
const LOST = ['revoked', 'lapsed', 'revoked around the log', 'may not read', 'token revoked', 'they stand'] as const;
/** The place: live, archived, or its row's seal replaced around the log, which a token revoked still sees past (401). */
const PLACES = ['live', 'environment archived', 'project archived', 'its seal replaced'] as const;
const ADMISSIONS = ['as asked', 'past the floor', 'past its deadline'] as const;
/** The cap's window since the requests before: still open, or passed (its rows gone), so that a key's next use would take the principal's lock. */
const WINDOWS = ['open', 'passed'] as const;
type Map = (typeof ASKED)[number] | (typeof SET)[number];
type Row = {
  map: Map; lost: (typeof LOST)[number]; place: (typeof PLACES)[number]; admission: (typeof ADMISSIONS)[number]; window: (typeof WINDOWS)[number];
};
type Key = (typeof KEYS)[number];

/**
 * Each statement's delay, on Postgres: 1.6 s, so that a statement more, or a lock's 1 s, passes the 3 s deadline. A
 * refusal is one statement, whatever the map holds (D153).
 */
const delayOf = () => (ENGINE !== 'postgres' ? 0 : 1600);
/** How long a grant that lapses stands: past the requests made while it does, cells side by side on Postgres, in turn on SQLite. */
const LAPSES_MS = ENGINE === 'postgres' ? 2500 : 300;
/**
 * Whether the cell's key is one they may have: they stand, it is held there with its value, and the request names it
 * now. Its answer is theirs to know of, and may differ: the rest of the row's must not.
 */
const usable = (row: Row, key: Key) => row.lost === 'they stand' && row.map !== 'renamed, its slug reused' && row.admission === 'as asked' && row.place === 'live'
  && (key === 'held' || key === 'made since' || key === 'used before');
/** What ended their standing, or refuses them though they stand, is no change of the log's: a cover made before holds. */
const unrecorded = (row: Row) => row.lost === 'lapsed' || row.lost === 'revoked around the log' || (row.lost === 'they stand' && row.place === 'its seal replaced');
/**
 * The one write a cell may make, its request's entry (R53), refused: never for a caller who does not stand there, whose
 * key is never read (W268, NoKeyBeforeStanding); for one who does, a place whose seal a writer replaced, the statement
 * stands them on its rows, which it does not check the seals of: a key fresh in their set, which takes no lock, used
 * in its statement, as asked, at a live place, by the ids its names name now, which the map holds (their asking's, a
 * place not renamed since; a map not read yet makes no use in its first call, D153). Not a repeat that rides the cover
 * of a use the same isolate made while they stood, no change of the log's since (their grant's end, a write around the
 * log, a seal replaced around it), which is answered on it, writing none (CoveredRefusalAnswered): the keys their asking
 * used, while standing, and, as they still stand, after. Nor a key that reads an archived place, which the call answers
 * `archived`, writing nothing (0045).
 */
const writes = (row: Row, key: Key) => row.lost === 'they stand' && key !== 'a reference, its source archived since' && row.window === 'open' && row.admission === 'as asked' && (row.place === 'live' || row.place === 'its seal replaced')
  && (row.map === 'while standing' || row.map === 'after') && (USED.has(key) || (row.map === 'while standing' && key === 'held'))
  && !(unrecorded(row) && ((row.map === 'while standing' && (key === 'held' || key === 'used before')) || (row.map === 'after' && row.lost === 'they stand' && key === 'used before')));
/**
 * What the caller is told of a cell's answer: the vault's reason for a refusal is the audit log's (D153), and every one
 * is the app's one `not_available`; a busy answer, a credential ended, a use allowed, and what the app answers itself
 * (`not served`), are each their own.
 */
const told = (code: string) => (code === 'ok' || code === 'not served' || code === 'credential' || code === 'bulk_limit' || code.startsWith('busy') ? code : 'no');
/**
 * The cap's period (a minute, at the 15-minute window): a key fresh in the set stays so within it, and one passed moves it
 * on, which decides first and writes no entry. So cells are made and asked with at least `ms` of one left.
 */
async function inPeriod(ms: number): Promise<void> {
  const period = refreshMs({ count: 1000, windowMs: 15 * 60_000 });
  const left = period - (Date.now() % period);
  if (left < ms) await sleep(left + 50);
}

const codeOf = (answer: NamedUseOutcome) => !answer.served ? 'not served' : answer.outcome.ok ? 'ok' : 'busy' in answer.outcome ? `busy:${answer.outcome.busy}` : answer.outcome.code;
/** How the app answers it (`routeOf`): by the vault's decision, by the credential's own check, busy, or not by name. */
const routeOf = (answer: NamedUseOutcome) => (answer.served ? answer.route : 'not served');
const count = async (query: ReturnType<typeof sql>) => Number((await rows<{ n: number | string }>(db.owner, query))[0]!.n);

/** One cell, in its own world and isolate: everything up to its request, then the request, measured. */
async function cell(row: Row, key: Key) {
  const reads = row.lost === 'may not read';
  const w = await namedWorld(db, { role: reads ? 'contributor' : 'developer' });
  const name = `K_${key.replaceAll(/[^a-z]+/g, '_').toUpperCase()}`;
  const keyOf = async (id: string) => {
    await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${id}`);
    return id;
  };
  const ends = Date.now() + LAPSES_MS;
  if (row.lost === 'lapsed') {
    const grant = { ...w.grant, expiresAt: ends };
    await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant },
      { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [grant] }, async (tx, value) => {
        await run(tx, sql`UPDATE vault_grants SET expires_at = ${ends} WHERE principal = ${w.principal}`);
        await seal('vault_members', 'principal', w.principal)(tx, value);
      });
  }
  // What a map set as it should never be points to, besides `dev`: another place where they stand, holding a key of
  // that name; an archived one of theirs, the same; a key of that name in `dev`, deleted; another credential of theirs.
  // Made first, so that the name is free in `dev` for the key's state, and their standing there outlives the row's.
  const elsewhere = row.map === 'another place' || row.map === 'another place, no key' || row.map === "another place's key" || row.map === 'an archived place'
    ? await w.environment(row.map === 'an archived place' ? 'old' : 'qa', row.map === 'an archived place')
    : null;
  const elsewhereKey = elsewhere === null ? null : await keyOf(await w.key('elsewhere', false, elsewhere));
  if (elsewhere !== null) await w.grantAt(elsewhere, 'developer');
  const gone = row.map === 'a key gone' ? await keyOf(await w.key()) : null;
  if (gone !== null) {
    await change({ kind: 'secret', id: gone }, { op: 'secret.delete' }, null, async (tx) => {
      await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()}, key = ${`${name}_WAS`} WHERE id = ${gone}`);
    });
  }
  const otherCredential = row.map === 'another credential' ? await w.credential() : null;
  const id = key === 'held' || key === 'used before' || key === 'deleted' || key === 'its row put back since' ? await keyOf(await w.key()) : null;
  // A source archived since lives in an environment of its own, which the archive leaves `dev` beside.
  const sourceAt = key === 'a reference, its source archived since' ? await w.environment('src') : undefined;
  const reference = key.startsWith('a reference') ? await w.reference(name, sourceAt) : null;
  const measured = await slowed(db, { connections: 1 });
  const ask = (purpose: NamedUseInput['purpose'], extra: Partial<NamedUseInput> = {}) => w.ask(name, { purpose, ...extra });
  // Used before: by another isolate of the principal's, while it stood: its row of the cap's fresh.
  if (USED.has(key)) {
    const other = await slowed(db, { connections: 1 });
    await other.vault.useNamed!(ask('use'));
    await other.end();
  }
  if (row.map === 'while standing' || row.map === 'renamed, its slug reused') await measured.vault.useNamed!(ask('use'));
  // Their standing goes.
  if (row.lost === 'revoked') await w.revoke();
  if (row.lost === 'lapsed') await sleep(Math.max(0, ends - Date.now()) + 50);
  if (row.lost === 'revoked around the log') await run(db.owner, sql`UPDATE credentials SET revoked_at = ${new Date()} WHERE id = ${w.credentialId}`);
  if (row.lost === 'token revoked') await w.revokeToken();
  const purpose = reads ? 'reveal' : 'use';
  if (row.map === 'after') await measured.vault.useNamed!(ask(purpose));
  // The key, since.
  if (key === 'made since') await keyOf(await w.key());
  if (key === 'deleted') {
    await change({ kind: 'secret', id: id! }, { op: 'secret.delete' }, null, async (tx) => {
      await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()}, key = ${`${name}_GONE`} WHERE id = ${id!}`);
    });
  }
  if (key === 'a reference, its source deleted since') await w.remove(reference!.source);
  if (key === 'a reference, ended since') await w.end(reference!);
  if (key === 'its row put back since') await w.putBack(id!);
  if (key === 'a reference, its source archived since') await w.archive(sourceAt!, false);
  if (key === 'a reference repointed around the log') {
    await run(db.owner, sql`UPDATE secret_references SET source_secret_id = ${await w.key('another source')} WHERE id = ${reference!.row}`);
  }
  // Their place renamed, its slug taken by a new one, their grant left on the old one (review d4 of #416): the map holds
  // the old place, and the key's state there, for the names the new one has now.
  let named = w.dev;
  if (row.map === 'renamed, its slug reused') {
    await w.rename(w.dev, 'dev-old');
    named = await w.environment('dev');
    if (row.lost !== 'revoked around the log') await w.grantAt(w.dev, 'developer');
  }
  // The place, since: a change of its environment, sealed, as the app makes it.
  if (row.place === 'environment archived' || row.place === 'project archived') await w.archive(named, row.place === 'project archived');
  if (row.place === 'its seal replaced') await w.forge(named);
  return {
    key,
    /** The request, its principal's lock held and every statement slow: its answer, its calls, what it wrote. */
    measure: async () => {
      setMap(row, { w, cache: measured.cache, name, elsewhere, elsewhereKey, gone, otherCredential });
      const entries = () => count(sql`SELECT count(*) AS n FROM log_uses WHERE credential = ${w.credentialId}`);
      const capRows = () => count(sql`SELECT count(*) AS n FROM log_bulk WHERE principal = ${w.principal}`);
      if (row.window === 'passed') await run(db.owner, sql`DELETE FROM log_bulk WHERE principal = ${w.principal}`);
      const [beforeEntries, beforeCap] = [await entries(), await capRows()];
      measured.slow(delayOf());
      const before = measured.statements();
      const at = Date.now();
      const request = ask(purpose, row.admission === 'past its deadline' ? { at: at - 4000, deadline: at - 1000 } : { at, deadline: at + 3000 });
      const work = () => measured.vault.useNamed!(request);
      const answer = ENGINE === 'postgres' ? await holding(db, principalLock(w.principal), work) : await work();
      measured.slow(0);
      // Its own last call, if it made one: one answered before any (busy at its deadline) weighs nothing.
      const last = measured.statements() > before ? measured.last() : null;
      const result = {
        code: codeOf(answer), route: routeOf(answer), calls: measured.statements() - before,
        entries: (await entries()) - beforeEntries, capRows: (await capRows()) - beforeCap,
        // Its last statement's form (`p_known`, the 12th argument, set is the cached form, which an isolate's history
        // would choose: Fable's review and review r12 of D153), and, weighed once the row's cells have all answered
        // (`weigh`), the buffers it reads inside (Postgres).
        cached: last !== null && last.args[11] != null, sent: last, buffers: null as number | null, keyBlocks: null as number | null, blocks: null as Weighed['blocks'] | null,
        // Standing, a refused key's request again from an isolate with no history (no map, seals or covers), on the same
        // world: what its call reads must not hang on what the measured isolate's history held.
        cold: null as HotCall | null, coldBuffers: null as number | null, coldKeyBlocks: null as number | null, coldBlocks: null as Weighed['blocks'] | null,
        coldAnswer: null as { code: string; route: string } | null,
      };
      await measured.end();
      // Its twin, on the same world, from an isolate with no history (no map, seals or covers): standing, the same
      // request, whose call must read what this one does; without standing, a request for a key this world never made, its
      // world's own baseline, which a refusal of no key read costs exactly as (each cell is a world of its own, whose rows
      // sit where theirs fell: CI read 3 or 4 blocks more of `projects` and `credentials` in one world than another).
      if (!usable(row, key)) {
        const fresh = await slowed(db, { connections: 1 });
        const now = Date.now();
        const times = row.admission === 'past its deadline' ? { at: now - 4000, deadline: now - 1000 } : { at: now, deadline: now + 3000 };
        const twin = await fresh.vault.useNamed!(row.lost === 'they stand' ? ask(purpose, times) : w.ask(`${name}_NEVER`, { purpose, ...times }));
        result.coldAnswer = { code: codeOf(twin), route: routeOf(twin) };
        result.cold = fresh.statements() > 0 ? fresh.last() : null;
        await fresh.end();
      }
      return result;
    },
  };
}

/**
 * The isolate's map of the request's names set as the row says (D150): its credential, its place and its key's id,
 * whatever their asking would have left it. Rows whose map is their asking's set nothing.
 */
function setMap(row: Row, at: {
  w: Awaited<ReturnType<typeof namedWorld>>; cache: Awaited<ReturnType<typeof slowed>>['cache']; name: string;
  elsewhere: string | null; elsewhereKey: string | null; gone: string | null; otherCredential: string | null;
}): void {
  const { w, cache, name } = at;
  const ids = (place: string, credential: string = w.credentialId) => ({
    credential, environment: place, slugs: { project: w.slug, environment: 'dev' },
  });
  const set = (place: string, key: string | null, credential?: string) => {
    cache.name(`${w.tokenHash.toString('base64')}\n${w.slug}\ndev`, ids(place, credential));
    cache.key(place, name, key);
  };
  switch (row.map) {
    case 'another place': case 'an archived place': return set(at.elsewhere!, at.elsewhereKey);
    case 'another place, no key': return set(at.elsewhere!, null);
    case 'a place never made': return set(randomUUID(), null);
    case 'a key gone': return set(w.dev, at.gone);
    case "another place's key": return set(w.dev, at.elsewhereKey);
    case 'a key never made': return set(w.dev, randomUUID());
    // The place named and no key: a key held there is then `moved`, read again, which the use by another's token is too.
    case 'another credential': return set(w.dev, null, at.otherCredential!);
    default: return undefined;
  }
}

/** `work` over `items`, side by side on Postgres; on SQLite, which writes one at a time, in turn. */
async function each<T, R>(items: readonly T[], work: (item: T) => Promise<R>): Promise<R[]> {
  if (ENGINE === 'postgres') return Promise.all(items.map(work));
  const done: R[] = [];
  for (const item of items) done.push(await work(item));
  return done;
}

/**
 * How many more shared buffers one refusal may read than another it is held alike to: a run's noise (a page split, a
 * heap page a world's rows spilled to). A key's own rows read before the standing was decided cost 30 to 90 more (W259:
 * 42 to 136 a refusal, W268's gate brought it to one figure), a form chosen by the isolate's history 10 to 34 (Fable's
 * review, review r12 of D153).
 */
const BUFFER_SLACK = 6;

/**
 * Standing only, how many more blocks of the key's own relations a refusal may fetch than the same request from an
 * isolate with no history (D155): the versions a key's history left dead, which a call that reads the key may find
 * pruned or not yet (CI read 17 beside 15 for a key deleted, once in four runs of the same code). They show only a
 * caller who may know of the key (R6). Without standing no key is read, and the blocks are held exactly alike.
 */
const KEY_BLOCK_SLACK = 3;

const labelOf = (row: Row) => `${row.map} / ${row.lost} / ${row.place} / ${row.admission} / window ${row.window}`;

/**
 * Every row, generated: each map of their asking's over every other dimension; each map set as it should never be
 * over every way of losing their standing and every place, as asked and past the floor, the window passed (a key of
 * the place named would take the principal's lock, were its use made). CI runs them in shards, a slice each (`shardOf`).
 */
const ROWS: Row[] = shardOf(import.meta.url, [
  ...ASKED.flatMap((map) => LOST.flatMap((lost) => PLACES.flatMap((place) => ADMISSIONS.flatMap((admission) =>
    WINDOWS.map((window) => ({ map, lost, place, admission, window })))))),
  ...SET.flatMap((map) => LOST.flatMap((lost) => PLACES.filter((place) => place !== 'its seal replaced').flatMap((place) => (['as asked', 'past the floor'] as const).map((admission) =>
    ({ map, lost, place, admission, window: 'passed' as const }))))),
], labelOf);

test(`a caller learns nothing of a key they may not have, whatever the isolate's map holds, in any of ${ROWS.length} rows of ${KEYS.length} key states (T158, D150, D153)`, { timeout: 7_200_000 }, async () => {
  const differing: string[] = [];
  /** The widest spread of buffers within a row's refusals, over the run. */
  let widest = 0;
  /** Standing, the widest gap between a refusal's buffers and the same request's from an isolate with no history. */
  let widestHistory = 0;
  /** Standing, the widest gap between the blocks of the key's relations a refusal fetched and its twin's. */
  let widestKeyBlocks = 0;
  /**
   * Each cell's buffers, and its cold twin's, weighed in turn once a batch's cells have all answered, in one session:
   * weighed while the others still ran, a cell read what their writes left half done (W268: a row of no key read spread
   * 7); each in a session of its own, on plans made anew, one now and then read hundreds more.
   */
  const weigh = async <T extends { sent: HotCall | null; buffers: number | null; keyBlocks: number | null; blocks: Weighed['blocks'] | null; cold: HotCall | null; coldBuffers: number | null; coldKeyBlocks: number | null; coldBlocks: Weighed['blocks'] | null }>(results: T[]) => {
    if (ENGINE !== 'postgres') return;
    // The statistics as the batch left them, before it is weighed, and none changing while it is (autovacuum is off on
    // this database's tables, `before`): an ANALYZE mid-batch would make the session plan anew, and one cell of a row
    // read hundreds of buffers above the rest (CI, W268). The key's relations as they are: vacuumed, their all-visible
    // pages would let a probe skip the heap and hide work of a key's history (review r4 of W268).
    await run(db.owner, sql`ANALYZE`);
    // Each cell is a world of its own, whose place, credential and account rows its setup wrote over a few times: the dead
    // versions it left cost a heap page or two more, whatever the key (a row of no key read spread 74 to 81, all of it in
    // `environments`). Those tables are vacuumed; the key's own relations are not. What a key's work reads of them (a
    // reference's source's environment, a personal config's parent) takes columns no index holds, a heap fetch that no
    // all-visible page spares (review r6 of W268).
    await run(db.owner, sql`VACUUM environments, projects, credentials, identities, vault_members, vault_grants, log_config, log_fence`);
    // One session for them all, so that every call is weighed on the same plans (`weighingSession`).
    const session = weighingSession();
    try {
      for (const r of results) {
        const warm = await weighed(r.sent, session);
        const cold = await weighed(r.cold, session);
        [r.buffers, r.keyBlocks, r.blocks, r.coldBuffers, r.coldKeyBlocks, r.coldBlocks] = [warm?.buffers ?? null, warm?.keyBlocks ?? null, warm?.blocks ?? null, cold?.buffers ?? null, cold?.keyBlocks ?? null, cold?.blocks ?? null];
      }
    } finally {
      await session.end();
    }
  };
  // The instance's one policy and roles, which the first world makes, before the cells' worlds run side by side.
  await namedWorld(db);
  /** A row's answers, as each of its cells' differs from its first's, or its first is allowed, or busy as asked. */
  const judge = (row: Row, all: ({ key: Key } & Awaited<ReturnType<Awaited<ReturnType<typeof cell>>['measure']>>)[]) => {
    const label = labelOf(row);
    // The keys they may not have: each answered alike (D153).
    const results = all.filter((result) => !usable(row, result.key));
    const [first] = results;
    for (const result of results) {
      if (result.capRows !== 0) differing.push(`${label}: ${result.key} wrote a row of the cap's`);
      if (result.entries !== (writes(row, result.key) ? 1 : 0)) differing.push(`${label}: ${result.key} wrote ${result.entries} entries`);
      if (told(result.code) !== told(first!.code) || result.route !== first!.route || result.calls !== first!.calls) {
        differing.push(`${label}: ${results.map((r) => `${r.key} ${r.code} by ${r.route} in ${r.calls}`).join(', ')}`);
        break;
      }
    }
    // The same form of the statement for each, the probe's (a named call never runs the cached form).
    if (results.some((r) => r.cached)) differing.push(`${label}: the cached form for ${results.filter((r) => r.cached).map((r) => r.key).join(', ')}`);
    if (row.lost !== 'they stand') {
      // No standing: no key read (W268, NoKeyBeforeStanding). Each refusal fetches of the key's own relations exactly what
      // its world's refusal of a key never made does, and as many blocks of them as every other key's; and all it reads,
      // beside that baseline, alike for every key, whatever it is or was: held, gone, a reference in any state, or never
      // made (BUFFER_SLACK, the run's noise).
      for (const r of results) {
        if (r.keyBlocks !== null && r.coldKeyBlocks !== null && r.keyBlocks !== r.coldKeyBlocks) {
          differing.push(`${label}: ${r.key}, blocks of the key's tables ${r.keyBlocks} beside ${r.coldKeyBlocks} for a key its world never made`);
        }
      }
      const keyBlocks = new Set(results.flatMap((r) => (r.keyBlocks === null ? [] : [r.keyBlocks])));
      if (keyBlocks.size > 1) differing.push(`${label}: blocks of the key's tables ${results.map((r) => `${r.key} ${r.keyBlocks}`).join(', ')}`);
      const read = results.flatMap((r) => (r.buffers === null || r.coldBuffers === null ? [] : [{ ...r, beyond: r.buffers - r.coldBuffers }]));
      const fewest = read.reduce<typeof read[number] | null>((a, r) => (a === null || r.beyond < a.beyond ? r : a), null);
      const most = read.reduce<typeof read[number] | null>((a, r) => (a === null || r.beyond > a.beyond ? r : a), null);
      if (fewest !== null && most !== null && most.beyond - fewest.beyond > BUFFER_SLACK) {
        // Which relations the most read beyond its baseline more of than the fewest: what the spread is made of.
        const beyond = (r: typeof read[number], name: string) => (r.blocks?.[name] ?? 0) - (r.coldBlocks?.[name] ?? 0);
        const names = new Set([fewest, most].flatMap((r) => [...Object.keys(r.blocks ?? {}), ...Object.keys(r.coldBlocks ?? {})]));
        const apart = [...names].flatMap((name) => (beyond(most, name) === beyond(fewest, name) ? [] : [`${name} ${beyond(fewest, name)}/${beyond(most, name)}`]));
        differing.push(`${label}: buffers beyond a key never made ${read.map((r) => `${r.key} ${r.beyond}`).join(', ')}; blocks apart (${fewest.key}/${most.key}): ${apart.join(', ')}`);
      }
      widest = Math.max(widest, fewest === null || most === null ? 0 : most.beyond - fewest.beyond);
    } else {
      // Standing, a key's refusal may cost what its shape does, a key they may know of (R6); never what the isolate's
      // history holds: each as many buffers as the same request from an isolate with none, on the same world, weighed
      // beside it, answering as it does. A use the map's ids made logs its request (R53), which one from no map does not:
      // those apart.
      for (const r of results) {
        if (r.coldAnswer !== null && (told(r.code) !== told(r.coldAnswer.code) || r.route !== r.coldAnswer.route)) {
          differing.push(`${label}: ${r.key} ${r.code} by ${r.route}, beside ${r.coldAnswer.code} by ${r.coldAnswer.route} from an isolate with no history`);
        }
        if (r.buffers === null || r.coldBuffers === null || r.entries !== 0) continue;
        widestHistory = Math.max(widestHistory, Math.abs(r.buffers - r.coldBuffers));
        if (Math.abs(r.buffers - r.coldBuffers) > BUFFER_SLACK) differing.push(`${label}: ${r.key}, buffers ${r.buffers} beside ${r.coldBuffers} from an isolate with no history`);
        // A warm call riding a cover reads the cover's entry (R53), which a call from no history has none of: `log_uses`
        // apart for it, every other relation of the key's held alike (review r6 of W268), within `KEY_BLOCK_SLACK`.
        const covered = r.sent?.args[8] != null;
        const [warmKey, coldKey] = covered ? [keyBlocksOf(r.blocks ?? {}, ['log_uses']), keyBlocksOf(r.coldBlocks ?? {}, ['log_uses'])] : [r.keyBlocks!, r.coldKeyBlocks!];
        widestKeyBlocks = Math.max(widestKeyBlocks, Math.abs(warmKey - coldKey));
        if (Math.abs(warmKey - coldKey) > KEY_BLOCK_SLACK) differing.push(`${label}: ${r.key}, blocks of the key's tables ${warmKey} beside ${coldKey} from an isolate with no history${covered ? ', a cover\'s entry apart' : ''}`);
      }
    }
    // Refused, or busy only as admission makes every request, never for a lock: no row is `ok`.
    if (first!.code === 'ok') differing.push(`${label}: allowed`);
    // As asked, never busy: no lock waited for, no statement more than its deadline holds.
    if (row.admission === 'as asked' && first!.code.startsWith('busy')) differing.push(`${label}: busy, as asked`);
  };
  // The floor of `at` is the instance's, so the rows that need it past their requests run as a phase of their own, the
  // floor raised only while they are measured.
  const floor = (row: Row) => row.admission === 'past the floor';
  const phases = [ROWS.filter((row) => !floor(row)), ROWS.filter(floor)];
  for (const phase of phases) {
    const inTurn = ENGINE !== 'postgres';
    // Three rows at a time: each cell holds connections of its own, and nine of them a row stay within Postgres's 100.
    for (let i = 0; i < phase.length; i += 3) {
      const batch = phase.slice(i, i + 3);
      /** The floor of `at` past the requests `row` makes from now, while `work` runs: a batch's rows share their admission but in turn. */
      const past = async <T>(row: Row, work: () => Promise<T>): Promise<T> => {
        if (!floor(row)) return work();
        await run(db.owner, sql`UPDATE log_fence SET at_floor = ${Date.now() + 60_000}`);
        try {
          return await work();
        } finally {
          await run(db.owner, sql`UPDATE log_fence SET at_floor = ${Date.now() - 60_000}`);
        }
      };
      if (inTurn) {
        // Each cell made and asked before the next is made: no other cell's change between.
        for (const row of batch) {
          const results = [];
          for (const key of KEYS) {
            await inPeriod(15_000);
            const made = await cell(row, key);
            results.push({ key, ...(await past(row, async () => {
              const result = await made.measure();
              await weigh([result]);
              return result;
            })) });
          }
          judge(row, results);
        }
        continue;
      }
      // Rows a few at a time, each with its own world per cell, made side by side, then asked side by side.
      await inPeriod(30_000);
      const cells = await each(batch, async (row) => ({ row, cells: await each(KEYS, (key) => cell(row, key)) }));
      const measured = await past(batch[0]!, async () => {
        const answered = await each(cells, async ({ row, cells: keys }) => ({ row, results: await each(keys, async (c) => ({ key: c.key, ...(await c.measure()) })) }));
        await weigh(answered.flatMap(({ results }) => results));
        return answered;
      });
      for (const { row, results } of measured) judge(row, results);
    }
  }
  console.log(`the widest spread of buffers within a row's refusals, beyond their world's key never made, no standing: ${widest}; standing, a refusal's beside an isolate with no history: ${widestHistory}, of the key's blocks ${widestKeyBlocks}`);
  assert.deepEqual(differing, []);
});
