// A request's several keys by name (T165, B2's PR 2; migration 0055; formal/ProbingMany.tla): what forks.matrix.ts
// holds of one key, for a batch of two, mixed. The vault's one call decides the caller's standing at the place first,
// from rows no key decides, then resolves each key's name, the request's names or every key the place holds, decides
// them all, and only then makes the rest by ids.
//
// A row is the place (dev; a fork; a fork of a fork; the caller's personal config of dev; dev, for `dev@me` while they
// have none), how they lost their standing or not (their grant at the place revoked, or ended, which no change records;
// a Contributor asking to read; their grant on dev, which the place inherits from, revoked; the place's parent archived,
// which cuts its chain), what the isolate's map holds for the names (never asked; asked while they stood; asked after),
// what the request asks (its two keys, or every key the place holds) and the cap's window. A cell is a batch of two keys,
// each in one of forks.matrix.ts's states: one held, one never made; one inherited, one removed; neither made; and so on.
//
// Without standing at the place, or with its chain cut, every cell of a row answers the same: the place's refusal, in
// one statement, nothing written, and the same blocks of the key's relations read, none of any key's (GateBeforeKeys,
// CutByPlace, NoKeyBeforeStanding): on Postgres with every cell's principal's lock held and every statement slow, so
// that a lock waited for, or a statement more, shows. Standing there, a batch with a key they may not have is refused
// before any lock (in its first statement, or a sealed key not mapped, its batch by ids' first round), entering nothing
// in the cap's set and waiting for no lock (DecideAllFirst); one whose every
// key they may have, or the place does not hold, hands back exactly those they may have, or is busy on the lock.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';

import type { NamedManyInput, NamedManyOutcome } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';

import { shardOf } from '../../../scripts/matrix-shard.ts';
import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { holding, namedWorld, principalLocks, slowed, weighed, weighingSession, type HotCall } from './named-world.ts';
import { emptyLog, useDatabases } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  // Pools of 4, as forks.matrix.ts's: it runs beside the other matrices on a Postgres of 100 connections.
  db = await openTestDatabase({ connections: 4 });
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

const WHERE = ['dev', 'fork', 'fork of a fork', 'mine', 'mine, none of theirs'] as const;
const LOST = ['revoked', 'lapsed', 'may not read', 'parent not read', 'parent archived', 'they stand'] as const;
const MAPS = ['never', 'while standing', 'after'] as const;
const ASKS = ['its two keys', 'every key'] as const;
const WINDOWS = ['open', 'passed'] as const;
const STATES = [
  'its own', 'inherited', 'inherited, made since', 'removed here', 'its own, deleted since', 'never made',
  'inherited, a reference ended since', 'inherited, its row put back since', "dev's, plain",
] as const;
type State = (typeof STATES)[number];
/** A batch: its two keys' states, mixed. */
const CELLS: readonly (readonly [State, State])[] = [
  ['its own', 'never made'],
  ['inherited', 'removed here'],
  ['never made', 'never made'],
  ['its own, deleted since', 'inherited, a reference ended since'],
  ['inherited, made since', 'its own'],
  ['inherited, its row put back since', 'never made'],
  ['its own', 'inherited'],
  ['removed here', 'inherited, made since'],
  // A plain value, which no use is made of: decided on the batch's first statement, its text handed back (T165, PR 2).
  ["dev's, plain", 'its own'],
];
type Row = { where: (typeof WHERE)[number]; lost: (typeof LOST)[number]; map: (typeof MAPS)[number]; ask: (typeof ASKS)[number]; window: (typeof WINDOWS)[number] };

const forked = (row: Row) => row.where === 'fork' || row.where === 'fork of a fork';
const mine = (row: Row) => row.where === 'mine' || row.where === 'mine, none of theirs';
/** Whether the place inherits from dev: a fork, a fork of a fork, their personal config; not dev itself. */
const inheriting = (row: Row) => row.where !== 'dev' && row.where !== 'mine, none of theirs';
/** Whether they stand at the place for what they ask, its chain whole (the gate). */
const stands = (row: Row) => {
  if (row.lost === 'revoked' || row.lost === 'lapsed' || row.lost === 'parent archived') return false;
  if (row.lost === 'may not read') return row.where === 'mine';
  return true;
};
/** Whether the key is held at the place, its own or one it inherits. */
const held = (row: Row, state: State) => state !== 'never made' && state !== 'its own, deleted since' && !(state === 'removed here' && inheriting(row));
/** Whether a key held is the place's own: at dev, every key is. */
const own = (row: Row, state: State) => state === 'its own' || !inheriting(row);
/** Whether a key held is one they may have: they stand, its value is there, and they read where it is held. */
const usable = (row: Row, state: State) => {
  if (!stands(row) || !held(row, state)) return false;
  if (state === 'inherited, a reference ended since' || state === 'inherited, its row put back since') return false;
  if (row.lost === 'may not read' || row.lost === 'parent not read') return own(row, state);
  return true;
};
const labelOf = (row: Row) => `${row.where} / ${row.lost} / ${row.map} / ${row.ask} / window ${row.window}`;
const count = async (query: ReturnType<typeof sql>) => Number((await rows<{ n: number | string }>(db.owner, query))[0]!.n);
// Each statement held back 1 s on Postgres, the use's deadline 3 s: a refusal decided on the first statement's rows, or
// a sealed key not mapped on the batch by ids' first round, the second, answers in time, with a second for the rest of
// its work (a cold isolate's first, on a loaded runner: at 1.2 s, CI's ran past it); a third statement's delays alone
// reach the deadline (`late`). forks.matrix.ts's one key holds its refusal to one statement, at 1.6 s.
const delayOf = () => (ENGINE !== 'postgres' ? 0 : 1000);
const LAPSES_MS = ENGINE === 'postgres' ? 2500 : 300;


/** An answer as the matrix compares it: whether they stood, and its outcome. */
function shapeOf(answer: NamedManyOutcome): { stands: boolean | null; code: string; keys: string[] } {
  if (!answer.served) return { stands: null, code: 'not served', keys: [] };
  if (answer.route !== 'name') return { stands: null, code: `${answer.route}:${'busy' in answer.outcome ? answer.outcome.busy : answer.outcome.code}`, keys: [] };
  const { outcome } = answer;
  const code = outcome.ok ? 'ok' : 'busy' in outcome ? `busy:${outcome.busy}` : outcome.index === null ? `place:${outcome.code}` : outcome.code;
  const keys = outcome.ok ? answer.keys.flatMap((key, i) => (outcome.values[i] === null ? [] : [key.key])).sort() : [];
  return { stands: answer.stands, code, keys };
}

/** One cell, in its own world and isolate: everything up to its request, then the request, measured. */
async function cell(row: Row, states: readonly [State, State]) {
  const reads = row.lost === 'may not read';
  const w = await namedWorld(db, { role: reads ? 'contributor' : 'developer', caller: mine(row) ? 'person' : 'bearer' });
  const names = ['K_A', 'K_B'] as const;
  const named = async (id: string, name: string) => {
    await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${id}`);
    return id;
  };
  let place = w.dev;
  let middle: string | null = null;
  if (forked(row)) {
    middle = row.where === 'fork of a fork' ? await w.fork('mid') : null;
    place = await w.environment('named', false, { parentId: middle ?? w.dev });
    for (const at of [place, ...(middle === null ? [] : [middle])]) await w.grantAt(at, reads ? 'contributor' : 'developer');
  }
  if (row.where === 'mine') place = await w.personal();
  const slug = forked(row) ? 'named' : mine(row) ? 'dev@me' : 'dev';
  const owner = row.where === 'mine' ? w.principal : null;
  // Each key as its state makes it, up to the request; what lands after the standing goes, after it.
  const later: (() => Promise<unknown>)[] = [];
  for (const [i, state] of states.entries()) {
    const name = names[i]!;
    const ofPlace = async () => named(await w.key('own', false, place, owner), name);
    const ofDev = async () => named(await w.key('dev'), name);
    if (state === 'its own') await ofPlace();
    if (state === 'its own, deleted since') {
      const id = await ofPlace();
      later.push(() => w.remove(id));
    }
    if (state === 'inherited') await ofDev();
    if (state === "dev's, plain") await w.plain('plain', name);
    if (state === 'inherited, made since') later.push(ofDev);
    if (state === 'removed here') {
      await ofDev();
      if (inheriting(row)) await w.dismiss(place, name);
    }
    if (state === 'inherited, a reference ended since') {
      const reference = await w.reference(name);
      later.push(() => w.end(reference));
    }
    if (state === 'inherited, its row put back since') {
      const id = await ofDev();
      later.push(() => w.putBack(id));
    }
  }
  const measured = await slowed(db, { connections: 1 });
  const purpose = reads ? 'reveal' : 'use';
  const ask = (extra: Partial<NamedManyInput> = {}): NamedManyInput => {
    const { key: _, requestId: __, forks: ___, ...one } = w.ask('UNUSED', { place: { project: w.slug, environment: slug }, purpose });
    return { ...one, keys: row.ask === 'every key' ? null : [...names], ...extra };
  };
  if (row.map === 'while standing') await measured.vault.useNamedMany!(ask());
  const ends = Date.now() + LAPSES_MS;
  const at = mine(row) ? w.dev : place;
  if (row.lost === 'revoked') await w.revokeAt(at);
  if (row.lost === 'lapsed') {
    await w.revokeAt(at, ends);
    await sleep(Math.max(0, ends - Date.now()) + 50);
  }
  if (row.lost === 'parent not read') await w.revokeAt(w.dev);
  if (row.lost === 'parent archived') await w.archive(middle ?? w.dev, false);
  if (row.map === 'after') await measured.vault.useNamedMany!(ask());
  for (const step of later) await step();
  return {
    states,
    principal: w.principal,
    measure: async () => {
      const entries = () => count(sql`SELECT count(*) AS n FROM log_uses WHERE credential = ${w.credentialId}`);
      const capRows = () => count(sql`SELECT count(*) AS n FROM bulk_cap WHERE principal = ${w.principal}`);
      if (row.window === 'passed') await run(db.owner, sql`DELETE FROM bulk_cap WHERE principal = ${w.principal}`);
      const [beforeEntries, beforeCap] = [await entries(), await capRows()];
      await measured.connect();
      measured.slow(delayOf());
      const before = measured.statements();
      const now = Date.now();
      const answer = await measured.vault.useNamedMany!(ask({ at: now, deadline: now + 3000 }));
      measured.slow(0);
      const result = {
        ...shapeOf(answer), calls: measured.statements() - before,
        entries: (await entries()) - beforeEntries, capRows: (await capRows()) - beforeCap,
        sent: measured.last() as HotCall | null, keyBlocks: null as number | null,
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
 * Every row, generated: each place, each way of losing standing or keeping it, each map, each ask, each window; `parent
 * not read` and `parent archived` where the place inherits from a dev it is not (a fork's; their personal config reads
 * dev's grant as its own). CI runs them in shards, a slice each (`shardOf`).
 */
const ROWS: Row[] = shardOf(import.meta.url, WHERE.flatMap((where) => LOST
  .filter((lost) => (lost !== 'parent not read' && lost !== 'parent archived') || where === 'fork' || where === 'fork of a fork')
  .flatMap((lost) => MAPS.flatMap((map) => ASKS.flatMap((ask) => WINDOWS.map((window) => ({ where, lost, map, ask, window })))))), labelOf);

test(`several keys by name, mixed: no batch tells what a caller may not have, in any of ${ROWS.length} rows of ${CELLS.length} batches (T165, D153)`, { timeout: 7_200_000 }, async () => {
  const differing: string[] = [];
  await namedWorld(db);
  for (const row of ROWS) {
    // Each cell's keys are made as their periods start (T204, `freshKeyId`): made and asked within a minute, each within one.
    const made = await each(CELLS, (states) => cell(row, states));
    const measureAll = () => each(made, async (c) => ({ states: c.states, ...(await c.measure()) }));
    const results = ENGINE === 'postgres' ? await holding(db, principalLocks(made.map((c) => c.principal)), measureAll) : await measureAll();
    const label = labelOf(row);
    const said = (r: (typeof results)[number]) => `[${r.states.join(' + ')}] ${r.code}${r.keys.length > 0 ? ` ${r.keys.join(',')}` : ''} in ${r.calls}`;
    if (!stands(row)) {
      // No standing, or the chain cut: one answer for every batch, in one statement, nothing written, no key read.
      const [first] = results;
      if (results.some((r) => r.stands !== false || r.code !== first!.code || r.calls !== first!.calls)) differing.push(`${label}: ${results.map(said).join('; ')}`);
      if (first!.calls !== 1) differing.push(`${label}: ${first!.calls} statements, not one`);
      for (const r of results) if (r.entries !== 0 || r.capRows !== 0) differing.push(`${label}: [${r.states.join(' + ')}] wrote ${r.entries} entries, ${r.capRows} rows of the cap's`);
      if (ENGINE === 'postgres') {
        await run(db.owner, sql`ANALYZE`);
        const session = weighingSession();
        try {
          for (const r of results) r.keyBlocks = (await weighed(r.sent, session))?.keyBlocks ?? null;
        } finally {
          await session.end();
        }
        const blocks = new Set(results.map((r) => r.keyBlocks));
        if (blocks.size > 1) differing.push(`${label}: blocks of the key's tables ${results.map((r) => `[${r.states.join(' + ')}] ${r.keyBlocks}`).join(', ')}`);
      }
      continue;
    }
    for (const r of results) {
      const covered = row.ask === 'every key' ? r.states.filter((state) => held(row, state)) : r.states;
      const refused = covered.some((state) => held(row, state) && !usable(row, state));
      if (r.stands !== true) {
        differing.push(`${label}: ${said(r)}, standing there`);
        continue;
      }
      if (refused) {
        // DecideAllFirst: refused before any call takes a lock, none waited for (Postgres holds theirs), nothing entered
        // in the cap's set: on the first statement's rows, or, a sealed key the isolate had not mapped, which that
        // statement only resolves, on the batch by ids' first round, its second.
        if (r.code === 'ok' || r.code.startsWith('busy') || r.calls > 2 || r.capRows !== 0) differing.push(`${label}: ${said(r)}, ${r.capRows} rows of the cap's, a key refused`);
        continue;
      }
      // Every key theirs, or not held: exactly those theirs, or busy on the lock another call holds.
      const theirs = (['K_A', 'K_B'] as const).filter((_, i) => usable(row, r.states[i]!)).sort();
      if (r.code.startsWith('busy')) continue;
      if (r.code !== 'ok' || r.keys.join(',') !== theirs.join(',')) differing.push(`${label}: ${said(r)}, theirs ${theirs.join(',') || 'none'}`);
    }
  }
  assert.deepEqual(differing, []);
});
