// What a refusal of the use matrices reads inside the vault's hot path, weighed alike in both: the vault's,
// `packages/vault/test/use.matrix.ts`, and the app's, `packages/server/test/named.matrix.ts` (D153, W268's
// NoKeyBeforeStanding: a caller standing nowhere reads no key, so as many buffers whatever the key).
import { setTimeout as sleep } from 'node:timers/promises';

import { postgresClient } from '@coffre/db/connect';

/** A `use_credential` (or `use_named_batch`, or `use_route`) call as it was sent: its text and its arguments, `$1` first. */
export type HotCall = { query: string; args: unknown[] };

/** A Postgres session of the hot login's, whose plans, made by its first call, weigh every call after it alike. */
export type WeighingSession = ReturnType<typeof postgresClient>;

/**
 * A session to weigh calls in (`weigh`), at `url`, the hot login's: one connection, planned as an instance's tables
 * grown past a few pages are. With no sequential scan where an index serves: a test's tables are a page or three, where
 * a scan that stops at its first match reads as many pages as precede the row it finds (T194: the `credentials` heap,
 * read 2 to 20 rows deep, as each world's credential fell), and where a key's rows read before its standing was decided
 * would cost no more than any key's, the table's every page whatever the key. With the plans for any values that the
 * server's plan cache keeps for the use statements at its own settings, within a session's first few calls (T207,
 * docs/design/planner-defaults.md), which its first call makes, for every call after it: refusing sequential scans
 * costs those plans so much more than each call's own that the cache would never keep them, and each call would be
 * weighed on a plan for its own values. Without JIT, which those costs would reach (past the hot login's 2 s
 * `statement_timeout`) and which reads no buffer. These are the weighing's own, never a login's or a function's.
 */
export function weighingSession(url: string): WeighingSession {
  return postgresClient(url, { max: 1, connection: { enable_seqscan: 'off', plan_cache_mode: 'force_generic_plan', jit: 'off' } });
}

/**
 * The relations a key's own work reads, and nothing else a refusal reads does: its row, its version, a reference, its
 * source, its row of the cap's, an entry a cover names, each with its indexes; and the index a key's object's newest
 * change is probed in, which a refusal's other probes (its credential's, principal's, roles', places') take one path
 * each through, whatever the key. A call that reads no key (W268, NoKeyBeforeStanding) fetches as many blocks of
 * them for every key: its probes by a key it never looked up are by none, which a B-tree answers reading nothing.
 */
const KEY_TABLES = ['secrets', 'secret_versions', 'secret_references', 'bulk_cap', 'log_uses'];
const KEY_INDEXES = ['log_changes_object_idx'];

/**
 * The tables of a world's own rows, which a matrix's cells each write over a few times as they are made (their place,
 * credential and account): `VACUUM` them before weighing. Their dead versions cost a heap page or more, whatever
 * the key, as the versions of a cell's rows fall on one page or on several (a row of no key read spread 74 to 81 in
 * `environments`, W268; 8 in `credentials`, T194). None is a key's: `KEY_TABLES` and `log_changes` stay unvacuumed, so
 * that no all-visible page lets a probe skip the heap and hide the work of a key's history (review r4 of W268). What a
 * key's work reads of these (a reference's source's environment, a personal config's parent) takes columns no index
 * holds, a heap fetch that no all-visible page spares (review r6 of W268).
 */
export const WORLD_TABLES = ['environments', 'projects', 'credentials', 'identities', 'principals', 'grants', 'log_config', 'checkpoint_fence'];

/** What a weighed call read: its shared buffers, of them the blocks `KEY_TABLES` and `KEY_INDEXES` gave, and every relation's blocks. */
export type Weighed = { buffers: number; keyBlocks: number; blocks: Record<string, number> };

/**
 * The shared buffers `call` reads in `session`, of them the key's relations' blocks, and each relation's: a call's
 * own, the counters' change across its `EXPLAIN (ANALYZE, BUFFERS)` in a transaction rolled back
 * (`pg_stat_get_xact_blocks_fetched` answers what the backend has not yet flushed, runs and calls before included).
 * After a run unweighed, which plans what the session had not; then the run of the fewest buffers of a few. Its time
 * and deadline are now's, so that it is not refused `late`; whatever it would write is rolled back.
 */
export async function weigh(session: WeighingSession, call: HotCall): Promise<Weighed> {
  let least: Weighed | null = null;
  for (let run = 0; run < 4; run += 1) {
    const read = await weighOnce(session, call);
    if (run === 0) continue;
    if (least !== null && least.buffers <= read.buffers) continue;
    least = read;
  }
  return least!;
}

/**
 * The sessions that may still see a row deleted by a transaction older than `$1`, a transaction id: in any of the
 * cluster's databases, one whose transaction took an id older than it, or whose snapshot's oldest is. Neither this
 * session (`pg_backend_pid`) nor one holding neither (a session between transactions, or reading with no snapshot yet:
 * `age(NULL)` is no age). Every other kind of session counts, not only clients: an autovacuum worker's ANALYZE runs in a
 * transaction of its own, whose id and snapshot hold rows back as a client's do; only a lazy VACUUM is left out of the
 * horizon (`PROC_IN_VACUUM`), and waiting on one too costs at most its run. `age` compares ids as Postgres does, modulo
 * 2³², which `pg_stat_activity`'s 32-bit ids need.
 */
const HOLDERS = `
  SELECT pid, backend_type AS kind, datname, state, xact_start::text AS since, backend_xid::text AS xid, backend_xmin::text AS xmin
    FROM pg_stat_activity
   WHERE pid <> pg_backend_pid()
     AND (age(backend_xid) > age($1::xid) OR age(backend_xmin) > age($1::xid))`;

/**
 * How often a wait still held up names what holds it, on stderr: a cadence of the log's, which bounds nothing. A batch
 * waits about 5 s (T225's runs); a wait a minute long is already one to look at, and one held by a session that never
 * ends names it each minute until CI cancels the job, at 30 minutes (`validate.yml`). The test runner shows a file's
 * output once the files before it are done, and all of it when it is stopped (SIGINT or SIGTERM), so the names reach
 * the log either way, where the test's own timeout, two hours, never comes.
 */
const NAME_HOLDERS_EVERY_MS = 60_000;

/**
 * Resolves once every row deleted before it is called is dead to every session started after: once no session that
 * might still see it (`HOLDERS`) is left, in any database of the cluster, since that is how far a new session's
 * snapshot looks (its xmin is the oldest id still running anywhere). Until then a new session's planner, probing an
 * end of `bulk_cap_pkey` for the range its estimates use (`get_actual_variable_range`, which skips only rows known
 * dead), takes a deleted row there for one that may still be seen and reads its heap page as a live row's; once that
 * ends, the first session to plan reads the dead row's page and the next row's, one block more, and marks the entry
 * dead, so that no session after it reads it. A transaction of another test's database ending between a call and its
 * twins moved that block from one to the next: `bulk_cap` 9 blocks beside 8 for a key never made, or 8 beside 9, in
 * the rows of the window passed, which delete their principal's rows of the cap's (T225: in CI, the other matrices'
 * work beside them on the one Postgres). Weighed after this, every call faces the index its first warm-up leaves.
 *
 * `watcher` must have the privileges of `pg_read_all_stats` (a superuser does: the owner, in compose and CI), not only
 * be a member of it (`USAGE`, not `MEMBER`: a membership granted `INHERIT FALSE` gives none): without them Postgres
 * still shows it other logins' `backend_xid` and `backend_xmin`, so it would wait as long, but hides their
 * `backend_type`, `state` and `xact_start`, which name a holder to whoever must end it. It waits until `signal`
 * aborts: the test's own timeout, the only bound there is on how long a transaction elsewhere in the cluster may run,
 * so no number of its own (R70). While it waits it names what holds it every `NAME_HOLDERS_EVERY_MS`, so that a wait
 * CI cancels first is not a silent one; aborted, it fails naming each session still in the way, on stderr as well as
 * in its error: a test that timed out reports its timeout alone, not the error it ends with. It polls every 25 ms: how
 * late past the last holder's end a batch is weighed, a delay of the test's alone, which bounds nothing.
 */
export async function deletesSettled(watcher: WeighingSession, signal: AbortSignal): Promise<void> {
  const [{ sees }] = await watcher.unsafe(`SELECT pg_has_role('pg_read_all_stats', 'USAGE') AS sees`) as unknown as { sees: boolean }[];
  if (!sees) throw new Error("deletesSettled needs a login with pg_read_all_stats's privileges (a superuser, or a member that inherits them): it could not name the sessions it waits on");
  // One past the newest transaction to have ended (a snapshot's xmax), as `pg_stat_activity`'s 32-bit ids are: every
  // row deleted before the call was deleted by a transaction older than this.
  const [{ ended }] = await watcher.unsafe(`SELECT (pg_snapshot_xmax(pg_current_snapshot())::text::numeric % 4294967296)::text AS ended`) as unknown as { ended: string }[];
  type Holder = { pid: number; kind: string | null; datname: string | null; state: string | null; since: string | null; xid: string | null; xmin: string | null };
  const named = (holders: Holder[]) => holders.map((h) => `pid ${h.pid} (${h.kind}, database ${h.datname ?? 'none'}, ${h.state ?? 'no state'}, its transaction begun ${h.since}, xid ${h.xid ?? 'none'}, xmin ${h.xmin ?? 'none'})`).join('; ');
  const began = performance.now();
  let nextNaming = began + NAME_HOLDERS_EVERY_MS;
  for (;;) {
    const holders = await watcher.unsafe(HOLDERS, [ended]) as unknown as Holder[];
    if (holders.length === 0) return;
    if (signal.aborted) {
      const message = `the rows a batch deleted may still be seen when the test's time ran out: ${holders.length} session(s) older than xid ${ended} still run, ${named(holders)}`;
      console.error(message);
      throw new Error(message);
    }
    if (performance.now() >= nextNaming) {
      console.error(`deletesSettled has waited ${Math.round((performance.now() - began) / 1000)} s for ${holders.length} session(s) older than xid ${ended}: ${named(holders)}`);
      nextNaming += NAME_HOLDERS_EVERY_MS;
    }
    await sleep(25, undefined, { signal }).catch(() => undefined);
  }
}

/**
 * How many calls of a new session `weighInTurn` weighs: a statement's first five runs each plan for their own values
 * (a session's first call runs each form once dry, T131), its sixth makes the plan for any values the cache keeps,
 * and its seventh runs on it, as every call after does.
 */
export const EARLY_CALLS = 7;

/**
 * What `call` reads at each of a new session's first `calls` calls, as a connection of the hot login's reads it in
 * production: at the server's own planner settings, which `weighingSession` leaves (T207, Sol's review r2;
 * docs/design/planner-defaults.md). A key's refusal is held to the same blocks of the key's relations as every other
 * key's at each call: its plans for each call's own values, and the making of them, included. Each call is weighed
 * once, in a transaction rolled back, and the marks it leaves (`MARKS`, a warm-up's) are set again after it, as a call
 * that commits leaves them. Sequential scans stay on: a table a page or three long is read whole by a scan, whatever
 * the key, which `weighingSession`'s weighing on its settled plans, sequential scans off, does not take for granted.
 */
export async function weighInTurn(url: string, call: HotCall, calls = EARLY_CALLS): Promise<Weighed[]> {
  const session = postgresClient(url, { max: 1 });
  try {
    const read: Weighed[] = [];
    for (let n = 0; n < calls; n += 1) {
      const { marks, ...weighed } = await weighOnce(session, call);
      read.push(weighed);
      for (const [name, value] of marks) await session.unsafe('SELECT set_config($1, $2, false)', [name, value]);
    }
    return read;
  } finally {
    await session.end();
  }
}

/** A key's name no world of the matrices makes. */
export const NEVER_MADE = 'NEVER_MADE_BY_ANY_WORLD';

/**
 * A named call's twin: the same request, of a key its world never made (`p_key`, the 19th argument). It reads all the
 * world's own rows the call does, and no key's.
 */
export function twinOf<T extends HotCall>(call: T): T {
  if (typeof call.args[18] !== 'string') throw new Error('a named call names its key, the 19th argument');
  const args = [...call.args];
  args[18] = NEVER_MADE;
  return { ...call, args } as T;
}

/**
 * A named call's control of no key: its twin (`twinOf`), and nothing the isolate kept of the key it asked of (Sol's
 * review r4): no id (`p_secret`, the 2nd argument), no cover (the 9th to 11th), no seals or cap (the 12th to 15th), its
 * caller, place and every other input as they were. `twinOf`'s twin keeps the key's id, and reads by it whatever the call
 * does: a dry run planned for the id passed (T207 r2) reads as many blocks for a held key's twin as for the key, and only
 * this one shows them.
 */
export function absentOf<T extends HotCall>(call: T): T {
  const { args } = twinOf(call);
  args[1] = null;
  for (let n = 8; n <= 14; n += 1) args[n] = null;
  return { ...call, args } as T;
}

/**
 * Where a key's refusal, weighed in turn in a session of its own (`weighInTurn`), fetched blocks of the key's relations
 * apart from a control's, weighed so too, at the same call: its twin, of a key never made (`twinOf`), and its twin with
 * nothing of the key the isolate kept (`absentOf`). One line a call and control, both counts and what they are made of.
 * Held to its own world's controls, not to another key's world: each cell is a world of its own, whose rows sit where
 * its writes put them, a block more or less of the caller's own from one world to another, the same for every key the
 * caller names. The pages a batch's rolled-back writes left are settled before (`weighedInTurn`, T207 r5).
 */
export function turnsApart(key: string, asked: readonly Weighed[], controls: { twin: readonly Weighed[]; absent: readonly Weighed[] }): string[] {
  return (['twin', 'absent'] as const).flatMap((of) => {
    const control = controls[of];
    const kind = of === 'twin' ? 'a key its world never made' : 'a key never made, asked with no id, cover or seal';
    return Array.from({ length: Math.max(asked.length, control.length) }, (_, n) => n).flatMap((n) => {
      const [a, t] = [asked[n], control[n]];
      if (a === undefined || t === undefined) return [`call ${n + 1} of a new session, ${key} weighed ${a === undefined ? 'not' : `but not ${kind}`}`];
      if (a.keyBlocks === t.keyBlocks) return [];
      return [`call ${n + 1} of a new session, ${key}: blocks of the key's tables ${a.keyBlocks} beside ${t.keyBlocks} for ${kind}; blocks apart (${of}/${key}): ${blocksApart(t.blocks, a.blocks).join(', ')}`];
    });
  });
}

/**
 * The settings the hot path's functions mark a session with once they have planned its statements (0060, 0068, 0069): a
 * session's own (`set_config(…, false)`), which a transaction rolled back takes back, and which Postgres lists in no
 * view (`pg_settings` hides a placeholder's).
 */
const MARKS = ['coffre.use_planned', 'coffre.route_planned'];

/** One run of `call`, rolled back: its buffers, its key's blocks, each relation's, and the marks it left (`MARKS`). */
async function weighOnce(session: WeighingSession, call: HotCall): Promise<Weighed & { marks: [string, string][] }> {
  const counters = `SELECT c.relname AS name, pg_stat_get_xact_blocks_fetched(c.oid)::int AS n FROM pg_class c
    WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'i', 'p')`;
  const args = [...call.args];
  const now = Date.now();
  // `callUse`'s order: credential, key, request, at, purpose, place, MAC, deadline; `callNamedBatch`'s, the names
  // first, then at, purpose and deadline; `callRoute`'s, its caller and route first, then at, purpose and deadline.
  if (call.query.includes('use_named_batch')) [args[8], args[10]] = [String(now), String(now + 3000)];
  else if (call.query.includes('use_route')) [args[13], args[15]] = [String(now), String(now + 3000)];
  else [args[3], args[7]] = [String(now), String(now + 3000)];
  const read = await session.begin(async (tx) => {
    const before = await tx.unsafe(counters) as unknown as { name: string; n: number }[];
    const [plan] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${call.query}`, args as never[]) as unknown as { 'QUERY PLAN': { Plan: Buffers }[] }[];
    const after = await tx.unsafe(counters) as unknown as { name: string; n: number }[];
    const marks = await tx.unsafe(`SELECT name, current_setting(name, true) AS setting FROM unnest($1::text[]) name WHERE current_setting(name, true) IS NOT NULL`, [MARKS] as never[]) as unknown as { name: string; setting: string }[];
    const was = new Map(before.map((row) => [row.name, row.n]));
    const blocks = Object.fromEntries(after.map((row) => [row.name, row.n - (was.get(row.name) ?? 0)]).filter(([, n]) => n !== 0));
    throw new RolledBack({ plan: plan!['QUERY PLAN'][0]!.Plan, blocks, marks: marks.map((m) => [m.name, m.setting] as [string, string]) });
  }).then(() => null, (error: unknown) => {
    if (error instanceof RolledBack) return error.read;
    throw error;
  });
  const buffers = read!.plan['Shared Hit Blocks'] + read!.plan['Shared Read Blocks'];
  return { buffers, keyBlocks: keyBlocksOf(read!.blocks), blocks: read!.blocks, marks: read!.marks };
}

/**
 * The blocks of the key's relations among a call's: `KEY_TABLES`, their indexes and partitions (named for their table),
 * `KEY_INDEXES`; but those of the tables `except` names.
 */
export function keyBlocksOf(blocks: Record<string, number>, except: readonly string[] = []): number {
  const of = (name: string, table: string) => name === table || name.startsWith(`${table}_`);
  return Object.entries(blocks).reduce((sum, [name, n]) =>
    sum + ((KEY_INDEXES.includes(name) || KEY_TABLES.some((table) => of(name, table))) && !except.some((table) => of(name, table)) ? n : 0), 0);
}

/** The relations whose blocks `a` and `b` read apart, each `name a/b`: what a spread between two weighed calls is made of. */
export function blocksApart(a: Record<string, number>, b: Record<string, number>): string[] {
  const names = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  return names.flatMap((name) => ((a[name] ?? 0) === (b[name] ?? 0) ? [] : [`${name} ${a[name] ?? 0}/${b[name] ?? 0}`]));
}

type Buffers = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number };

class RolledBack extends Error {
  readonly read: { plan: Buffers; blocks: Record<string, number>; marks: [string, string][] };

  constructor(read: { plan: Buffers; blocks: Record<string, number>; marks: [string, string][] }) {
    super('rolled back');
    this.read = read;
  }
}
