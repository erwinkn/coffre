// What a refusal of the use matrices reads inside the vault's hot path, weighed alike in both: the vault's,
// `packages/vault/test/use.matrix.ts`, and the app's, `packages/server/test/named.matrix.ts` (D153, W268's
// NoKeyBeforeStanding: a caller standing nowhere reads no key, so as many buffers whatever the key).
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
const KEY_TABLES = ['secrets', 'secret_versions', 'secret_references', 'log_bulk', 'log_uses'];
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
export const WORLD_TABLES = ['environments', 'projects', 'credentials', 'identities', 'vault_members', 'vault_grants', 'log_config', 'log_fence'];

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
 * Where a key's refusal, weighed in turn in a session of its own (`weighInTurn`), fetched blocks of the key's relations
 * apart from its twin's (`twinOf`, weighed so too) at the same call: one line a call, both counts and what they are made
 * of. Held to its own world's twin, not to another key's world: a session's first call plans and runs each form once
 * for no key (0063's dry run, T131), whose probe of the caller's own row of the cap's (`log_bulk`, by principal) falls
 * where that world's rows put it, a block more or less from one world to another (CI read 9 beside 8 for a key held
 * once, in one row of 144), the same for every key the caller names.
 */
export function turnsApart(key: string, asked: readonly Weighed[], twin: readonly Weighed[]): string[] {
  return Array.from({ length: Math.max(asked.length, twin.length) }, (_, n) => n).flatMap((n) => {
    const [a, t] = [asked[n], twin[n]];
    if (a === undefined || t === undefined) return [`call ${n + 1} of a new session, ${key} weighed ${a === undefined ? 'not' : 'but not its twin'}`];
    if (a.keyBlocks === t.keyBlocks) return [];
    return [`call ${n + 1} of a new session, ${key}: blocks of the key's tables ${a.keyBlocks} beside ${t.keyBlocks} for a key its world never made; blocks apart (twin/${key}): ${blocksApart(t.blocks, a.blocks).join(', ')}`];
  });
}

/**
 * The settings the hot path's functions mark a session with once they have planned its statements (0060, 0063): a
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
