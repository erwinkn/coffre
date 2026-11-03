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
  const counters = `SELECT c.relname AS name, pg_stat_get_xact_blocks_fetched(c.oid)::int AS n FROM pg_class c
    WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'i', 'p')`;
  let least: Weighed | null = null;
  for (let run = 0; run < 4; run += 1) {
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
      const was = new Map(before.map((row) => [row.name, row.n]));
      const blocks = Object.fromEntries(after.map((row) => [row.name, row.n - (was.get(row.name) ?? 0)]).filter(([, n]) => n !== 0));
      throw new RolledBack({ plan: plan!['QUERY PLAN'][0]!.Plan, blocks });
    }).then(() => null, (error: unknown) => {
      if (error instanceof RolledBack) return error.read;
      throw error;
    });
    if (run === 0) continue;
    const buffers = read!.plan['Shared Hit Blocks'] + read!.plan['Shared Read Blocks'];
    if (least !== null && least.buffers <= buffers) continue;
    least = { buffers, keyBlocks: keyBlocksOf(read!.blocks), blocks: read!.blocks };
  }
  return least!;
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
  readonly read: { plan: Buffers; blocks: Record<string, number> };

  constructor(read: { plan: Buffers; blocks: Record<string, number> }) {
    super('rolled back');
    this.read = read;
  }
}
