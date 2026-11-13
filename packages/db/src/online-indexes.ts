// Indexes built without blocking writes. A plain CREATE INDEX holds
// its table's SHARE lock while it builds, which every insert waits behind:
// half a second on an audit log of 440,000 entries, and minutes on a day of
// uses. CREATE INDEX CONCURRENTLY holds only SHARE UPDATE EXCLUSIVE, which no
// insert, update or delete waits for, but cannot run in a transaction, and the
// migrator applies the migrations in one. So a migration's CONCURRENTLY
// statements are left out of its transaction, and the migrator builds each
// after it commits, on every run, until it is built: a run cut short, or one
// whose build gave up waiting, leaves it to the next. coffre works without
// them meanwhile, only slower at scale.
import { lockNotAvailable } from './dialect.ts';
import { quoteIdentifier, type PostgresClient } from './postgres.ts';

/** A migration's `CREATE INDEX CONCURRENTLY`, as drizzle-kit writes one for an index declared `.concurrently()`. */
export type OnlineIndex = { name: string; table: string; unique: boolean; body: string };

/** One the run left unbuilt, and why: the next run builds it. */
export type UnbuiltIndex = { name: string; table: string; reason: string };

const CONCURRENT = /^CREATE (UNIQUE )?INDEX CONCURRENTLY (?:IF NOT EXISTS )?"([^"]+)" ON "([^"]+)" (.+?);?\s*$/s;

/** The statement without the comment lines before it, as a migration file puts them. */
function bare(statement: string): string {
  return statement.replace(/^(?:\s*--[^\n]*\n)*\s*/, '');
}

/** The index `statement` builds online, or null for any other statement, which the migrations' transaction runs. */
export function onlineIndex(statement: string): OnlineIndex | null {
  const match = CONCURRENT.exec(bare(statement));
  if (match === null) return null;
  return { unique: match[1] !== undefined, name: match[2]!, table: match[3]!, body: match[4]! };
}

/** Every index the migrations build online, in their order. */
export function onlineIndexes(sqlTexts: readonly string[]): OnlineIndex[] {
  return sqlTexts.flatMap((text) => text.split('--> statement-breakpoint').map(onlineIndex).filter((index) => index !== null));
}

/** The longest name Postgres keeps whole (NAMEDATALEN − 1). */
const NAME_BYTES = 63;

/**
 * What a build needs of the migrator's session. `briefly` runs a statement
 * that queues inserts behind it while it waits for its lock (the empty
 * index on a partitioned table, an ATTACH), under the migrations' own short
 * waits and retries; the concurrent builds wait under the session's
 * `lock_timeout`, which `waitLong` sets, for they queue no insert.
 */
export type OnlineSession = {
  client: Pick<PostgresClient, 'unsafe'>;
  briefly: <T>(run: () => Promise<T>) => Promise<T>;
  waitShort: () => Promise<void>;
  waitLong: () => Promise<void>;
};

/**
 * Build `index` if it is not built: valid, on its table and, for a table
 * partitioned by day (`log_uses`, `log_reads`), on every day. A
 * partitioned table takes no CREATE INDEX CONCURRENTLY, so its index is made
 * empty on the table alone (`ON ONLY`, invalid until every day has one),
 * each day's is built concurrently and attached, and a day made since takes
 * one as it is attached (`make_day`, `make_reads_day`), empty. An invalid
 * index a cut-short build left is dropped and built again.
 */
export async function buildOnline(session: OnlineSession, index: OnlineIndex): Promise<void> {
  const { client } = session;
  const [table] = await client.unsafe<{ kind: string }[]>('SELECT c.relkind::text AS kind FROM pg_class c WHERE c.oid = to_regclass($1)', [`public.${quoteIdentifier(index.table)}`]);
  if (table === undefined) throw new Error(`table ${index.table} for index ${index.name} does not exist`);
  const unique = index.unique ? 'UNIQUE ' : '';
  if (table.kind !== 'p') {
    await concurrently(session, index.name, `CREATE ${unique}INDEX CONCURRENTLY ${quoteIdentifier(index.name)} ON ${quoteIdentifier(index.table)} ${index.body}`);
    return;
  }
  // Valid once every day has its own (a day made since takes one as it is made): built. Asked first, since even
  // CREATE INDEX IF NOT EXISTS takes the table's SHARE lock, which holds its inserts, before it finds the index there.
  if (await valid(client, index.name)) return;
  await session.waitShort();
  await session.briefly(() => client.unsafe(`CREATE ${unique}INDEX IF NOT EXISTS ${quoteIdentifier(index.name)} ON ONLY ${quoteIdentifier(index.table)} ${index.body}`));
  let remade = false;
  for (;;) {
    const days = await client.unsafe<{ day: string }[]>(`
      SELECT p.relname::text AS day FROM pg_inherits h JOIN pg_class p ON p.oid = h.inhrelid
       WHERE h.inhparent = to_regclass($1) AND p.relkind = 'r'
         AND NOT EXISTS (SELECT 1 FROM pg_inherits x JOIN pg_index i ON i.indexrelid = x.inhrelid
                          WHERE x.inhparent = to_regclass($2) AND i.indrelid = p.oid)
       ORDER BY p.relname`, [`public.${quoteIdentifier(index.table)}`, `public.${quoteIdentifier(index.name)}`]);
    if (days.length === 0) {
      const state = await revalidated(session, index, remade);
      if (state === 'valid') return;
      if (state === 'remade') remade = true;
      continue;
    }
    for (const { day } of days) {
      const own = dayIndexName(index, day);
      try {
        await concurrently(session, own, `CREATE ${unique}INDEX CONCURRENTLY ${quoteIdentifier(own)} ON ${quoteIdentifier(day)} ${index.body}`);
      } catch (error) {
        // Retention dropped the day meanwhile: nothing to index.
        if ((error as { code?: string }).code === '42P01') continue;
        throw error;
      }
      await session.waitShort();
      await session.briefly(() => client.unsafe(`ALTER INDEX ${quoteIdentifier(index.name)} ATTACH PARTITION ${quoteIdentifier(own)}`)).catch(async (error: unknown) => {
        // Retention detached the day after the build (55000: its index's table is no partition of the
        // parent's), or dropped it with its index (42P01): nothing to attach, and the next pass lists
        // the days still there. A day still attached fails the build, whatever the error.
        if (!(await partOf(client, day, index.table))) return;
        throw error;
      });
    }
  }
}

/** A parent index still invalid once made again, which the run reports unbuilt for the next to build. */
export class StillInvalid extends Error {}

/**
 * Whether the partitioned `index` is valid, once every day has its own:
 * `valid`; `look` when the caller is to list the days again; `remade` when
 * it is to build every day's again. Postgres checks a parent only as a day's
 * index is attached, so a day retention detached before its attach leaves
 * the parent invalid with every day still there indexed. Attaching a day's
 * index again has it checked again, from Postgres 14.23, 15.18, 16.14 and
 * 17.10 (May 2026); before those, it changes nothing, and the parent, with
 * every day's index, is dropped and made again, over no day's index: the
 * caller builds them all again, oldest first, so that the last attached is
 * the newest day, which retention does not detach, and that attach checks
 * the parent on any Postgres. `remade` says the caller did so already: a
 * parent invalid again is left to the next run (`StillInvalid`).
 */
async function revalidated(session: OnlineSession, index: OnlineIndex, remade: boolean): Promise<'valid' | 'look' | 'remade'> {
  const { client } = session;
  const name = `public.${quoteIdentifier(index.name)}`;
  const valid = async () => {
    const [parent] = await client.unsafe<{ valid: boolean }[]>('SELECT i.indisvalid AS valid FROM pg_index i WHERE i.indexrelid = to_regclass($1)', [name]);
    if (parent === undefined) throw new Error(`index ${index.name} on ${index.table} went missing while it was built`);
    return parent.valid;
  };
  const remake = async () => {
    const unique = index.unique ? 'UNIQUE ' : '';
    await session.waitShort();
    await session.briefly(async () => {
      await client.unsafe(`DROP INDEX IF EXISTS ${quoteIdentifier(index.name)}`);
      await client.unsafe(`CREATE ${unique}INDEX IF NOT EXISTS ${quoteIdentifier(index.name)} ON ONLY ${quoteIdentifier(index.table)} ${index.body}`);
    });
  };
  if (await valid()) return 'valid';
  const [child] = await client.unsafe<{ child: string; day: string }[]>(`
    SELECT c.relname::text AS child, t.relname::text AS day
      FROM pg_inherits h JOIN pg_class c ON c.oid = h.inhrelid JOIN pg_index i ON i.indexrelid = c.oid JOIN pg_class t ON t.oid = i.indrelid
     WHERE h.inhparent = to_regclass($1) LIMIT 1`, [name]);
  // No day left: made again over none, the parent is valid.
  if (child === undefined) {
    await remake();
    return 'look';
  }
  await session.waitShort();
  try {
    await session.briefly(() => client.unsafe(`ALTER INDEX ${quoteIdentifier(index.name)} ATTACH PARTITION ${quoteIdentifier(child.child)}`));
  } catch (error) {
    // Retention detached or dropped that day meanwhile: the next pass looks again.
    if (!(await partOf(client, child.day, index.table))) return 'look';
    throw error;
  }
  if (await valid()) return 'valid';
  if (remade) throw new StillInvalid(`index ${index.name} on ${index.table} was left invalid by a day retention detached as it was built, twice`);
  await remake();
  return 'remade';
}

/** Whether `day` is still a partition of `table`: retention detaches a day a run before it drops it. */
async function partOf(client: OnlineSession['client'], day: string, table: string): Promise<boolean> {
  const [row] = await client.unsafe<{ held: boolean }[]>(
    'SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = to_regclass($1) AND inhparent = to_regclass($2)) AS held',
    [`public.${quoteIdentifier(day)}`, `public.${quoteIdentifier(table)}`],
  );
  return row?.held === true;
}

/** A day's own index, named as Postgres names one it makes for an attached day: `log_uses_number_idx` on `log_uses_20261109` is `log_uses_20261109_number_idx`. */
function dayIndexName(index: OnlineIndex, day: string): string {
  const suffix = index.name.startsWith(`${index.table}_`) ? index.name.slice(index.table.length + 1) : index.name;
  const name = `${day}_${suffix}`;
  if (Buffer.byteLength(name) > NAME_BYTES) throw new Error(`index name ${name} is longer than Postgres keeps`);
  return name;
}

/** Whether index `name` is there and valid: built, and on a partitioned table, on every day. */
export async function valid(client: OnlineSession['client'], name: string): Promise<boolean> {
  const [found] = await client.unsafe<{ valid: boolean }[]>('SELECT i.indisvalid AS valid FROM pg_index i WHERE i.indexrelid = to_regclass($1)', [`public.${quoteIdentifier(name)}`]);
  return found?.valid === true;
}

/** `create`, a concurrent build of index `name`, unless it is built; an invalid one, a build cut short, dropped first. */
async function concurrently(session: OnlineSession, name: string, create: string): Promise<void> {
  const { client } = session;
  const [found] = await client.unsafe<{ valid: boolean }[]>('SELECT i.indisvalid AS valid FROM pg_index i WHERE i.indexrelid = to_regclass($1)', [`public.${quoteIdentifier(name)}`]);
  if (found?.valid === true) return;
  await session.waitLong();
  if (found !== undefined) await client.unsafe(`DROP INDEX CONCURRENTLY IF EXISTS ${quoteIdentifier(name)}`);
  await client.unsafe(create);
}

/** Why a build gave up, for the run's report, or null for a failure that is coffre's to fix, which throws. */
export function unbuiltReason(error: unknown): string | null {
  if (lockNotAvailable(error)) return 'it waited too long for the transactions before it (a backup, a session left open) to end';
  if ((error as { code?: string }).code === '57014') return 'its build was cancelled';
  if (error instanceof StillInvalid) return 'retention detached a day while it was built';
  return null;
}

/** What a run that left indexes unbuilt says, for whoever migrates; null when it built them all. */
export function unbuiltNote(unbuilt: readonly UnbuiltIndex[]): string | null {
  if (unbuilt.length === 0) return null;
  const one = unbuilt.length === 1;
  const names = unbuilt.map(({ name, table }) => `${name} on ${table}`).join(', ');
  const reasons = [...new Set(unbuilt.map(({ reason }) => reason))].join('; ');
  return `${one ? 'An index is' : `${unbuilt.length} indexes are`} not built yet (${names}): ${reasons}. coffre works without ${one ? 'it' : 'them'}, slower on a large log; migrate again to build ${one ? 'it' : 'them'}, which holds up no write`;
}
