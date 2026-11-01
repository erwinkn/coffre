// The Worker `hyperdrive-pinning.ts` deploys behind a throwaway Hyperdrive: each request runs transactions of every
// shape coffre sends, through `HyperdrivePool` as a Worker of coffre's does, and says whether each one's statements
// all ran on one backend, in one transaction, and kept exactly what it committed. The driver alone, no Drizzle: what
// reaches Hyperdrive is the driver's (a write left to `later` is a statement marked `later`, as `later` marks it), and
// the bundle stays small enough to upload through an API call. See the script for how to run it.
import { HyperdrivePool } from '../src/hyperdrive.ts';

type Env = { HYPERDRIVE: { connectionString: string } };
type Statement = Promise<Record<string, unknown>[]> & { later: boolean; execute(): unknown };
type Sql = { unsafe(text: string, values?: unknown[]): Statement };

/** Where a statement ran: its backend and its transaction's id. */
type Where = { pid: number; xid: string };

/** One transaction's outcome: its shape, whether it held, and why not. */
export type Outcome = { shape: string; ok: boolean; pid: number | null; why?: string };

const HERE = 'SELECT pg_backend_pid() AS pid, txid_current()::text AS xid';

async function here(tx: Sql, n?: number): Promise<Where> {
  const [row] = await (n === undefined ? tx.unsafe(HERE) : tx.unsafe(`${HERE}, $1::int AS n`, [n]));
  return { pid: Number(row!.pid), xid: String(row!.xid) };
}

/** Each statement's backend and transaction alike: one backend, one transaction. */
function alike(shape: string, seen: Where[]): Outcome {
  const [first] = seen;
  const ok = first !== undefined && seen.every((where) => where.pid === first.pid && where.xid === first.xid);
  return { shape, ok, pid: first?.pid ?? null, ...(ok ? {} : { why: JSON.stringify(seen) }) };
}

/** The rows a transaction tagged `tag` kept, by backend and transaction. */
async function kept(pool: HyperdrivePool, tag: string): Promise<Where[]> {
  const rows = (await pool.unsafe('SELECT pid, xid FROM coffre_pinning WHERE tag = $1 ORDER BY n', [tag])) as unknown as Record<string, unknown>[];
  return rows.map((row) => ({ pid: Number(row.pid), xid: String(row.xid) }));
}

const TAGGED = 'INSERT INTO coffre_pinning (tag, n, pid, xid) VALUES ($1, $2, pg_backend_pid(), txid_current()::text)';

/** A write nothing awaits, as `later` (@coffre/db) sends one: it goes with the COMMIT. */
function later(tx: Sql, text: string, values: unknown[]): void {
  const query = tx.unsafe(text, values);
  query.later = true;
  query.execute();
}

function begin<T>(pool: HyperdrivePool, work: (tx: Sql) => Promise<T>): Promise<T> {
  return (pool.begin as unknown as (work: (tx: Sql) => Promise<T>) => Promise<T>)(work);
}

async function failed(shape: string, pool: HyperdrivePool, tag: string, work: (tx: Sql) => Promise<void>): Promise<Outcome> {
  const refused = await begin(pool, work).then(() => false, () => true);
  const rows = await kept(pool, tag);
  const ok = refused && rows.length === 0;
  return { shape, ok, pid: null, ...(ok ? {} : { why: `refused ${refused}, kept ${rows.length} rows` }) };
}

/** Each shape, run once on `pool`. */
const SHAPES: Record<string, (pool: HyperdrivePool, tag: string) => Promise<Outcome>> = {
  // 0.15's: the first statement with a parameter, then another.
  'first with a parameter': async (pool) => alike('first with a parameter', await begin(pool, async (tx) => [await here(tx, 1), await here(tx)])),
  // Without one: one Query message, `begin;\n<statement>`.
  'first without a parameter': async (pool) => alike('first without a parameter', await begin(pool, async (tx) => [await here(tx), await here(tx, 2)])),
  // The vault's: SET LOCAL first.
  'after SET LOCAL': async (pool) => alike('after SET LOCAL', await begin(pool, async (tx) => {
    await tx.unsafe('SET LOCAL lock_timeout = 5000');
    return [await here(tx), await here(tx, 3)];
  })),
  // T179's: BEGIN with a group of three, then a statement alone.
  'BEGIN with a group': async (pool) => alike('BEGIN with a group', await begin(pool, async (tx) => [
    ...(await Promise.all([here(tx, 4), here(tx), here(tx, 5)])),
    await here(tx),
  ])),
  // T179's, the vault's decision as it opens: SET LOCAL, a row locked, a read, in one group behind BEGIN.
  'SET LOCAL in a group': async (pool) => alike('SET LOCAL in a group', await begin(pool, async (tx) => {
    const [, [locked], read] = await Promise.all([
      tx.unsafe('SET LOCAL lock_timeout = 5000'),
      tx.unsafe(`${HERE} FROM coffre_pinning_lock WHERE id = $1 FOR SHARE`, [1]),
      here(tx, 7),
    ]);
    return [{ pid: Number(locked!.pid), xid: String(locked!.xid) }, read, await here(tx)];
  })),
  // T179's: reads together, then writes nothing awaits, which go with the COMMIT under one Sync: kept, each on the
  // reads' backend and in their transaction.
  'writes with the COMMIT': async (pool, tag) => {
    const read = await begin(pool, async (tx) => {
      const seen = await Promise.all([here(tx), here(tx, 6)]);
      later(tx, TAGGED, [tag, 1]);
      later(tx, TAGGED, [tag, 2]);
      return seen;
    });
    const rows = await kept(pool, tag);
    if (rows.length !== 2) return { shape: 'writes with the COMMIT', ok: false, pid: read[0]!.pid, why: `kept ${rows.length} rows, not 2` };
    return alike('writes with the COMMIT', [...read, ...rows]);
  },
  // A group of which one fails: nothing of it kept, the write before the failure included.
  'a group that fails': async (pool, tag) => failed('a group that fails', pool, tag, async (tx) => {
    await Promise.allSettled([here(tx), tx.unsafe(TAGGED, [tag, 1]), tx.unsafe('SELECT 1 / $1::int', [0])]);
  }),
  // A write left to the COMMIT that fails: the COMMIT skipped, nothing kept.
  'a write with the COMMIT that fails': async (pool, tag) => failed('a write with the COMMIT that fails', pool, tag, async (tx) => {
    await here(tx);
    later(tx, TAGGED, [tag, 1]);
    later(tx, "INSERT INTO coffre_pinning (tag, n, pid, xid) VALUES ($1, $2::int, 0, '0')", [tag, 'two']);
  }),
  // Work that throws after a write: rolled back.
  'a rollback': async (pool, tag) => failed('a rollback', pool, tag, async (tx) => {
    await tx.unsafe(TAGGED, [tag, 1]);
    throw new Error('rolled back');
  }),
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pool = new HyperdrivePool(env.HYPERDRIVE.connectionString, { groupReads: true });
    try {
      if (url.pathname === '/setup') {
        await pool.unsafe('CREATE TABLE IF NOT EXISTS coffre_pinning (tag text NOT NULL, n int NOT NULL, pid int NOT NULL, xid text NOT NULL)');
        await pool.unsafe('TRUNCATE coffre_pinning');
        await pool.unsafe('CREATE TABLE IF NOT EXISTS coffre_pinning_lock (id int PRIMARY KEY)');
        await pool.unsafe('INSERT INTO coffre_pinning_lock VALUES (1) ON CONFLICT DO NOTHING');
        return Response.json({ ok: true });
      }
      if (url.pathname !== '/run') return new Response('not found', { status: 404 });
      // `n` transactions, each shape in turn from `from`, one after another on this call's one connection.
      const n = Number(url.searchParams.get('n') ?? '20');
      const from = Number(url.searchParams.get('from') ?? '0');
      const names = Object.keys(SHAPES);
      const outcomes: Outcome[] = [];
      for (let i = 0; i < n; i += 1) {
        const name = names[(from + i) % names.length]!;
        const tag = `${url.searchParams.get('run') ?? 'run'}-${from + i}`;
        outcomes.push(await SHAPES[name]!(pool, tag).catch((error: unknown) => ({ shape: name, ok: false, pid: null, why: String(error) })));
      }
      return Response.json({ outcomes });
    } finally {
      await pool.end();
    }
  },
};
