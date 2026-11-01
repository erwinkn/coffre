import { randomBytes, randomUUID } from 'node:crypto';

import type { Database } from '@coffre/db';
import { sql, type SQL } from 'drizzle-orm';

import { entryMac } from '../src/log-entry.ts';
import { ENGINE, rows, run } from './database.ts';

/**
 * 0.15's entries as the change and use paths write them (plans PR 4 and
 * 5), for the checkpointer's tests: numbered from the sequence on Postgres,
 * in the insert and under the fence shared, as `use_credential` and
 * `change_input` number theirs (a number taken before the fence could land
 * after a barrier that counted it, past the pair that closed over it);
 * after every number taken on SQLite. MAC'd over their tree and every
 * column but the number (log-entry.ts).
 */
export function logWriter(owner: Database, macKey: Buffer) {
  let sqliteNext = 1n;
  /** The entry `insert` makes, given its number's SQL: one transaction, a file's turn on SQLite, the fence on Postgres. */
  const append = async (insert: (number: SQL) => SQL): Promise<bigint> => {
    if (ENGINE === 'sqlite') {
      // Each write a transaction, so that it waits its turn in the file's queue (connect.ts) behind the checkpointer's;
      // numbered in it, after every number taken, the store's own included (a retention change, say).
      return owner.transaction(async (tx) => {
        const [row] = await rows<{ n: string }>(tx, sql`SELECT CAST(max(coalesce((SELECT max(number) FROM log_changes), 0), coalesce((SELECT max(number) FROM log_uses), 0)) AS TEXT) AS n`);
        if (BigInt(row!.n) >= sqliteNext) sqliteNext = BigInt(row!.n) + 1n;
        const number = sqliteNext++;
        await run(tx, insert(sql`${number}`));
        return number;
      });
    }
    return owner.transaction(async (tx) => {
      await run(tx, sql`SELECT pg_advisory_xact_lock_shared(1668244070, 0)`);
      const [row] = await rows<{ n: string }>(tx, sql`${insert(sql`nextval('log_number')`)} RETURNING number::text AS n`);
      return BigInt(row!.n);
    });
  };
  return {
    /** Every entry, pair and tile gone, the floor at now less the deadline, as a new log. */
    async empty(): Promise<void> {
      for (const table of ['log_checkpoints', 'log_tiles', 'log_changes', 'log_uses']) await run(owner, sql.raw(`DELETE FROM ${table}`));
      // The reads' projection of that log (T166), its cursor back at the start.
      await run(owner, sql`DELETE FROM log_reads`);
      await run(owner, sql`DELETE FROM log_read_days`);
      await run(owner, sql`INSERT INTO log_reads_cursor (only_row, through, pair, at, mac) VALUES (true, 0, 0, 0, NULL) ON CONFLICT (only_row) DO UPDATE SET through = 0, pair = 0, at = 0, mac = NULL`);
      await run(owner, sql`UPDATE log_fence SET at_floor = ${Date.now() - 3000}`);
      sqliteNext = 1n;
    },
    /** Today's and tomorrow's uses (Postgres partitions them by day). */
    async days(): Promise<void> {
      if (ENGINE !== 'postgres') return;
      const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
      await run(owner, sql`SELECT make_day(${day(Date.now())}::date), make_day(${day(Date.now() + 86_400_000)}::date)`);
    },
    async change(payload = '{"op":"genesis"}', at = Date.now(), object: string = randomUUID()): Promise<bigint> {
      const row = { at, requestId: `c-${randomUUID()}`, object, actor: 'vault', payload, seal: randomBytes(16) };
      const mac = entryMac(macKey, { tree: 'changes', row });
      return append((number) => sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (${number}, ${row.at}, ${row.requestId}, ${row.object}, ${row.actor}, ${row.payload}, ${row.seal}, ${mac})`);
    },
    async use(at = Date.now(), forged = false): Promise<bigint> {
      const row = { at, requestId: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
      const mac = forged ? randomBytes(16) : entryMac(macKey, { tree: 'uses', row });
      return append((number) => sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
        VALUES (${number}, ${row.at}, ${row.requestId}, ${row.credential}, ${row.secret}, ${row.purpose}, ${mac}, ${row.place})`);
    },
  };
}
