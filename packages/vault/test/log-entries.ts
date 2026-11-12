import { randomBytes, randomUUID } from 'node:crypto';

import type { Database } from '@coffre/db';
import { sql, type SQL } from 'drizzle-orm';

import { entryMac, type LogMacKey, type UseRow } from '../src/log-entry.ts';
import { rows, run } from './database.ts';

/**
 * 0.15's entries as the change and use paths write them (plans PR 4 and
 * 5), for the checkpointer's tests: numbered from the sequence, in the
 * insert and under the fence shared, as `use_credential` and
 * `change_input` number theirs (a number taken before the fence could land
 * after a barrier that counted it, past the pair that closed over it).
 * MAC'd over their tree and every column but the number (log-entry.ts).
 */
export function logWriter(owner: Database, macKey: LogMacKey) {
  /** The entry `insert` makes, given its number's SQL: one transaction, the fence. */
  const append = async (insert: (number: SQL) => SQL): Promise<bigint> => {
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
      await run(owner, sql`DELETE FROM log_read_place_days`);
      await run(owner, sql`INSERT INTO log_reads_cursor (only_row, through, pair, at, mac) VALUES (true, 0, 0, 0, NULL) ON CONFLICT (only_row) DO UPDATE SET through = 0, pair = 0, at = 0, mac = NULL`);
      await run(owner, sql`UPDATE checkpoint_fence SET at_floor = ${Date.now() - 3000}, retired = '{}'`);
    },
    /** Today's and tomorrow's uses (Postgres partitions them by day). */
    async days(): Promise<void> {
      const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
      await run(owner, sql`SELECT make_day(${day(Date.now())}::date), make_day(${day(Date.now() + 86_400_000)}::date)`);
    },
    async change(payload = '{"op":"genesis"}', at = Date.now(), object: string = randomUUID()): Promise<bigint> {
      const row = { at, requestId: `c-${randomUUID()}`, object, actor: 'vault', payload, seal: randomBytes(16) };
      const mac = entryMac(macKey, { tree: 'changes', row });
      return append((number) => sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (${number}, ${row.at}, ${row.requestId}, ${row.object}, ${row.actor}, ${row.payload}, ${row.seal}, ${mac})`);
    },
    /**
     * `n` uses stamped now, 1,000 a statement, under the fence as one: for a log grown to size (the verifier's cost
     * test and bench).
     */
    async uses(n: number): Promise<void> {
      for (let done = 0; done < n; done += 1000) {
        const batch = Array.from({ length: Math.min(1000, n - done) }, () => {
          const row = { at: Date.now(), requestId: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
          return sql`(nextval('log_number'), ${row.at}, ${row.requestId}, ${row.credential}, ${row.secret}, ${row.purpose}, ${entryMac(macKey, { tree: 'uses', row })}, NULL)`;
        });
        await owner.transaction(async (tx) => {
          await run(tx, sql`SELECT pg_advisory_xact_lock_shared(1668244070, 0)`);
          await run(tx, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place) VALUES ${sql.join(batch, sql`, `)}`);
        });
      }
    },
    /** `forged`: a random MAC, or the one `forged` makes of the row's columns (another key's, say). */
    async use(at = Date.now(), forged: boolean | ((row: Omit<UseRow, 'number' | 'mac'>) => Buffer) = false): Promise<bigint> {
      const row = { at, requestId: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
      const mac = typeof forged === 'function' ? forged(row) : forged ? randomBytes(16) : entryMac(macKey, { tree: 'uses', row });
      return append((number) => sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
        VALUES (${number}, ${row.at}, ${row.requestId}, ${row.credential}, ${row.secret}, ${row.purpose}, ${mac}, ${row.place})`);
    },
  };
}
