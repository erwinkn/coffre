import type { SQLWrapper } from 'drizzle-orm';
import type { PgDialect } from 'drizzle-orm/pg-core';

import type { Transaction } from './database.ts';
import { engineOf } from './dialect.ts';

/**
 * A write of a transaction's whose answer its work does not need: asked now,
 * and not waited for. On Postgres it goes with the statements asked beside it,
 * at the latest with the transaction's COMMIT, under one Sync, a round trip
 * less on Hyperdrive (postgres-js/index.ts, `gather`); if it fails, Postgres
 * skips the COMMIT and the transaction fails with its error, rolled back. On
 * SQLite it runs in its turn, and the transaction's COMMIT waits for it,
 * failing as it did (`laterSettled`, connect.ts).
 *
 *   audited(ctx, async (tx, log) => {
 *     const [row, refs] = await Promise.all([read(tx), refsOf(tx)]);   BEGIN, the head, both reads: one Sync
 *     later(tx, tx.update(secrets).set(…).where(…));
 *     log.push(allowed(ctx, 'secret.write', …));                        the update, the append, COMMIT: one Sync
 *   });
 *
 * On Postgres the statement goes straight to the transaction's connection,
 * as Drizzle writes it (`sqlToQuery`), so that nothing between them can fail
 * where the transaction would not hear it.
 */
export function later(tx: Transaction, statement: SQLWrapper): void {
  if (engineOf(tx) === 'sqlite') {
    // A query builder runs itself; a statement of `sql`, through libsql's Drizzle's `run`.
    const builder = statement as unknown as { execute?: () => Promise<unknown> };
    // Once: Drizzle's `run` answers a statement that runs again each time it is awaited.
    const answer = Promise.resolve(typeof builder.execute === 'function' ? builder.execute() : (tx as unknown as { run(query: SQLWrapper): PromiseLike<unknown> }).run(statement));
    return hold((tx as unknown as { session: { tx: object } }).session.tx, answer);
  }
  const { sql, params } = (tx as unknown as { dialect: PgDialect }).dialect.sqlToQuery(statement.getSQL());
  const client = clientOf(tx) as { unsafe(text: string, values: unknown[]): { later: boolean; execute(): unknown } };
  // Made a microtask later, as Drizzle makes a statement once it is awaited: so it goes behind what was asked before it,
  // the head's lock `audited` asks ahead of a work whose first statement this is (postgres-js's `flush`, by `made`).
  queueMicrotask(() => {
    // The transaction's own statement: what it fails with, the transaction hears (`inTransaction`), and fails with.
    const query = client.unsafe(sql, params);
    // Nothing awaits it: the COMMIT may go with it (`settleWithCommit`).
    query.later = true;
    query.execute();
  });
}

/** postgres.js's transaction under Drizzle's. */
function clientOf(tx: Transaction): object {
  return (tx as unknown as { session: { client: object } }).session.client;
}

/** On SQLite, by its libsql transaction: the writes asked of it with `later`, which its COMMIT waits for. */
const held = new WeakMap<object, Promise<unknown>[]>();

function hold(client: object, answer: Promise<unknown>): void {
  // Handled here, and failed again at the COMMIT: never an unhandled rejection meanwhile.
  answer.catch(() => {});
  const list = held.get(client);
  if (list === undefined) held.set(client, [answer]);
  else list.push(answer);
}

/** Before a SQLite transaction commits: every write `later` asked of it has answered, or the first that failed throws. */
export async function laterSettled(client: object): Promise<void> {
  const list = held.get(client);
  if (list === undefined) return;
  held.delete(client);
  for (const outcome of await Promise.allSettled(list)) if (outcome.status === 'rejected') throw outcome.reason;
}
