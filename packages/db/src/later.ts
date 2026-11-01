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
 * where the transaction would not hear it. It is built when called, and
 * started a microtask later, as Drizzle starts a statement it is asked
 * for: a group goes in the order its statements were started.
 */
export function later(tx: Transaction, statement: SQLWrapper): void {
  if (engineOf(tx) === 'sqlite') {
    // Through `tx`, whatever database a builder was made on (one made outside the transaction would wait for it, which
    // waits for it), with libsql's Drizzle's `run`, started now by its `then`, so each goes in the order `later` was
    // called (`run` runs again each time it is awaited, so once, here).
    const answer = (tx as unknown as { run(query: SQLWrapper): PromiseLike<unknown> }).run(statement).then((result) => result) as Promise<unknown>;
    return hold(tx, answer);
  }
  const { sql, params } = (tx as unknown as { dialect: PgDialect }).dialect.sqlToQuery(statement.getSQL());
  // The transaction's own statement, built now: a value it cannot send throws here, to the work; what it fails with once
  // sent, the transaction hears (`inTransaction`), and fails with.
  const query = (clientOf(tx) as { unsafe(text: string, values: unknown[]): { later: boolean; execute(): unknown } }).unsafe(sql, params);
  // Nothing awaits it: the COMMIT may go with it (`settleWithCommit`).
  query.later = true;
  // Started a microtask later, as Drizzle starts a statement it awaits (`await client.unsafe(…)`): so the order it goes
  // in among them (`Query.made`) is the order they were asked in, the head's lock `lockLogHeadRead` starts first included.
  // Not returned from the callback: its failure is the transaction's to hear (`inTransaction`), not this promise's.
  void Promise.resolve().then(() => {
    query.execute();
  });
}

/** postgres.js's transaction under Drizzle's. */
function clientOf(tx: Transaction): object {
  return (tx as unknown as { session: { client: object } }).session.client;
}

/**
 * On SQLite, by Drizzle's transaction or savepoint: the writes asked of it with `later`, which its work answers for
 * once it returns (`laterSettled`, called by `trackCommits`), before its COMMIT or its savepoint's release.
 */
const held = new WeakMap<object, Promise<unknown>[]>();

function hold(tx: object, answer: Promise<unknown>): void {
  // Handled here, and failed again as the work returns: never an unhandled rejection meanwhile.
  answer.catch(() => {});
  const list = held.get(tx);
  if (list === undefined) held.set(tx, [answer]);
  else list.push(answer);
}

/**
 * A transaction's or savepoint's work returned: every write `later` asked of it has answered, or the first that failed
 * throws, which rolls it back. One whose work failed drops them (`laterDropped`): rolled back with it, a failure among
 * them is the rollback's, not the transaction around it. Nothing on Postgres, whose COMMIT rides with them.
 */
export async function laterSettled(tx: object): Promise<void> {
  const list = held.get(tx);
  if (list === undefined) return;
  held.delete(tx);
  for (const outcome of await Promise.allSettled(list)) if (outcome.status === 'rejected') throw outcome.reason;
}

/** A transaction's or savepoint's work failed: what `later` asked of it goes with its rollback. */
export function laterDropped(tx: object): void {
  held.delete(tx);
}
