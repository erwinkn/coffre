/**
 * Work to do once a transaction has committed, and never if it rolls back.
 *
 * Drizzle has no such hook, so every database this package opens has its
 * `transaction` wrapped (`trackCommits`): it gives each transaction a list,
 * runs the list after COMMIT returns, and drops it on a rollback. A nested
 * transaction, a savepoint, hands its list to the one around it when it is
 * released, so nothing runs before the outermost commit.
 *
 * The log's append uses it to remember the head it wrote only once that
 * head is in the database (log.ts).
 */

type Pending = (() => void)[];

/** What anything that opens transactions looks like, a database or a transaction. */
type Transactional = { transaction: (...args: never[]) => Promise<unknown> };

const pending = new WeakMap<object, Pending>();

/**
 * Run `then` once `tx` has committed, all the way out. Returns false, and
 * never runs it, for a transaction this package did not open.
 */
export function afterCommit(tx: object, then: () => void): boolean {
  const list = pending.get(tx);
  if (list === undefined) return false;
  list.push(then);
  return true;
}

/** `db`, its transactions tracked for `afterCommit`. */
export function trackCommits<T extends Transactional>(db: T, outer: Pending | null = null): T {
  const run = db.transaction.bind(db) as (work: (tx: Transactional) => Promise<unknown>, ...rest: unknown[]) => Promise<unknown>;
  const transaction = async (work: (tx: Transactional) => Promise<unknown>, ...rest: unknown[]) => {
    const list: Pending = [];
    const result = await run((tx) => {
      pending.set(tx, list);
      return work(trackCommits(tx, list));
    }, ...rest);
    if (outer !== null) outer.push(...list);
    else for (const then of list) then();
    return result;
  };
  db.transaction = transaction as T['transaction'];
  return db;
}
