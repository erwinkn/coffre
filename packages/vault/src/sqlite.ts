/** What a parameter may be: the types both backends bind as they are. */
export type SqlValue = string | number | null;

/**
 * The SQLite the vault's store runs on: a Durable Object's own database on
 * Workers (`sqlite-durable-object.ts`), a file of the vault's own on Node
 * (`sqlite-node.ts`). Synchronous, so a decision's reads and writes run with
 * nothing in between, and one statement per call: neither backend runs the
 * rest of a string the same way, so neither is asked to.
 */
export interface Sqlite {
  run(sql: string, ...params: SqlValue[]): void;
  get<T>(sql: string, ...params: SqlValue[]): T | undefined;
  all<T>(sql: string, ...params: SqlValue[]): T[];
  /** Rows one at a time, for reads too long to hold at once. */
  iterate<T>(sql: string, ...params: SqlValue[]): Iterable<T>;
  /** `fn` atomically: all its writes or, when it throws, none. Transactions do not nest. */
  transaction<T>(fn: () => T): T;
}
