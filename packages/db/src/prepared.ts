import type { Query } from 'drizzle-orm';

import { tablesOf, type Queryable } from './database.ts';
import { engineOf } from './dialect.ts';

/** What Drizzle works out from a select builder before it can run it, once per dialect. */
type Built = { query: Query; fields: unknown; joinsNotNullableMap: unknown; engine: 'postgres' | 'sqlite' };

/** The part of a select builder `prepared` reads, once. */
type Select = PromiseLike<unknown> & { toSQL(): Query; prepare(...name: never[]): unknown };

/**
 * A select built once per process, or once per isolate on Workers, and run
 * with new values each time. Drizzle rebuilds a query's SQL from its
 * builder at every run, and that was most of a short query's CPU; this
 * builds it from `build` the first time a database of its dialect asks,
 * then hands the SQL and its columns to that call's own session
 * (`session.prepareQuery`), which binds `values` to the placeholders
 * (`sql.placeholder`) and maps the rows as the builder would.
 *
 * `build` must not depend on anything but the database's dialect, and the
 * values go to the driver as they are, not through a column's encoding:
 * strings, numbers, bigints and bytes.
 *
 *   const member = prepared((db) => db.select().from(tablesOf(db).vaultMembers).where(eq(…, sql.placeholder('principal'))));
 *   const [row] = await member(db, { principal });
 */
export function prepared<Q extends Select>(
  build: (db: Queryable) => Q,
): (db: Queryable, values?: Record<string, unknown>) => Promise<Awaited<Q>> {
  // By the dialect's tables: one Postgres build, one SQLite build.
  const builds = new WeakMap<object, Built>();
  return (db, values = {}) => {
    const tables = tablesOf(db);
    let built = builds.get(tables);
    if (built === undefined) {
      const builder = build(db);
      // Drizzle's own preparation, which runs nothing, says which columns come back and which joins may be null.
      // Unnamed on Postgres: no statement is prepared on the server, whose connections a call does not keep.
      const { fields, joinsNotNullableMap } = (builder as unknown as { prepare(): { fields: unknown; joinsNotNullableMap: unknown } }).prepare();
      built = { query: builder.toSQL(), fields, joinsNotNullableMap, engine: engineOf(db) };
      builds.set(tables, built);
    }
    const session = (db as unknown as { session: Session }).session;
    const query = built.engine === 'sqlite'
      ? session.prepareQuery(built.query, built.fields, 'all', true)
      : session.prepareQuery(built.query, built.fields, undefined, true);
    query.joinsNotNullableMap = built.joinsNotNullableMap;
    return (built.engine === 'sqlite' ? query.all(values) : query.execute(values)) as Promise<Awaited<Q>>;
  };
}

/** Drizzle's session, Postgres's or SQLite's, as `prepared` calls it. */
type Session = {
  prepareQuery(query: Query, fields: unknown, nameOrMethod: string | undefined, isResponseInArrayMode: boolean): {
    joinsNotNullableMap: unknown;
    execute(values: Record<string, unknown>): Promise<unknown>;
    all(values: Record<string, unknown>): Promise<unknown>;
  };
};
