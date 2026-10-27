import type { Client } from '@coffre/db';
import { postgresClient, type PostgresClient } from '@coffre/db/connect';

/** Bound broken connections and blocked SQL in tests, including the vault's pool; `allowExitOnIdle` closes it once idle. */
export function testPostgresPool(connectionString: string, allowExitOnIdle = false): PostgresClient {
  return postgresClient(connectionString, {
    connect_timeout: 5,
    idle_timeout: allowExitOnIdle ? 1 : 10,
    connection: { statement_timeout: 10_000 },
  });
}

/**
 * A statement a client ran, as it was sent: the rows it answered, the rows
 * it read or changed (node-postgres's `rowCount`), whether a transaction
 * held it, and how long it took.
 */
export type Sent = { text: string; values: unknown[]; rows: number; count: number; held: boolean; ms: number };

type Answer = PromiseLike<unknown> & { then: PromiseLike<unknown>['then']; execute?: () => unknown };

/** What postgres.js sends of a transaction's own: its BEGIN, COMMIT or ROLLBACK, and its savepoints. */
const TRANSACTION = /^\s*(begin|commit|rollback|savepoint|release\s+savepoint|prepare\s+transaction)\b/i;

/**
 * `client`, telling `heard` of each statement it runs, once answered or
 * failed. Drizzle's statements go through `unsafe`. A transaction's BEGIN,
 * COMMIT or ROLLBACK, and its savepoints, postgres.js sends itself: a
 * postgres.js client's `debug` hook hears them as it sends them, a COMMIT
 * that fails included. A client without one (`HyperdrivePool`, which makes
 * one per call) has them inferred: BEGIN with a transaction's first
 * statement, which carries it, and its end once it has one; a transaction
 * that asks nothing sends nothing.
 */
export function watched<C extends Client>(client: C, heard: (sent: Sent) => void): C {
  const statement = (text: string) => heard({ text, values: [], rows: 0, count: 0, held: true, ms: 0 });
  const options = (client as { options?: { debug?: unknown } }).options;
  const hooked = options !== undefined;
  if (hooked) {
    const before = options.debug;
    options.debug = (connection: number, text: string, ...rest: unknown[]) => {
      if (typeof before === 'function') before(connection, text, ...rest);
      if (TRANSACTION.test(text)) statement(text.trim().replace(/\s+/g, ' '));
    };
  }
  /** `first`: told as the transaction it watches asks its first statement, which carries its BEGIN. */
  const watch = <T extends object>(target: T, held: boolean, first?: () => void): T =>
    new Proxy(target, {
      get(on, key) {
        const value: unknown = Reflect.get(on, key, on);
        if (typeof value !== 'function') return value;
        if (key === 'unsafe') {
          return (text: string, values: unknown[] = [], ...rest: unknown[]) => {
            first?.();
            const query = (value as (...args: unknown[]) => Answer).call(on, text, values, ...rest);
            // Heard through the hook, as postgres.js sends it.
            if (hooked && TRANSACTION.test(text)) return query;
            const then = query.then.bind(query);
            const started = performance.now();
            // Once: postgres.js's transaction attaches a `catch` of its own to each of its statements, a second `then`.
            let told = false;
            const hear = (rows: number, count: number) => {
              if (told) return;
              told = true;
              heard({ text, values, rows, count, held, ms: performance.now() - started });
            };
            query.then = ((resolve, reject) =>
              then(
                (answer) => {
                  const rows = Array.isArray(answer) ? answer.length : 0;
                  hear(rows, (answer as { count?: number | null }).count ?? rows);
                  return answer;
                },
                (error: unknown) => {
                  hear(0, 0);
                  throw error;
                },
              ).then(resolve, reject)) as Answer['then'];
            // Started by `execute()` and never awaited, it is heard all the same; `catch` and `finally` go through `then`.
            const execute = query.execute?.bind(query);
            if (execute !== undefined) {
              query.execute = () => {
                execute();
                void query.then(() => {}, () => {});
                return query;
              };
            }
            return query;
          };
        }
        if (key === 'begin' || key === 'savepoint') {
          return (...args: unknown[]) => {
            const work = args.pop() as (tx: object) => unknown;
            const options = typeof args[0] === 'string' ? args[0] : '';
            let asked = false;
            const begun = key === 'begin'
              ? () => {
                if (asked) return;
                asked = true;
                statement(`begin ${options}`.trim());
              }
              : first;
            if (!hooked && key === 'savepoint') {
              begun?.();
              statement('savepoint');
            }
            const run = (value as (...beginArgs: unknown[]) => Promise<unknown>).call(on, ...args, (tx: object) => work(watch(tx, true, begun)));
            if (hooked) return run;
            return run.then(
              (result) => {
                if (key === 'begin' && asked) statement('commit');
                return result;
              },
              (error: unknown) => {
                if (key === 'savepoint' || asked) statement(key === 'begin' ? 'rollback' : 'rollback to savepoint');
                throw error;
              },
            );
          };
        }
        return (value as (...args: unknown[]) => unknown).bind(on);
      },
    });
  return watch(client, false);
}

/** A client that answers every statement with `answer`'s rows, reaching no server, and opens no transaction. */
export function answering(answer: (text: string, values: unknown[]) => Record<string, unknown>[] = () => []): Client {
  const unsafe = (text: string, values: unknown[] = []) => {
    let asArrays = false;
    const statement = {
      values: () => {
        asArrays = true;
        return statement;
      },
      then: (resolve: (rows: unknown) => unknown, reject: (error: unknown) => unknown) =>
        Promise.resolve()
          .then(() => {
            const rows = answer(text, values);
            return Object.assign(asArrays ? rows.map((row) => Object.values(row)) : rows, { count: rows.length });
          })
          .then(resolve, reject),
    };
    return statement;
  };
  const begin = async () => {
    throw new Error('no transaction here');
  };
  return { unsafe, begin } as unknown as Client;
}
