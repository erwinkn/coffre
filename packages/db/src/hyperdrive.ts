import type { Client } from './database.ts';
import { plainRead } from './postgres-js/index.ts';
import { postgresClient, textTypes, type PostgresClient } from './postgres.ts';

/** Postgres through a Hyperdrive binding: `postgres(env.HYPERDRIVE)`. */
export type PostgresDatabase = { readonly engine: 'postgres'; readonly hyperdrive: { readonly connectionString: string } };

/** Postgres through Hyperdrive, the one database a Worker runs on, the app's and the vault's. */
export function postgres(hyperdrive: { readonly connectionString: string }): PostgresDatabase {
  if (typeof hyperdrive?.connectionString !== 'string') {
    throw new Error('postgres() was given no Hyperdrive binding: one the code names (HYPERDRIVE, VAULT_HYPERDRIVE, HOT_HYPERDRIVE) is missing from its wrangler.jsonc, or bound under another name');
  }
  return { engine: 'postgres', hyperdrive };
}

/** A statement asked of the pool, sent at its turn once awaited or `execute`d, as postgres.js sends one. */
type Statement = Promise<unknown> & { values(): Statement; execute(): Statement };

/** A read asked while a group gathers (`groupReads`): sent with the others at its turn, and answered with its own rows. */
type Gathered = { text: string; values: unknown[]; arrays: () => boolean; resolve: (rows: unknown) => void; reject: (error: unknown) => void };


/** What the client refuses to write of a group, before anything of it is sent (`build`, postgres-js/connection.ts). */
const UNSENT = new Set(['GROUP_UNTYPED', 'MAX_PARAMETERS_EXCEEDED', 'UNDEFINED_VALUE']);

/**
 * postgres.js for one call on Workers, through Hyperdrive: one connection,
 * opened by the first query, which every query and transaction of the
 * call takes its turn on.
 *
 * Hyperdrive keeps the pool to the database; a Worker's connections belong
 * to the call that opened them, so each call opens its own. One, not one per
 * query: on Cloudflare, a call that opened several Hyperdrive connections at
 * once was now and then cancelled as hung, with nothing left pending, and
 * every connection costs a round trip before the query can be sent.
 *
 * The turns keep a transaction whole: statements go to the connection in
 * the order they are asked, each once the one before it has answered; a
 * transaction holds the connection from BEGIN until it ends, and a query
 * asked meanwhile waits until then, so nothing runs inside a transaction it
 * is not part of. So code inside a transaction must query through the
 * transaction: a query on the database there would wait for the transaction
 * to end, which waits for it. Neither the vault nor the server does.
 *
 * With `groupReads`, the plain reads (`select …`, outside a transaction)
 * asked while the pool waits for their turn, or in the same task, take it
 * together, sent under one Sync (`group` in postgres-js/index.ts): on
 * Hyperdrive, which sends a client's Syncs on one at a time, a round trip
 * for them all, where each alone took one. They run as one implicit
 * transaction, so if one fails they all do, with its error; each is a
 * read, so none had anything to keep. Anything else asked meanwhile, a
 * write or a transaction, closes the group, and goes after it: statements
 * still go in the order they are asked.
 *
 * Closed by `end`, once what was asked has answered; asked again after, as
 * a call's background work may, it opens a connection again. Unless `end`
 * was given a time to close by and reached it: then the connection closes
 * at once, failing what is still asked, and nothing opens it again.
 */
export class HyperdrivePool implements Client {
  readonly #connectionString: string;
  /** How long the connection may sit idle before it closes, or undefined: closed by `end` alone. */
  readonly #closeIdleMs: number | undefined;
  /** The client, made by the first statement; null before it, and once `end` closed it. */
  #client: PostgresClient | null = null;
  /** The end of the last turn asked: the next one starts once it has. */
  #tail: Promise<unknown> = Promise.resolve();
  /** Turns asked and not done: waiting, or under way. */
  #busy = 0;
  /** What waits for every turn to be done: `end`. */
  readonly #idle: (() => void)[] = [];
  /** Whether plain reads asked together go together (`groupReads`). */
  readonly #groupReads: boolean;
  /** The reads that will take the next group's turn, while it has not started: what a read asked now joins. */
  #gathering: Gathered[] | null = null;
  /** Closed at the time `end` was given, with turns still asked: none opens a connection again. */
  #cut = false;

  /**
   * `closeIdleMs`: for what outlives a call, a Durable Object, which queries
   * now and then: the connection closes once it has been idle that long,
   * and the next query connects again. `groupReads`: plain reads asked
   * together go together, under one Sync.
   */
  constructor(connectionString: string, options: { closeIdleMs?: number; groupReads?: boolean } = {}) {
    if (connectionString.trim().length === 0) {
      throw new Error('Hyperdrive returned an empty connection string');
    }
    this.#connectionString = connectionString;
    this.#closeIdleMs = options.closeIdleMs;
    this.#groupReads = options.groupReads === true;
  }

  readonly unsafe = ((...args: Parameters<PostgresClient['unsafe']>) => {
    let values = false;
    let answer: Promise<unknown> | undefined;
    const [text, parameters = [], options] = args;
    /** Its turn, asked once: the first `then`, `catch`, `finally` or `execute` asks it. */
    const asked = () =>
      (answer ??= this.#groupReads && options === undefined && plainRead(text)
        ? this.#gather({ text, values: parameters, arrays: () => values })
        : this.#turn(() => {
          const query = this.#connected().unsafe(...args);
          return values ? query.values() : query;
        }));
    const statement = {
      values: () => {
        values = true;
        return statement;
      },
      execute: () => {
        void asked().catch(() => {});
        return statement;
      },
      then: (resolve?: (value: unknown) => unknown, reject?: (error: unknown) => unknown) => asked().then(resolve, reject),
      catch: (reject: (error: unknown) => unknown) => asked().catch(reject),
      finally: (done: () => void) => asked().finally(done),
      [Symbol.toStringTag]: 'Statement',
    } as Statement;
    return statement;
  }) as unknown as PostgresClient['unsafe'];

  /** A transaction: its turn lasts until it has committed or rolled back. */
  readonly begin = ((...args: unknown[]) =>
    this.#turn(() => (this.#connected().begin as (...beginArgs: unknown[]) => Promise<unknown>)(...args))) as PostgresClient['begin'];

  /**
   * A read, in the group gathering for the next turn, or in a new one: it
   * starts a task later, so that the reads asked with it join, and once
   * the turns before it are done, which those asked while they ran join.
   */
  #gather(read: Omit<Gathered, 'resolve' | 'reject'>): Promise<unknown> {
    let members = this.#gathering;
    if (members === null) {
      const gathered: Gathered[] = (members = []);
      const asked = new Promise((resolve) => setTimeout(resolve, 0));
      void this.#turn(async () => {
        await asked;
        if (this.#gathering === gathered) this.#gathering = null;
        try {
          const client = this.#connected();
          const alone = async (member: Gathered) => {
            const query = client.unsafe(member.text, member.values);
            member.resolve(await (member.arrays() ? query.values() : query));
          };
          if (gathered.length === 1) return await alone(gathered[0]!);
          try {
            const answers = await client.group(gathered.map((member) => ({ query: member.text, parameters: member.values, arrays: member.arrays() })));
            gathered.forEach((member, i) => member.resolve(answers[i]));
          } catch (error) {
            // A statement the client could not write, a value whose type only the server can say among them: nothing of
            // the group went, and each goes alone, so that only that one fails, as it would have.
            if (!UNSENT.has((error as { code?: unknown }).code as string)) throw error;
            for (const member of gathered) await alone(member).catch(member.reject);
          }
        } catch (error) {
          for (const member of gathered) member.reject(error);
        }
      });
      // After its turn is asked, which closes any group gathering before it.
      this.#gathering = gathered;
    }
    return new Promise((resolve, reject) => members.push({ ...read, resolve, reject }));
  }

  /**
   * Close the connection once every turn asked is done: what a Worker hands `waitUntil` when the call is done. By
   * `by` (ms since the epoch) at the latest, if given: then at once, what is still asked failing, the statement under
   * way included, and none of it sent again. A use's call past its deadline, whose answer has gone, so lets go of
   * Hyperdrive: what it asked and Hyperdrive had not sent goes with the connection (use.ts, `HELD_PAST_DEADLINE_MS`).
   */
  async end(by?: number): Promise<void> {
    // A statement awaited just before reaches the pool a few promise steps later, through Drizzle's session: a task
    // later, every one has taken its turn, and none opens a connection that this would leave open.
    await new Promise((resolve) => setTimeout(resolve, 0));
    let timer: ReturnType<typeof setTimeout> | undefined;
    const reached = by === undefined ? null : new Promise<'cut'>((resolve) => (timer = setTimeout(() => resolve('cut'), Math.max(0, by - Date.now()))));
    while (this.#busy > 0 && !this.#cut) {
      const idle = new Promise<void>((resolve) => this.#idle.push(resolve));
      if ((await (reached === null ? idle : Promise.race([idle, reached]))) === 'cut') this.#cut = true;
    }
    clearTimeout(timer);
    const client = this.#client;
    this.#client = null;
    await client?.end(this.#cut ? { timeout: 0 } : undefined).catch(() => {});
  }

  /** `go` once every turn asked before it is done. Anything but a group's closes the group gathering: it goes after. */
  #turn<T>(go: () => PromiseLike<T>): Promise<T> {
    this.#gathering = null;
    this.#busy += 1;
    const answer = this.#tail.then(go);
    this.#tail = answer.then(
      () => this.#done(),
      () => this.#done(),
    );
    return answer;
  }

  /** One turn done: once none is left, what waits for the pool to be idle goes on. */
  #done(): void {
    this.#busy -= 1;
    if (this.#busy === 0) for (const resolve of this.#idle.splice(0)) resolve();
  }

  /** The call's client, made the first time. postgres.js opens its connection again when one is lost. */
  #connected(): PostgresClient {
    if (this.#cut) throw new Error("the call's connection was closed at the time it was given (`end`): nothing more is sent");
    this.#client ??= textTypes(postgresClient(this.#connectionString, {
      max: 1,
      idle_timeout: this.#closeIdleMs === undefined ? undefined : this.#closeIdleMs / 1000,
      // No timer left to outlive the call: `end` closes the connection, or idling does.
      max_lifetime: null,
    }));
    return this.#client;
  }
}
