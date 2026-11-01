import type { RowList } from './index.ts';
import type { Column } from './result.ts';

/** A statement as sent: its text, its parameters' types (0 for the server to say), and its columns once described. */
export interface Statement {
  string: string;
  types: number[];
  /** Once described: by a RowDescription, or NoData's none. */
  columns: Column[] | null;
}

export interface QueryOptions {
  /** Sent with the simple protocol, one Query message: what a statement with no parameters is, by default. */
  simple: boolean;
}

/**
 * One statement of a group (`group`, index.ts): its text and values, whether
 * its rows come as arrays, and what the connection works out as it sends it.
 */
export interface Member {
  text: string;
  args: unknown[];
  arrays: boolean;
  parameters: unknown[];
  statement: Statement | null;
}

/** Statements made so far (`Query.made`). */
let made = 0;

/**
 * A statement, sent once awaited (`then`, `catch`, `finally`) or `execute`d,
 * a task later, through the pool or the transaction that made it: its
 * `handler`. A promise of its result, its rows as objects or, after
 * `values()`, as arrays.
 */
export class Query<T = unknown> extends Promise<T> {
  readonly text: string;
  readonly args: unknown[];
  readonly options: QueryOptions;
  readonly #handler: (query: Query) => void;
  /** Where it was made, when the client debugs. */
  readonly #origin: Error | null;
  /** Its rows as arrays of values rather than objects. */
  arrays = false;
  executed = false;

  // What the connection works out as it sends it.
  parameters: unknown[] = [];
  statement: Statement | null = null;
  /** Whether its parameters' types are asked of the server before its values go (`typedByServer`, connection.ts). */
  describeFirst = false;
  /** A transaction's first statement: its BEGIN, sent ahead of it under its Sync (`begin`, index.ts); and whether it took. */
  begin: string | null = null;
  began = false;
  /**
   * Coffre: a group's statements, sent under one Sync and answered together, each its own result (`group`, index.ts),
   * and the one answering now. Null for a statement of its own.
   */
  group: Member[] | null = null;
  member = 0;
  /**
   * Coffre: a transaction's statement whose answer nothing awaits (`later`, @coffre/db): its COMMIT may go with it, under
   * its Sync (`settleWithCommit`, index.ts). One that something awaits must answer first, so that what awaits it may
   * still ask, or be refused and roll the transaction back.
   */
  later = false;
  /** Coffre: a group that failed: the results of its statements answered before the one that failed (`together`, index.ts). */
  answered: unknown[] | null = null;

  /** Coffre: when it was made, among every statement of the process: a transaction's group goes in this order (`flush`, index.ts). */
  readonly made = (made += 1);

  readonly resolve: (value: unknown) => void;
  readonly reject: (error: unknown) => void;

  constructor(text: string, args: unknown[], handler: (query: Query) => void, options: QueryOptions, debug: boolean) {
    let resolve!: (value: T) => void;
    let reject!: (error: unknown) => void;
    super((a, b) => {
      resolve = a;
      reject = b;
    });
    this.text = text;
    this.args = args;
    this.options = options;
    this.#handler = handler;
    this.#origin = debug ? new Error() : null;
    this.resolve = resolve as (value: unknown) => void;
    this.reject = reject;
  }

  /** Where it was made, for its error's stack: nothing unless the client debugs. */
  get origin(): string {
    return this.#origin?.stack ?? '';
  }

  /** What `then` and the like make: a plain promise, not another statement. */
  static get [Symbol.species](): PromiseConstructor {
    return Promise;
  }

  values(): Query<RowList<unknown[][]>> {
    this.arrays = true;
    return this as never;
  }

  execute(): this {
    void this.#handle();
    return this;
  }

  // `any` for what it fails with, as Promise's own `then` and `catch` take it.
  override then<A = T, B = never>(onfulfilled?: ((value: T) => A | PromiseLike<A>) | null, onrejected?: ((reason: any) => B | PromiseLike<B>) | null): Promise<A | B> {
    void this.#handle();
    return super.then(onfulfilled, onrejected);
  }

  override catch<B = never>(onrejected?: ((reason: any) => B | PromiseLike<B>) | null): Promise<T | B> {
    void this.#handle();
    return super.catch(onrejected);
  }

  override finally(onfinally?: (() => void) | null): Promise<T> {
    void this.#handle();
    return super.finally(onfinally);
  }

  /** Sent once, a task after it is first asked for. */
  async #handle(): Promise<void> {
    if (this.executed) return;
    this.executed = true;
    await null;
    this.#handler(this);
  }
}
