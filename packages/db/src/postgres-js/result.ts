import type { Statement } from './query.ts';

/** A backend's process id and secret key, as BackendKeyData gave them: what a CancelRequest names. */
export interface Backend {
  pid: number | null;
  secret: number | null;
}

/** What Postgres said of a column, in a RowDescription. */
export interface Column {
  name: string;
  /** How its text is read, by its type; as text when there is none. */
  parser: ((text: string) => unknown) | undefined;
  table: number;
  number: number;
  type: number;
}

/**
 * A statement's rows, with what its CommandComplete said beside them: `count`
 * (rows inserted, updated, deleted or returned), `command`, and `state`, the
 * backend that ran it. Not enumerable, so that a result spreads as its rows.
 */
export class Result extends Array<unknown> {
  declare count: number | null;
  declare state: Backend | null;
  declare command: string | null;
  declare columns: Column[] | null;
  declare statement: Statement | null;

  constructor() {
    super();
    Object.defineProperties(this, {
      count: { value: null, writable: true },
      state: { value: null, writable: true },
      command: { value: null, writable: true },
      columns: { value: null, writable: true },
      statement: { value: null, writable: true },
    });
  }

  /** What `map`, `filter` and the like make: a plain array. */
  static get [Symbol.species](): ArrayConstructor {
    return Array;
  }
}
