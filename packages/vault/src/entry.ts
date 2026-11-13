import { randomUUID } from 'node:crypto';

import { leafHash } from '@coffre/core/log';

import { checked, macOf, type Key } from './rows.ts';

/**
 * A log entry (docs/design/0.16.md, "The log"). A request appends one to
 * `log_pending`, and the signer moves it under one of the log's two trees.
 * Its body is JSON, stored as written: the stored bytes are what its hash
 * and its MAC cover, so nothing ever has to write the same JSON twice.
 */
export type Entry = {
  /** Random, so that no two entries share a hash: the signer refuses one it has signed. */
  id: string;
  /** When, in milliseconds, by the vault's clock. The signer refuses an entry past its date, and prunes by this. */
  at: number;
  /** What was done: `member.role`, `secret.read`. */
  action: string;
  /** Who did it, `user:<email>` or `token:<name>`, and with which credential. Null for what the vault does by itself. */
  actor: string | null;
  credential: string | null;
  /** The app's request, for whoever reads the log beside the app's own. */
  request: string | null;
  ip: string | null;
  /** What it mentions, `secret:<id>` and the like: one `log_index` row each. */
  objects: readonly string[];
  /**
   * A change's rows, each by its name (`nameOf`), with the MAC it replaced
   * and the MAC it wrote, hex, null for none. The signer takes the entry
   * only if each `was` is what its mirror holds.
   */
  rows: readonly { row: string; was: string | null; now: string | null }[];
  /** What else the action's page shows. Never a value. */
  detail: Readonly<Record<string, unknown>>;
};

/** What an operation says of its entry. The vault adds the id, the time and the rows. */
export type Said = Omit<Entry, 'id' | 'at' | 'rows'> & {
  /** Under the tree kept for good, or the one that ages out: uses, and a session's coming and going. */
  kept: boolean;
};

/** An entry as `log_pending` holds it, and its hash, which the vault tells the signer to expect. */
export type Pending = { kept: boolean; body: string; mac: Buffer; hash: Buffer };

/** The MAC covers which tree the entry goes under, then its body. */
const covered = (kept: boolean, body: string) => `${kept ? 'kept' : 'aging'}\n${body}`;

export function pending(key: Key, said: Said, at: number, rows: Entry['rows']): Pending {
  const { kept, ...rest } = said;
  const entry: Entry = { id: randomUUID(), at, ...rest, rows };
  const body = JSON.stringify(entry);
  return { kept, body, mac: macOf(key, key.entries, covered(kept, body)), hash: leafHash(Buffer.from(body)) };
}

/** The entry a `log_pending` row holds, if its MAC is the vault's. */
export function entryOf(keys: readonly Key[], row: { kept: boolean; body: string; mac: Uint8Array }): Entry | undefined {
  return checked(keys, (key) => key.entries, covered(row.kept, row.body), row.mac) === undefined ? undefined : (JSON.parse(row.body) as Entry);
}
