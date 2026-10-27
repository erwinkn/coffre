import type { CredentialColumns, ObjectChange, PreparedChange, Vault } from '@coffre/core/vault';
import type { Transaction } from '@coffre/db';
import { appChanges, isStaleChange } from '@coffre/db/log';

import { ApiError, vaultRefused } from './errors.ts';

/**
 * 0.15's log, the app's side (docs/design/0.15-plan.md, "As built: PR 4b").
 * With 0.15's log on, a write of the app's to an object a use decides on
 * (a credential, a key, an environment) is a change of the log, which
 * commits with the rows in the app's own transaction, and answers once it
 * is sealed (R51):
 *
 * 1. **Before the transaction:** the vault seals the changes (`prepare`)
 *    from the rows as the app read them and as it will write them. No vault
 *    call is made inside a transaction (AGENTS.md).
 * 2. **In it** (`audited`), once the rows and 0.14's entries are written:
 *    `app_change`, one round trip, under the head the transaction holds,
 *    then the fence: head, row, fence (Migration015.tla's AppHeadFirst). A
 *    row whose seal moved since it was read refuses (`ObjectMoved`): the
 *    write is read and prepared again (`retrying`).
 * 3. **After its commit:** the vault answers once the newest is sealed.
 *
 * Row and entry commit together or not at all, as the app's rows and its
 * 0.14 entries do. With 0.14's log, the default, none of this runs.
 */

/** The actor of the app's own changes, made for no one's request: a key rotation's revokes, an unknown token signed out. */
export const COFFRE_ACTOR = 'coffre';

/** Whether the vault keeps 0.15's log, as it says (`about().log`): asked once per vault, then kept, settled. */
const keeping = new WeakMap<Vault, boolean>();

export async function keeps015(vault: Vault): Promise<boolean> {
  const known = keeping.get(vault);
  if (known !== undefined) return known;
  const keeps = (await vault.about()).log === '0.15' && vault.prepare !== undefined && vault.waitSealed !== undefined;
  keeping.set(vault, keeps);
  return keeps;
}

/**
 * A row whose seal moved since it was read, or a set of rows a write chose
 * again under the head that is not the one it prepared: another write came
 * between. Read and prepare again (`retrying`); left to the caller, 409.
 */
export class ObjectMoved extends ApiError {
  constructor() {
    super('conflict', 'what this changes was changed while it ran: try again', 'changed');
  }
}

/** The changes of one write, sealed, for its transaction to commit. */
export class AppChanges {
  readonly #vault: Vault;
  readonly #changes: readonly ObjectChange[];
  readonly #calls: readonly PreparedChange[];
  #numbers: bigint[] = [];
  #dropped = false;
  #only: Set<string> | null = null;

  private constructor(vault: Vault, changes: readonly ObjectChange[], calls: readonly PreparedChange[]) {
    this.#vault = vault;
    this.#changes = changes;
    this.#calls = calls;
  }

  /**
   * The changes `actor` is about to make, sealed by the vault; null with
   * 0.14's log, where none is made, and none read: `changes` may be the read
   * of the rows they are of, which 0.14's write does not need. A row the
   * vault refuses (`tampered`: not the vault's) refuses the write.
   */
  static async prepare(
    vault: Vault,
    actor: string | ((changes: readonly ObjectChange[]) => string),
    of: readonly ObjectChange[] | (() => Promise<readonly ObjectChange[]>),
  ): Promise<AppChanges | null> {
    if (!(await keeps015(vault))) return null;
    const changes = typeof of === 'function' ? await of() : of;
    if (changes.length === 0) return new AppChanges(vault, [], []);
    const outcome = await vault.prepare!({ actor: typeof actor === 'function' ? actor(changes) : actor, changes: [...changes] });
    if (!outcome.ok) throw vaultRefused(outcome.refusal);
    return new AppChanges(vault, changes, outcome.changes);
  }

  /**
   * That the transaction revoked exactly the credentials these changes
   * revoke: a set it chose again under the head (every live credential of a
   * member, say) that is not the one prepared from its read before is a
   * write meanwhile, read again (`ObjectMoved`). Otherwise a credential
   * issued meanwhile would be revoked with no change, its row no longer the
   * log's.
   */
  expectRevoked(ids: Iterable<string>): void {
    const prepared = new Set(this.#changes.filter(({ before, after }) => before !== null && !before.columns.revoked && after.revoked).map(({ id }) => id));
    const written = new Set(ids);
    if (prepared.size !== written.size || [...written].some((id) => !prepared.has(id))) throw new ObjectMoved();
  }

  /** The write ends without writing what these changes are of (a code expired, a token unknown): none is made, unless kept again. */
  drop(): void {
    this.#dropped = true;
  }

  /** The write writes them after all. */
  keep(): void {
    this.#dropped = false;
  }

  /** Whether a change of this object, by id, was prepared: a write makes no other. */
  has(id: string): boolean {
    return this.#calls.some((call) => call.id === id);
  }

  /**
   * The write wrote only these objects' rows, by id (another write sealed the
   * others first, say): only their changes are made. One it wrote with no
   * change prepared is a row the log would not cover: read again.
   */
  only(ids: Iterable<string>): void {
    const written = new Set(ids);
    if ([...written].some((id) => !this.has(id))) throw new ObjectMoved();
    this.#only = written;
  }

  /** In the transaction, its rows and 0.14 entries written: each change, under the fence (`app_change`). */
  async commit(tx: Transaction): Promise<void> {
    if (this.#dropped) return;
    const only = this.#only;
    let numbers: (bigint | null)[];
    try {
      numbers = await appChanges(tx, only === null ? this.#calls : this.#calls.filter((call) => only.has(call.id)));
    } catch (error) {
      if (isStaleChange(error)) throw new Error("an object this write changes is not its newest change's: a row was put back around coffre", { cause: error });
      throw error;
    }
    if (numbers.some((number) => number === null)) throw new ObjectMoved();
    this.#numbers = (numbers as bigint[]).filter((number) => number > 0n);
  }

  /** After the commit: once the newest change is sealed, and every one before it (R51). */
  async sealed(): Promise<void> {
    if (this.#numbers.length === 0) return;
    const newest = this.#numbers.reduce((a, b) => (a > b ? a : b));
    const outcome = await this.#vault.waitSealed!({ number: newest.toString() });
    if (!outcome.ok) throw new Error(`change ${newest} was committed but not sealed: ${outcome.refusal.message}`);
  }
}

/** A write that reads its rows, prepares their changes and commits them, again while one moved under it, up to `tries` times. */
export async function retrying<T>(write: () => Promise<T>, tries = 3): Promise<T> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await write();
    } catch (error) {
      if (!(error instanceof ObjectMoved) || attempt >= tries) throw error;
    }
  }
}

/** A credential's row as its object takes it: whose, what kind, its scope as stored, revoked or not, and its end, the earlier of its expiry and its hard end. */
export function credentialColumns(row: {
  id: string;
  principal: string;
  kind: string;
  scope: string | null;
  revokedAt: Date | null;
  expiresAt: Date;
  notAfter?: Date | null;
}): CredentialColumns {
  const ends = [row.expiresAt.getTime(), ...(row.notAfter == null ? [] : [row.notAfter.getTime()])];
  return { id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: row.revokedAt !== null, expiresAt: Math.min(...ends) };
}

/** Each live credential revoked: its change. */
export function revokes(rows: readonly CredentialRowRead[]): ObjectChange[] {
  const now = new Date();
  return rows.map((row) => credentialChange(row, { ...row, revokedAt: now }));
}

type CredentialRowRead = Parameters<typeof credentialColumns>[0] & { seal: Buffer | null };

/** A credential's change: made (no row before), or from its row as read, with its seal. */
export function credentialChange(
  before: CredentialRowRead | null,
  after: Parameters<typeof credentialColumns>[0],
): ObjectChange {
  return {
    kind: 'credential',
    id: after.id,
    before: before === null ? null : { columns: credentialColumns(before), seal: before.seal === null ? null : before.seal.toString('base64') },
    after: credentialColumns(after),
  };
}
