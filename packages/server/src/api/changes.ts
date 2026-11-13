import { randomUUID } from 'node:crypto';
import { protects } from '@coffre/core/access';
import type { Envelope } from '@coffre/core/envelope';
import type { BindingColumns, ConnectionColumns, CredentialColumns, EndedBinding, EnvironmentColumns, MadeBinding, NotedRow, NoteInput, ObjectChange, PreparedChange, RequestTrace, SecretColumns, Vault, VersionColumns } from '@coffre/core/vault';
import type { Queryable, Transaction } from '@coffre/db';
import { holdIssues, isMovedChange, isStaleChange, laterChanges, laterEvents, newestCommitted, type ChangeNumbers } from '@coffre/db/log';

import { askedOnce, askOnce, type AskedOnce } from '../asked-once.ts';
import { eventOf, sameEvent, type AuditEntry } from '../db/audit.ts';
import { authMac } from '../auth-rows.ts';
import type { BindingRow, CredentialRow, ObjectRead, SecretRead } from '../db/queries.ts';
import type { Caller } from './caller.ts';
import { POLICY_CHANGED } from './context.ts';

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
 * 2. **In it** (`audited`), once the rows are written: `app_change`, in
 *    the statement that appends 0.14's entries (no round trip of its own),
 *    under the head the transaction holds, then the issue lock and, but for
 *    an issue, the fence: head, row, issue lock, fence (AppHeadFirst;
 *    WriteLocks.tla's IssueBeforeFence). A row whose seal moved since it was
 *    read refuses (`ObjectMoved`): the write is read and prepared again
 *    (`retrying`).
 * 3. **After its commit:** the vault answers once the newest is sealed.
 *
 * Row and entry commit together or not at all, as the app's rows and its
 * 0.14 entries do.
 */

/** The actor of the app's own changes, made for no one's request: a key rotation's revokes, an unknown token signed out. */
export const COFFRE_ACTOR = 'coffre';

type Kept = { log: boolean; uses: boolean; batches: boolean; namedBatches: boolean; sealing: boolean; credentials: boolean; issues: boolean; binds: boolean; sweeps: boolean; writes: boolean; admits: boolean; owners: readonly string[] };

/**
 * What the vault keeps of 0.15, as it says (`about()`): asked once per vault (asked-once.ts), then kept, settled. An
 * isolate's first call settles the vault's keys and its bulk cap (vault.ts, `#settled`): its concurrent
 * first requests wait for that one call's answer rather than each settling the vault again (T201).
 */
const keeping = new WeakMap<Vault, AskedOnce<Kept>>();

function about015(vault: Vault): Promise<Kept> {
  let kept = keeping.get(vault);
  if (kept === undefined) keeping.set(vault, (kept = askedOnce()));
  return askOnce(kept, () => asked015(vault));
}

async function asked015(vault: Vault): Promise<Kept> {
  const about = await vault.about();
  const log = about.log === '0.15' && vault.prepare !== undefined && vault.waitSealed !== undefined;
  const kept = {
    log,
    uses: log && about.uses === true && vault.use !== undefined,
    batches: log && about.uses === true && about.batchUses === true && vault.use !== undefined && vault.useMany !== undefined,
    namedBatches: log && about.uses === true && about.namedBatches === true && vault.useNamedMany !== undefined,
    sealing: log && about.sealing === true && vault.sealing !== undefined,
    credentials: log && about.credentials === true && vault.signIn !== undefined && vault.revokeCredential !== undefined,
    issues: log && about.issues === true && vault.issueToken !== undefined,
    binds: log && about.binds === true && vault.changeBindings !== undefined,
    sweeps: log && about.binds === true && about.sweeps === true && vault.changeBindings !== undefined,
    writes: log && about.writes === true && vault.writeKeys !== undefined,
    admits: log && about.admits === true && vault.admitRead !== undefined && vault.admitWrite !== undefined,
    // The deployment's configuration, which a vault re-applies at its start and an isolate never sees change (R3).
    owners: about.owners ?? [],
  };
  return kept;
}

/** Whether the vault keeps 0.15's log: the app's writes are its changes. */
export async function keeps015(vault: Vault): Promise<boolean> {
  return (await about015(vault)).log;
}

/** Whether the vault says whether its checkpointer seals (`sealing`; T169): what `/readyz` asks under 0.15's log. */
/** The Owners the deployment names (`owners`, R3), as the vault said once for the isolate. */
export async function deploymentOwners(vault: Vault): Promise<readonly string[]> {
  return (await about015(vault)).owners;
}

export async function vaultSaysSealing(vault: Vault): Promise<boolean> {
  return (await about015(vault)).sealing;
}

/** A vault that makes sign-ins through trust bindings and revokes credentials itself (`vaultMakesCredentials`). */
export type CredentialsVault = Vault & Required<Pick<Vault, 'signIn' | 'revokeCredential'>>;

/**
 * Whether the vault makes sign-ins through trust bindings and revokes
 * credentials itself, each in one call (`signIn`, `revokeCredential`;
 * T149): with 0.15's log, a vault of this release does. A boolean, never
 * the vault: a vault an async function returns is awaited, and a Worker's
 * stub, or a proxy, answers `then` as it answers any method.
 */
export async function vaultMakesCredentials(vault: Vault): Promise<boolean> {
  return (await about015(vault)).credentials;
}

/** Whether the vault issues tokens itself too, in one call (`issueToken`; T149, PR 2). A boolean, as `vaultMakesCredentials` says why. */
export async function vaultIssuesTokens(vault: Vault): Promise<boolean> {
  return (await about015(vault)).issues;
}

/** Whether the vault decides a key write on one read of its own (`writeKeys`, T179 PR 3): the app's key write then makes five round trips. */
export async function vaultWrites(vault: Vault): Promise<boolean> {
  return (await about015(vault)).writes;
}

/** Whether the vault decides a member's first add on one read of its own (`admitRead`, `admitWrite`; T179 PR 5): the add then makes three round trips. */
export async function vaultAdmits(vault: Vault): Promise<boolean> {
  return (await about015(vault)).admits;
}

/** Whether the vault answers 0.15's uses too: the app opens each value through one (keys.ts, `openValues`). */
export async function uses015(vault: Vault): Promise<boolean> {
  return (await about015(vault)).uses;
}

/**
 * Whether the vault answers a request's several keys by name in one call (`useNamedMany`, T165, B2's PR 2): one of this
 * release does. One older, mid-deploy, says nothing, and the request reads its keys as before.
 */
export async function namesMany(vault: Vault): Promise<boolean> {
  return (await about015(vault)).namedBatches;
}

/** Whether the vault answers a request's several keys in one call (`useMany`, T167): one of this release does. */
export async function usesMany(vault: Vault): Promise<boolean> {
  return (await about015(vault)).batches;
}

/**
 * A row whose seal moved since it was read, or a set of rows a write chose
 * again under the head that is not the one it prepared: another write came
 * between. Read and prepare again (`retrying`); left to the caller, 409.
 */
export class ObjectMoved extends ApiError {
  /** `retryAfter`: said once a write's tries are spent (a two-trip write's three, two-trips.md, "Retries"). */
  constructor(retryAfter?: string) {
    super('conflict', 'what this changes was changed while it ran: try again', 'changed', retryAfter);
  }
}

/**
 * The changes of one write, sealed, for its transaction to commit; and its events, what it does that no change records
 * (a project made, a passkey added; 0.16), signed with them, which commit in the same transaction, after them.
 */
export class AppChanges {
  readonly #vault: Vault;
  readonly #changes: readonly ObjectChange[];
  readonly #calls: readonly PreparedChange[];
  /** The events asked for, and as the vault signed them, in the same order. */
  readonly #asked: readonly NoteInput[];
  readonly #events: readonly NotedRow[];
  /** The entries of changes no call carries, each an event signed beside them, by its change's id: they commit with it. */
  readonly #alone: readonly { id: string; row: NotedRow }[];
  /** The ones its work's entries are (`entries`): only they commit. */
  #logged: NotedRow[] = [];
  /** The numbers of the changes its transaction made, which answer with its COMMIT (`commit`). */
  #numbers: ChangeNumbers | null = null;
  /** Whether its transaction reached `commit`: only then can it fail with what `failed` maps. */
  #committed = false;
  #dropped = false;
  #only: Set<string> | null = null;

  private constructor(
    vault: Vault, changes: readonly ObjectChange[], calls: readonly PreparedChange[], asked: readonly NoteInput[] = [], events: readonly NotedRow[] = [],
    alone: readonly { id: string; row: NotedRow }[] = [],
  ) {
    this.#vault = vault;
    this.#changes = changes;
    this.#calls = calls;
    this.#asked = asked;
    this.#events = events;
    this.#alone = alone;
  }

  /**
   * The changes `actor` is about to make, sealed by the vault; null with
   * 0.14's log, where none is made, and none read: `changes` may be the read
   * of the rows they are of, which 0.14's write does not need. A row the
   * vault refuses (`tampered`: not the vault's) refuses the write; one that
   * is no longer its object's newest change's (`moved`) is read again.
   * `events`, signed in the same call, commit with them: each its own (`eventOf`), drawn for this attempt.
   */
  static async prepare(
    vault: Vault,
    actor: string | ((changes: readonly ObjectChange[]) => string),
    of: readonly ObjectChange[] | (() => Promise<readonly ObjectChange[]>),
    events: readonly NoteInput[] = [],
  ): Promise<AppChanges | null> {
    if (!(await keeps015(vault))) {
      if (events.length > 0) throw new Error('a vault without 0.15\'s log signs no event: the app records nothing without one');
      return null;
    }
    const changes = typeof of === 'function' ? await of() : of;
    if (changes.length === 0 && events.length === 0) return new AppChanges(vault, [], []);
    const by = typeof actor === 'function' ? actor(changes) : actor;
    const outcome = await vault.prepare!({ actor: by, changes: [...changes], ...(events.length === 0 ? {} : { events: [...events] }) });
    // A row read is no longer its object's newest change's: a write came between, read again (`retrying`), as
    // `app_change` answers a row moved since it was read.
    if (!outcome.ok && outcome.refusal.code === 'moved') throw new ObjectMoved();
    if (!outcome.ok) throw vaultRefused(outcome.refusal);
    if ((outcome.events?.length ?? 0) !== events.length) throw new Error(`the vault signed ${outcome.events?.length ?? 0} of ${events.length} events`);
    // An entry rides its change's first logged call. A change that makes none carries it nowhere: a row the log never
    // held, a key brought back that its log never held, a change that changes nothing (archived meanwhile by another
    // request). Its entry is then an event of its own, signed now, one more call, and it commits with the change.
    const unridden = changes.filter((change) => change.entry !== null
      && !outcome.changes.some((call) => call.kind === change.kind && call.id === change.id && call.payload !== null));
    if (unridden.length === 0) return new AppChanges(vault, changes, outcome.changes, events, outcome.events ?? []);
    const signed = await vault.prepare!({ actor: by, changes: [], events: unridden.map((change) => ({ ...change.entry!, id: randomUUID() })) });
    if (!signed.ok) throw vaultRefused(signed.refusal);
    if (signed.events?.length !== unridden.length) throw new Error(`the vault signed ${signed.events?.length ?? 0} of ${unridden.length} events`);
    const alone = unridden.map((change, i) => ({ id: change.id, row: signed.events![i]! }));
    return new AppChanges(vault, changes, outcome.changes, events, outcome.events ?? [], alone);
  }

  /**
   * Changes the vault prepared with its own decision (`Vault.writeKeys`, T179 PR 3), from the objects its read held:
   * nothing asked of it again.
   */
  static of(vault: Vault, calls: readonly PreparedChange[]): AppChanges {
    return new AppChanges(vault, [], calls);
  }

  /**
   * That the transaction revoked exactly the credentials these changes
   * revoke: a set it chose again under the head (every live credential of a
   * member, say) that is not the one prepared from its read before is a
   * write meanwhile, read again (`ObjectMoved`). Otherwise a credential
   * issued meanwhile would be revoked with no change, its row no longer the
   * log's.
   */
  expectRevoked(ids: Iterable<string>, kind: 'credential' | 'connection' = 'credential'): void {
    const prepared = this.#changes.filter((change) => change.kind === kind && change.before !== null && !change.before.columns.revoked && change.after.revoked).map(({ id }) => id);
    if (!sameIds([...ids], prepared)) throw new ObjectMoved();
  }

  /** The write ends without writing what these changes are of (a code expired, a token unknown): none is made, unless kept again. Its events the work logged still are. */
  drop(): void {
    this.#dropped = true;
  }

  /** The write writes them after all. */
  keep(): void {
    this.#dropped = false;
  }

  /**
   * The entries its work logged, in the transaction, before `commit`: each that is one of the events prepared, field for
   * field but its id, commits as that event; those it logged none of do not (a project found made already logs no
   * `project.create`). The others are handed back, for `audit_log` while the app still appends there (until each
   * change carries its entry): an entry of a prepared action that says otherwise (a slug renamed meanwhile)
   * is still recorded, as before, never lost. An entry a change carries is not logged: logged too, it is an error.
   *
   *   prepared: project.create { slug: 'market' }, project.move { to: 'apps' }
   *   logged:   project.create { slug: 'market' }               commits project.create alone, as its event
   */
  entries(log: readonly AuditEntry[]): AuditEntry[] {
    const used = new Set<number>();
    const carried = this.#carried();
    const rest: AuditEntry[] = [];
    this.#logged = [];
    for (const entry of log) {
      const i = this.#asked.findIndex((asked, j) => !used.has(j) && asked.action === entry.action && sameEvent(eventOf(entry, asked.credential, asked.id), asked));
      if (i !== -1) {
        used.add(i);
        this.#logged.push(this.#events[i]!);
        continue;
      }
      // Once only (#569): a site hands its entry to its change in the commit that stops logging it.
      if (carried.some((carry) => carry.action === entry.action && sameEvent(eventOf(entry, carry.credential, ''), { ...carry, id: '' }))) {
        throw new Error(`the entry ${entry.action} is carried by its change and logged too: a site logs it once, on its change`);
      }
      rest.push(entry);
    }
    return rest;
  }

  /** The entries the prepared changes carry (`ObjectChange.entry`). */
  #carried(): Entry[] {
    return this.#changes.flatMap((change) => change.entry === null ? [] : [change.entry]);
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

  /**
   * In the transaction, its rows written, as its last statements: each
   * change (`app_change_strict`), after the 0.14 entries; or, given
   * `append`, which appends them, in its statement, one round trip less
   * under 0.14's head (T123). `append` runs whatever this write dropped.
   * Nothing awaits them: they go with the COMMIT, under its Sync
   * (`later`), and their numbers answer after it (`sealed`). A row moved
   * since it was read fails the transaction, which `failed` says is
   * `ObjectMoved`: read and prepared again (`retrying`).
   */
  async commit(tx: Transaction, append?: (calls: readonly PreparedChange[]) => Promise<ChangeNumbers | null>): Promise<void> {
    this.#committed = true;
    const only = this.#only;
    const calls = this.#dropped ? [] : only === null ? this.#calls : this.#calls.filter((call) => only.has(call.id));
    // An environment's slug moved (a rename, a deletion's tombstone): what the vault's issue compares of the policy. The
    // issue lock exclusive, its rows written and before the fence its append takes, orders the issue against it (`holdIssues`).
    if (calls.length > 0 && this.#changes.some((change) => change.kind === 'environment' && change.before !== null
      && change.before.columns.slug !== change.after.slug && (only === null || only.has(change.id)))) await holdIssues(tx, { final: true });
    this.#numbers = append === undefined ? await laterChanges(tx, calls) : await append(calls);
    // The events its work logged, after its changes, whether or not it dropped them: a code spent and refused at once
    // records its refusal with it (`pollDevice`). Then the entries no call carries, of the changes it makes.
    const alone = this.#dropped ? [] : this.#alone.filter(({ id }) => only === null || only.has(id)).map(({ row }) => row);
    laterEvents(tx, [...this.#logged, ...alone]);
  }

  /**
   * What the transaction that committed these changes failed with, as its caller hears it: a row moved since it was
   * read is `ObjectMoved`, read again; one that is not its object's newest change's, put back around coffre, says so.
   * Before `commit`, no change ran, and the error is the work's own, unchanged (as the vault's `Changes.failed`).
   */
  failed(error: unknown): unknown {
    if (!this.#committed) return error;
    if (isMovedChange(error)) return new ObjectMoved();
    if (isStaleChange(error)) return new Error("an object this write changes is not its newest change's: a row was put back around coffre", { cause: error });
    return error;
  }

  /** After the commit: once the newest change is sealed, and every one before it (R51). */
  async sealed(db: Queryable): Promise<void> {
    const newest = this.#numbers === null ? null : await newestCommitted(db, this.#numbers);
    if (newest === null) return;
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

/**
 * A credential's row as its object takes it: whose, what kind, its scope as stored, revoked or not, its end, the earlier
 * of its expiry and its hard end, and its account's generation when it was issued.
 */
export function credentialColumns(row: {
  id: string;
  principal: string;
  kind: string;
  scope: string | null;
  revokedAt: Date | null;
  expiresAt: Date;
  notAfter?: Date | null;
  generation: number;
}): CredentialColumns {
  const ends = [row.expiresAt.getTime(), ...(row.notAfter == null ? [] : [row.notAfter.getTime()])];
  return {
    id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: row.revokedAt !== null, expiresAt: Math.min(...ends), generation: row.generation,
  };
}

/**
 * A credential revoked by the vault itself, in one call (T149,
 * `Vault.revokeCredential`): from its row as read, live, the app's
 * (`liveCredentialsWhere`) and the log's (sealed), to revoked by
 * `revokedBy`, the app's MAC over the revoked row with it, and, for a
 * caller whose right to it the policy weighs, that policy, held to under
 * the fence. False when it moved meanwhile (revoked, or
 * changed): whoever asks reads it again. A row the log does not bear out
 * refuses, as a write to it does (`app_change`), the vault reporting it.
 */
export async function revokedByVault(
  vault: Required<Pick<Vault, 'revokeCredential'>>,
  chainKey: Buffer,
  row: CredentialRow,
  by: { actor: string; revokedBy: string; reason: 'revoke' | 'sign_out'; via: string | null; trace: RequestTrace | null; caller: Pick<Caller, 'policy' | 'policySeq'> | null },
): Promise<boolean> {
  if (row.seal === null) throw new Error(`the credential ${row.id} is 0.14's, which the log never held: it is revoked as 0.14 revokes it`);
  const revokedAt = new Date();
  const outcome = await vault.revokeCredential({
    actor: by.actor,
    before: { columns: credentialColumns(row), seal: Buffer.from(row.seal).toString('base64') },
    authMacFrom: Buffer.from(row.authMac).toString('base64'),
    authMac: authMac(chainKey, 'credentials', { ...row, revokedAt }).toString('base64'),
    revokedAt: revokedAt.getTime(),
    revokedBy: by.revokedBy,
    reason: by.reason,
    via: by.via,
    trace: by.trace,
    // The policy the caller's right was weighed on, which the vault holds to under the fence, as `policyStill` under 0.14's head.
    policy: by.caller === null ? null : {
      seq: by.caller.policySeq?.toString() ?? null,
      protected: Object.values(by.caller.policy.protectedIn).flat().map(({ environmentId, slug }) => ({ environmentId, slug })),
    },
  });
  if (outcome.ok) return true;
  if (outcome.refused === 'moved') return false;
  if (outcome.refused === 'policy') throw new ApiError('conflict', "the instance's roles or protected environments changed while this ran: try again", POLICY_CHANGED);
  if (outcome.refused === 'busy') throw new ApiError('unavailable', 'coffre is busy: try again shortly', 'busy', '1');
  throw new Error(`the credential ${row.id} is not the log's (${outcome.refused}): a row was put back around coffre`);
}

/** Each live credential revoked: its change. */
export function revokes(rows: readonly CredentialRowRead[]): ObjectChange[] {
  const now = new Date();
  return rows.map((row) => credentialChange(row, { ...row, revokedAt: now }, null));
}

type CredentialRowRead = Parameters<typeof credentialColumns>[0] & { seal: Buffer | null };

/** What a change carries (`ObjectChange.entry`): its site's entry less its id (`entryOf`), or null for none. */
export type Entry = Omit<NoteInput, 'id'>;

/** A credential's change: made (no row before), or from its row as read, with its seal; its entry, or null. */
export function credentialChange(
  before: CredentialRowRead | null,
  after: Parameters<typeof credentialColumns>[0],
  entry: Entry | null,
): ObjectChange {
  return {
    kind: 'credential',
    id: after.id,
    before: before === null ? null : { columns: credentialColumns(before), seal: before.seal === null ? null : before.seal.toString('base64') },
    after: credentialColumns(after),
    entry,
  };
}

/** An MCP connection's row as its object takes it (T147): whose, at which generation, its end, revoked or not. */
export function connectionColumns(row: { id: string; principal: string; generation: number; expiresAt: Date; revokedAt: Date | null }): ConnectionColumns {
  return { id: row.id, principal: row.principal, generation: row.generation, expiresAt: row.expiresAt.getTime(), revoked: row.revokedAt !== null };
}

type ConnectionRowRead = Parameters<typeof connectionColumns>[0] & { seal: Buffer | null };

/**
 * An MCP connection's change (T147): made (no row before), or from its row as read, with its seal. A use through it
 * decides on its object, so each of its ends is a change, under the fence, as a credential's revoke is.
 */
export function connectionChange(before: ConnectionRowRead | null, after: Parameters<typeof connectionColumns>[0], entry: Entry | null): ObjectChange {
  return {
    kind: 'connection',
    id: after.id,
    before: before === null ? null : { columns: connectionColumns(before), seal: sealText(before.seal) },
    after: connectionColumns(after),
    entry,
  };
}

/** Each live connection revoked: its change, carrying no entry (a site whose revoke has one sets it). */
export function connectionRevokes(rows: readonly ConnectionRowRead[]): ObjectChange[] {
  const now = new Date();
  return rows.map((row) => connectionChange(row, { ...row, revokedAt: now }, null));
}

/** Two sets of ids alike: a set a write chose again under the head, and the one it prepared. */
export function sameIds(a: readonly string[], b: readonly string[]): boolean {
  const set = new Set(a);
  return set.size === new Set(b).size && b.every((id) => set.has(id));
}

/** A seal as `prepare` takes it. */
function sealText(seal: Buffer | null): string | null {
  return seal === null ? null : seal.toString('base64');
}

/**
 * A key's change: from its read (none, a key made now; archived, no object),
 * to its columns after (null: archived, or erased with its place). Its
 * object holds its version's id, nature and wrapped data key, never the
 * ciphertext (0.15-plan.md, "As built: PR 4b"): each version has a data key
 * of its own, and the envelope's AEAD binds the ciphertext to it.
 *
 * `'as read'`: the key as its rows hold it. Archived, it is brought back so
 * (an unarchive, an override made again, a reference written again
 * unchanged) and restores: the vault holds those rows to the object its log
 * last sealed, since nothing checked them while it was archived (T134).
 * Any other change over an archived key brings its own value or reference,
 * a version or reference row this write made, never its rows'.
 */
export function secretChange(id: string, before: SecretRead | undefined, after: SecretColumns | null | 'as read', entry: Entry | null): ObjectChange {
  // Archiving leaves no seal (`secret.delete`): an archived row with one was archived around coffre, and no change moves it.
  if (before?.archived === true && before.seal !== null) throw new Error(`the key ${id} was archived around coffre, its seal kept: its row is not its newest change's`);
  if (after === 'as read') {
    if (before === undefined) throw new Error(`the key ${id} has no row to bring back as read`);
    if (before.archived) return { kind: 'secret', id, before: null, after: before.columns, restores: true, entry };
    return { kind: 'secret', id, before: { columns: before.columns, seal: sealText(before.seal) }, after: before.columns, entry };
  }
  if (before?.archived === true && after !== null && (after.version?.id ?? null) === (before.columns.version?.id ?? null) && after.reference === before.columns.reference) {
    throw new Error(`the key ${id} is archived: brought back as its rows hold it, it restores ('as read'); written, it takes a version or reference of its own`);
  }
  return { kind: 'secret', id, before: before === undefined || before.archived ? null : { columns: before.columns, seal: sealText(before.seal) }, after, entry };
}

/** A key's columns with a new version of its own: its value, no reference. */
export function writtenSecret(at: Pick<SecretColumns, 'id' | 'projectId' | 'environmentId'>, version: VersionColumns): SecretColumns {
  return { id: at.id, projectId: at.projectId, environmentId: at.environmentId, source: null, reference: null, version };
}

/** A version's columns, as its row stores them: its id, whether it is sensitive, a plain one's text, and the data key wrapped in its envelope. */
export function versionColumns(
  id: string,
  envelope: Pick<Envelope, 'kekProvider' | 'kekId' | 'kekVersion' | 'wrappedDek'>,
  { sensitive, plaintext }: { sensitive: boolean; plaintext: string | null },
): VersionColumns {
  const { kekProvider, kekId, kekVersion, wrappedDek } = envelope;
  return { id, sensitive, plaintext, kekProvider, kekId, kekVersion, wrappedDek: wrappedDek.toString('base64') };
}

/** An environment's change: made (no read), or from its row as read, with its seal. */
export function environmentChange(before: ObjectRead<EnvironmentColumns> | undefined, after: EnvironmentColumns, entry: Entry | null): ObjectChange {
  return { kind: 'environment', id: after.id, before: before === undefined ? null : { columns: before.columns, seal: sealText(before.seal) }, after, entry };
}

/**
 * A binding's row as its object takes it (PR 3a): its columns, with the
 * instance it was made on (PR 3b), its row's `origin`, or `publicUrl` for
 * one made before the column; its seal (null for one the vault never sealed).
 */
export function sealedBinding(row: BindingRow, publicUrl: string): { columns: BindingColumns; seal: string | null } {
  return {
    columns: {
      id: row.id, principal: row.principal, generation: row.generation, profile: row.profile, issuer: row.issuer, origin: row.origin ?? publicUrl, jwksUri: row.jwksUri, claims: row.claims,
      scope: row.scope, policy: row.policy, revoked: row.revokedAt !== null,
    },
    seal: sealText(row.seal ?? null),
  };
}

/** A binding the vault makes (`changeBindings`) on `origin`, this instance's public URL: its row, as the vault writes it, and the app's MAC over it. */
export function madeBinding(chainKey: Buffer, origin: string, row: Omit<BindingRow, 'authMac' | 'lastUsedAt' | 'revokedAt' | 'revokedBy' | 'seal' | 'origin' | 'closedAt' | 'closedBy'>, entry: Entry | null): MadeBinding {
  const signed = { ...row, revokedAt: null };
  return {
    ...sealedBinding({ ...row, origin, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null, seal: null, closedAt: null, closedBy: null }, origin).columns,
    jwks: row.jwks ?? null, label: row.label ?? null, createdBy: row.createdBy, createdAt: row.createdAt.getTime(), authMac: authMac(chainKey, 'service_bindings', signed).toString('base64'),
    entry,
  };
}

/**
 * A binding the vault ends (`changeBindings`), with the live credentials it
 * issued, each as read with its seal and MAC (no seal for one 0.14 made, or
 * written around the vault), and the app's MAC over it revoked at `at`.
 * Under the switch the vault ends every binding, its own and 0.14's: one
 * left to the app could be a binding of the log's whose seal a writer
 * cleared, and its object would stand past its end (reviews r1, r2).
 */
export function endedBinding(chainKey: Buffer, publicUrl: string, row: BindingRow, credentials: readonly CredentialRow[], at: Date, entry: Entry | null): EndedBinding {
  return {
    entry,
    before: sealedBinding(row, publicUrl) as EndedBinding['before'],
    authMacFrom: Buffer.from(row.authMac).toString('base64'),
    authMac: authMac(chainKey, 'service_bindings', { ...row, revokedAt: at }).toString('base64'),
    credentials: credentials.map((credential) => ({
      before: { columns: credentialColumns(credential), seal: credential.seal === null ? null : Buffer.from(credential.seal).toString('base64') },
      authMacFrom: Buffer.from(credential.authMac).toString('base64'),
      authMac: authMac(chainKey, 'credentials', { ...credential, revokedAt: at }).toString('base64'),
    })),
  };
}

/** Whether the vault makes and ends bindings itself, and signs in through none it did not seal (`about().binds`, PR 3a). */
export async function vaultBinds(vault: Vault): Promise<boolean> {
  return (await about015(vault)).binds;
}

/** Whether the vault ends a binding in batches too, closing it first (`changeBindings`' `sweep`, `about().sweeps`; W331). */
export async function vaultSweeps(vault: Vault): Promise<boolean> {
  return (await about015(vault)).sweeps;
}

/**
 * A new environment's object, 0.15's (`environmentObject`): its own id's
 * protection as the policy has it, a protected fork's (`protectIds`), which
 * `audited` holds to the policy as it commits (`policyStill`). Its project
 * is live: an archived one takes no environment, which each maker checks
 * under the head.
 */
export function madeEnvironment(caller: Pick<Caller, 'policy'>, row: Omit<EnvironmentColumns, 'protected' | 'archived' | 'projectArchived'>): EnvironmentColumns {
  return { ...row, protected: protects(caller.policy, row.id), archived: false, projectArchived: false };
}

/** The protection a new environment's row carries with 0.15's log, its object's; none with 0.14's, which keeps it in the policy. */
export function madeProtection(made: EnvironmentColumns, changes: AppChanges | null): { protected?: boolean } {
  return changes === null ? {} : { protected: made.protected === true };
}
