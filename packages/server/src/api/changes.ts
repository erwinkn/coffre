import { protects } from '@coffre/core/access';
import type { Envelope } from '@coffre/core/envelope';
import type { BindingColumns, CredentialColumns, EndedBinding, EnvironmentColumns, MadeBinding, ObjectChange, PreparedChange, SecretColumns, Vault, VersionColumns } from '@coffre/core/vault';
import type { Transaction } from '@coffre/db';
import { appChanges, holdIssues, isStaleChange } from '@coffre/db/log';

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
 *    an issue, the fence: head, row, issue lock, fence (Migration015.tla's
 *    AppHeadFirst, IssueBeforeFence). A row whose seal moved since it was
 *    read refuses (`ObjectMoved`): the write is read and prepared again
 *    (`retrying`).
 * 3. **After its commit:** the vault answers once the newest is sealed.
 *
 * Row and entry commit together or not at all, as the app's rows and its
 * 0.14 entries do. With 0.14's log, the default, none of this runs.
 */

/** The actor of the app's own changes, made for no one's request: a key rotation's revokes, an unknown token signed out. */
export const COFFRE_ACTOR = 'coffre';

/** What the vault keeps of 0.15, as it says (`about()`): asked once per vault, then kept, settled. */
const keeping = new WeakMap<Vault, { log: boolean; uses: boolean; credentials: boolean; issues: boolean; binds: boolean }>();

async function about015(vault: Vault): Promise<{ log: boolean; uses: boolean; credentials: boolean; issues: boolean; binds: boolean }> {
  const known = keeping.get(vault);
  if (known !== undefined) return known;
  const about = await vault.about();
  const log = about.log === '0.15' && vault.prepare !== undefined && vault.waitSealed !== undefined;
  const kept = {
    log,
    uses: log && about.uses === true && vault.use !== undefined,
    credentials: log && about.credentials === true && vault.signIn !== undefined && vault.revokeCredential !== undefined,
    issues: log && about.issues === true && vault.issueToken !== undefined,
    binds: log && about.binds === true && vault.changeBindings !== undefined,
  };
  keeping.set(vault, kept);
  return kept;
}

/** Whether the vault keeps 0.15's log: the app's writes are its changes. */
export async function keeps015(vault: Vault): Promise<boolean> {
  return (await about015(vault)).log;
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

/** Whether the vault answers 0.15's uses too: the app opens each value through one (keys.ts, `openValues`). */
export async function uses015(vault: Vault): Promise<boolean> {
  return (await about015(vault)).uses;
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
    const prepared = this.#changes.filter((change) => change.kind === 'credential' && change.before !== null && !change.before.columns.revoked && change.after.revoked).map(({ id }) => id);
    if (!sameIds([...ids], prepared)) throw new ObjectMoved();
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

  /**
   * In the transaction, its rows written: each change (`app_change`), after
   * the 0.14 entries; or, given `append`, which appends them, in its
   * statement, one round trip less under 0.14's head (T123). `append` runs
   * whatever this write dropped.
   */
  async commit(tx: Transaction, append?: (calls: readonly PreparedChange[]) => Promise<(bigint | null)[]>): Promise<void> {
    const only = this.#only;
    const calls = this.#dropped ? [] : only === null ? this.#calls : this.#calls.filter((call) => only.has(call.id));
    // An environment's slug moved (a rename, a deletion's tombstone): what the vault's issue compares of the policy. The
    // issue lock exclusive, its rows written and before the fence its append takes, orders the issue against it (`holdIssues`).
    if (calls.length > 0 && this.#changes.some((change) => change.kind === 'environment' && change.before !== null
      && change.before.columns.slug !== change.after.slug && (only === null || only.has(change.id)))) await holdIssues(tx);
    let numbers: (bigint | null)[];
    try {
      numbers = append === undefined ? await appChanges(tx, calls) : await append(calls);
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
  by: { actor: string; revokedBy: string; reason: 'revoke' | 'sign_out'; via: string | null; caller: Pick<Caller, 'policy' | 'policySeq'> | null },
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
export function secretChange(id: string, before: SecretRead | undefined, after: SecretColumns | null | 'as read'): ObjectChange {
  // Archiving leaves no seal (`secret.delete`): an archived row with one was archived around coffre, and no change moves it.
  if (before?.archived === true && before.seal !== null) throw new Error(`the key ${id} was archived around coffre, its seal kept: its row is not its newest change's`);
  if (after === 'as read') {
    if (before === undefined) throw new Error(`the key ${id} has no row to bring back as read`);
    if (before.archived) return { kind: 'secret', id, before: null, after: before.columns, restores: true };
    return { kind: 'secret', id, before: { columns: before.columns, seal: sealText(before.seal) }, after: before.columns };
  }
  if (before?.archived === true && after !== null && (after.version?.id ?? null) === (before.columns.version?.id ?? null) && after.reference === before.columns.reference) {
    throw new Error(`the key ${id} is archived: brought back as its rows hold it, it restores ('as read'); written, it takes a version or reference of its own`);
  }
  return { kind: 'secret', id, before: before === undefined || before.archived ? null : { columns: before.columns, seal: sealText(before.seal) }, after };
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
export function environmentChange(before: ObjectRead<EnvironmentColumns> | undefined, after: EnvironmentColumns): ObjectChange {
  return { kind: 'environment', id: after.id, before: before === undefined ? null : { columns: before.columns, seal: sealText(before.seal) }, after };
}

/** A binding's row as its object takes it (PR 3a): its columns, its seal (null for one the vault never sealed). */
export function sealedBinding(row: BindingRow): { columns: BindingColumns; seal: string | null } {
  return {
    columns: {
      id: row.id, principal: row.principal, generation: row.generation, profile: row.profile, issuer: row.issuer, jwksUri: row.jwksUri, claims: row.claims,
      scope: row.scope, policy: row.policy, revoked: row.revokedAt !== null,
    },
    seal: sealText(row.seal ?? null),
  };
}

/** A binding the vault makes (`changeBindings`): its row, as `insertBinding` writes it, and the app's MAC over it. */
export function madeBinding(chainKey: Buffer, row: Omit<BindingRow, 'authMac' | 'lastUsedAt' | 'revokedAt' | 'revokedBy' | 'seal'>): MadeBinding {
  const signed = { ...row, revokedAt: null };
  return {
    ...sealedBinding({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null, seal: null }).columns,
    jwks: row.jwks ?? null, label: row.label ?? null, createdBy: row.createdBy, createdAt: row.createdAt.getTime(), authMac: authMac(chainKey, 'service_bindings', signed).toString('base64'),
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
export function endedBinding(chainKey: Buffer, row: BindingRow, credentials: readonly CredentialRow[], at: Date): EndedBinding {
  return {
    before: sealedBinding(row) as EndedBinding['before'],
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
