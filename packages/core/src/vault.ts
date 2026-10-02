import type { AccessFault } from './access-fault.ts';
import type { Role } from './access.ts';

export { checkpointMessage, verifyCheckpoint } from './checkpoint.ts';
export { describeAccessFault, type AccessFault, type FaultGrant, type FaultNames } from './access-fault.ts';

/**
 * The vault as the app sees it: the contract between `@coffre/server` and
 * `@coffre/vault`, kept in core so that neither side owns it. Every argument
 * and result is plain JSON: strings, numbers, booleans, arrays and objects,
 * never a Buffer, a Date, a class or a function. So it crosses a Workers RPC
 * boundary, or a process boundary later, as it is, and the in-process
 * transport proves it by round-tripping everything through JSON.
 *
 * The app says who is asking and the vault decides. The app never holds a
 * key: it encrypts a value under a fresh data key, has the vault wrap that
 * key, and stores the result; to read, it names stored versions and the
 * vault loads their keys itself.
 *
 * Decisions come back as values: `{ ok: false, refusal }` for a refusal, which
 * the vault has already logged. Only a fault (a bug, the store down) throws.
 */
export interface Vault {
  /** Unwrap data keys for `principal`: all of them, or none. */
  unwrap(input: UnwrapInput): Promise<Outcome<{ keys: string[] }>>;
  /**
   * Wrap fresh data keys for new versions `principal` writes: all, or none.
   * `seqs` are the `key.wrap` entries, one per key, which the app's
   * `secret.write` entries name as related.
   */
  wrap(input: WrapInput): Promise<Outcome<{ wrapped: WrappedKey[]; seqs: number[] }>>;
  /**
   * Wrap existing data keys again for new versions of the same secrets,
   * under the current key: restoring an old value. It needs a write grant,
   * not a read one, since the key never leaves the vault.
   */
  rewrap(input: RewrapInput): Promise<Outcome<{ wrapped: WrappedKey[]; seqs: number[] }>>;

  /**
   * What one principal holds right now: the app asks once per request. A
   * decision, its rows checked: lists of who holds what read the rows
   * themselves, and need not ask.
   */
  access(principal: string): Promise<Access>;
  /** Set roles at several places for one principal: all of it, or none. */
  setAccess(input: SetAccessInput): Promise<Outcome<{ changes: AccessChange[] }>>;
  /**
   * Add a member, bring back a removed one, or change whether they are an
   * owner. `generation` is theirs now: sessions and tokens of an earlier
   * one are dead.
   */
  admit(input: AdmitInput): Promise<Outcome<{ created: boolean; owner: boolean; generation: number }>>;
  /** Remove a member: revoke every grant and refuse them until admitted again, from `generation` on. */
  remove(input: RemoveInput): Promise<Outcome<{ revoked: Grant[]; generation: number }>>;

  /**
   * Sign the log up to its last entry, in an `audit.checkpoint` entry of
   * the vault's, if the whole chain recomputes from its first entry, the
   * vault's entries by their MACs, and the prefix the last checkpoint signed
   * is still there. The vault reads the log itself: it takes nobody's word
   * for where it ends, or for what came before. It checks every
   * member's row too, as `access` would, and logs a `vault.tampered` for
   * each one changed around it: lists read rows without asking the vault.
   */
  checkpoint(): Promise<Outcome<{ checkpoint: Checkpoint }>>;
  /**
   * What the vault's configuration says, which the app shows: the keys its
   * checkpoints verify under, by the key id each checkpoint names (the one
   * it signs with now, and those of the KEKs it replaced), and the root
   * admins, as principals.
   */
  about(): Promise<{ checkpointKeys: Record<string, CheckpointKey>; rootAdmins: string[] }>;
  /**
   * Check the whole log: rehash it from the first entry, the vault's
   * entries by their MACs, every checkpoint against the prefix it signed,
   * and replay it to see that who is a member, and what they hold, follow
   * from it. A verdict and nothing else, so anyone may ask; the app asks
   * for owners.
   */
  verifyLog(input: VerifyLogInput): Promise<LogVerification>;
}

/**
 * The vault's entries that change what a member holds: what their row's
 * `access_seq` names, and what a finding about them is newer than while it
 * stands.
 */
export const ACCESS_ACTIONS = ['member.add', 'member.restore', 'member.owner', 'member.remove', 'access.grant', 'access.revoke'] as const;

/** A refusal, already logged by the time the app sees it. */
export type Refusal = { code: RefusalCode; message: string };

export type RefusalCode =
  /** The principal was removed; only `admit` brings them back. */
  | 'removed'
  /** The principal was never admitted. */
  | 'not_a_member'
  /** No grant covers the place for what was asked. */
  | 'no_grant'
  /** A grant covered it, but has expired. */
  | 'expired'
  /** Too many unwraps in the window; see `BulkLimit`. */
  | 'bulk_limit'
  /** The wrapped key does not belong to the secret it was presented as. */
  | 'bad_claim'
  /** Not allowed to manage access, members or the log. */
  | 'not_allowed'
  /** Root admins come from the vault's configuration and cannot be changed. */
  | 'root_admin'
  /** Well-formed, but not something the rules allow: a project role on an environment, an owner token. */
  | 'invalid'
  /** The vault's own log no longer carries the head the last checkpoint signed, or does not rehash since. */
  | 'log_broken'
  /**
   * A KEK the vault is given does not open what it wrapped: a restore with
   * the wrong key, or a key mistyped under the right id. Every key
   * operation is refused until the vault restarts with the right one.
   */
  | 'wrong_kek'
  /**
   * The member's row or grants were changed outside the vault, or put back
   * from before a later change: it refuses them until an owner removes them,
   * which starts their access over from the log.
   */
  | 'tampered';

export type Outcome<T> = ({ ok: true } & T) | { ok: false; refusal: Refusal };

/**
 * A proposed version the app will store. The ids bind its key, and `path`
 * is the app's label for the write's log. Reads name stored version ids
 * instead, so the vault reads the binding and wrapped key itself.
 */
export type SecretRef = {
  projectId: string;
  environmentId: string;
  secretId: string;
  version: number;
  /** `market/prod/DATABASE_URL`. */
  path: string;
};

/** A wrapped data key and the key encryption key that wrapped it; `bytes` is base64. */
export type WrappedKey = { kekProvider: string; kekId: string; kekVersion: string; bytes: string };

/** Why someone reads: shown in the log, and the same rules apply to each. */
export type Purpose = 'reveal' | 'run' | 'compare' | 'sync';

/** Ties the vault's entries to the app's request and audit rows. */
type Correlation = {
  requestId?: string | null;
  /**
   * The one action the call is part of, the app's id for it: a reveal's
   * reads, a write's versions, an access change. Its entries share it.
   */
  operationId?: string | null;
};

export type UnwrapInput = Correlation & {
  principal: string;
  purpose: Purpose;
  items: { secretVersionId: string }[];
};

export type WrapInput = Correlation & {
  principal: string;
  /** `key` is a fresh 32-byte data key, base64. */
  items: { secret: SecretRef; key: string }[];
};

export type RewrapInput = Correlation & {
  principal: string;
  /** `secret` is the proposed new version; `secretVersionId` is the stored source. */
  items: { secret: SecretRef; secretVersionId: string }[];
};

export type Grant = {
  projectId: string;
  /** Null for the whole project. */
  environmentId: string | null;
  role: Role;
  /** ISO 8601, or null for no end. */
  expiresAt: string | null;
  grantedAt: string;
  grantedBy: string;
};

export type Access = {
  principal: string;
  /**
   * `unknown` for someone never admitted, `tampered` for a member whose row
   * fails the vault's integrity check: refused everything, as `removed` is.
   * Root admins are always active.
   */
  status: 'active' | 'removed' | 'unknown' | 'tampered';
  /** Advanced by removal, even if the app cannot commit its credential revocations. */
  generation: number;
  isRootAdmin: boolean;
  /** Root admins and users admitted as owners, while active. */
  isOwner: boolean;
  /** Live grants only, and none unless active. */
  grants: Grant[];
  /** When the status last changed, and who changed it; null for root admins and strangers. */
  since: string | null;
  by: string | null;
};

/** One place: a role to hold there, with an optional end, or null for none. */
export type GrantChange = {
  projectId: string;
  environmentId: string | null;
  role: Role | null;
  expiresAt: string | null;
};

export type AccessChange = 'created' | 'updated' | 'revoked' | 'unchanged';

export type SetAccessInput = Correlation & {
  actor: string;
  principal: string;
  changes: GrantChange[];
};

export type AdmitInput = Correlation & {
  actor: string;
  principal: string;
  /** Left out, an existing member keeps their role and a new one is not an owner. */
  owner?: boolean;
};

export type RemoveInput = Correlation & {
  actor: string;
  principal: string;
  /**
   * For a sync: the environment it pushes from. Whoever may manage it there
   * may stop the sync, also once its grant there is revoked and only the
   * one on its credential is left.
   */
  source?: { projectId: string; environmentId: string };
};

/**
 * A prefix of the log the vault signed: every entry up to `seq`, the last
 * of which has `hash`, which pins every byte before it. Kept as the vault's
 * `audit.checkpoint` entry, just after the prefix it signs.
 */
export type Checkpoint = {
  seq: number;
  /** The hash of entry `seq`, hex. */
  hash: string;
  signedAt: string;
  keyId: string;
  /** Ed25519 over `checkpointMessage(...)`, base64. */
  signature: string;
};

/**
 * A public key the vault's checkpoints verify under, base64. One it
 * replaced vouches only for checkpoints whose prefix ends before `until`,
 * its first entry under the key that replaced it; the one it signs with now
 * has none.
 */
export type CheckpointKey = { publicKey: string; until: number | null };

/** An entry of the vault's log, and so the chain up to it. */
export type LogHead = { seq: number; hash: string };

export type VerifyLogInput = {
  /**
   * The last entry the app verified, its own entries by its key: the vault
   * checks the log still holds it, so between them both authors' entries
   * are authenticated over the same prefix.
   */
  upTo?: LogHead | null;
};

/**
 * Whether the vault's log holds, with the number of entries in it. On a
 * failure, the entry where it breaks, or null when the chain holds but the
 * members and grants do not follow from it. Then `fault` says which, as
 * facts the app can word with names: `reason` has only ids.
 * Full checks report live key batches in `pending`; overdue ones fail.
 */
export type LogVerification =
  | { ok: true; entries: number; pending?: number }
  | { ok: false; failedAtSeq: number | null; reason: string; fault?: AccessFault };
