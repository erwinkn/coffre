import type { Role } from '../../core/src/access.ts';

/**
 * The vault as the app sees it. Every argument and result is plain JSON:
 * strings, numbers, booleans, arrays and objects, never a Buffer, a Date,
 * a class or a function. So it crosses a Workers RPC boundary, or a process
 * boundary later, as it is, and the in-process transport proves it by
 * round-tripping everything through JSON.
 *
 * The app says who is asking and the vault decides. The app never holds a
 * key: it encrypts a value under a fresh data key, has the vault wrap that
 * key, and stores the result; to read, it hands the wrapped key back with
 * who wants it and why.
 *
 * Decisions come back as values: `{ ok: false, refusal }` for a refusal, which
 * the vault has already logged. Only a fault (a bug, the store down) throws.
 */
export interface Vault {
  /** Unwrap data keys for `principal`: all of them, or none. */
  unwrap(input: UnwrapInput): Promise<Outcome<{ keys: string[] }>>;
  /** Wrap fresh data keys for new versions `principal` writes: all, or none. */
  wrap(input: WrapInput): Promise<Outcome<{ wrapped: WrappedKey[] }>>;
  /**
   * Wrap existing data keys again for new versions of the same secrets,
   * under the current key: restoring an old value. It needs a write grant,
   * not a read one, since the key never leaves the vault.
   */
  rewrap(input: RewrapInput): Promise<Outcome<{ wrapped: WrappedKey[] }>>;

  /** What one principal holds right now: the app asks once per request. */
  access(principal: string): Promise<Access>;
  /** Everyone admitted, removed or not, and the root admins, in one call. */
  members(): Promise<Access[]>;
  /** Set roles at several places for one principal: all of it, or none. */
  setAccess(input: SetAccessInput): Promise<Outcome<{ changes: AccessChange[] }>>;
  /** Add a member, bring back a removed one, or change whether they are an owner. */
  admit(input: AdmitInput): Promise<Outcome<{ created: boolean; owner: boolean }>>;
  /** Remove a member: revoke every grant and refuse them until admitted again. */
  remove(input: RemoveInput): Promise<Outcome<{ revoked: Grant[] }>>;

  /** Sign the head of the app's audit log, if it extends the last one signed. */
  checkpoint(input: CheckpointInput): Promise<Outcome<{ checkpoint: Checkpoint }>>;
  /** The last head signed, and the key to check signatures with. */
  latestCheckpoint(): Promise<{ checkpoint: Checkpoint | null; publicKey: string }>;
  /** A page of the vault's own log, newest first, with its chain verified. Root admins only. */
  log(input: LogInput): Promise<Outcome<LogPage>>;
}

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
  /** The head does not extend the last checkpoint: the app's log was rewritten, or two heartbeats raced. */
  | 'checkpoint_diverged';

export type Outcome<T> = ({ ok: true } & T) | { ok: false; refusal: Refusal };

/**
 * One secret version, as the app names it. The ids bind the key: the vault
 * unwraps under exactly these, so a wrapped key presented as another
 * secret's fails. `path` is only the app's label for the log.
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
type Correlation = { requestId?: string | null };

export type UnwrapInput = Correlation & {
  principal: string;
  purpose: Purpose;
  items: { secret: SecretRef; wrapped: WrappedKey }[];
};

export type WrapInput = Correlation & {
  principal: string;
  /** `key` is a fresh 32-byte data key, base64. */
  items: { secret: SecretRef; key: string }[];
};

export type RewrapInput = Correlation & {
  principal: string;
  /** `secret` is the new version; `from` the version whose key it reuses. */
  items: { secret: SecretRef; from: number; wrapped: WrappedKey }[];
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
  /** `unknown` for someone never admitted. Root admins are always active. */
  status: 'active' | 'removed' | 'unknown';
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

export type RemoveInput = Correlation & { actor: string; principal: string };

export type CheckpointInput = {
  /** The app log's last sequence number, and that row's hash, hex. */
  seq: number;
  headHash: string;
  /**
   * The app log's hash, now, at the last checkpoint's sequence number; null
   * only when the vault has signed nothing yet. The vault signs only a head
   * that still carries the one it signed before, so a log rewritten and
   * re-chained behind the last checkpoint is never signed again.
   */
  previous: { seq: number; hash: string } | null;
};

export type Checkpoint = {
  seq: number;
  headHash: string;
  signedAt: string;
  keyId: string;
  /** Ed25519 over `checkpointMessage(...)`, base64. */
  signature: string;
};

export type LogInput = {
  actor: string;
  /** Entries before this sequence number; the newest when left out. */
  before?: number;
  limit?: number;
};

export type LogEntry = {
  seq: number;
  at: string;
  actor: string;
  action: string;
  outcome: 'allow' | 'refuse';
  code: string | null;
  subject: string | null;
  detail: Record<string, unknown>;
  hash: string;
};

export type LogPage = {
  entries: LogEntry[];
  /** Whether the whole chain, not just this page, recomputes. */
  verification: { ok: true; entries: number } | { ok: false; failedAtSeq: number; reason: string };
};
