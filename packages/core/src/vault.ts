import { createHash } from 'node:crypto';

import type { AccessFault } from './access-fault.ts';
import type { CredentialScope, GrantPlace, InstanceRole, Policy, Role, RoleDefinition, Scope, ServiceSetting } from './access.ts';

export { checkpointMessage, checkpointVerifier, verifyCheckpoint } from './checkpoint.ts';
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
   * `secret.write` entries name as related. `sensitive` says, per key,
   * whether its wrap binds it as sensitive: a vault older than 0.10 answers
   * none, binding none, and the app stores no sensitive version it wrapped.
   */
  wrap(input: WrapInput): Promise<Outcome<Wrapped>>;
  /**
   * Wrap existing data keys again for new versions of the same secrets,
   * under the current key: restoring an old value, or making one stricter.
   * It needs a write grant, not a read one, since the key never leaves the
   * vault. A new version is never less sensitive than the one it is made
   * from, or than its secret's newest: a value is made looser only by
   * being written again (`invalid`).
   */
  rewrap(input: RewrapInput): Promise<Outcome<Wrapped>>;

  /**
   * Make secrets references to others: whoever can read the holder's
   * environment reads the source through it (docs/design/environments.md).
   * The vault checks that `principal` reads each source and writes each
   * holder, by their own grants, and logs a `reference.create` per item:
   * that entry, under the vault's MAC, is the reference. `seqs` are the
   * entries, which the app stores beside each reference and names when it
   * reads through one (`UnwrapInput`'s `via`). All, or none.
   */
  reference(input: ReferenceInput): Promise<Outcome<{ seqs: number[] }>>;
  /**
   * End references, each with a `reference.end` naming its creation:
   * `replaced` when the holder gets a value of its own, which takes write on
   * the holder; `broken` otherwise, which takes write on the holder, or
   * managing the source's project's access. An ended reference reads no
   * more, whatever any row says. All, or none.
   */
  endReferences(input: EndReferencesInput): Promise<Outcome<{ seqs: number[] }>>;

  /**
   * What one principal holds right now: the app asks once per request,
   * and at sign-in for each verified email. A decision, its rows checked:
   * lists of who holds what read the rows themselves, and need not ask.
   * A person the vault's `owners` names who is no Owner of all of it
   * becomes one here, logged (`reason: 'owners'`).
   */
  access(principal: string): Promise<Access>;
  /**
   * Set roles at several places for one principal: all of it, or none.
   * With `admit`, a service account that is not a member is admitted
   * first, in the same decision, as `admit` would: `admitted` says so.
   */
  setAccess(input: SetAccessInput): Promise<Outcome<{ changes: AccessChange[]; admitted?: Admitted }>>;
  /**
   * Add a member, bring back a removed one, or change a person's instance
   * role and its scope. `generation` is theirs now: sessions and tokens of
   * an earlier one are dead.
   */
  admit(input: AdmitInput): Promise<Outcome<Admitted>>;
  /**
   * Remove a member: revoke every grant and refuse them until admitted
   * again, from `generation` on. An Owner, only an Owner of the whole
   * instance removes, and never the last.
   */
  remove(input: RemoveInput): Promise<Outcome<{ revoked: Grant[]; generation: number }>>;
  /**
   * The instance's settings, as the vault's newest `settings.change` entry
   * says, by its MAC: an entry is where they live, so each change is logged
   * by being made. Everywhere, until someone narrows it.
   */
  settings(): Promise<Settings>;
  /** Change the instance's settings: those who run it, never anyone else. */
  setSettings(input: SetSettingsInput): Promise<Outcome<{ settings: Settings }>>;

  /**
   * The instance's access policy (`Policy` in @coffre/core/access): its
   * roles, as an Owner edited and made them, and its protected
   * environments, as the vault's newest `policy.change` says, by its MAC.
   * As it ships, before any. A vault older than 0.10 has none, and the app
   * decides as it ships.
   */
  policy(): Promise<Policy>;
  /**
   * Change the policy by one change, its own `policy.change` entry, which
   * names it and what it was (docs/design/roles.md):
   * - a project or instance role defined, or put back as it ships (null),
   *   or, one an Owner made, deleted while no grant names it: an Owner of
   *   the whole instance, and never the Owner role, nor the instance's
   *   Member;
   * - environments of one project protected, by whoever manages its
   *   environments, before their rows exist too (a fork's); or
   *   unprotected, by an Owner of the whole instance.
   * The policy after it, and the newest `policy.change`, which it is as of:
   * the change's own, when it changed anything.
   */
  changePolicy(input: ChangePolicyInput): Promise<Outcome<{ policy: Policy; seq: number | null }>>;

  /**
   * Sign the log up to its last entry, in an `audit.checkpoint` entry of
   * the vault's, if the chain recomputes from the last checkpoint, the
   * vault's entries by their MACs, and that checkpoint's prefix is still
   * there, whole. The entry keeps the checkpoint's tally beside it: what a
   * walk from the first entry has gathered by the prefix's end (the
   * vault's keys, its key batches under way, who is a member and what they
   * hold), so that the next checkpoint, and every verification, go on from
   * there and read only what is new. A log longer than one walk, as after
   * an upgrade from 0.10.0, is signed a stretch a call, behind its head,
   * until the checkpoints catch up. Each call also rehashes a stretch of
   * what was signed before, round and round, which an entry edited in place
   * fails: then it refuses, and every verification reports the refusal.
   * A rehash the database fails moves on next time, and `warning` says so;
   * a refusal it would have cleared stands meanwhile. The vault reads the log itself: it takes nobody's word for where
   * it ends, or for what came before. It checks every member's row too, as
   * `access` would, and logs a `vault.tampered` for each one changed around
   * it: lists read rows without asking the vault.
   */
  checkpoint(): Promise<Outcome<{ checkpoint: Checkpoint; warning?: string }>>;
  /**
   * What the vault's configuration says, which the app shows: the keys its
   * checkpoints verify under, by the key id each checkpoint names (the one
   * it signs with now, and those of the KEKs it replaced).
   */
  about(): Promise<{
    checkpointKeys: Record<string, CheckpointKey>;
    /**
     * The emails of those the deployment names Owners of the whole instance
     * (`owners`), lowercased: the vault makes them Owners, and refuses to
     * demote or remove them. Absent from a vault of 0.5, which names none.
     */
    owners?: string[];
    /**
     * @deprecated Always empty: an app of 0.5, deployed after this vault,
     * lists and checks root admins here until it is. Gone in 0.7.
     */
    rootAdmins: [];
  }>;
  /**
   * What an escrowed vault key is checked against: the vault key it wraps
   * under now, and each one's check, as the vault wrote it. None of it is
   * secret, and the vault answers no guess: a check opens only under its key.
   */
  keyChecks(): Promise<KeyChecks>;
  /**
   * Check the log from a checkpoint's tally, the newest unless `from`
   * names another, or the first entry: the vault's entries since by their
   * MACs, every checkpoint among them against the prefix it signed, the key
   * batches accounted for, and the members and grants replayed on from the
   * tally to see that the rows follow. With `to`, a later checkpoint, the
   * walk stops at the prefix it signed and must come to the tally it keeps:
   * a stretch of the whole log, walked from the first entry a stretch at a
   * time. The links and hashes of the chain are the caller's to recompute
   * through `upTo`, as the app does first; with none, the vault recomputes
   * them itself, no further than one walk. A verdict and nothing else, so
   * anyone may ask; the app asks for those who read the whole log
   * (`readsWholeLog`).
   */
  verifyLog(input: VerifyLogInput): Promise<LogVerification>;
}

/**
 * The vault's entries that change what a member holds: what their row's
 * `access_seq` names, and what a finding about them is newer than while it
 * stands.
 */
export const ACCESS_ACTIONS = ['member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke'] as const;

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
  /** The wrapped key does not belong to the secret it was presented as, or a reference is not the vault's. */
  | 'bad_claim'
  /**
   * A person asked for a sensitive value to be handed back (`handsBack`):
   * nobody sees one, Owners included. Their apps use it through the
   * credential proxy, and service accounts read it.
   */
  | 'sensitive'
  /**
   * The project or environment was deleted for good: nothing under it is
   * opened or wrapped again, whatever grant would cover it.
   */
  | 'deleted'
  /** The reference read through was ended: broken, or replaced by a value. */
  | 'ended'
  /**
   * A personal config's value, which only its owner opens or writes, and
   * only while they read the environment it is a config of: no grant or
   * role reaches it, an Owner's included. Nor does any reference.
   */
  | 'personal'
  /** Not allowed to manage access, members or the log. */
  | 'not_allowed'
  /**
   * The change would leave the instance without an Owner of all of it: the
   * last one is not demoted, narrowed or removed, by anyone, until another
   * is made.
   */
  | 'last_owner'
  /** Well-formed, but not something the rules allow: a project role on an environment, a service account with an instance role. */
  | 'invalid'
  /**
   * A change to the policy weighed from one revision of it (`revision`)
   * when another came since: asked again, it is weighed as the policy is now.
   */
  | 'policy_changed'
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
  /**
   * Whether the version is sensitive: its value is never handed back to a
   * person, on any credential of theirs, only used for them or read by a
   * service account. Its data key's wrap binds it, so a version written
   * sensitive opens as nothing else. Absent, or false, for a secret or a
   * plain value.
   */
  sensitive?: boolean;
};

/** What a wrap or rewrap answers: each key as wrapped, its entry, and whether its wrap binds it sensitive. */
export type Wrapped = { wrapped: WrappedKey[]; seqs: number[]; sensitive: boolean[] };

/** A wrapped data key and the key encryption key that wrapped it; `bytes` is base64. */
export type WrappedKey = { kekProvider: string; kekId: string; kekVersion: string; bytes: string };

/**
 * The vault key the vault wraps under now, by provider and ID, and each
 * vault key's check, newest first: a known value wrapped under it
 * (`KEY_CHECK_VALUE` in `@coffre/core/kek`), in its newest `key.check`
 * entry that carries the vault's MAC, at `seq`.
 */
export type KeyChecks = { current: { kekProvider: string; kekId: string }; checks: (WrappedKey & { seq: number })[] };

/**
 * Why someone reads: shown in the log, and the same rules apply to each. A
 * fork reads to `copy`. The credential proxy reads to `use`, a value it
 * injects into a request and never hands back, or to `expose`, one it
 * gives a person's app as it is (`coffre run`'s plan).
 */
export type Purpose = 'reveal' | 'run' | 'compare' | 'copy' | 'use' | 'expose';

/**
 * Whether a read hands values back to whoever asked, which a person never
 * gets of a sensitive value: every purpose but the proxy's `use` and a
 * fork's `copy` that keeps them sensitive (`keepsSensitive`), a dry run's
 * `compare` included, which tells them whether a guess was right, and any
 * purpose a later app may name.
 */
export function handsBack(read: { purpose: string; keepsSensitive?: boolean }): boolean {
  if (read.purpose === 'use') return false;
  return !(read.purpose === 'copy' && read.keepsSensitive === true);
}

/** Ties the vault's entries to the app's request and audit rows. */
type Correlation = {
  requestId?: string | null;
  /**
   * The one action the call is part of, the app's id for it: a reveal's
   * reads, a write's versions, an access change. Its entries share it.
   */
  operationId?: string | null;
  /**
   * The credential the request came in on, when a trust binding issued it
   * for a CI run: the vault copies it into the entries it writes, and never
   * decides on it, so that a read leads back to its run (docs/design/oidc.md).
   */
  credentialId?: string | null;
};

/**
 * The scope of the credential the request came in on, a service token's or
 * a trust binding's: unlike the correlation, the vault decides on it, and
 * its principal holds nothing past it (`allows`). Null, or left out, for a
 * session's, which carries all its member holds.
 */
export type Through = { credentialScope?: CredentialScope | null };

export type UnwrapInput = Correlation & Through & {
  principal: string;
  purpose: Purpose;
  /**
   * That a `copy` keeps each sensitive value sensitive in what it writes:
   * the vault opens a sensitive value to copy for a person only when told
   * so, which an app older than 0.10, that would write it as a secret
   * anyone with read sees, never says.
   */
  keepsSensitive?: boolean;
  /**
   * `via` reads a source's current version through a reference: the vault
   * checks the reader's grants on the holder's environment, as its
   * `reference.create` entry names it, not on the source's. `through`, an
   * environment's id, is the fork an inherited value is read in: the vault
   * logs the read there too, and decides on the value's own environment.
   */
  items: { secretVersionId: string; via?: Via; through?: string }[];
};

/** A reference, as a read names it: its id, and the seq of the vault's `reference.create` entry. */
export type Via = { reference: string; seq: number };

/** Where a reference is held: the holder's ids, and its path for the log. A new holder's row may not exist yet. */
export type HolderRef = { projectId: string; environmentId: string; secretId: string; path: string };

export type ReferenceInput = Correlation & Through & {
  principal: string;
  /** `id` is the reference's, a fresh UUID; the vault reads the source by its id. */
  items: { id: string; holder: HolderRef; source: { secretId: string } }[];
};

export type EndReferencesInput = Correlation & Through & {
  principal: string;
  /** `abandoned`: sealed for a write that stored nothing, so that no row written later revives it. */
  reason: 'replaced' | 'broken' | 'abandoned';
  items: Via[];
};

export type WrapInput = Correlation & Through & {
  principal: string;
  /** `key` is a fresh 32-byte data key, base64. */
  items: { secret: SecretRef; key: string }[];
};

export type RewrapInput = Correlation & Through & {
  principal: string;
  /** `secret` is the proposed new version; `secretVersionId` is the stored source. */
  items: { secret: SecretRef; secretVersionId: string }[];
};

/**
 * A grant: on a project, or one of its environments (`projectId` is the
 * environment's project; `GrantPlace` in @coffre/core/access).
 */
export type Grant = GrantPlace & {
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
   */
  status: 'active' | 'removed' | 'unknown' | 'tampered';
  /** Advanced by removal, even if the app cannot commit its credential revocations. */
  generation: number;
  /**
   * Their instance role and its scope, while active: `member` everywhere
   * for service accounts and anyone not active. Scopes name projects by id.
   */
  role: InstanceRole;
  scope: Scope;
  /** Live grants only, and none unless active. */
  grants: Grant[];
  /** When the status last changed, and who changed it; null for strangers. */
  since: string | null;
  by: string | null;
  /** The instance's policy, which every decision about them reads: absent from a vault older than 0.10, which decides as it ships. */
  policy?: Policy;
};

/**
 * One place: a role to hold there, with an optional end, or null for none.
 * An environment's place names its project too.
 */
export type GrantChange = GrantPlace & {
  role: Role | null;
  expiresAt: string | null;
};

export type AccessChange = 'created' | 'updated' | 'revoked' | 'unchanged';

export type SetAccessInput = Correlation & Through & {
  actor: string;
  principal: string;
  changes: GrantChange[];
  /**
   * Admit the principal, a service account, unless it is a member: a
   * grant refused admits nobody. A vault older than this refuses one that
   * is not a member, `not_a_member`, and admits nobody either.
   */
  admit?: boolean;
};

export type AdmitInput = Correlation & Through & {
  actor: string;
  principal: string;
  /**
   * A person's instance role, and where it applies (everywhere, left out).
   * Left out, an existing member keeps theirs and a new one is a `member`.
   * Changing it takes someone who runs the instance, about someone else;
   * making someone an Owner, or changing an Owner's, an Owner of the whole
   * instance, who may change their own too. It never leaves the instance
   * without an Owner of all of it (`last_owner`), nor demotes one the
   * deployment names (`owners`; `not_allowed`).
   */
  role?: InstanceRole;
  scope?: Scope;
};

/** A member as `admit` left them; `created` when they were not one before. */
export type Admitted = { created: boolean; role: InstanceRole; scope: Scope; generation: number };

export type RemoveInput = Correlation & Through & {
  actor: string;
  principal: string;

};

/** What the instance's settings hold. */
export type Settings = {
  /** Where people set up service accounts themselves (`ServiceSetting` in @coffre/core/access), projects by id. */
  serviceAccounts: ServiceSetting;
};

export type SetSettingsInput = Correlation & Through & {
  actor: string;
  settings: Settings;
};

/** One change to the policy (`changePolicy`). */
export type PolicyChange =
  | { kind: 'role'; role: Role; definition: RoleDefinition | null }
  | { kind: 'instance-role'; role: InstanceRole; definition: RoleDefinition | null }
  | { kind: 'protect'; projectId: string; environmentIds: string[]; protected: boolean };

/**
 * A policy's revision, as a decision made from it names it: its newest
 * `policy.change` (null for none), and the slug of each environment it
 * protects, by id, which a scoped instance role's filters match, and
 * which a rename or a deletion changes with no `policy.change` of its own
 * (docs/design/roles.md, "What changes the policy"). Equal revisions decide
 * alike.
 *
 *   57.3f9a0c2e81b4d7a6   change 57, prod protected as `prod`
 *   57.b20e94d1c6a8f305   change 57, prod renamed `staging`
 */
export function policyRevision(seq: number | bigint | null, policy: Pick<Policy, 'protectedIn'>): string {
  const places = Object.values(policy.protectedIn).flat()
    .map(({ environmentId, slug }) => `${environmentId}=${slug ?? ''}`)
    .sort();
  return `${seq === null ? 'none' : String(seq)}.${createHash('sha256').update(places.join('\n')).digest('hex').slice(0, 16)}`;
}

/** A revision as `policyRevision` writes it. */
export const POLICY_REVISION = /^(none|[1-9][0-9]{0,15})\.[0-9a-f]{16}$/;

export type ChangePolicyInput = Correlation & Through & {
  actor: string;
  change: PolicyChange;
  /**
   * The policy the caller decided from, as its revision
   * (`policyRevision`): its newest `policy.change` and the rows of the
   * environments it protects. Refused, `policy_changed`, unless the policy
   * under the vault's head is still that one, so that a request carries on
   * from the policy it made (`seq`) only where nothing came between, and a
   * change previewed is made as previewed. Unchecked when absent.
   */
  revision?: string;
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
   * The last entry the app verified, every link and hash up to it
   * recomputed and its own entries checked by its key: the vault checks the
   * log still holds it, so between them both authors' entries are
   * authenticated over the same stretch, and the vault leaves the links to
   * the app.
   */
  upTo?: LogHead | null;
  /**
   * Where the vault's walk starts: the seq of one of its `audit.checkpoint`
   * entries that keeps a tally, or `start`, the first entry. The newest
   * such checkpoint when absent, and a vault older than 0.10.1 walks from
   * the first entry whatever it says.
   */
  from?: number | 'start';
  /**
   * A later checkpoint's entry, whose prefix `upTo` is: the walk ends
   * there, and must come to the tally it keeps. The members' rows and the
   * key batches are as they are now, not then, so only a walk without one
   * holds them to the log.
   */
  to?: number;
};

/**
 * Whether the vault's log holds, with the number of its entries through
 * where the walk ended, `through`: `upTo`, the prefix `to` signed, or as
 * far as one walk goes. On a failure, the entry where it breaks, or null
 * when the chain holds but the members and grants do not follow from it.
 * Then `fault` says which, as facts the app can word with names: `reason`
 * has only ids. A walk that ends at the present reports live key batches in
 * `pending`; overdue ones fail.
 */
export type LogVerification =
  | { ok: true; entries: number; pending?: number; through?: number }
  | { ok: false; failedAtSeq: number | null; reason: string; fault?: AccessFault };
