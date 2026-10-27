import { createHash } from 'node:crypto';

import type { AccessFault } from './access-fault.ts';
import type { CallerKind, CredentialScope, GrantPlace, InstanceRole, Policy, Role, RoleDefinition, Scope, ServiceSetting } from './access.ts';

export type { CallerKind } from './access.ts';

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
  /**
   * Unwrap data keys for `principal`: all of them, or none. Given the
   * revision of an answer of `access` the app decided the read on
   * (`accessRevision`), only while the principal's access is still that
   * one, under their row and the head the decision holds: otherwise it
   * refuses `access_changed` and logs no read, and says, by naming it back,
   * that it checked. A vault older than 0.14.1 names none: it checked none.
   */
  unwrap(input: UnwrapInput): Promise<Outcome<Unwrapped>>;
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
   * being written again (`invalid`). Except one: a key's current sensitive
   * value made a secret, in place, by an Owner of its project, or of the
   * whole instance, on no credential's scope (`ownsProject`; `not_allowed`
   * for anyone else), its entry saying `was: 'sensitive'`.
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
   * unless the request reads values on an answer it kept (`accessRevision`),
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
   *   unprotected, by an Owner of the project or of the whole instance
   *   (`ownsProject`), as far as that project protected them.
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
    /**
     * `'0.15'` when the vault keeps 0.15's log: the app then writes the
     * changes to its rows through it (`prepare`). Absent before 0.15.
     */
    log?: '0.15';
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
  /**
   * 0.15's use (docs/design/0.15-plan.md, PR 5): one key read on one
   * credential, logged as its request and decided on what one statement
   * read, the value's data key handed back once its entry has committed.
   * Behind the 0.15 switch, which nothing turns on yet: a vault without the
   * hot path's login has none.
   */
  use?(input: UseInput): Promise<UseOutcome>;

  /**
   * 0.15's log (docs/design/0.15-plan.md, "As built: PR 4b"): the changes
   * the app is about to write to objects its own rows hold (credentials,
   * keys, environments), each sealed, as entries the app's transaction
   * commits with its rows (`app_change`, migration 0025), before it asks.
   * The vault reads nothing: it checks each row's columns as the app read
   * them against their seal (`tampered` if the vault never made it), works
   * out the changes that turn them into the columns the app will write, and
   * seals what they leave. Whether each seal is still its object's newest
   * is the transaction's to check, under the fence. Only with 0.15's log on
   * (`about().log`); a vault older than 0.15 has none.
   */
  prepare?(input: PrepareInput): Promise<Outcome<Prepared>>;
  /**
   * Answers once the log's entry `number` is sealed in a signed checkpoint
   * and, if a witness is configured, witnessed or past its 2 s (R51): what a
   * change the app committed waits for before it answers. Only with 0.15's
   * log on.
   */
  waitSealed?(input: { number: string }): Promise<Outcome<{ witnessed: boolean | null }>>;
  /**
   * Check 0.15's log (docs/design/0.15-plan.md, PR 8): both trees from a
   * signed pair, every entry by its MAC and request, the log replayed on
   * from the replay the vault kept there (the newest, unless `from` names
   * another pair, or `start`, the first), and, once a walk reaches the
   * present, every input row and bulk row held to the replay. No more than
   * one walk a call: `next` says where the next stretch goes on. With 0.14's
   * log alone, `kept` false; a vault older than 0.15 has none.
   */
  verifyTrees?(input: TreeVerificationInput): Promise<TreeVerification>;
}

export type TreeVerificationInput = {
  /** The pair to go on from, by the number it seals up to, `start` for the first, or the newest replay kept when absent. */
  from?: string;
};

/**
 * 0.15's log as a walk found it. `problems` names what does not hold, each
 * at its entry where it has one: a checkpoint whose heads the entries do
 * not give, an entry whose MAC fails, a replay fault, a row not the
 * replay's. Numbers are decimal text: the log's are 64-bit.
 */
export type TreeVerification =
  | { kept: false }
  | {
      kept: true;
      ok: boolean;
      problems: string[];
      /** The pair the walk went on from, by its `upto`; null for the first. */
      from: string | null;
      /** The newest pair it walked, and when it was signed (ms); null before the first. */
      checkpoint: { upto: string; at: number } | null;
      /** Pairs walked, entries sealed under them, and entries above the newest. */
      checkpoints: number;
      sealed: number;
      unsealed: number;
      /** Whether it reached the present, its rows held to the replay; else where the next stretch goes on. */
      done: boolean;
      next: string | null;
    };

/**
 * The columns of a row the app writes that a decision of 0.15's reads, as
 * the vault's objects take them (packages/vault/src/objects.ts): times in
 * ms since the epoch, uuids as text, JSON as stored.
 */
export type CredentialColumns = {
  id: string;
  principal: string;
  kind: string;
  /** Its scope as stored, JSON; null for a session's. */
  scope: string | null;
  revoked: boolean;
  /** The earlier of its expiry and its hard end, if any, in whole ms: a stored time's sub-millisecond part dropped, never rounded. */
  expiresAt: number | null;
};

/** One object's change, as the app will write it: its columns before (null: it makes the object), their seal, and after. */
export type ObjectChange =
  | ChangeOf<'credential', CredentialColumns, CredentialColumns>
  /** A key's: null after, archived or erased (no object). */
  | ChangeOf<'secret', SecretColumns, SecretColumns | null>
  | ChangeOf<'environment', EnvironmentColumns, EnvironmentColumns>;

type ChangeOf<K extends string, Before, After> = {
  kind: K;
  id: string;
  /**
   * As the app read the row, with its seal: null for no object (no row, or
   * a key archived); a null seal, a row the vault never sealed (0.14's,
   * before the cutover).
   */
  before: { columns: Before; seal: string | null } | null;
  after: After;
};

/** The version a key's value is: its ids, its nature and its wrapped data key. Never its ciphertext. */
export type VersionColumns = {
  id: string;
  sensitive: boolean;
  /** Whether the value is plain: kept as text, with no data key the vault opens. */
  plain: boolean;
  kekProvider: string;
  kekId: string;
  kekVersion: string;
  /** The wrapped data key, base64. */
  wrappedDek: string;
};

/**
 * A live key's columns (`secrets`): where it is, its current version, or,
 * for a reference, the source its newest `secret_references` row names
 * while it has no version of its own (null for a key with a value).
 */
export type SecretColumns = { id: string; projectId: string; environmentId: string; source: string | null; version: VersionColumns | null };

/** An environment's columns (`environments`). Its slug as stored: a deleted one's carries a tombstone, `dev~deleted-…`. */
export type EnvironmentColumns = {
  id: string;
  projectId: string;
  slug: string;
  owner: string | null;
  parentId: string | null;
  /** Null until the cutover writes it (0022): not protected. */
  protected: boolean | null;
  archived: boolean;
};

export type PrepareInput = {
  /** Who makes the changes, as their entries name them: `user:…`, `token:…`, or the app's own (`coffre`). */
  actor: string;
  changes: ObjectChange[];
};

/**
 * A change sealed, for the app's transaction to commit (`app_change`): its
 * entry's fields, the seal it moves the row from and to, and its MAC, bytes
 * in base64. A row the vault never sealed is the log's to leave alone until
 * the cutover: its call (`requestId` null) only checks, under the fence,
 * that the log has no change of its object either.
 */
export type PreparedChange = {
  kind: ObjectChange['kind'];
  id: string;
  requestId: string | null;
  at: number;
  /** The object's key in the log (`log_object`). */
  object: string;
  actor: string;
  payload: string | null;
  sealFrom: string | null;
  seal: string | null;
  mac: string | null;
};

export type Prepared = { changes: PreparedChange[] };

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
   * A service account asked for a sensitive value to be handed back on a
   * credential no Owner of its project issued (`readsSensitive`, R32): it
   * reads every other value there, and that one once an Owner issues it a
   * token or binding.
   */
  | 'not_owner_issued'
  /**
   * A workload asked for a value its credential does not list where the
   * value is held (`useOnly`) for anything but the proxy's use: to read
   * it, compare a guess with it or copy it, or to make a reference to it.
   * It uses that value through coffre, and never holds it, nor moves it
   * where it would.
   */
  | 'use_only'
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
  /**
   * A read decided on an earlier answer of `access` about its principal
   * (`accessRevision`) that is not theirs now: nothing was read, and no
   * read logged; with a key service, the intent it logged is closed, each
   * key refused.
   * Asked again on the answer now, it is decided as they are now.
   */
  | 'access_changed'
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
 * The credential the request came in on, which the vault decides on, unlike
 * the correlation.
 *
 * `credentialScope` is a service token's or a trust binding's scope: its
 * principal holds nothing past it (`allows`). Null, or left out, for a
 * session's, which carries all its member holds.
 *
 * `caller` is what kind of credential it is (`CallerKind`): a person's, on
 * a `user:` principal; a bearer's or a workload's, on a `token:` one. A
 * workload's comes with its scope, or the vault refuses the call outright,
 * and is handed back only the values the scope lists where each is held
 * (`useOnly`, docs/design/workload-access.md, section 6.1): any other is
 * refused `use_only`. An app older than 0.11 says none, and has no
 * workloads: the vault, deployed first, decides for it as before.
 */
export type Through = { credentialScope?: CredentialScope | null; caller: CallerKind };

export type UnwrapInput = Correlation & Through & {
  principal: string;
  purpose: Purpose;
  /**
   * The revision of the answer of `access` the app decided this read on,
   * kept from an earlier request (`Access.revision`): the vault refuses
   * `access_changed` unless its answer now has the same. Absent when the
   * app asked this request.
   */
  accessRevision?: string;
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
  /**
   * The credential proxy's record of what the values go into, the app's
   * `credential.use` entry: the vault appends it beside its reads, once it
   * releases them, under the log's head it already holds, so that the app
   * takes the head no more for it. Where it was, from where, and its
   * metadata, JSON, as the app wrote them; its actor is `principal`. Named
   * back (`used`) once appended: a vault older than 0.14.5 names nothing,
   * and the app appends it itself.
   */
  use?: UseRecord;
};

/**
 * The longest `UseRecord.metadata` the vault appends, in characters: room for
 * a use naming a few hundred keys. The app appends a longer one itself, under
 * the head, as before 0.14.5.
 */
export const USE_METADATA_LENGTH = 16_384;

/** The app's `credential.use` entry, for the vault to append (`UnwrapInput.use`). */
export type UseRecord = { projectId: string | null; environmentId: string | null; sourceIp: string | null; metadata: string };

/** An unwrap's answer: each item's key, the answer it was decided on, and whether it appended the use it was given. */
export type Unwrapped = { keys: string[]; accessRevision?: string; used?: true };

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
  /**
   * The answer, in a word (`accessRevision`): the app keeps the answer
   * between requests, and a read it decides on the kept one names it, which
   * the vault refuses unless its answer now has the same. Absent from a
   * vault older than 0.14.1, whose answers the app keeps for nothing.
   */
  revision?: string;
};

/**
 * An answer of `access` in a word: equal for two answers that say the same,
 * whatever order the rows came back in, and different for any change to
 * what they say, a grant lapsed, the policy's or the member's.
 */
export function accessRevision(access: Access): string {
  const { revision: _, grants, ...rest } = access;
  const facts = canonical({ ...rest, grants: grants.map(canonical).sort() });
  return createHash('sha256').update(facts).digest('base64url').slice(0, 32);
}

/** A value as JSON whose every object's keys are sorted, at every depth. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value).filter(([, item]) => item !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

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

// --- 0.15's use -------------------------------------------------------------

/** A use as the app asks for it: on which credential, which key, through which place, why, and when. */
export type UseInput = {
  credential: string;
  secretId: string;
  /** The fork an inherited value is read in (`UnwrapInput`'s `through`); null for the key's own environment. */
  place: string | null;
  purpose: Purpose;
  keepsSensitive?: boolean;
  /**
   * The request's id, a whole number below 2^63 as text, unique within its
   * millisecond, and its time, ms since the epoch: a retry of a request
   * whose answer was lost passes both unchanged, and finds the entry the
   * first one wrote (`replayed`).
   */
  requestId: string;
  at: number;
  /** When it must have answered: at most 3 s after `at` (R53). */
  deadline: number;
};

/** Why a use is refused: the rules' codes, and those of sealed inputs. */
export type UseCode =
  | RefusalCode
  /** An input's row is not its object's newest change's: put back from before one, deleted, or written around the log. */
  | 'stale'
  /** The credential is not one, was revoked, or had ended at the request's time. */
  | 'credential'
  /** No such key. */
  | 'missing'
  /** The log holds no policy, so no cap: never served, as the vault writes one before its first use. */
  | 'no_policy';

/** Why a use was not decided at all: the app answers 503, with `Retry-After`. */
export type UseBusy = 'late' | 'overloaded' | 'replayed' | 'ahead' | 'unconfigured';

/** A value a use opened: its data key, base64, and the version it decrypts, with what its ciphertext is bound to. */
export type UsedValue = {
  key: string;
  versionId: string;
  context: { projectId: string; environmentId: string; secretId: string; owner?: string; sensitive?: true };
  envelope: { version: number; ciphertext: string; iv: string; authTag: string };
};

/**
 * A use's answer. Allowed: the value, and the entry it was logged as (or,
 * a repeat, rode on: `covered`). Refused: why, logged as the request it
 * was. Busy: nothing was decided, ask again in `retryAfter` seconds:
 * `late` (past its deadline, or below the floor), `overloaded` (refused at
 * admission), `replayed` (a retry of a call that wrote: the first one's
 * entry stands, its value never left), `ahead` (its time past the
 * database's clock), `unconfigured` (no policy logged yet).
 */
export type UseOutcome =
  | { ok: true; number: string; covered: boolean; value: UsedValue }
  | { ok: false; code: UseCode; number: string | null }
  | { ok: false; busy: UseBusy; retryAfter: number };
