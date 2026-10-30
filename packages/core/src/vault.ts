import { createHash } from 'node:crypto';

import type { AccessFault } from './access-fault.ts';
import type { CallerKind, CredentialScope, GrantPlace, InstanceRole, Policy, Role, RoleDefinition, Scope, ServiceSetting } from './access.ts';

export type { CallerKind } from './access.ts';

export { checkpointMessage, checkpointVerifier, verifyCheckpoint } from './checkpoint.ts';
export { describeAccessFault, type AccessFault, type FaultGrant, type FaultNames } from './access-fault.ts';
export {
  answerFrom,
  CLOSED_POLICY,
  CLOSED_SETTINGS,
  DEFAULT_SETTINGS,
  live,
  livePolicy,
  NO_EDITS,
  policyFrom,
  PRINCIPAL,
  readEdits,
  roleOf,
  settingsFrom,
  view,
  type GrantFacts,
  type MemberFacts,
  type PolicyEdits,
  type PolicyEnvironment,
  type ProtectedPlace,
} from './answers.ts';

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
    /**
     * `true` when the vault also answers 0.15's uses (`use`): its log is
     * 0.15's and it has the hot path's login. The app then opens each value
     * through a use (docs/design/0.15-plan.md, PR 5b). Absent otherwise.
     */
    uses?: true;
    /**
     * `true` when the vault also answers a request's several keys in one call (`useMany`; T167). Said here, as a
     * Worker's stub answers any method's name: a vault older than this app, mid-deploy, says nothing, and the app makes
     * a use a key. Absent otherwise.
     */
    batchUses?: true;
    /**
     * `true` when the vault makes sign-ins through trust bindings and revokes
     * credentials itself (`signIn`, `revokeCredential`; T149): its log is
     * 0.15's. Said here, as a Worker's stub answers any method's name.
     * Absent otherwise.
     */
    credentials?: true;
    /** `true` when the vault issues tokens itself too (`issueToken`; T149, PR 2). Absent otherwise. */
    issues?: true;
    /** `true` when the vault makes and ends trust bindings itself, and signs in through none it did not seal (`changeBindings`; T149, PR 3a). Absent otherwise. */
    binds?: true;
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
   * Behind the 0.15 switch: the app opens each value through it when the
   * vault says so (`about().uses`). A vault without the hot path's login
   * has none.
   */
  use?(input: UseInput): Promise<UseOutcome>;

  /**
   * 0.15's use as the request names it, one call (T145, PR B; formal/Probing.tla): the vault finds the ids of what it
   * names, from its own cache or with one read on a miss, uses the key by them, and answers with the rows the app checks
   * (`NamedUseOutcome.app`) and what it decided the caller holds (`standing`). A key the place does not hold, and a plain
   * value, it decides on the caller's standing there, logging nothing. Absent from a vault without 0.15's uses.
   */
  useNamed?(input: NamedUseInput): Promise<NamedUseOutcome>;

  /**
   * A request's several keys as one call (T167, B2; formal/Batching.tla): each key's use made as `use` makes it, in the
   * request's order, in one statement, and decided on what it read; a second call, only once every key is allowed, for
   * those that take the principal's lock. All or nothing: every value, or the first key refused, or busy. Absent from a
   * vault without 0.15's uses (`about().batchUses` says whether it has it).
   */
  useMany?(input: UseManyInput): Promise<UseManyOutcome>;

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
   * 0.15 (T149, D146; docs/design/credential-lifecycle.md): a sign-in
   * through a trust binding, a CI run's or a workload's, made by the vault
   * in one statement (`sign_in`, migration 0034; formal/Lifecycle.tla).
   * The app verifies the proof and names the binding as it read it; the
   * vault makes the credential's object from those columns, and the
   * statement goes ahead only while they are the binding's row, its
   * account active at its generation, its rate not spent and the token
   * not, under their locks: the issue lock, never the fence, so no use
   * waits on it (R58), and no 0.14 head. No 0.14 entry either: the change
   * records the sign-in (D147). Answers once it is sealed (R51). Only with
   * 0.15's log on.
   */
  signIn?(input: SignInInput): Promise<SignInOutcome>;
  /**
   * 0.15 (T149): a credential revoked by the vault in one statement
   * (`revoke_credential`, migration 0034), from its columns as the app
   * read them and their seal: under its row's lock and the fence, held for
   * the statement's work alone (RevokeTakesFence). The app has weighed who
   * may. Answers once sealed (R51). Only with 0.15's log on.
   */
  revokeCredential?(input: RevokeCredentialInput): Promise<RevokeCredentialOutcome>;
  /**
   * 0.15 (T149, PR 2): a token issued by the vault, which weighs it itself
   * (`issue_token`, migration 0036; formal/Lifecycle.tla's issue): a
   * service account's token, a person's personal token, or a handle. The
   * app names the scope it worked out and the row it would hand out; the
   * vault reads the issuer, the account and the credential the request came
   * in on, decides with the rules of `@coffre/core/access` whether the
   * issuer may give that scope (R15, R32), and then writes it in one
   * statement that holds those rows shared and goes ahead only while they
   * are as it read them (IssuerLocked, IssuerCAS). Nothing held between
   * the two; the issue lock, never the fence (R58). Answers once sealed.
   */
  issueToken?(input: IssueTokenInput): Promise<IssueTokenOutcome>;
  /**
   * With 0.15's log, a service's trust bindings changed by the vault itself
   * (T149, PR 3a; D148): the binding a manager makes, weighed as a service
   * token's issue is (who may give the account that scope, R15, R32), and
   * those it replaces ended, with the credentials each issued; or, making
   * none, an unbind. One statement, which holds what it read as read;
   * answers once sealed. A sign-in takes only a binding the vault sealed.
   */
  changeBindings?(input: ChangeBindingsInput): Promise<ChangeBindingsOutcome>;
  /**
   * 0.15's cutover from 0.14 (docs/design/0.15-plan.md, PR 9;
   * formal/Migration015.tla): once, before 0.15's log serves anything, every
   * object 0.14 left sealed as 0.14 accepts it (`genesis`), and the log's
   * first `cutover` change naming 0.14's last head (the anchor). Without
   * `input`, whether it is done, and if not, where 0.14's chain is
   * verified from (its newest checkpoint's prefix), for the app to check
   * its own entries from there. With `input`, what the app vouches for under
   * its key, which the vault never holds: it holds each row to it under its
   * locks. Once done, done for good: a second call finds the marker.
   */
  cutover?(input?: CutoverInput): Promise<CutoverOutcome>;
  /**
   * Check 0.15's log (docs/design/0.15-plan.md, PR 8), as the audit page
   * does on every visit: the newest signed pair, held to the pairs held
   * outside, and every entry after it by its MAC and request, a tick's
   * worth (R25). Nothing walks the whole log on a request (D145). With
   * 0.14's log alone, `kept` false; a vault older than 0.15 has none.
   */
  verifyTrees?(): Promise<TreeVerification>;
}

/**
 * 0.15's log as its check found it. `problems` names what does not hold,
 * each at its entry where it has one: a checkpoint not signed, or not the
 * one held outside; an entry whose MAC fails, or under another's request.
 * Numbers are decimal text: the log's are 64-bit.
 */
export type TreeVerification =
  | { kept: false }
  | {
      kept: true;
      /** Checked to the head, and nothing wrong found. */
      ok: boolean;
      problems: string[];
      /** The newest pair checked, and when it was signed (ms); null before the first. */
      checkpoint: { upto: string; at: number } | null;
      /** The entries above the newest pair it checked. */
      unsealed: number;
      /**
       * Whether more lie there than a check reads (`ABOVE_NEWEST`, 2,000): a
       * checkpointer behind. Not checked to the head, so `ok` is false; no
       * problem either, and never a break of the log.
       */
      capped: boolean;
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
  /** Its account's generation when it was issued (`credentials.generation`). */
  generation: number;
};

/**
 * An MCP connection's (`mcp_connections`), as its object takes them (T147):
 * whose it is, at which generation of their account it was approved, its
 * end, and whether it was revoked. What a refresh moves (its tokens' hashes)
 * and its last use are no part of it.
 */
export type ConnectionColumns = {
  id: string;
  principal: string;
  generation: number;
  /** Its `expires_at`, in whole ms: a stored time's sub-millisecond part dropped, never rounded. */
  expiresAt: number;
  revoked: boolean;
};

/** One object's change, as the app will write it: its columns before (null: it makes the object), their seal, and after. */
export type ObjectChange =
  | ChangeOf<'credential', CredentialColumns, CredentialColumns>
  | ChangeOf<'connection', ConnectionColumns, ConnectionColumns>
  /**
   * A key's: null after, archived or erased (no object). `restores`: an
   * archived key unarchived, `after` its rows as read: the vault holds them
   * to the object its log last sealed, and refuses another (`stale`).
   */
  | (ChangeOf<'secret', SecretColumns, SecretColumns | null> & { restores?: true })
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

/** The version a key's value is: its ids, its nature and its wrapped data key; a plain one's text. Never its ciphertext. */
export type VersionColumns = {
  id: string;
  sensitive: boolean;
  /** A plain value's text, which it is (no data key the vault opens); null for any other. Its object holds its digest. */
  plaintext: string | null;
  kekProvider: string;
  kekId: string;
  kekVersion: string;
  /** The wrapped data key, base64. */
  wrappedDek: string;
};

/**
 * A live key's columns (`secrets`): where it is, its current version, or,
 * for a reference, the source its newest `secret_references` row names
 * while it has no version of its own, and that row's id (both null for a
 * key with a value, and for one whose newest reference row has ended:
 * `ended_at`).
 */
export type SecretColumns = { id: string; projectId: string; environmentId: string; source: string | null; reference: string | null; version: VersionColumns | null };

/** An environment's columns (`environments`). Its slug as stored: a deleted one's carries a tombstone, `dev~deleted-…`. */
export type EnvironmentColumns = {
  id: string;
  projectId: string;
  slug: string;
  owner: string | null;
  parentId: string | null;
  /** Null until the cutover writes it (0022): not protected. */
  protected: boolean | null;
  /** Its own `archived_at`. */
  archived: boolean;
  /** Its project's: 0.14 takes an environment of an archived project as archived. */
  projectArchived: boolean;
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
  /** An unarchive's: the seal of the object it restores, which must still be its log's newest sealed one; else null. */
  restores: string | null;
};

export type Prepared = { changes: PreparedChange[] };

/**
 * A sign-in through a trust binding (`Vault.signIn`). Times in ms since the
 * epoch, bytes in base64.
 */
export type SignInInput = {
  /** The account it signs in as, `token:<id>`. */
  principal: string;
  /**
   * The binding as the app read it, with its seal: the vault decides only
   * on one whose seal is its own (PR 3a), and the statement holds the row
   * to it and to its object's newest change.
   */
  binding: { columns: BindingColumns; seal: string | null };
  /** The credential the app hands out once made: its row, the app's MAC over it (`auth_mac`) with it. */
  credential: SignInCredential;
  /** The id of the app's log key, under whose key the MAC was made: refused once the app has rotated from it (`retired`). */
  appKey: string;
  /** The ID token's signing input's hash, spent once; null for a proof that spends none. */
  spent: string | null;
  /**
   * The last instant the proof holds by its own times, ms (an ID token's
   * `exp` and its `iat`'s hour, each with their tolerance): checked again
   * in the statement, by the database's clock. Null: its credential's
   * `notAfter` bounds it.
   */
  validUntil: number | null;
  /** What the change records of the sign-in besides (D147): the proof, its issuer, and the run's claims. */
  record: { proof: string; issuer: string; run: Record<string, string | number> };
  /**
   * The run's ID token, for the vault to verify itself (D148, PR 3b), when
   * its sealed binding carries the issuer's keys (its `jwksUri` their
   * digest, as a Kubernetes cluster's does), with those keys as its row
   * keeps them; the vault then takes `spent`, `validUntil` and `record.run`
   * from the token, not from the app. Null for a binding of keys its issuer
   * publishes, which the vault does not fetch (it asks no issuer anything),
   * and for a proof that is no ID token (an AWS signed request):
   * the app verifies those, so a compromised app could sign a run in
   * through such a binding, within its limits.
   */
  idToken: { token: string; jwks: string } | null;
  /** A workload's DPoP proof, whose key the session is bound to, which the vault verifies; null for a CI run's sign-in. */
  dpop: string | null;
};

/**
 * A trust binding's columns as its object takes them (T149, PR 3a): what a
 * sign-in through it decides on. Its keys by `jwksUri` (the issuer's
 * discovered URL, or `sha256:<hex>` of keys uploaded with it); its claims
 * and policy as the row keeps them, canonical JSON.
 */
export type BindingColumns = {
  id: string;
  principal: string;
  generation: number;
  profile: string;
  issuer: string;
  /**
   * The instance's public URL it was made on (PR 3b): its base audience, as
   * a token for it must name it (`expectedAudiences`), and where a workload's
   * DPoP proof is signed for. No column: the app names it, and the seal
   * holds it, so a binding of another URL's is none of this instance's.
   */
  origin: string;
  jwksUri: string;
  claims: string;
  scope: string | null;
  policy: string | null;
  revoked: boolean;
};

/** A binding the vault makes (`changeBindings`): its object's columns and the rest of its row, with the app's MAC over it. */
export type MadeBinding = BindingColumns & { jwks: string | null; label: string | null; createdBy: string; createdAt: number; authMac: string };

/** A binding a change ends: as the app read it, with its seal and MAC, the app's MAC over it revoked, and the credentials it issued that are live. */
export type EndedBinding = {
  /** Its seal null for one 0.14 made, which the log never held: ended all the same, its row revoked with no change. */
  before: { columns: BindingColumns; seal: string | null };
  authMacFrom: string;
  authMac: string;
  /**
   * Every live credential it issued, each as `revokeCredential` names one: the statement holds the set to the rows. One
   * with no seal (0.14's, or written around the vault) is ended all the same, its row revoked with no change.
   */
  credentials: { before: { columns: CredentialColumns; seal: string | null }; authMacFrom: string; authMac: string }[];
};

export type ChangeBindingsInput = {
  /** Who changes them, as its entry names them. */
  actor: string;
  /** The credential the request came in on, by id; null for none. */
  via: string | null;
  /** The issuer's access as the app weighed the scope on (`access_seq`), decimal; null when it weighed none. */
  actorAccess: string | null;
  /** The MCP connection the request came through, at the caller's generation, held to still connected; null for none. */
  connection: { id: string; generation: number } | null;
  /** The binding it makes; null for an unbind. Its account at its generation, as its columns name them. */
  make: MadeBinding | null;
  /** With a binding made, the account's live bindings as the app read them, by id, which it was weighed beside; else null. */
  live: string[] | null;
  /** The keys a binding made reads (its policy's `reads`), by id and the name they were asked by: none moves before the write. */
  reads: { id: string; key: string }[];
  /** The bindings it ends: those the new one replaces, or the one unbound. */
  ends: EndedBinding[];
  /** Why they end, for the changes' record. */
  reason: 'replaced' | 'keys_moved' | 'unbound';
  revokedAt: number;
  revokedBy: string;
  /** The policy the app weighed on: the newest `policy.change`'s seq and the protected environments' slugs. */
  policy: { seq: string | null; protected: { environmentId: string; slug: string | null }[] };
  appKey: string;
};

/**
 * Why bindings were not changed, nothing written: as an issue's
 * (`IssueTokenRefusal`); `stale` or `tampered`, a row the log does not
 * hold as its newest (put back) or not the vault's seal; `unlogged`, the
 * credential the request came in on one 0.14 made (a binding 0.14 made,
 * the vault ends itself, with no change);
 * `full`, the account holds as many live bindings as one may
 * (`MAX_BINDINGS`), besides those the change ends.
 */
export type ChangeBindingsRefusal = IssueTokenRefusal | 'stale' | 'tampered' | 'full';

/** A point of 0.14's chain: an entry's number and its hash (hex); `-1` and the zero hash before the first. */
export type ChainMark = { seq: string; hash: string };

/**
 * What the app vouches for, of 0.14's, at the cutover (`Vault.cutover`):
 * what 0.14 accepts that only the app's key says, each checked as 0.14's
 * app checks it.
 */
export type CutoverInput = {
  /**
   * The stretch of 0.14's chain whose app entries the app checked by their
   * MACs, every link included: from where the vault said it verifies from,
   * to the head as the app read it. An app entry after `to` sends the
   * cutover back to the app (`moved`).
   */
  checked: { from: ChainMark; to: ChainMark };
  /**
   * Each credential 0.14 accepts as it stands, its object's columns as
   * read: its MAC the app's, not revoked nor past its end, its sign-in
   * account not unlinked, and no revoke of it in the log (`token.revoke`,
   * `sign_out`). One a binding issued is left out: 0.14 reads its scope
   * from the binding, so its row holds none to seal.
   */
  credentials: CredentialColumns[];
  /** Each trust binding 0.14 accepts as it stands: its MAC the app's, not revoked, and no `token.unbind` of it. */
  bindings: BindingColumns[];
  /** Each MCP connection 0.14 accepts as it stands (T147): its MAC the app's, not revoked nor past its end. */
  connections: ConnectionColumns[];
  /** Each place 0.14's chain deleted, by an authentic `project.delete` or `environment.delete`, with the tombstone it gave the slug. */
  deleted: { kind: 'project' | 'environment'; id: string; tombstone: string }[];
};

/**
 * The cutover's answer: done (now, or before); not yet, with where 0.14's
 * chain is verified from; `moved`, a 0.14 write since the app read what it
 * vouched for (ask again); `refused`, 0.14's chain or rows not as 0.14
 * accepts them, which a cutover does not seal (an operator's to look at).
 */
export type CutoverOutcome =
  | { ok: true; done: true }
  | { ok: true; done: false; from: ChainMark }
  | { ok: false; refused: 'moved' | 'refused'; why: string };

export type ChangeBindingsOutcome = { ok: true; number: string; witnessed: boolean | null } | { ok: false; refused: ChangeBindingsRefusal; why?: string };

/** The row a sign-in writes (`credentials`): a service's credential for a CI run, or a workload's key-bound session. */
export type SignInCredential = {
  id: string;
  kind: 'service' | 'workload';
  tokenHash: string;
  tokenHint: string;
  label: string | null;
  scope: string | null;
  places: string | null;
  expiresAt: number;
  notAfter: number | null;
  jkt: string | null;
  authMac: string;
};

/**
 * Why a sign-in made nothing, the statement's own words: the account or
 * the binding not as named, frozen, its rate spent (or a lock not had in
 * time), its times past or too far, the token spent, the app's key one it
 * rotated from.
 */
/** Why a sign-in made nothing; `unsealed`: its binding is none the vault sealed (one 0.14 made, or a row not its object), which signs nobody in (PR 3a). */
export type SignInRefusal = 'unbound' | 'frozen' | 'busy' | 'expired' | 'replayed' | 'retired' | 'unsealed' | 'proof';

/**
 * A sign-in's answer. `proof`: the vault's check of the token or the DPoP
 * proof refused it, `reason` saying why as the app's refusals do
 * (`ExchangeReason`), and a key the binding's uploaded set lacks naming
 * it (`kid`).
 */
export type SignInOutcome =
  | { ok: true; number: string; witnessed: boolean | null }
  | { ok: false; refused: Exclude<SignInRefusal, 'proof'> }
  | { ok: false; refused: 'proof'; reason: string; message: string; kid: string | null };

/** A token the vault issues (`Vault.issueToken`). Times in ms since the epoch, bytes in base64. */
/**
 * What the app's entry would name a request by, which a change's record
 * keeps for the audit pages where 0.14's entry stood (D147, T164): the
 * credential or MCP connection whose act it was, as an entry's
 * `credentialId` (a run's credential, a personal token, an app connected
 * through MCP); and, through MCP, the app and the approval, as its `via`.
 * The app's word, which the vault records and never weighs.
 */
export type RequestTrace = {
  credentialId: string;
  mcp: { connectionId: string; clientId: string; clientName: string; approvalId: string | null } | null;
};

export type IssueTokenInput = {
  /** Who issues it, `user:…` or `token:…`: the request's caller. */
  actor: string;
  /** The credential the request came in on, by id; null for none (a request the app made itself). */
  via: string | null;
  /** Whose act it was, for its change's record (`RequestTrace`); none for a request on no such credential. */
  trace?: RequestTrace | null;
  /** Whom it acts as: a service account's `token:<id>`, or the actor, for a personal token or a handle. */
  principal: string;
  /** The principal's generation it is issued at. */
  generation: number;
  /**
   * The issuer's access the app weighed the scope on: the vault's newest
   * access entry about them (`issuerNow`), which the vault holds the issue
   * to (`access`, as `issuerStill`); null to hold it to none.
   */
  actorAccess: string | null;
  credential: IssuedTokenRow;
  /** The policy the app weighed the scope on: its newest `policy.change`, and the environments it protected (`policyStill`'s). */
  policy: { seq: string | null; protected: { environmentId: string; slug: string | null }[] };
  /** The id of the app's log key, under whose key the row's MAC was made (`SignInInput.appKey`). */
  appKey: string;
};

/** The row a token's issue writes (`credentials`). */
export type IssuedTokenRow = {
  id: string;
  kind: 'service' | 'personal' | 'handle';
  tokenHash: string;
  tokenHint: string;
  label: string | null;
  /** Its scope as stored (`storedScope`): what the vault weighs, and seals. */
  scope: string;
  /** A handle's environments, as made for; null for any other. */
  places: string | null;
  expiresAt: number;
  /** Who issued it, as its row names them: the actor's id. */
  createdBy: string;
  authMac: string;
};

/**
 * Why a token was not issued, the vault's own words: the issuer may not
 * give that scope, or that kind of token (`refused`); the credential the
 * request came in on, or the issuer, ended (`ended`); the account it is for
 * is not the member it was weighed as (`gone`); the issuer's access moved
 * since the app weighed it (`access`); what it was weighed on moved
 * while it was written, each of the three times the vault weighed it
 * (`moved`), or the policy did (`policy`); a lock not had in time
 * (`busy`); the app's key one it rotated from (`retired`); the credential
 * the request came in on one 0.14 made, which the log never held, so
 * nothing the vault could authenticate (`unlogged`: the app issues on it
 * as before).
 */
export type IssueTokenRefusal = 'refused' | 'ended' | 'gone' | 'access' | 'moved' | 'policy' | 'busy' | 'retired' | 'unlogged';

export type IssueTokenOutcome = { ok: true; number: string; witnessed: boolean | null } | { ok: false; refused: IssueTokenRefusal; why?: string };

/** A revoke (`Vault.revokeCredential`): the credential as the app read it, and the app's MACs over its row before and after. */
export type RevokeCredentialInput = {
  /** Who revokes it, as its entry names them: `user:…`, `token:…`, or the app's own (`coffre`). */
  actor: string;
  /** Its object's columns as read, and their seal: a row the log holds (one 0.14 made, with none, the app revokes as 0.14 does). */
  before: { columns: CredentialColumns; seal: string };
  authMacFrom: string;
  authMac: string;
  revokedAt: number;
  revokedBy: string;
  /** Why, for its change's record: a revoke, or its holder's sign-out. */
  reason: 'revoke' | 'sign_out';
  /** The credential the request came in on, for its change's record. */
  via: string | null;
  /** Whose act it was, for its change's record (`RequestTrace`); none for a request on no such credential. */
  trace?: RequestTrace | null;
  /**
   * The policy the caller's right to revoke it was weighed on, held to under
   * the fence (as `policyStill` holds a write to it under 0.14's head): the
   * newest `policy.change`'s sequence number, and the environments it
   * protected, by id, with their slugs (null: deleted). Null for a revoke no policy weighs
   * (its holder's own sign-out).
   */
  policy: { seq: string | null; protected: { environmentId: string; slug: string | null }[] } | null;
};

/**
 * A revoke: its change's number, or why nothing was written: the row not
 * as read, or revoked already (`moved`); not its object's newest change's
 * (`stale`); its seal not the vault's (`tampered`, a finding); the policy
 * it was weighed on changed (`policy`); a lock not had in time (`busy`).
 */
export type RevokeCredentialOutcome =
  | { ok: true; number: string; witnessed: boolean | null }
  | { ok: false; refused: 'moved' | 'stale' | 'tampered' | 'policy' | 'busy' };

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

/** What each refusal says, as the vault answers it and the app shows it. */
export const REFUSAL_MESSAGES: Record<RefusalCode, string> = {
  removed: 'this member was removed',
  not_a_member: 'not a member',
  no_grant: 'no grant covers this',
  expired: 'the grant that covered this has expired',
  bulk_limit: 'too many secrets read in too short a time',
  bad_claim: 'the key does not belong to this secret',
  deleted: 'this project or environment was deleted',
  ended: 'the reference read through was ended',
  personal: "a personal config's values are its owner's alone",
  sensitive: "a sensitive value is never shown to anyone, Owners included: `coffre run` gives your app a placeholder for it through the credential proxy, and a service account reads it",
  not_owner_issued: 'a service account reads a sensitive value only on a token or trust binding an Owner of its project issued',
  use_only: "a workload uses this value through coffre and never holds it: list it in its binding's reads, where the value is held, if it must",
  not_allowed: 'not allowed to change this',
  last_owner: 'the last Owner of the whole instance stays one: make someone else an Owner first',
  invalid: 'not something the rules allow',
  policy_changed: "the instance's roles or protected environments changed while this was asked: try again",
  access_changed: 'what this member holds changed since the read was decided: try again',
  log_broken: 'the vault log does not hold from the last checkpoint',
  wrong_kek: "this vault's key does not open the data it holds",
  tampered: "this member's record failed the vault's integrity check",
};

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

/** The longest a use may take from its time to its answer, held in Postgres too (R53): no use is decided later than this after its `at`. */
export const USE_DEADLINE_MS = 3000;

/** A use's request id: 63 random bits, as text, unique within its millisecond (hot-path-one.md, "Row size"). */
export function newUseRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return (new DataView(bytes.buffer).getBigUint64(0) >> 1n).toString();
}

/** A use as the app asks for it: on which credential, which key, through which place, why, and when. */
export type UseInput = {
  /**
   * What the request came in on (T147): a credentials row, by id; with
   * `way`, an MCP connection or a Cloudflare service binding, by id, or,
   * behind Cloudflare Access, which signs a browser in with no row of
   * coffre's, the person (`user:…`), whose account is all the use weighs.
   */
  credential: string;
  way?: UseWay;
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

/**
 * A request's several keys as the app asks for them (`Vault.useMany`): what `UseInput` names but its key, once, and
 * each key with the place it is read through and its own request id, which its entry takes.
 */
export type UseManyInput = Omit<UseInput, 'secretId' | 'place' | 'requestId'> & {
  items: readonly { secretId: string; place: string | null; requestId: string }[];
};

/**
 * A request's several keys' answer, all or nothing: every value, in the request's order, each with its entry (or the
 * one it rode on); or the first key refused, by its index in the request, logged as its request was (`number`) or not
 * (null: decided before anything of it was written, as a use's refusal by ids is); or busy, nothing decided.
 */
export type UseManyOutcome =
  | { ok: true; values: { number: string; covered: boolean; value: UsedValue }[] }
  | { ok: false; index: number; code: UseCode; number: string | null }
  | { ok: false; busy: UseBusy; retryAfter: number };

/** The way in a use came through that has no credentials row (`UseInput.way`): each a sealed object of the log but Access. */
export type UseWay = 'connection' | 'binding' | 'access';

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
  | 'no_policy'
  /**
   * A use by name of a key that reads an archived place, a reference's source's: it reads nothing until that place is
   * back (review r4 of D153). Decided before anything is written, never logged as a use: the app logs the request.
   */
  | 'archived';

/** What a use's refusal says: the rules' as `REFUSAL_MESSAGES`, and those of sealed inputs. */
export function useRefusalMessage(code: UseCode): string {
  switch (code) {
    case 'stale':
      return 'what this read decides on is not as the vault last sealed it: it was put back, or written around coffre';
    case 'credential':
      return 'that credential is unknown, expired or revoked';
    case 'missing':
      return 'no such key';
    case 'no_policy':
      return "the vault's log holds no bulk cap yet";
    case 'archived':
      return 'what it reads is archived';
    default:
      return REFUSAL_MESSAGES[code];
  }
}

/** A use as the request names it (`Vault.useNamed`). */
export type NamedUseInput = {
  /** The token the request came in on, hashed as its credential's row holds it, base64. */
  tokenHash: string;
  /** Where, by slugs; null for the one environment a handle was made for (the credential proxy's stable URL). */
  place: { project: string; environment: string } | null;
  /**
   * With `place` null, the environments the request does not mean, by slugs: served not by name when the handle's is
   * one (the stable URL's segments that name an environment of the handle's instead, one the proxy reads as its
   * person's own config).
   */
  unless?: readonly { project: string; environment: string }[];
  /** The key, by name; null for none: the caller's standing at the place alone, as for a key it does not hold. */
  key: string | null;
  /**
   * The credentials the app's config accepts (review r6 and r7 of D153): `signin`, whether the deployment signs in
   * through coffre's own sign-in (under Cloudflare Access no coffre token is a credential); `issuers`, each sign-in
   * provider it configures, `<provider id>:<issuer hash>`, which a browser session's identity must name. The call
   * holds the token's credential to them first, before anything else it reads: one the app would refuse is answered
   * as a token no credential has, whatever the request names.
   */
  accepts: CredentialAcceptance;
  purpose: Purpose;
  keepsSensitive?: boolean;
  requestId: string;
  at: number;
  deadline: number;
};

/** What a named use's credential must be for the app to take it (`NamedUseInput.accepts`). */
export type CredentialAcceptance = { signin: boolean; issuers: readonly string[] };

/**
 * A named use's answer. `served: false`: none the vault serves this way (a fork, a personal config, a handle of
 * several environments, or a place its stable URL does not mean), and the app reads it as ever. Otherwise the route
 * the request takes, which the vault picks on the credential and its account alone (`routeOf`; D153, review r2):
 *
 * - `credential`: the credential's own check answers (401; a token of 0.10's sealed first): no credential its seals
 *   bear out, or one ended. `outcome`, the vault's refusal, which the app does not answer with.
 * - `busy`: nothing decided, admission's answer, whatever the request names.
 * - `name`: the use's outcome, a plain value's text where one was allowed, and every refusal of the key alike; the rows
 *   the app checks before anything leaves (the credential's with its MAC, the place's, the key's), as `app_read`
 *   answers them, JSON; the key's id (null for none held); the place, by slugs; and the caller as the vault decided
 *   them, from the sealed rows the use read (one who holds nothing where roles, policy or place were not as sealed).
 */
export type NamedUseOutcome =
  | { served: false }
  | { served: true; route: 'credential'; outcome: Extract<UseOutcome, { code: UseCode }> }
  | { served: true; route: 'busy'; outcome: Extract<UseOutcome, { busy: UseBusy }> }
  | {
    served: true; route: 'name'; secretId: string | null; outcome: UseOutcome | { ok: true; plain: string; versionId: string }; app: string | null; standing: Access;
    /** The place the use was at, by its slugs as the vault read them: the one named, or the handle's own. */
    place: { project: string; environment: string } | null;
    /** The same place by its ids, as the vault's own rows read it, on either engine: where a refusal is logged. */
    at: { projectId: string; environmentId: string } | null;
  };

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
