import { createHash } from 'node:crypto';

import type { AccessFault } from './access-fault.ts';
import type { CallerKind, CredentialScope, GrantPlace, Holdings, InstanceRole, Policy, Role, RoleDefinition, Scope, ServiceSetting } from './access.ts';
import type { AccessAnswers, AccessChanges } from './changes/access.ts';
import type { PlacesAnswers, PlacesChanges } from './changes/places.ts';
import type { SecretsAnswers, SecretsChanges } from './changes/secrets.ts';
import type { SigninAnswers, SigninChanges, Unasked } from './changes/signin.ts';
import type { WorkloadAnswers, WorkloadChanges, WorkloadsUnasked } from './changes/workloads.ts';
import type { BindingPolicy, Constraints } from './identity/index.ts';

export type { CallerKind } from './access.ts';

export { checkpointMessage, checkpointVerifier, verifyCheckpoint } from './checkpoint.ts';
export { describeAccessFault, type AccessFault, type FaultGrant, type FaultNames } from './access-fault.ts';

/**
 * The vault as the app sees it (docs/design/0.16.md, "The contract"): the
 * contract between `@coffre/server` and `@coffre/vault`, kept in core so
 * that neither side owns it. Every argument and answer is plain JSON:
 * strings, numbers, booleans, arrays and objects, never a Buffer, a Date, a
 * class or a function. So it crosses a Workers RPC boundary, or a process
 * boundary, as it is, and the in-process transport proves it by
 * round-tripping everything through JSON.
 *
 * The app says what a request showed and the vault decides: it finds the
 * credential by its token, reads what it holds and opens the values
 * itself. The app holds no key, no ciphertext it can open and no grant it
 * decides on.
 *
 * A decision comes back as a value: `{ refused }` for a refusal, which
 * wrote nothing of what was asked. A refused use writes nothing at all; a
 * change refused to a caller who stands, one log entry that says so, once
 * a minute in each instance for that caller and what they asked. Only a
 * fault throws: a bug, or the database down.
 */
export interface Vault {
  /** Open values for whoever presented a token: a reveal, `coffre run`, an export, a proxied request, a signature. */
  use(input: UseInput): Promise<Used | Refused>;
  /**
   * What `use` would give, as of now, without opening or writing anything:
   * each key's secret and version, or why it is refused. What a watch
   * compares before it reads (`GET …/version`).
   */
  peek(input: UseInput): Promise<Peeked | Refused>;
  /**
   * Who a request's credential is and all it holds, for the app to scope a
   * page's queries with. Nothing is opened or changed on the answer: a use
   * and a change read their caller themselves.
   */
  caller(input: Presented): Promise<Called | Refused>;
  /**
   * Make a change: one operation, named as its log entry's action is, with
   * its input. All of it, or none.
   */
  change<O extends Change['op']>(input: Asked<O>): Promise<{ answer: Answers[O] } | Refused>;
}

/** Where a request came from, which every call carries. */
export type Trace = {
  /** The app's id for the request, for the log. */
  request: string | null;
  /** The address it came from, for the log, and for a workload's binding that names its sources. */
  ip: string | null;
};

/**
 * What a request showed, which every call but a change nobody asks starts
 * with. The app never says who is asking: the vault finds the credential
 * by its token.
 */
export type Presented = Trace & {
  /** The SHA-256 of the token the request presented, in lowercase hex. */
  token: string;
  /**
   * The thumbprint of the key that signed the request's proof (RFC 9449),
   * once the app has held the proof to the request: a workload's session
   * is its key's alone. Null with no proof.
   */
  proof: string | null;
};

/**
 * A change as the app sends it: its operation's input, with what the
 * request showed, or for one nobody asks (`Unasked`), where it came from
 * alone.
 */
export type Asked<O extends Change['op']> = O extends Change['op'] ? (O extends Unasked | WorkloadsUnasked ? Trace : Presented) & Extract<Change, { op: O }> : never;

export type UseInput = Presented & {
  /** The place, by its slugs. */
  project: string;
  environment: string;
  /** The caller's personal config of that environment, `@me`, where they have one. */
  mine: boolean;
  /** The keys asked for, by name, 1,000 at most: null is every key the environment has. */
  keys: string[] | null;
  /** `use`: the value is used for the caller, by the credential proxy, and never handed back. Any other hands it back. */
  purpose: Purpose;
  /** The upstream credential the values are used for, by its name in the deployment's configuration (`stripe`). Null for none. */
  upstream: string | null;
};

/**
 * Why someone reads, which the log shows. `use`: the credential proxy
 * injects the value into a request and never hands it back. Every other
 * hands the value back: `reveal` of one key, `run` of an environment,
 * `compare` of a guess in a dry run, `expose` by the proxy to a person's
 * own app.
 */
export const PURPOSES = ['reveal', 'run', 'compare', 'expose', 'use'] as const;
export type Purpose = (typeof PURPOSES)[number];

/** One key's value, or why this caller is not given it. `secret` is where the value is held: a reference's source. */
export type UsedValue = { key: string; secret: string; version: number; sensitive: boolean; value: string } | { key: string; refused: string };

export type Used = {
  principal: string;
  /** The credential's id. */
  credential: string;
  values: UsedValue[];
  /** For a workload's session, what only the app can hold its request to: an unsigned upload its binding must allow, a narrowed session's methods and paths. */
  workload: { binding: string; profile: string; policy: BindingPolicy; constraints: Constraints | null } | null;
};

/** What a use would give: each key's secret and version, or why it is refused; nothing opened. */
export type Peeked = {
  principal: string;
  /** The credential's id. */
  credential: string;
  items: ({ key: string; secret: string; version: number } | { key: string; refused: string })[];
};

/**
 * Who a request is: its principal, `user:<email>` or `token:<name>`, the
 * credential it came in on, and what it holds, as `allows` in
 * `@coffre/core/access` decides on it: its role in the instance and that
 * role's scope, its live grants, a token's own scope, the definitions of
 * the roles it holds and of no other (a role absent from `policy` is one
 * the caller does not hold, not one that grants nothing to anyone), and
 * every environment the instance protects.
 */
export type Called = {
  principal: string;
  /** `expiresAt` is ISO 8601. */
  credential: { id: string; kind: string; expiresAt: string };
  holds: Holdings & { policy: Policy };
};

/** Why a call is not answered. Nothing it asked was written. */
export type Refused = { refused: string };

/**
 * Every change the vault makes: its operation, and what that one takes.
 * Each area's are in a file of its own (`changes/`), with what each
 * answers once it is made.
 */
export type Change = SecretsChanges | PlacesChanges | AccessChanges | SigninChanges | WorkloadChanges;
export type Answers = SecretsAnswers & PlacesAnswers & AccessAnswers & SigninAnswers & WorkloadAnswers;

export type * from './changes/access.ts';
export type * from './changes/places.ts';
export type * from './changes/secrets.ts';
export type * from './changes/signin.ts';
export type * from './changes/workloads.ts';

// 0.14's contract, from here on: each type goes with the last of the server's code that names it.

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
