import { CREDENTIAL_NAME, EXCHANGE_SKEW_SECONDS, RunProofRefused, UPLOADED_KEYS, verifyProof, verifyRunToken, WORKLOAD_SIGN_IN_PATH, type RunProof, type WorkloadProfile } from '@coffre/core/identity';
import { randomUUID, timingSafeEqual } from 'node:crypto';

import {
  allows,
  assignableToEnvironment,
  DEFAULT_POLICY,
  definitionProblem,
  EVERYWHERE,
  FIXED_ROLES,
  givesService,
  guarded,
  grantKind,
  INSTANCE_ROLES,
  isBuiltinRole,
  isCredentialScope,
  type CredentialScope,
  isInstanceRole,
  isRole,
  isScope,
  managesService,
  mayManageAccess,
  normalDefinition,
  normalScope,
  NOTHING,
  ownsInstance,
  ownsProject,
  PROJECT_ONLY_PERMISSIONS,
  ROLE_ID,
  ROLE_ID_RULE,
  ROLES,
  runsInstance,
  setsUpServices,
  type HeldKey,
  type Holdings,
  type InstanceRole,
  type Permission,
  type Place,
  type Policy,
  type Role,
  type RoleDefinition,
  type Scope,
  type ServiceAccount,
  type ServiceSetting,
  readScope,
} from '@coffre/core/access';
import { GENESIS_HASH, verifyEntries, type LogKey, type StoredEntry } from '@coffre/core/audit';
import { openPair, type LogEntry, type PairNotes, type StoredPair } from '@coffre/core/merkle';
import { checkContext, ownerKey, type SecretContext } from '@coffre/core/envelope';
import { shownMember } from '@coffre/core/schemas';
import {
  DEK_BYTES,
  KEY_CHECK,
  KEY_CHECK_CONTEXT,
  KEY_CHECK_VALUE,
  KekBadClaimError,
  KekCancelledError,
  KekUnavailableError,
  LocalKekProvider,
  type KeyOperation,
  type KekProvider,
  type WrappedDek,
} from '@coffre/core/kek';
import {
  checkpointMessage,
  REFUSAL_MESSAGES,
  checkpointVerifier,
  describeAccessFault,
  POLICY_REVISION,
  answerFrom,
  CLOSED_POLICY,
  live,
  PRINCIPAL,
  CLOSED_SETTINGS,
  livePolicy,
  NO_EDITS,
  policyRevision,
  readEdits,
  roleOf,
  settingsFrom,
  view,
  type PolicyEdits,
  type Access,
  type AccessChange,
  type AccessFault,
  type AdmitInput,
  type ChangePolicyInput,
  type Admitted,
  type Checkpoint,
  type CheckpointKey,
  type EndReferencesInput,
  type Grant,
  type GrantChange,
  type KeyChecks,
  type LogHead,
  type LogVerification,
  type Outcome,
  type PolicyChange,
  type Prepared,
  type PrepareInput,
  type Purpose,
  type ReferenceInput,
  type Refusal,
  type RefusalCode,
  type RemoveInput,
  type IssueTokenInput,
  type ChangeBindingsInput,
  type ChangeBindingsOutcome,
  type CutoverInput,
  type CutoverOutcome,
  type ChangeBindingsRefusal,
  type IssueTokenOutcome,
  type IssueTokenRefusal,
  type RevokeCredentialInput,
  type RevokeCredentialOutcome,
  type RewrapInput,
  type ObjectChange,
  type SecretRef,
  type SetAccessInput,
  type SetSettingsInput,
  type Settings,
  type Sealing,
  type SignInInput,
  type SignInOutcome,
  type SignInRefusal,
  type Through,
  type UnwrapInput,
  USE_METADATA_LENGTH,
  type Unwrapped,
  type UseInput,
  type NamedManyInput,
  type NamedManyOutcome,
  type ProxyItemInput,
  type ProxyItemOutcome,
  type RouteUseInput,
  type RouteUseOutcome,
  type NamedUseInput,
  type UseManyInput,
  type UseManyOutcome,
  type NamedUseOutcome,
  type UseOutcome,
  type UseRecord,
  type Wrapped,
  type Vault,
  type Via,
  type ReadsVerification,
  type TreeVerification,
  type VerifyLogInput,
  type VouchedEntry,
  type VouchInput,
  type WrapInput,
  type AdmitReadInput,
  type AdmitReadOutcome,
  type RecordRefusalInput,
  type RecordRefusalOutcome,
  type AdmitWriteInput,
  type AdmitWriteOutcome,
  type WriteKeysInput,
  type WriteKeysOutcome,
  type WrappedKey,
  VOUCHED_AT_ONCE,
  canonicalDefinition,
  definitionKeys,
  proxyDefinitionProblem,
  MAX_PARENTS,
  MAX_PROXY_ITEMS,
  type ClearedItem,
  type ProxyDefinition,
  type ProxyInput,
  type ProxyItemView,
  type SavedProxyItem,
  type ProxyView,
  type ReleaseProxyInput,
  type ReserveProxyInput,
  type SaveProxyInput,
  isConfirmation,
  type Confirmation,
  LOCK_WAIT_MS,
} from '@coffre/core/vault';
import type { Database, Queryable, Transaction } from '@coffre/db';
import { engineOf, isUnavailable, isUniqueViolation, lockNotAvailable, SNAPSHOT } from '@coffre/db/dialect';
import { changeName, everyProjectConversion, findingMetadata, newestAccess, newestChangeNames, reportStands, roleColumns, storedRole } from '@coffre/db/grants';
import { appendEntries, HeadBusy, holdFence, holdIssues, isMovedChange, laterHead, lockLogHead, lockLogHeadQueued, missingEntry, newestAuthentic, newestCommitted, type Appended, type ChangeNumbers, type Authenticity, type HeadLine, type Newest, type NewEntry } from '@coffre/db/log';

import { KeyAccounting } from './accounting.ts';
import { addRefusal, callRefusal, openRefusal, refusalRow, writeRefusal } from './refusal.ts';
import { ADMIT_KINDS, admitStanding, callAdmit, decideAdmit, holdAdmit, openTicket, OWNERS_ONLY, parseAdmitInputs, scopeSlugs, sealTicket, SETS_UP_ONLY, TICKET_MS, validateAdmitRead, type AdmitAsked, type AdmitTicket } from './admit.ts';
import { admitChange, Changes, changesHold, heldByLog, heldFrom, keptFrom, keptObjects, macsOf, Moved, NotLogged, prepareChanges, type ChangeKeys, type Held } from './changes.ts';
import { signer, type Signer } from './checkpoint.ts';
import { CutoverRefused, cutoverPayload, cutoverRow, genesisCalls, Moved as VouchMoved, planCutover } from './cutover.ts';
import { bindingsCall, changeBindings, checkBinding, checkChangeBindings, checkIssue, givenPins, issueCall, issueToken, readPins, revokeCredential, signIn, SIGN_IN_TRIES, weighIssue, weighService, type Answer, type IssueRead } from './credentials.ts';
import { bindingObject, credentialObject } from './objects.ts';
import { proveIn, type SealThrough } from './checkpointer.ts';
import { keyRefusals, placeIn, readerOf, referenceRefusal, refuses, sensitiveRefusals, useOnlyRefusals, type Reader, type SecretPlace } from './decide.ts';
import type { ResolvedVaultConfig } from './config.ts';
import {
  applyOp, canonical, limitChange, noEdits, objectKey, POLICY_REF, RESERVED_REF, roleRef, ROLES_REF, sealed as sealedObject, sealKey, sealOf,
  type CredentialInput, type EnvironmentInput, type Input, type Op, type PrincipalInput, type ProxyInput as ProxyObject, type ProxyItem, type Ref, type RolesInput,
  type RoleTable, type SecretInput,
} from './inputs.ts';
import { roleChanges, type StoredRole } from './role-rows.ts';
import { frozenHoldings, notCleared, proxyView, reservedProblem, routeRefusal, type ResolvedKey } from './proxy.ts';
import { TICK_MS } from './log-checkpointer.ts';
import { authentic, changeEntry, changeHolds, logMacKey, useEntry as usedEntry, type LogMacKey } from './log-entry.ts';
import { logStore } from './log-store.ts';
import { checkReads, cursorVouched, readVouched, type ReadRow } from './reads.ts';
import { carries, further, ownEntries, rehash, relink, START, vaultLogKey, VERIFY_BATCH, withCause, type Position } from './log.ts';
import { apply, replayFault, type LoggedMember, type Replayed } from './replay.ts';
import { principalObject } from './objects.ts';
import { memberMac, rowKey, sameGrants, sealed, standing } from './rows.ts';
import { snapshot, type Asked, type Snapshot } from './snapshot.ts';
import * as store from './store.ts';
import { accessDigest, CHECKPOINT, EMPTY_TALLY, expectedKey, TALLY_VERSION, Walk, type AccessTally, type Expected, type TalliedCheckpoint, type Tally } from './tally.ts';
import { ACCESS_ACTIONS, type CheckedChange, type EnvironmentRow, type EnvironmentSeal, type GrantRow, type HeldObject, type Member, type MemberLog, type ReadKind } from './store.ts';
import { callWrite, decideWrite, parseInputs, secretColumnsOf, validateWriteKeys, WRITE_KINDS, writeStanding } from './write.ts';
import { proxyItem, use, UseCache, useLimits, useMany, useNamed, useNamedMany, useRoute, type UseLimits, type UsePath } from './use.ts';
import { verifierKeys, verifyTrees, type VerifierKeys } from './verifier.ts';
import { alone, entryVouched, keyringOf, type Keyring } from './keyring.ts';


export type VaultOptions = {
  /**
   * How long every key operation of one call may take, in milliseconds;
   * 5 seconds unless set. Past it, a call fails as an outage.
   */
  keyBudgetMs?: number;
  /** Milliseconds added to the database's clock where the vault decides by it. Tests move time with it. */
  clockOffset?: () => number;
  /** How far one call walks the log (`WALKS`); tests shorten them. */
  walks?: Partial<Walks>;
  /** How long a reservation of code's proxy names (`reserveProxy`) waits for the log's head in all; `CALL_DEADLINE_MS` unless set. Tests shorten it. */
  codeWaitMs?: number;
  /**
   * Which log the vault keeps (0.15's plan, "Behind one switch"): 0.15's,
   * the default since its flip (plan PR 10), where each decision that
   * changes an input also logs it as a change of 0.15's log (`changes.ts`),
   * or 0.14's alone, for the suites until 0.16 removes it. Not a
   * deployment's to set: once cut over, the database refuses 0.14's writes.
   */
  log?: '0.14' | '0.15';
  /**
   * Under 0.15's log, what a change waits for before it answers: its entry
   * sealed in a signed checkpoint, and witnessed or past the witnesses'
   * bound (R51): the checkpointer's `sealThrough` (checkpointer.ts). A
   * change whose entry it does not seal fails, though committed. Required
   * under 0.15's log.
   */
  sealThrough?: SealThrough;
  /**
   * Under 0.15's log, the pairs held where no database writer reaches: the
   * signer's memory (`durableHeldOutside` on Workers, the Node runner's
   * `heldOutside`), later a witness's. The verifier holds every walk to
   * them; without, a database rolled back whole to an earlier pair would
   * verify until the signer's next tick refuses it (verifier.ts). Required
   * under 0.15's log, as `sealThrough` is (T151).
   */
  heldOutside?: () => Promise<readonly PairNotes[]>;
  /**
   * Under 0.15's log, whether the checkpointer seals (T169), bounded: what
   * `sealing()` answers, and `/readyz` asks. The Node runner's `sealing`;
   * on Workers the entrypoint asks the object itself. Without, it seals.
   */
  sealing?: () => Promise<Sealing> | Sealing;
  /**
   * 0.15's uses, per isolate (use.ts, `useLimits`): how long a cover holds, how many names it maps, how many keys a
   * statement makes uses of. `inFlight`, the keys in flight at once, is derived (`USES_IN_FLIGHT`, `@coffre/core/memory`):
   * only a test sets it.
   */
  uses?: Partial<UseLimits>;
  /**
   * Whether a call's I/O ends with its request, as on Workers, where a call whose request has ended may never settle:
   * then a use's place in admission lapses past its deadline, settled or not (use.ts, `HELD_PAST_DEADLINE_MS`), its
   * connection closed by then (cloudflare.ts). Not a deployment's to set.
   */
  callsEndWithRequest?: boolean;
  /**
   * Whether the isolate's throttle refuses uses while fewer than two in three are answered in time (use.ts, `Throttle`). Always
   * on but in a test about something else whose isolate answers uses `late` on purpose. Not a deployment's to set.
   */
  throttled?: boolean;
};


/**
 * A vault's configuration made ready to use, once per process, or once per
 * isolate on Workers: its signer, its log key, and how far it has verified
 * the log. It holds settled values only, never work under way: on Workers,
 * a call's I/O is that call's, and a call that waited on another's would be
 * cancelled with it, as hung (isolate.test.ts). Everything else is in the database, so any number of instances
 * share one set of members, one log and one bulk count.
 */
export type PreparedVault = {
  config: ResolvedVaultConfig;
  /** What signs checkpoints now: the first of `signers`. */
  signer: Signer;
  /** A signer for each of its signing keys: a checkpoint is signed by the one whose log key wrote its entry. */
  signers: Signer[];
  /** What the vault's entries are MACed with now: the first of `logKeys`. */
  logKey: LogKey;
  /** Each signing key's log key: those after the first verify only entries before `since`. */
  logKeys: LogKey[];
  options: Required<Omit<VaultOptions, 'walks' | 'log' | 'sealThrough' | 'heldOutside' | 'sealing' | 'uses' | 'callsEndWithRequest' | 'throttled'>> & { walks: Walks };
  /**
   * 0.15's log, when it is on: the keys its changes are sealed and MACed
   * with, from the vault's signing keys, and what each waits on to answer.
   * Null under 0.14's alone.
   */
  log015: (ChangeKeys & { macs: readonly LogMacKey[]; sealThrough: SealThrough; heldOutside: () => Promise<readonly PairNotes[]>; sealing: () => Promise<Sealing> | Sealing }) | null;
  /** Whether this process wrote its bulk cap into 0.15's log, or found it there (`#limit`). */
  limited: boolean;
  /** Whether this process made every role's row what the log's roles object says, sealed, or found it so (`#syncRoles`). */
  rolesSynced: boolean;
  /** Whether 0.15's log is cut over from 0.14, as this process found it (`cutover`): until then, nothing of 0.15's runs. */
  cutover: boolean;
  /**
   * Whether this process found 0.15's log's cutover written, sealed or not
   * yet (`#settled`): from then on every environment row is sealed, and the
   * vault checks each one it decides on (`#placeFault`).
   */
  marked: boolean;
  /** How far the chain is rehashed, by any call of this process: its head must still be there. */
  verified: Position;
  /** What member rows are sealed under now; rows.ts. */
  rowKey: Buffer;
  /** Each signing key's row key: those after the first vouch for rows only until `since`, when the rows are sealed again. */
  rowKeys: Buffer[];
  /** Its first entry under its current key, where the keys it replaced stop counting, once settled (`#settle`). */
  since: bigint | null;
  /** Why it writes nothing, once settled that it may not. */
  superseded: string | null;
  /** Tampering this process has logged already, so that a forged row is one entry, not one per request. */
  reported: Set<string>;
  /** Whether its KEKs are decided to open what they wrapped, or not: `#kekMismatch`. */
  kekChecked: boolean;
  /** Why not, once decided that they do not. */
  wrongKek: string | null;
  /**
   * Whether this process has done what it does once, at its start
   * (`#convert`): the grants on every project of 0.4 there were replaced,
   * then everyone the deployment names made an Owner (`#declare`).
   */
  converted: boolean;
  /** What 0.15's verifier checks the log with (verifier.ts), once a call first needs them. */
  verifier: VerifierKeys | null;
  /** The log's MAC key under each signing key, which `vouch` checks an entry with: made once a call first needs them. */
  /** This isolate's 0.15 uses: their admission count, seal cache and covers (use.ts). */
  uses: UseCache;
};

export async function prepareVault(config: ResolvedVaultConfig, options: VaultOptions = {}): Promise<PreparedVault> {
  return {
    config,
    ...(await keysOf(config.signingKeys)),
    options: { keyBudgetMs: options.keyBudgetMs ?? KEY_BUDGET_MS, codeWaitMs: options.codeWaitMs ?? CALL_DEADLINE_MS, clockOffset: options.clockOffset ?? (() => 0), walks: { ...WALKS, ...options.walks } },
    log015: (options.log ?? '0.15') === '0.15' ? log015(config.signingKeys, options.sealThrough, options.heldOutside, options.sealing) : null,
    limited: false,
    rolesSynced: false,
    cutover: false,
    marked: false,
    verifier: null,
    uses: new UseCache(useLimits(options.uses), { callsEndWithRequest: options.callsEndWithRequest === true, throttled: options.throttled !== false }),
    verified: START,
    reported: new Set(),
    since: null,
    superseded: null,
    kekChecked: false,
    wrongKek: null,
    converted: false,
  };
}

/** 0.15's change keys from the vault's signing keys, the first sealing and MACing, each checking a seal. */
function log015(
  seeds: readonly Uint8Array[],
  sealThrough: SealThrough | undefined,
  heldOutside: (() => Promise<readonly PairNotes[]>) | undefined,
  sealing: (() => Promise<Sealing> | Sealing) = () => ({ ok: true }),
): NonNullable<PreparedVault['log015']> {
  if (sealThrough === undefined) throw new Error("0.15's log answers a change once its entry is sealed (R51): give the vault the checkpointer's sealThrough");
  if (heldOutside === undefined) throw new Error("0.15's log is verified against the pairs held where no database writer reaches: give the vault the checkpointer's heldOutside");
  const macs = seeds.map((seed) => logMacKey(seed));
  return { seals: seeds.map((seed) => sealKey(seed)), mac: macs[0]!, macs, sealThrough, heldOutside, sealing };
}

/** The vault's own keys, from each of its signing keys, the one it signs with first. */
async function keysOf(seeds: readonly Uint8Array[]) {
  const signers = await Promise.all(seeds.map((seed) => signer(seed)));
  const logKeys = seeds.map((seed) => vaultLogKey(seed));
  const rowKeys = seeds.map((seed) => rowKey(seed));
  return { signer: signers[0], signers, logKey: logKeys[0], logKeys, rowKey: rowKeys[0], rowKeys };
}


/**
 * The vault over `db`, and, for 0.15's uses, over `hot`, the hot path's own
 * login (`coffre_vault_hot`: its lock and statement timeouts, generic
 * plans; schema 0022). Cheap: on Workers, one per call, over that call's connections.
 */
export function openVault(db: Database, prepared: PreparedVault, hot?: Database): Required<Vault> {
  return new VaultService(db, prepared, hot);
}

/** Every key operation of one call, together, with no lock held meanwhile (R75): how long the call waits for its key service. */
const KEY_BUDGET_MS = 5_000;

/**
 * How long a statement of a read's decision runs, a wait for a lock
 * included: a read waits only for what changes its reader, and for the
 * log's head. Longer is a queue, which holds the read's connection while it
 * waits; refused, it fails as unavailable at once, and its caller tries
 * again later.
 */
const READ_LOCK_TIMEOUT_MS = 3_000;

/**
 * How long a whole read call may take, from its start to its answer, its
 * refusal's entries, the record of a vault key's check and, with a key
 * service, its intent and its own budget (added) included: each transaction's waits are bounded by what is left of it, and
 * past it the call fails as unavailable (`Overdue`) rather than start
 * another. So a caller hears within it, ok or 503, never tens of seconds later.
 *
 * A write's work has no such bound (R75: writes may take longer), but its lock waits do: each is `LOCK_WAIT_MS`, and a
 * decision whose wait gave up is decided again, after a pause, for as long as this much time from its first attempt
 * allows (`#decideNow`, `retryingLocks`); past it, it fails as unavailable, its last 55P03 said.
 */
export const CALL_DEADLINE_MS = 5_000;

/**
 * How many reads may wait for the log's head at once, through all of the
 * vault's connections; the next is refused at once, as unavailable, holding
 * no connection while it waits (`lockLogHeadQueued`). A read holds the head
 * for a few round trips, about 150 ms through Hyperdrive, so this many
 * clear within a read's bound (2.4 s of its 3), and no more than this many
 * of the pool's connections wait. A burst of 50 reads at a 2-vCPU database
 * a 30 ms round trip away: 17 read within 2.2 s, 33 refused at once.
 */
export const READ_HEAD_WAITERS = 16;

/** The reads' places in line for the head. */
const READ_QUEUE: HeadQueue = { waiters: READ_HEAD_WAITERS, line: 'reads' };

/** The code's proxy names' one place in line for the head (`reserveProxy`): one call of a deploy's herd waits; the rest read again. */
const CODE_QUEUE: HeadQueue = { waiters: 1, line: 'code' };

/**
 * A retry policy, not a constraint: how long a call that gave up waiting (a lock past `LOCK_WAIT_MS`, a reservation
 * refused the code's place) pauses before it tries again, at first, about the few round trips a holder of the log's
 * head holds it for; doubled each time, up to the most, under one lock wait, so that a call retried tries again within
 * a wait of its holder's letting go. Jittered (×0.5 to ×1.5), so a herd spreads.
 */
const LOCK_PAUSE_MS = 25;
const LOCK_PAUSE_MAX_MS = 400;

/** How many releases a checkpoint prunes at most: one short statement, a few each scheduled run. */
const RELEASES_PRUNED = 10_000;

/** A call past its deadline (a read's `CALL_DEADLINE_MS`, a reservation's `codeWaitMs`): unavailable, as a statement past its bound (57014) is. */
class Overdue extends Error {
  readonly code = '57014';
  constructor() {
    super('this call took longer than it may: ask again shortly');
    this.name = 'Overdue';
  }
}

/** The bound of a transaction of a call due at `deadline`: `ms`, or what is left of the call, if less. */
function within(deadline: number | undefined, ms: number): number {
  if (deadline === undefined) return ms;
  const left = deadline - Date.now();
  if (left <= 0) throw new Overdue();
  return Math.min(ms, left);
}

/**
 * `work`, a transaction, again while one of its lock waits gave up (`LOCK_WAIT_MS`, 55P03: it rolled back, having
 * committed nothing), after a pause (`LOCK_PAUSE_MS`, doubled to `LOCK_PAUSE_MAX_MS`), for as long as `by` allows; then
 * the give-up is thrown, unavailable (R75: a short wait and retries, never a long wait holding a connection and a place
 * in a lock's queue). The pause holds no lock, and on Workers no Hyperdrive connection: its transaction is over. Not a
 * place in line refused (`HeadBusy`, also 55P03), which is overload refused at once (R44).
 */
async function retryingLocks<T>(work: () => Promise<T>, by: number): Promise<T> {
  for (let pause = LOCK_PAUSE_MS; ; pause = Math.min(2 * pause, LOCK_PAUSE_MAX_MS)) {
    try {
      return await work();
    } catch (error) {
      if (!lockNotAvailable(error) || causedBy(error, HeadBusy)) throw error;
      // The pause, cut short at `by`, and one attempt more there; none past it.
      const left = by - Date.now();
      if (left <= 0) throw error;
      await new Promise((resolve) => setTimeout(resolve, Math.min(pause * (0.5 + Math.random()), left)));
    }
  }
}

/** Whether `error`, or anything it was caused by, is a `type`. */
function causedBy(error: unknown, type: abstract new (...args: never[]) => unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if (cause instanceof type) return true;
  }
  return false;
}

/** A person, and a service account: only a person sets one up (`givesService`). */
const PERSON = /^user:/;
const SERVICE = /^token:/;

/** Who acts for the vault itself, as when it makes an Owner its deployment names. */
const VAULT_ACTOR = 'system:vault';

/** The cutover's own entry in 0.14's log (`cutover`): the head its change in 0.15's names, or, denied, why it did not cut over. */
const CUTOVER = 'log.cutover';

/** Genesis changes a statement: eleven parameters each, well within Postgres's 65,535 a statement. */
const GENESIS_BATCH = 2000;

const NOT_CUT_OVER = "0.15's log is not cut over from 0.14 yet: the app asks the vault to (`cutover`) before anything else";

// A KEK's check: a known value, the size of a data key, wrapped under it in
// a context no secret has (the nil UUID), and kept in a `key.check` entry
// (@coffre/core/kek). Opening it again tells the vault its KEK is the one
// that wrapped the data, without opening any data; `coffre verify keys`
// holds an escrowed key to it the same way.

/** How many stored keys a KEK with no check yet is tried on: one that opens proves it. */
const KEY_CHECK_SAMPLE = 3;

/** The vault's first entry under a new key, which the keys it replaced count only before (`#settle`). */
const KEY_ROTATE = 'key.rotate';

/** Why a tampered member is not started over under 0.15's log (`#startOver`). */
const START_OVER_015 = "this member's record failed the vault's integrity check, and 0.15's log changes no member whose row it does not hold: a reseal makes it the log's again";

/** A new member row, before the decision seals it (`#seal`). */
const UNSEALED = { accessSeq: 0n, mac: Buffer.alloc(32) };

/** A member's object in 0.15's log (inputs.ts). */
function memberRef(principal: string) {
  return { kind: 'principal' as const, id: principal };
}

/** An instance role and its scope as a member's row gives them back (`roleColumns`, then `storedRole`): what 0.15's ops carry, so that the object they make is the row's. */
function asStored(role: InstanceRole, scope: Scope): { role: InstanceRole; scope: Scope } {
  return storedRole(roleColumns(role, scope));
}

/** A grant's place, and what it holds, as a member's object in 0.15's log has it. */
function inputGrant(grant: Pick<GrantRow, 'projectId' | 'environmentId' | 'environmentSlug' | 'role' | 'expiresAt'>) {
  return { projectId: grant.projectId, environmentId: grant.environmentId, environmentSlug: grant.environmentSlug, role: grant.role, expiresAt: grant.expiresAt };
}

/**
 * The environments an issue was weighed on, each once, with the slug it was weighed with first: what `issue_token`
 * holds under the issue lock (IssuePolicyHeld).
 */
function weighed(slugs: readonly { environmentId: string; slug: string | null }[]): { environmentId: string; slug: string | null }[] {
  const seen = new Set<string>();
  return slugs.filter(({ environmentId }) => !seen.has(environmentId) && seen.add(environmentId) !== undefined);
}

function placeOf(grant: store.Place) {
  return { projectId: grant.projectId ?? null, environmentId: grant.environmentId ?? null, environmentSlug: grant.environmentSlug ?? null };
}

/** Why a change to a tampered member is refused: under 0.14's log, removal starts them over; under 0.15's, only a reseal (`START_OVER_015`). */
const TAMPERED_SUBJECT = "this member's record failed the vault's integrity check: remove them to start over";
const TAMPERED_SUBJECT_015 = "this member's record failed the vault's integrity check: a reseal makes it the log's again";

/** Why a decision on a place whose row is not as 0.15's log holds it is refused (T159): the row, not the member, is at fault. */
const TAMPERED_PLACE = "an environment it is about failed the vault's integrity check: its row is not as the log holds it";

/** The action of the vault's entry that holds the instance's settings, and changes them (`settings`). */
const SETTINGS = 'settings.change';

/** The action of the vault's entry that holds the instance's access policy, and changes it (`policy`). */
const POLICY = 'policy.change';

/** The actions of the vault's entries about proxy definitions written in the UI (0.16): a save, code's reservation, an Owner's release. */
const PROXY_SAVE = 'proxy.save';
const PROXY_CODE = 'proxy.code';
const PROXY_RELEASE = 'proxy.release';

/** Who reserves the names code defines: the deployment, through the app's own call at its gate; no person or token makes one. */
const CODE_ACTOR = 'system:deployment';

/** An object the log does not bear out, read for a display alone: as if gone, which marks or shows nothing it could vouch for. */
function notLogged(error: unknown): Held {
  if (error instanceof NotLogged) return { log: 'gone' };
  throw error;
}

/** Why a change to who is an Owner, scoped or not, is refused to anyone else: Owners make and unmake Owners. */

/** Why nobody demotes or removes a person the deployment names (`owners`), themselves included. */
function declaredOwner(principal: string): string {
  return `the deployment names ${principal.slice('user:'.length)} an Owner (owners, in the vault's configuration): take them off that list and deploy first`;
}

/** Why a person's change to a service account is refused. */
const NOT_THEIRS = 'a person gives a service account at most what they hold, where the instance lets them set one up, and only to one whose every grant they hold';

/** Who asks for checkpoints: the app's scheduled job. */
const SCHEDULER = 'system:coffre-scheduler';

/** A refusal and the entries that record it. */
class Refused {
  readonly refusal: Refusal;
  readonly entries: NewEntry[];

  constructor(refusal: Refusal, entries: NewEntry[]) {
    this.refusal = refusal;
    this.entries = entries;
  }
}

/** A decision that read a member as absent who has been admitted since: it is made again. */
class Retry {}

/** What each `vault.tampered` entry reports, to mark it logged once committed. */
const REPORTED = new WeakMap<NewEntry, string>();

/** The newest change of a member's a check of their row weighed (`#report`), by its name (`changeName`): its MAC. */
function weighedOf(log: MemberLog): string {
  return changeName(log.newest?.row.mac ?? null);
}

/** Each environment row's check, once made (`#placeFault`): one HMAC a row, however many parts of a decision read it. */
const PLACE_FAULTS = new WeakMap<EnvironmentSeal, 'tampered' | 'stale' | null>();

/** A key service that did not answer, and the entries that record what it did do. */
class Outage {
  readonly error: unknown;
  readonly entries: NewEntry[];

  constructor(error: unknown, entries: NewEntry[]) {
    this.error = error;
    this.entries = entries;
  }
}

/** A rewrap that would make a value less sensitive than it is. */
const LOOSER = 'a value is made less sensitive only by writing it again: an old version comes back, and a key is made stricter, as sensitive as its newest version or more; only its current sensitive value is made a secret in place, by an Owner of its project';

function refusal(code: RefusalCode, message: string): Refusal {
  return { code, message };
}

/**
 * A decision in progress: its transaction, the member rows it locked, its
 * time, and what it will commit. Changes to members and grants wait until
 * the entries are appended, so each row carries its entry's time and the
 * log replays to it exactly (replay.ts).
 */
type Decision = {
  tx: Transaction;
  members: Map<string, Member>;
  /** The database's clock, read once the members are locked. */
  at: number;
  /** What the decision reads, in one statement once the members are locked, under the head. */
  reads: Snapshot;
  log: NewEntry[];
  writes: ((at: number) => Promise<void>)[];
  /** Members whose row or grants the writes change: sealed again once they have run. */
  touched: Set<string>;
  /**
   * What each member this decision changes holds once its writes have run:
   * the grants it verified against their row's MAC, with its own changes
   * applied as they run. `#seal` seals this set, never a fresh read, which
   * could hold a grant inserted around the vault while it decided.
   */
  grants: Map<string, GrantRow[]>;
  /** `vault.tampered` entries, committed with the decision whatever it decides. */
  reports: NewEntry[];
  /** Run once the entries are appended, with the seq each was given. */
  after: ((seqOf: (entry: NewEntry) => number) => void)[];
  /**
   * Checks made again once the log's head is locked, just before this
   * decision's entries append: what another decision could have changed
   * since it checked, such as a reference ended while a read through it
   * was deciding. A `Refused` there refuses the decision.
   */
  underLock: ((locked: Queryable) => Promise<void>)[];
  /** Under 0.15's log, the changes its writes make, each staged beside its write (`changes.ts`); null under 0.14's alone. */
  changes: Changes | null;
};

/**
 * What a decision reads besides its members' standing, with it (`Snapshot`):
 * places, references' ends, and the distinct keys a principal would hold
 * released in the vault's window, with `keys` too: the bulk limit's count.
 */
type Reads = Pick<Asked, 'environments' | 'references'> & { released?: { principal: string; keys: readonly string[] } };

/**
 * How a decision is made: `asked` is what it reads besides its members, and
 * `reads` says it changes none of them (`#decide`). `deadline`, a read's (`reads`) or a reservation's
 * of code's names: when its whole call must have answered, every wait in
 * every transaction it takes included (`CALL_DEADLINE_MS`, `codeWaitMs`).
 */
type How<T = unknown> = {
  asked?: Reads; reads?: boolean; deadline?: number;
  /** Held by another, wait for the head only in one of this line's places, else refuse at once (`HeadBusy`): a read's always. */
  queue?: HeadQueue;
  /**
   * Read first, in the decision's transaction, before any lock: an answer ends it there, the head never taken and
   * nothing written; null decides. On the decision's own connection, so that the read and the decision it may lead to
   * take one turn of the pool, never two (`reserveProxy`).
   */
  first?: (tx: Transaction) => Promise<T | null>;
};

/** A line of places to wait for the log's head in, and how many (`lockLogHeadQueued`). */
type HeadQueue = { waiters: number; line?: HeadLine };

/** The actions of the entries the vault writes about keys. */
type KeyAction = 'secret.read' | 'key.wrap' | 'key.rewrap';

/** What ties an entry to the app's request, and to the one action it is part of. */
type Correlation = { requestId?: string | null; operationId?: string | null; credentialId?: string | null; confirmed?: Confirmation | null };

/**
 * What the one asking holds through the credential their request came in
 * on: no more than its scope (`allows`), and, a workload's, handed back
 * only what the scope lists (`useOnly`). A scope that is not one, a kind of
 * caller its principal cannot be, or a workload with no scope to list what
 * it reads, is a bug of the app's, which fails the call. None said is an
 * app older than 0.11, which has no workloads (`Through`).
 */
function through(standing: Standing, { credentialScope, caller }: Through): Standing {
  const { principal } = standing;
  if (caller !== undefined && !(caller === 'person' ? principal.startsWith('user:') : (caller === 'bearer' || caller === 'workload') && principal.startsWith('token:'))) {
    throw new Error(`caller must be person for a user: principal, bearer or workload for a token: one, got: ${String(caller)}`);
  }
  if (caller === 'workload' && credentialScope == null) throw new Error('a workload caller comes with its credential scope, which lists what it reads');
  if (credentialScope != null && !isCredentialScope(credentialScope)) throw new Error('credentialScope must be a list of grants, one a place');
  const held = { ...(credentialScope == null ? {} : { credentialScope }), ...(caller === undefined ? {} : { kind: caller }) };
  return { ...standing, live: { ...standing.live, ...held }, all: { ...standing.all, ...held } };
}

/**
 * The credential a CI run's request came in on, and what confirmed an act a fresh check guards (`Confirmation`), as its
 * entries record them: copied, never decided on.
 */
function traced(correlation: Correlation): { credentialId?: string; confirmedBy?: string; confirmedAt?: string } {
  return {
    ...(correlation.confirmed == null ? {} : { confirmedBy: correlation.confirmed.by, confirmedAt: correlation.confirmed.at }),
    ...(correlation.credentialId == null ? {} : { credentialId: correlation.credentialId }),
  };
}

/** Why a member's row is not the one the vault last wrote; rows.ts. */
type Fault = 'mac' | 'stale';

/**
 * What someone holds, read once per decision; `fault` when their row fails
 * its check, and they hold nothing. `stored` is the grants as read, which
 * the check verified when `fault` is null.
 */
type Standing = {
  principal: string; status: Access['status']; live: Holdings; all: Holdings; fault: Fault | null; stored: GrantRow[];
  /** Under 0.15's log, what their row was checked against (`#onLog`): its newest change, its MAC checked when no fault. */
  log?: MemberLog;
};

/**
 * What a call's start reads first, asked together (`#start`): each step's
 * first read, by the step, and only for a step still due (undefined
 * otherwise; a step that finds none reads for itself).
 */
type StartReads = {
  /** `#settle`'s: the vault's newest `key.rotate`, its newest entry, and its first under its current key. */
  rotation?: Promise<StoredEntry | undefined>;
  newest?: Promise<StoredEntry | undefined>;
  first?: Promise<bigint | undefined>;
  /** The cutover's change, null for none (the cutover mark's, and `#cutoverSealed`'s), and the newest checkpoint, its seal's (the Owners' declaration's). */
  cutover?: Promise<bigint | null>;
  checkpoint?: Promise<StoredPair | null>;
  /** `#convert`'s: who holds a grant on every project of 0.4. */
  holders?: Promise<string[]>;
  /** `#limit`'s: the policy as 0.15's log holds it. */
  policy?: Promise<HeldObject>;
  /** `#syncRoles`': the roles' rows, and their whole object as the log holds it. */
  roles?: Promise<StoredRole[]>;
  whole?: Promise<Held>;
};

/**
 * How one key operation of a call came out: its value; or a bad claim, a
 * key that does not open as the secret it was presented as; or no answer
 * from the key service.
 */
type KeyOutcome<T> = { ok: true; value: T } | { ok: false; code: string; error?: unknown };

/**
 * The one implementation of `Vault`. Every decision is one transaction on
 * the shared database: it locks the rows of the members it is about, reads
 * what it needs, decides, appends its entries under the log's lock, and
 * only then changes members and grants. Locks come in one order
 * everywhere, a member row, then the log's head, then the app's rows, so
 * any number of vault instances and app servers decide side by side
 * without a cycle (docs/design/single-database.md, question 2).
 *
 * Key operations run inside the decision, after the check, for a call the
 * rules allow: a KMS logs each one, and should never show a key opened for
 * a read coffre refused. With a key service, the call's intent is logged
 * first, in its own transaction, so a vault that dies at KMS leaves a
 * record that pairs with what KMS logged; and every key's outcome is
 * logged, a partial outage included.
 */
class VaultService implements Vault {
  readonly #db: Database;
  readonly #prepared: PreparedVault;
  readonly #config: ResolvedVaultConfig;
  readonly #hot: Database | undefined;

  constructor(db: Database, prepared: PreparedVault, hot?: Database) {
    this.#db = db;
    this.#prepared = prepared;
    this.#config = prepared.config;
    this.#hot = hot;
  }

  /** 0.15's use (use.ts), on the hot path's login. */
  async use(input: UseInput): Promise<UseOutcome> {
    return use(this.#usePath(), input);
  }

  /** 0.15's use as the request names it (use.ts, `useNamed`), on the hot path's login. */
  async useNamed(input: NamedUseInput): Promise<NamedUseOutcome> {
    return useNamed(this.#usePath(), input);
  }

  /** A request's several keys as one call (use.ts, `useMany`; T167), on the hot path's login. */
  async useMany(input: UseManyInput): Promise<UseManyOutcome> {
    return useMany(this.#usePath(), input);
  }

  /** A request's several keys as it names them, one call (use.ts, `useNamedMany`; T165, B2's PR 2), on the hot path's login. */
  async useNamedMany(input: NamedManyInput): Promise<NamedManyOutcome> {
    return useNamedMany(this.#usePath(), input);
  }

  /** A route use (use.ts, `useRoute`; T186 PR C): a UI definition's keys, each decided for its caller and its editor, on the hot path's login. */
  async useRoute(input: RouteUseInput): Promise<RouteUseOutcome> {
    return useRoute(this.#usePath(), input);
  }

  /** A place's UI definitions as a use would find them (use.ts, `proxyItem`; T186 PR C), on the hot path's login. */
  async proxyItem(input: ProxyItemInput): Promise<ProxyItemOutcome> {
    return proxyItem(this.#usePath(), input);
  }

  /** What 0.15's uses run on, every way they are asked (use.ts, `UsePath`). */
  #usePath(): UsePath {
    // Behind the switch: a vault keeping 0.14's log alone has no 0.15 objects to decide on.
    const { log015, uses: cache } = this.#prepared;
    if (log015 === null) throw new Error("0.15's uses need 0.15's log: the vault's log option is '0.14'");
    if (this.#hot === undefined) throw new Error("0.15's uses need the hot path's login: configure the vault's hotDatabase");
    // An isolate's first uses read the cutover's marker (`#cutOverYet`) within their admission, as any call holds a connection.
    const ready = this.#prepared.cutover ? undefined : () => this.#cutOverYet();
    return {
      db: this.#hot, sealKeys: log015.seals, macKey: log015.mac, macKeys: log015.macs ?? [log015.mac], keks: this.#config.keks, cache, ...(ready === undefined ? {} : { ready }),
      oldWrite: (principal, old, through, starts) => this.#oldWrite(principal, old, through, starts),
    };
  }

  /**
   * Whether 0.14's newest access entry about `principal` that carries the
   * vault's MAC, at or below `through`, is past `old`, what the principal's
   * newest change accounts for (Migration015.tla's UsesSeeOldWrites, of the
   * newest authentic write): asked by a use whose probe found `through` in
   * the vault's name past it, which, but for a write the cutover refused to
   * let land, is one forged there. Read from `through` down, never above: the
   * use's statement committed before this reads, and a change's entry since
   * is none it decided on (review r1). Each forged one is passed over; past
   * `LOOK_BACK` of them, the use is refused as if it were not. It writes
   * nothing: no report, which would wait for 0.14's head, or for the
   * vault's settling, past the use's deadline (reviews r3, r4). The next
   * decision about the principal reports what is forged (`#integrity`).
   * Each page it reads back is asked of `starts` first: none once the use
   * has lost its race (T177).
   */
  async #oldWrite(principal: string, old: bigint | null, through: bigint, starts: () => void): Promise<boolean> {
    // On Workers the use's vault is opened over its one hot connection (cloudflare.ts, `openVault(hot, prepared, hot)`):
    // this reads on it, never a second connection in the call.
    const newest = await newestAccess(this.#db, principal, { authentic: (entry) => this.#authentic(entry), forged: () => {} }, through, starts);
    if (newest === 'unreached') return true;
    return typeof newest !== 'string' && (old === null || newest.seq > old);
  }

  async #now(db: Queryable): Promise<number> {
    return (await store.now(db)) + this.#prepared.options.clockOffset();
  }

  /** A snapshot's clock, as the vault keeps time (`#now`). */
  #at(reads: Snapshot): number {
    return reads.at + this.#prepared.options.clockOffset();
  }

  /** What a decision about `principals` reads, and `asked` besides, in one statement: under the head when `head` is set. */
  #snapshot(tx: Transaction, principals: readonly string[], asked: Reads, head: boolean, queue?: HeadQueue): Promise<Snapshot> {
    const { released, ...rest } = asked;
    return snapshot(tx, {
      ...rest,
      principals,
      head,
      seals: this.#checksSeals(),
      // A read waits for the head in one of a few places in line, or is refused at once; a code's names in one (`reserveProxy`).
      ...(queue === undefined ? {} : { waiters: queue.waiters, line: queue.line }),
      ...(released === undefined ? {} : { released: { ...released, windowMs: this.#config.bulkLimit.windowMs, clockOffsetMs: this.#prepared.options.clockOffset(), cap: this.#config.bulkLimit.count } }),
    });
  }

  /**
   * Decide in one transaction, with `principals`' rows locked first, then
   * the log's head. A `Refused` or an `Outage` rolls back all but its own
   * entries, which commit on their own: then the refusal is the answer, and
   * the outage fails the call.
   *
   * Every change to the policy, the settings, a member or a place appends
   * under the head, so whatever the decision reads of them stands until it
   * commits: no decision acts on a policy read before it. A key service
   * is asked between decisions, never in one (`#keys`, R75). A read
   * (`reads`) changes no member: it takes their rows shared, so that one
   * member's reads decide side by side (`lockMembers`). A change waits for
   * each lock `LOCK_WAIT_MS` at most, and is decided again when it gave up
   * (`#decideNow`).
   */
  async #decide<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>, how: How<T> = {}): Promise<Outcome<T>> {
    const superseded = await this.#settled();
    if (superseded !== null) return { ok: false, refusal: refusal('wrong_kek', superseded) };
    return this.#decideNow(principals, decide, how);
  }

  /** `#decide`, once the vault is settled. */
  async #decideNow<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>, how: How<T> = {}): Promise<Outcome<T>> {
    // Every decision of 0.15's log's after its cutover, whichever path it comes by (`#declare`, `#convert`, `#limit`).
    await this.#cutOverYet();
    const reports: NewEntry[] = [];
    // A read's call is due from its first decision, unless its caller set when.
    const due = how.reads === true ? { ...how, deadline: how.deadline ?? Date.now() + CALL_DEADLINE_MS } : how;
    // A change's lock waits, retried until then: a read's give up within its deadline, a refusal at once (R44).
    const retries = how.reads === true ? null : due.deadline ?? Date.now() + CALL_DEADLINE_MS;
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.#decideOnce(principals, decide, reports, due, retries);
      } catch (error) {
        // A member who had no row when this decision locked theirs, and has
        // one now: another decision admitted them meanwhile. Again, with it.
        // A 0.15 change's row moved from the seal it read (ChangeCAS): read it again (ChangeRereads).
        if (attempt < 3 && (error instanceof Retry || error instanceof Moved || isUniqueViolation(error))) continue;
        throw error;
      }
    }
  }

  /**
   * One attempt of `#decide`. A change's transaction (`retries`, a time) is tried again while a lock wait of its gave
   * up, rolled back (`retryingLocks`): the transaction alone, never what follows its commit, the seal wait among it.
   */
  async #decideOnce<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>, reports: NewEntry[], { asked = {}, reads: shared = false, deadline, queue, first }: How<T>, retries: number | null = null): Promise<Outcome<T>> {
    // The changes of the attempt under way, whose failure, heard as the transaction's, they say (`Changes.failed`).
    let staged: Changes | null = null;
    try {
      const transaction = () => this.#db.transaction(async (tx) => {
        const answered = first === undefined ? null : await first(tx);
        if (answered !== null) return { result: answered, numbers: null };
        // The bound on lock waits, the members' rows, then the head and everything the decision reads, in one statement
        // (`snapshot` says why it holds): asked together, they go in that order under one Sync (postgres-js's `gather`).
        const [, members, reads] = await Promise.all([
          // A call with a deadline bounds each statement too: a queue for the head, which each holder updates, starts a
          // waiter's lock clock over at every holder (`boundLockWaits`; review r16 of #467). A change's own lock waits
          // are short (`LOCK_WAIT_MS`), its statements otherwise as long as its work takes.
          shared
            ? store.boundLockWaits(tx, within(deadline, READ_LOCK_TIMEOUT_MS), within(deadline, READ_LOCK_TIMEOUT_MS))
            : store.boundLockWaits(tx, within(deadline, LOCK_WAIT_MS), deadline === undefined ? undefined : within(deadline, Infinity)),
          principals.length === 0 ? new Map<string, Member>() : store.lockMembers(tx, principals, shared),
          this.#snapshot(tx, principals, asked, true, shared ? READ_QUEUE : queue),
        ]);
        const log015 = this.#prepared.log015;
        const d: Decision = {
          tx, members, at: this.#at(reads), reads, log: [], writes: [], touched: new Set(), grants: new Map(), reports, after: [], underLock: [],
          changes: (staged = log015 === null ? null : new Changes(log015)),
        };
        const result = await decide(d);
        // Each object 0.15's log will change, read and checked before the writes change its rows.
        await d.changes?.prepare(tx);
        // A read is logged once per place, whichever way it ends (`readsByPlace`).
        const entries = [...reports, ...readsByPlace(d.log)];
        let at = d.at;
        // Each member's newest access entry, which their row names (rows.ts).
        const accessSeq = new Map<string, bigint>();
        if (entries.length > 0) {
          // Under the head the decision's reads took.
          if (d.reads.head === null) throw new Error('a decision appends only under the head it read with');
          // Nothing awaits it: what it says comes from the head the snapshot read, and it goes with what follows.
          const appended = await this.#append(tx, entries, d.underLock, d.reads, { final: true });
          at = appended.occurredAt;
          entries.forEach((entry, i) => {
            if (isAccessEntry(entry)) accessSeq.set(entry.subjectPrincipal!, appended.seqStart + BigInt(i));
          });
          const seqs = new Map(entries.map((entry, i) => [entry, Number(appended.seqStart) + i]));
          for (const then of d.after) then((entry) => seqs.get(entry)!);
        }
        for (const write of d.writes) await write(at);
        const sealing = new Set([...d.touched, ...accessSeq.keys()]);
        // Under a share lock, a write to the row would wait for every other read holding it, and they for it.
        if (shared && sealing.size > 0) throw new Error('a read changes no member, and seals no row');
        const written = new Map<string, Input>();
        for (const principal of sealing) {
          const resealed = await this.#seal(d, principal, accessSeq.get(principal));
          if (resealed === null) continue;
          written.set(objectKey(memberRef(principal)), resealed.object);
          d.changes?.cite(memberRef(principal), resealed.accessSeq);
        }
        // Last: the fence, which they take exclusive (0.14's append took it already, OldWritesFence), is held from
        // here to the commit, so as few round trips as can be. The append comes first, and its trigger took the issue
        // lock before the fence (0026): a change taking the fence before the issue lock would wait in a circle with the
        // barrier, which takes them in that order (Migration015.tla, IssueBeforeFence).
        // With the COMMIT, under its Sync: their numbers answer after it.
        const numbers = d.changes === null ? null : await d.changes.commit(tx, at, written);
        return { result, numbers };
      });
      const committed = await (retries === null ? transaction() : retryingLocks(transaction, retries));
      this.#reported(reports);
      // A change answers once its entries are sealed (R51; HotPathOne's CommitBeforeAnswer): the newest of them, with
      // every number below it.
      const newest = committed.numbers === null ? null : await newestCommitted(this.#db, committed.numbers);
      if (newest !== null) await this.#prepared.log015!.sealThrough(newest);
      return { ok: true, ...committed.result };
    } catch (thrown) {
      const caught = (staged as Changes | null)?.failed(thrown) ?? thrown;
      const error = caught instanceof NotLogged ? this.#notLogged(reports, caught) : caught;
      if (!(error instanceof Refused || error instanceof Outage)) throw error;
      const entries = [...reports, ...readsByPlace(error.entries)];
      if (entries.length > 0) {
        // A refusal's entries are written whatever the decision's bound: it answers only once they are. A read's, within
        // its call's deadline: past it, the call fails as unavailable, having released nothing.
        const record = () => this.#db.transaction(async (tx) => {
          if (shared) await store.boundLockWaits(tx, within(deadline, READ_LOCK_TIMEOUT_MS), within(deadline, READ_LOCK_TIMEOUT_MS));
          else await store.boundLockWaits(tx, LOCK_WAIT_MS);
          // In one of the head's places in line, as the read's decision waited, or refused at once.
          if (shared) await lockLogHeadQueued(tx, READ_HEAD_WAITERS);
          await this.#append(tx, entries);
        });
        // A change's, its lock waits retried as its decision's are, within the call's time.
        await (shared ? record() : retryingLocks(record, deadline ?? Date.now() + CALL_DEADLINE_MS));
      }
      this.#reported(reports);
      if (error instanceof Outage) throw error.error;
      return { ok: false, refusal: error.refusal };
    }
  }

  /**
   * Seal `principal`'s row again over what this decision left them holding,
   * naming `accessSeq`, their newest access entry, when it wrote one. The
   * table must hold exactly that: a grant written around the vault while it
   * decided (its row lock does not stop one) is refused, with the decision,
   * rather than sealed in. It answers the member's object as the rows now
   * hold it, and the access entry their row names, for 0.15's log.
   */
  async #seal(d: Decision, principal: string, accessSeq: bigint | undefined): Promise<{ object: PrincipalInput; accessSeq: bigint } | null> {
    // The row and the grants together, one round trip: plain reads, after the decision's writes, under its row lock.
    const [row, held] = await Promise.all([store.member(d.tx, principal), store.grants(d.tx, principal)]);
    if (row === undefined) return null;
    const decided = d.grants.get(principal);
    if (decided === undefined) throw new Error(`sealing ${principal} without the grants this decision verified`);
    if (!sameGrants(held, decided)) {
      this.#report(d.reports, principal, 'mac', row.mac.toString('hex'));
      throw new Refused(refusal('tampered', REFUSAL_MESSAGES.tampered), []);
    }
    const next = { ...row, accessSeq: accessSeq ?? row.accessSeq };
    // Nothing awaits it: it goes with the next member's reads, or the changes and the COMMIT.
    await store.updateMember(d.tx, principal, { accessSeq: next.accessSeq, mac: memberMac(this.#prepared.rowKey, next, decided) }, { final: true });
    // The member's object as the rows hold it now, which 0.15's change of it must have left, and the access entry its
    // row names, which that change accounts for (`changes.ts`).
    return { object: principalObject(row, decided), accessSeq: next.accessSeq };
  }

  /**
   * Whether `row`, with these grants, is the row the vault last wrote: its
   * MAC holds, and it is the newest the log says. Before 0.15's cutover,
   * 0.14's log says it: the row names the newest access entry about the
   * member. A genuine row put back from before a later change passes the
   * first and fails the second. Entries in the vault's name that fail their
   * MAC are passed over, and reported: otherwise whoever can insert a row
   * could lock any member out. Once the cutover is written, 0.15's log says
   * it, as a use checks it (`#onLog`). `logs`, each member's as read with
   * the rows (`#sweep`, `#rotate`), else the snapshot's, else read here.
   */
  async #integrity(
    db: Queryable, principal: string, row: Member | undefined, grants: readonly GrantRow[], reports: NewEntry[], reads?: Snapshot,
    logs?: ReadonlyMap<string, MemberLog>,
  ): Promise<Fault | null> {
    // Read first under 0.15's log, which its 0.4 MAC's finding names too (`#report`): the read `#onLog` makes anyway.
    const log = this.#checksSeals() ? await this.#memberLog(db, principal, reads, logs) : null;
    if (row !== undefined && !this.#sealed(row, grants)) {
      this.#report(reports, principal, 'mac', row.mac.toString('hex'), null, log === null ? undefined : weighedOf(log));
      return 'mac';
    }
    if (log !== null) return this.#onLog(db, principal, row, grants, reports, reads, log);
    const newest = await this.#newestAccess(db, principal, reports, reads);
    // No row, and no entry of the vault's own: someone never admitted. No
    // row, but one: one deleted, unless it was admitted since the row was
    // read. Too many forged to see past: neither a row nor the lack of one holds.
    const seq = typeof newest !== 'string' ? newest.seq : newest === 'unreached' ? undefined : null;
    if (row === undefined ? seq === null : seq === row.accessSeq) return null;
    if (row === undefined && (await store.member(db, principal)) !== undefined) throw new Retry();
    this.#report(reports, principal, 'stale', `${row?.accessSeq ?? 'none'}<${seq ?? newest}`);
    return 'stale';
  }

  /**
   * `#integrity` once 0.15's cutover is written (T179 PR 2;
   * docs/design/two-trips.md, "Compatibility"): the member's row as 0.15's
   * log holds it (Migration015.tla's MemberHolds), not a walk back through
   * 0.14's entries, which one statement cannot make (`write_request`, PR 3).
   * A use's check (`checkSeals`, `checkedOf`) is the same, the newest
   * change's MAC included (T190, `changeHolds`, which this one calls too):
   *
   * - the row's seal is the vault's over its object, the row and its grants
   *   (`principalObject`): `mac` otherwise, written around the vault;
   * - and its object's newest change's, once that change's MAC holds under
   *   one of the vault's keys (`mac` otherwise, its seal or `old` edited):
   *   `stale` otherwise, put back from before a change. No row is right only while the log has no change of
   *   the member either (a row the log never sealed has no seal: `mac`);
   * - and 0.14's log holds no access entry of the vault's past the one that
   *   change accounts for (its `old`; UsesSeeOldWrites): one there is a 0.14
   *   write the new log never saw, `stale`, which a seal the row passes
   *   could hide. The newest is read unchecked with the rest; only past
   *   `old` is it checked, and the forged passed over and reported, as
   *   before.
   *
   * The 0.4 MAC (`#sealed`) is checked first still: it covers columns the
   * object does not (`created_by`, `status_changed_by`).
   */
  async #onLog(
    db: Queryable, principal: string, row: Member | undefined, grants: readonly GrantRow[], reports: NewEntry[], reads: Snapshot | undefined,
    log: MemberLog,
  ): Promise<Fault | null> {
    const { newest } = log;
    // What each finding below names: the newest change it weighed (`#report`).
    const weighed = weighedOf(log);
    // The newest change's own MAC, under the vault's key its tag names, as a use checks one (`changeHolds`, T190): its
    // seal and `old` are only what a writer could not have edited once it holds (0.14's walk checked each entry it took so).
    if (newest !== null && !changeHolds(this.#prepared.log015!.macs, newest.row)) {
      this.#report(reports, principal, 'mac', 'log:change', null, weighed);
      return 'mac';
    }
    if (row === undefined) {
      if (newest !== null) {
        // Deleted outright, unless another decision admitted them since the row was read.
        if ((await store.member(db, principal)) !== undefined) throw new Retry();
        this.#report(reports, principal, 'stale', 'log:none', null, weighed);
        return 'stale';
      }
    } else {
      if (!sealedObject(this.#prepared.log015!.seals, memberRef(principal), principalObject(row, grants), log.seal)) {
        this.#report(reports, principal, 'mac', 'log:seal', null, weighed);
        return 'mac';
      }
      if (newest === null || newest.seal === null || log.seal === null || !newest.seal.equals(log.seal)) {
        this.#report(reports, principal, 'stale', 'log:newest', null, weighed);
        return 'stale';
      }
    }
    const old = newest?.old ?? null;
    const seen = reads !== undefined && reads.grants.has(principal) ? reads.newestAccess.get(principal)?.seq ?? null : log.access;
    if (seen === undefined) throw new Error("a member's log read without their newest access entry");
    if (seen === null || (old !== null && seen <= old)) return null;
    const authentic = await this.#newestAccess(db, principal, reports, reads);
    if (authentic === 'none' || authentic === 'forged' || (authentic !== 'unreached' && old !== null && authentic.seq <= old)) return null;
    this.#report(reports, principal, 'stale', `log:old<${typeof authentic === 'string' ? authentic : authentic.seq}`, null, weighed);
    return 'stale';
  }

  /**
   * Whether the vault checks the rows it decides on against 0.15's log: the
   * environments' (T159) and the members' (T179 PR 2, `#onLog`), under it,
   * once its cutover is written, which seals every row. Every read of them
   * asks their seals then (`seals`).
   */
  /** Why a change to, or an issue for, a tampered member is refused, and what recovers them under this log. */
  #tamperedSubject(): string {
    return this.#checksSeals() ? TAMPERED_SUBJECT_015 : TAMPERED_SUBJECT;
  }

  #checksSeals(): boolean {
    const { log015, cutover, marked } = this.#prepared;
    return log015 !== null && (cutover || marked);
  }

  /**
   * Why environment `id`'s row, as a decision read it, is not as 0.15's log
   * holds it (T159; R53, every decision input sealed): its seal is not the
   * vault's over its object (`tampered`: re-parented, renamed, its tombstone
   * set or cleared around the log), or not its object's newest change's
   * (`stale`: put back from before a change, or written with none), or
   * that change's MAC does not hold (`tampered`, T190: its seal column
   * written to match a row put back). A live
   * object in a project whose slug is a tombstone is `tampered` too: a
   * project's deletion under 0.15's log deletes each of its environments, as
   * the cutover sealed them, so only a writer leaves one so (review r2). Each
   * is reported, once, as a change refused on it is (`#notLogged`), the row's
   * and not any member's. Null when it is as the log holds it, and for a row
   * read without its seals: under 0.14's log alone, or before the cutover.
   */
  #placeFault(id: string, row: EnvironmentRow, reports: NewEntry[]): 'tampered' | 'stale' | null {
    const read = row.sealed;
    if (read === undefined) return null;
    let fault = PLACE_FAULTS.get(read);
    if (fault === undefined) {
      const log015 = this.#prepared.log015!;
      // The newest change's seal is held to the row only once that change's MAC holds (T190, review r3): else a row
      // put back after an archive or a protection, its old seal written into the change, passes as the log's.
      fault = !sealedObject(log015.seals, { kind: 'environment', id }, read.object, read.seal) || (row.deleted && !read.object.deleted)
          || (read.change !== null && !changeHolds(log015.macs, read.change)) ? 'tampered'
        : read.newest === null || !read.newest.equals(read.seal!) ? 'stale' : null;
      PLACE_FAULTS.set(read, fault);
    }
    if (fault !== null) this.#report(reports, null, fault === 'tampered' ? 'mac' : 'stale', `log.environment:${id}`);
    return fault;
  }

  /**
   * A member's grants whose places hold: each on an environment, on a row
   * as 0.15's log holds it, which its project is read from (the grant's row
   * names none of its own). One on a row that is not, or on no row, holds
   * nothing (T159): where it is is a writer's. Their other grants stand.
   * Each row from `rows` when there, else read, with its seals.
   */
  async #heldGrants(db: Queryable, grants: readonly GrantRow[], reports: NewEntry[], rows?: ReadonlyMap<string, EnvironmentRow>): Promise<GrantRow[]> {
    if (!this.#checksSeals()) return [...grants];
    const ids = [...new Set(grants.flatMap((grant) => (grant.environmentId === null ? [] : [grant.environmentId])))];
    const missing = ids.filter((id) => !rows?.has(id));
    const read = missing.length === 0 ? new Map<string, EnvironmentRow>() : await store.environmentsById(db, missing, { seals: true });
    const faulty = new Set(ids.filter((id) => {
      const row = rows?.get(id) ?? read.get(id);
      if (row !== undefined) return this.#placeFault(id, row, reports) !== null;
      this.#report(reports, null, 'stale', `log.environment:${id}`);
      return true;
    }));
    return grants.filter((grant) => grant.environmentId === null || !faulty.has(grant.environmentId));
  }

  /**
   * Refuse a decision about places whose rows are not as 0.15's log holds
   * them (`#placeFault`), each reported: what it would decide on them is a
   * writer's (T159). Ids with no row are left to the decision, which knows
   * no such place.
   */
  #placesHold(rows: ReadonlyMap<string, EnvironmentRow>, ids: Iterable<string>, reports: NewEntry[]): void {
    let hold = true;
    for (const id of new Set(ids)) {
      const row = rows.get(id);
      if (row !== undefined && this.#placeFault(id, row, reports) !== null) hold = false;
    }
    if (!hold) throw new Refused(refusal('tampered', TAMPERED_PLACE), []);
  }

  /**
   * The policy `edits` make over the rows of the environments they protect
   * (`livePolicy`), a row not as 0.15's log holds it taken as still
   * protected, its slug unknown: one deleted or renamed around the log
   * narrows what anyone holds there, never widens it (T159).
   */
  #livePolicy(rows: ReadonlyMap<string, EnvironmentRow>, edits: PolicyEdits, at: number, reports: NewEntry[]): Policy {
    const held = new Map([...rows].map(([id, row]) => [id, this.#placeFault(id, row, reports) === null ? row : { ...row, slug: null, deleted: false }]));
    return livePolicy(held, edits, at);
  }

  /** The newest access entry about `principal` that carries the vault's MAC (`newestAccess` in @coffre/db/grants). */
  #newestAccess(db: Queryable, principal: string, reports: NewEntry[], reads?: Snapshot): Promise<Newest> {
    if (reads === undefined || !reads.grants.has(principal)) return newestAccess(db, principal, this.#check(reports, principal));
    // The snapshot's newest first, read with the rest; the pages before it, as they are asked.
    const newest = reads.newestAccess.get(principal);
    return newestAuthentic(
      (limit, before) => (before === undefined ? Promise.resolve(newest === undefined ? [] : [newest]) : store.accessEntriesAbout(db, principal, limit, before)),
      this.#check(reports, principal),
    );
  }

  /** Entries in the vault's name told apart by their MACs, each it did not write reported, about `principal`. */
  #check(reports: NewEntry[], principal: string | null): Authenticity {
    return {
      authentic: (entry) => this.#authentic(entry),
      forged: (entry) => this.#report(reports, principal, 'forged_entry', String(entry.seq), entry.seq),
    };
  }

  /** Whether `entry` carries the vault's MAC: under any of its keys before `since`, and only its current one from there. */
  #authentic(entry: StoredEntry): boolean {
    return verifyEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash, keys: this.#keysFor(entry) }).ok;
  }

  /** The vault's log keys an entry may be under: any of them before `since`, and only its current one from there. */
  #keysFor(entry: StoredEntry): LogKey[] {
    const { logKeys, since } = this.#prepared;
    return since !== null && entry.seq >= since ? logKeys.slice(0, 1) : logKeys;
  }

  /**
   * Whether `row`, with these grants, carries the MAC of the vault's row
   * key, or of one it replaced before the rotation sealed every row again
   * (`#rotate`).
   */
  #sealed(row: Member, grants: readonly GrantRow[]): boolean {
    const { rowKeys, since } = this.#prepared;
    return (since === null ? rowKeys : rowKeys.slice(0, 1)).some((key) => sealed(key, row, grants));
  }

  /** A member's `MemberLog`: the one a decision or snapshot read, or one statement now. */
  async #memberLog(db: Queryable, principal: string, reads?: Snapshot, logs?: ReadonlyMap<string, MemberLog>): Promise<MemberLog> {
    return logs?.get(principal) ?? reads?.memberLogs.get(principal) ?? (await store.memberLogs(db, [principal])).get(principal)!;
  }

  /**
   * A `vault.tampered` entry, once per process for each thing found: `#reported` marks it once committed. A member's
   * row (`mac`, `stale`) found under 0.15's log names the newest change of theirs the check weighed (`weighed`, its
   * MAC, `changeName`, `findingMetadata`; T179 PR 4a), which a later change replaces as their newest: the same thing
   * found again after one is another finding. Passed where the check read it (`#onLog`); otherwise read as the entry
   * appends (`#weigh`).
   */
  #report(
    reports: NewEntry[], principal: string | null, code: Fault | 'forged_entry', detail: string, relatedSeq: bigint | null = null,
    weighed?: string,
  ): void {
    const key = `${principal}|${code}|${detail}|${weighed ?? ''}`;
    if (this.#prepared.reported.has(key) || reports.some((entry) => REPORTED.get(entry) === key)) return;
    const entry: NewEntry = {
      actor: VAULT_ACTOR,
      action: 'vault.tampered',
      decision: 'deny',
      code,
      subjectPrincipal: principal,
      relatedSeq,
      metadata: weighed === undefined ? '{}' : findingMetadata(weighed),
    };
    REPORTED.set(entry, key);
    reports.push(entry);
  }

  /**
   * A change refused because 0.15's log does not hold its object as its row
   * is (`changes.ts`): a row put back, or written around the vault. Reported
   * as a tampered row is, and refused: adoption or a reseal (plan PR 9)
   * makes it the log's again, never a change on top of it.
   */
  #notLogged(reports: NewEntry[], error: NotLogged): Refused {
    const { ref } = error;
    this.#report(reports, ref?.kind === 'principal' ? ref.id : null, error.fault === 'tampered' ? 'mac' : 'stale', ref === null ? 'log.object' : `log.${ref.kind}:${ref.id}`);
    return new Refused(refusal('tampered', error.message), []);
  }

  /**
   * Under 0.15's log, each finding about a member's row that does not name
   * the change it weighed, because what found it read no change (a grant
   * written in during the decision, `#seal`; a change refused, `#notLogged`),
   * names their newest as it appends: one read, in its transaction, for
   * all of them. A change committed between the check and this read is one
   * whose own check passed their row: the finding then stands until the
   * next, as 0.14's rule held it past the access entry that change wrote.
   */
  async #weigh(tx: Transaction, entries: readonly NewEntry[]): Promise<void> {
    if (!this.#checksSeals()) return;
    const unweighed = entries.filter((entry) => REPORTED.has(entry) && entry.subjectPrincipal != null && (entry.code === 'mac' || entry.code === 'stale') && entry.metadata === '{}');
    if (unweighed.length === 0) return;
    const names = await newestChangeNames(tx, [...new Set(unweighed.map((entry) => entry.subjectPrincipal!))]);
    for (const entry of unweighed) entry.metadata = findingMetadata(names.get(entry.subjectPrincipal!)!);
  }

  /** Mark these reports as logged, once their transaction has committed. */
  #reported(reports: readonly NewEntry[]): void {
    for (const entry of reports) {
      const key = REPORTED.get(entry);
      if (key !== undefined) this.#prepared.reported.add(key);
    }
  }

  /** Reports found outside a decision, committed on their own. */
  async #record(reports: NewEntry[]): Promise<void> {
    if (reports.length === 0 || (await this.#settled()) !== null) return;
    await this.#db.transaction((tx) => this.#append(tx, reports));
    this.#reported(reports);
  }

  // --- its keys over time -------------------------------------------------------

  /**
   * Null when the vault may write, once its keys are settled (`#settle`);
   * otherwise why not. Settled by the first call of a process; one that
   * fails leaves it to the next.
   */
  async #settled(): Promise<string | null> {
    const prepared = this.#prepared;
    if (prepared.superseded !== null) return prepared.superseded;
    // Each call that finds it unsettled reads for itself, over its own
    // database; calls that race settle it alike, and a rotation they race
    // to write goes in once (`#rotate`).
    const start = this.#start();
    if (start === null) return null;
    if (prepared.since === null) await this.#settle(start);
    // Under 0.15's log, nothing of its own before the cutover (`cutover`): the conversion and the Owners it names, and
    // the bulk cap, after it, as decisions of 0.15's log.
    if (prepared.superseded === null && prepared.log015 !== null && !prepared.cutover && !prepared.marked) {
      if ((await (start.cutover ?? store.cutoverNumber(this.#db))) === null) return prepared.superseded;
      prepared.marked = true;
    }
    // A log with no entry of the vault's holds nothing to convert, and stays empty until someone acts.
    if (prepared.superseded === null && prepared.since !== null && !prepared.converted) await this.#convert(start);
    if (prepared.superseded === null && prepared.log015 !== null && !prepared.limited) await this.#limit(start);
    if (prepared.superseded === null && prepared.log015 !== null && !prepared.rolesSynced) await this.#syncRoles(start);
    return prepared.superseded;
  }

  /**
   * What a call's start reads first, asked at once (T206): one round trip
   * on Workers, where the vault's pool sends plain reads asked together
   * under one Sync (`groupReads`, cloudflare.ts), as Node's pool sends them
   * on connections side by side; asked one after another, as each step
   * came to it, they made a cold isolate's first call some ten round
   * trips before its first decision. Each is the unlocked read its step
   * began with, which it checks as it did: only asked sooner, before the
   * steps between, none of which writes what another of them reads. A
   * step that reads again, a retry or under a lock, reads the database.
   * Local to the call, as an isolate keeps no pending promise (AGENTS.md).
   * Only the reads of steps still due, and null when none is: the vault is
   * settled.
   */
  #start(): StartReads | null {
    const db = this.#db;
    const prepared = this.#prepared;
    const log015 = prepared.log015 !== null;
    const settle = prepared.since === null;
    const convert = !prepared.converted;
    // The cutover mark's, until the cutover or the mark; the Owners' declaration's, until the conversion lands.
    const cutover = log015 && !prepared.cutover && (!prepared.marked || convert);
    const limit = log015 && !prepared.limited;
    const sync = log015 && !prepared.rolesSynced;
    if (!settle && !convert && !cutover && !limit && !sync) return null;
    const asked: StartReads = {
      rotation: settle ? store.latestVaultEntry(db, [KEY_ROTATE]) : undefined,
      newest: settle ? store.vaultPage(db, undefined, 1).then(([entry]) => entry) : undefined,
      // None once a rotation to the key is logged (R48): `#settle` reads it again if it needs it after all.
      first: settle ? store.firstVaultEntryUnder(db, prepared.logKey.keyId, { unlessRotated: true }) : undefined,
      cutover: cutover ? store.cutoverNumber(db) : undefined,
      checkpoint: cutover && convert ? logStore(db).newest() : undefined,
      holders: convert ? store.everyProjectHolders(db) : undefined,
      policy: limit ? store.readObject(db, POLICY_REF as Ref & { kind: 'policy' }) : undefined,
      roles: sync ? store.roleRows(db) : undefined,
      whole: sync ? heldByLog(prepared.log015!, db, ROLES_REF as Ref & { kind: 'roles' }) : undefined,
    };
    // A step that returns first leaves the reads after it unawaited: their failures are the call's own, not unhandled.
    for (const read of Object.values(asked)) (read as Promise<unknown> | undefined)?.catch(() => {});
    return asked;
  }

  /**
   * Replace every grant on every project of 0.4 with what 0.5 has instead
   * (`convertEveryProjectGrants` in @coffre/core/access): a person's
   * instance role and its scope, and project grants on the projects there
   * are now. Once per process, before its first call does anything else:
   * one decision per member who holds any, as `system:vault`, each grant it
   * replaces an `access.revoke` that says what became of it. Another
   * process that converts the same member at once finds nothing left under
   * their lock. A member whose row fails its check is left as they are, and
   * so is one the vault has reported changed around it since the last
   * change to what they hold, even if their row checks out again now (a
   * genuine row put back). `reportStands` is the rule, which `coffre
   * migrate` applies too, holding no key, to every entry in the vault's
   * name: it lists and marks a member so reported, forged or not.
   * Removing them clears both. Then everyone the deployment names becomes
   * an Owner (`#declare`): after, so that what their grants become is what
   * `coffre migrate` says, by the same rule over the same rows
   * (`everyProjectConversion`), which cannot tell who the configuration
   * names. Until both finish, each call does again what is left, a few
   * reads once nothing is.
   */
  async #convert(start: StartReads): Promise<void> {
    const holders = await (start.holders ?? store.everyProjectHolders(this.#db));
    for (const principal of holders) {
      await this.#decideNow([principal], (d) => this.#replaceEveryProject(d, principal));
    }
    // A conversion decided reads the cutover's seal again, as it did; none, and the Owners' declaration takes the start's.
    this.#prepared.converted = await this.#declare(this.#config.owners.map((email) => `user:${email}`), holders.length === 0 ? start : undefined);
  }

  /**
   * Under 0.15's log, the deployment's bulk cap written into it before the
   * vault serves anything (plan PR 3, `limitChange`): a `bulk.limit` change
   * whenever the log's policy says otherwise, as any change, under the head
   * and the fence. Uses read the cap from it (CapSealed), never from the
   * configuration. Once per process; until it lands, each call tries again.
   * A cap the log already holds is read first, with no lock: every isolate
   * that starts finds it there, and takes neither 0.14's head nor the fence
   * for it, which every other start would queue behind (PR 5b's bench).
   */
  async #limit(start: StartReads): Promise<void> {
    const { row: logged } = await (start.policy ?? store.readObject(this.#db, POLICY_REF as Ref & { kind: 'policy' }));
    if (limitChange(logged?.kind === 'policy' ? logged : null, this.#config.bulkLimit) === null) {
      this.#prepared.limited = true;
      return;
    }
    const outcome = await this.#decideNow([], async (d) => {
      const { row } = await store.readObject(d.tx, POLICY_REF as Ref & { kind: 'policy' });
      const op = limitChange(row?.kind === 'policy' ? row : null, this.#config.bulkLimit);
      if (op !== null) d.changes!.stage(POLICY_REF as Ref & { kind: 'policy' }, op, VAULT_ACTOR);
    });
    if (outcome.ok) this.#prepared.limited = true;
  }

  /**
   * Under 0.15's log, every role's row made what the log's roles object
   * says, sealed (T178, 0.16; formal/Roles.tla's sync): a change of each
   * that is not, as any change, under the head and the fence, once per
   * process, before the vault serves anything, after the bulk cap. 0.15.0's
   * changes of the roles object leave the rows of the roles they change
   * unsealed, and a writer may move any: each start puts them right, so
   * that 0.17, which reads them, finds every one sealed (0.17 follows a
   * 0.16 that started, NeverSkip). The rows are read first with no lock:
   * an isolate that finds them in step takes none. A roles object the log
   * does not bear out is refused wherever it is read: its rows wait for a
   * start after an Owner writes it again.
   */
  async #syncRoles(start: StartReads): Promise<void> {
    const log015 = this.#prepared.log015!;
    const wholeOf = (held: Held): RolesInput => (held.log === 'live' && held.object.kind === 'roles' ? held.object : noEdits());
    try {
      const [rows, whole] = await Promise.all([start.roles ?? store.roleRows(this.#db), start.whole ?? heldByLog(log015, this.#db, ROLES_REF as Ref & { kind: 'roles' })]);
      if (roleChanges(log015.seals, wholeOf(whole), rows).length > 0) {
        const outcome = await this.#decideNow([], async (d) => {
          const [held, under] = await Promise.all([d.changes!.held(d.tx, ROLES_REF as Ref & { kind: 'roles' }), store.roleRows(d.tx)]);
          for (const { ref, op } of roleChanges(log015.seals, wholeOf(held), under)) d.changes!.stage(ref, op, VAULT_ACTOR);
        });
        if (!outcome.ok) return;
      }
    } catch (error) {
      if (!(error instanceof NotLogged)) throw error;
    }
    this.#prepared.rolesSynced = true;
  }

  async #replaceEveryProject(d: Decision, principal: string): Promise<void> {
    const row = d.members.get(principal);
    const subject = await this.#standing(d.tx, principal, row, d.at, d.reports, d.reads);
    if (row === undefined || subject.status !== 'active') return;
    const everyProject = subject.stored.filter((grant) => grant.projectId === null && grant.environmentId === null);
    if (everyProject.length === 0) return;
    // Weighed against the change their row was just checked against, its MAC with it (`#onLog`), not the newest read
    // again: that read's number is no MAC's (review r1 of #476). Without 0.15's log checked, none: only 0.14's findings
    // are the vault's then (review r2).
    const weighed = subject.log === undefined ? null : weighedOf(subject.log);
    if (await reportStands(d.tx, principal, this.#check(d.reports, principal), weighed)) return;
    // The projects there are now, read under the log's head, which a deletion holds; each environment by its slug as 0.15's
    // log holds its row (T159, review r7): a grant on a slug in every project becomes one on each place that answers to
    // it, never on one a writer renamed into it.
    const before = roleOf(principal, row);
    const conversion = everyProjectConversion(principal, before.role, subject.stored, d.at, await this.#livePlaces(d));
    const after = { role: conversion.role, scope: conversion.scope };
    const replacedBy = { role: after.role, scope: after.scope, grants: conversion.grants.length };
    d.grants.set(principal, [...subject.stored]);
    d.touched.add(principal);
    const correlation = { operationId: randomUUID() };
    const drop = (grant: GrantRow) =>
      d.writes.push(async () => {
        await store.deleteGrant(d.tx, principal, grant);
        d.grants.set(principal, d.grants.get(principal)!.filter((held) => held !== grant));
      });

    for (const grant of everyProject) {
      drop(grant);
      d.changes?.stage(memberRef(principal), { op: 'access.revoke', place: placeOf(grant) }, VAULT_ACTOR);
      // A lapsed one goes with no entry: it changes nothing anyone holds.
      if (!live(grant, d.at)) continue;
      const narrowed = conversion.narrowed.filter((loss) => loss.grant.environmentSlug === grant.environmentSlug);
      d.log.push(accessEntry(VAULT_ACTOR, 'access.revoke', principal, 'allow', correlation, {
        role: null,
        expiresAt: null,
        previousRole: grant.role,
        ...located(grant).detail,
        replacedBy,
        ...(narrowed.length === 0 ? {} : { narrowed: narrowed.map(({ grant: _, ...loss }) => loss) }),
      }));
    }
    if (JSON.stringify(standing(after)) !== JSON.stringify(standing(before))) {
      d.log.push(accessEntry(VAULT_ACTOR, 'member.role', principal, 'allow', correlation, {
        ...after,
        previousRole: before.role,
        previousScope: before.scope,
        reason: 'every-project',
      }));
      d.writes.push(() => store.updateMember(d.tx, principal, after));
      d.changes?.stage(memberRef(principal), { op: 'member.role', ...asStored(after.role, after.scope) }, VAULT_ACTOR);
    }
    for (const given of conversion.grants) {
      const place = { projectId: given.projectId, environmentId: given.environmentId, environmentSlug: null };
      // Whatever they held there, lapsed or not, makes way: the conversion never gives less there than it was.
      const there = subject.stored.find((grant) => grantKind(grant) !== null && placeKey(grant) === placeKey(place));
      if (there !== undefined) drop(there);
      d.writes.push(async (at) => {
        const grant = { principal, ...place, role: given.role, expiresAt: given.expiresAt, grantedAt: at, grantedBy: VAULT_ACTOR };
        await store.insertGrant(d.tx, grant);
        d.grants.get(principal)!.push(grant);
      });
      d.changes?.stage(memberRef(principal), { op: 'access.grant', grant: inputGrant({ ...place, role: given.role, expiresAt: given.expiresAt }) }, VAULT_ACTOR);
      d.log.push({
        ...accessEntry(VAULT_ACTOR, 'access.grant', principal, 'allow', correlation, {
          role: given.role,
          expiresAt: given.expiresAt === null ? null : iso(given.expiresAt),
          previousRole: given.replaces,
          reason: 'every-project',
        }),
        ...located(place).ids,
      });
    }
  }

  /**
   * Which of its keys count where. Those it replaced, from the KEKs in
   * previousKeks, verify only what came before its first entry under its
   * current key, `since`, and vouch for no member row after it. The first
   * call finds that entry, or makes it when every entry of the vault's is
   * still under a key it replaced (`#rotate`). A vault whose key the log has
   * moved on from, or that holds no key its newest entries are under,
   * writes nothing: `superseded` says why.
   */
  async #settle(start?: StartReads): Promise<void> {
    const prepared = this.#prepared;
    const current = prepared.logKey.keyId;
    for (let attempt = 1; ; attempt += 1) {
      // The start's reads first; a retry, after a rotation that raced another, reads again.
      const asked = attempt === 1 ? start : undefined;
      const rotation = await (asked?.rotation ?? store.latestVaultEntry(this.#db, [KEY_ROTATE]));
      if (rotation?.keyId === current && this.#authentic(rotation)) {
        prepared.since = rotation.seq;
        return;
      }
      const newest = await (asked?.newest ?? store.vaultPage(this.#db, undefined, 1).then(([entry]) => entry));
      // A log the vault has not written to: nothing to settle until it does.
      if (newest === undefined) return;
      // The start's says only where it found one: none may mean a rotation to the key it did not walk past.
      const first = (await asked?.first) ?? (await store.firstVaultEntryUnder(this.#db, current));
      if (first !== undefined && newest.keyId === current) {
        prepared.since = first;
        return;
      }
      if (first === undefined && prepared.logKeys.some((key) => key.keyId === newest.keyId)) {
        try {
          prepared.since = await this.#rotate(newest.keyId);
          return;
        } catch (error) {
          if (attempt < 3 && error instanceof Retry) continue;
          throw error;
        }
      }
      prepared.superseded =
        first === undefined
          ? `the vault's entries are under ${newest.keyId}, a key this vault does not hold: it was given the wrong vault key or signing key, or a vault key it replaced is missing from previousKeks in its config`
          : `the log moved on from this vault's key, ${current}, to ${newest.keyId}: a vault given a newer vault key replaced it, and a replaced key writes nothing more`;
      return;
    }
  }

  /**
   * Move the vault to its current key: every member row it can vouch for
   * sealed again under the current row key, then a `key.rotate` entry, its
   * first under the key, after which the keys it replaced count for
   * nothing. One transaction, which locks every row as a decision does,
   * then the log's head. Another instance that rotated first, or a member
   * admitted since the rows were read, sends it back to `#settle`.
   */
  async #rotate(from: string): Promise<bigint> {
    const reports: NewEntry[] = [];
    // Its lock waits retried as a change's are (`retryingLocks`): each attempt reports afresh.
    const since = await retryingLocks(() => this.#db.transaction(async (tx) => {
      reports.length = 0;
      await store.boundLockWaits(tx, LOCK_WAIT_MS);
      const principals = (await store.allMembers(tx)).map((row) => row.principal);
      const rows = principals.length === 0 ? new Map<string, Member>() : await store.lockMembers(tx, principals);
      await lockLogHead(tx);
      const [newest] = await store.vaultPage(tx, undefined, 1);
      if (newest?.keyId !== from || (await store.allMembers(tx)).length !== rows.size) throw new Retry();
      const held = await store.grants(tx);
      // A process's first call settles its key before it learns the cutover (`#settled`): learnt here, since a row
      // must be held to the log that holds it. Since 0.16.0, a member added down the two-trip path and changed no
      // further has no 0.14 access entry, which 0.14's rule reads as stale: left under the old key, refused after
      // (review r1 of #490). The cutover is never undone, so a retry finds it the same.
      if (this.#prepared.log015 !== null && !this.#checksSeals() && (await store.cutOver(tx))) this.#prepared.marked = true;
      // Once 0.15's log holds the rows, each one's seals, all in one read (`#onLog`).
      const logs = this.#checksSeals() ? await store.memberLogs(tx, [...rows.keys()]) : undefined;
      for (const row of rows.values()) {
        const grants = held.filter((grant) => grant.principal === row.principal);
        // A row that fails is reported, and left under the key it was sealed with, which fails it from now on.
        if ((await this.#integrity(tx, row.principal, row, grants, reports, undefined, logs)) === null) {
          await store.updateMember(tx, row.principal, { mac: memberMac(this.#prepared.rowKey, row, grants) });
        }
      }
      const rotated = { actor: VAULT_ACTOR, action: KEY_ROTATE, decision: 'allow' as const, metadata: JSON.stringify({ from }) };
      // Each key service's intent still open, under the head every outcome appends under: no vault on the key this
      // retires can log its outcomes after this, nor does it hold a lock this waits for while its key service answers
      // (R75). So they are logged here, under the new key, each key refused (formal/Coffre.tla's RotationClosesIntents).
      const closed = await this.#closeIntents(tx);
      return (await this.#append(tx, [rotated, ...closed, ...reports])).seqStart;
    }), Date.now() + CALL_DEADLINE_MS);
    this.#reported(reports);
    return since;
  }

  /**
   * An outcome for each key of each key service's intent still open and not yet overdue, refused (`wrong_kek`, the
   * code a superseded vault answers: its call cannot release anything now), `uncertain` since its key service may have
   * answered, `closedBy` the rotation. Under the head, and the intents read by their MACs: one the vault never wrote is
   * not closed, nor one already overdue, which is a call that ended without its outcomes, and stays a finding.
   */
  async #closeIntents(tx: Transaction): Promise<NewEntry[]> {
    const at = await this.#now(tx);
    // The longest an intent is open: its call's budget from its own time, and the margin after it (`#keys`), whatever the
    // key budget of the isolate that logged it, this one's or the default (Fable's review of #538): each is then held
    // to its own `expiresAt`.
    const lifetime = 2 * CALL_DEADLINE_MS + Math.max(KEY_BUDGET_MS, this.#prepared.options.keyBudgetMs);
    const entries = await store.recentIntents(tx, at - lifetime);
    const accounting = new KeyAccounting();
    const logged = new Map<bigint, StoredEntry>();
    for (const entry of entries) {
      if (!this.#authentic(entry)) continue;
      accounting.add(entry);
      if (entry.action === 'key.intent') logged.set(entry.seq, entry);
    }
    return accounting.state().intents.filter((intent) => intent.expiresAt > at).flatMap((intent) => {
      const raw = logged.get(BigInt(intent.seq))!;
      const keys = (JSON.parse(raw.metadata) as { keys: { logged?: Logged }[] }).keys;
      return intent.keys.filter((key) => !intent.seen.includes(key.item)).map((key): NewEntry => {
        // As the call would have logged it (`loggedAs`, in its intent): its place, its holder's (`also`), its version.
        // A wrap's secret may have no row yet (a new key is wrapped before the app writes it), so it is named in the
        // metadata alone, as `keyEntry` names it, never in the column, whose foreign key would refuse it (review r6).
        const as = keys[key.item]?.logged ?? {
          projectId: null, environmentId: null, secretId: intent.operation === 'key.wrap' ? null : key.secretId, secretVersionId: null,
          detail: { subject: key.subject, ...(intent.operation === 'key.wrap' ? { secretId: key.secretId } : {}), version: key.version },
        };
        return {
          actor: intent.actor,
          action: intent.operation,
          decision: 'deny',
          code: 'wrong_kek',
          projectId: as.projectId,
          environmentId: as.environmentId,
          secretId: intent.operation === 'key.wrap' ? null : as.secretId,
          secretVersionId: as.secretVersionId,
          operationId: raw.operationId,
          requestId: raw.requestId,
          relatedSeq: BigInt(intent.seq),
          metadata: JSON.stringify({ ...as.detail, intent: intent.intentId, item: key.item, uncertain: true, closedBy: KEY_ROTATE }),
        };
      });
    });
  }

  /**
   * Append under the vault's current key, unless the log's newest rotation
   * is to a key it does not hold: a vault given a newer KEK has replaced
   * this one, which writes nothing more. Checked under the head's lock, so
   * that an instance still running with the replaced KEK, as during a
   * deploy, cannot write after the rotation. Under 0.15's log, its entries
   * say so (`log015`): once cut over, the log refuses a write without it.
   */
  async #append(
    tx: Transaction,
    entries: readonly NewEntry[],
    underLock: readonly ((locked: Queryable) => Promise<void>)[] = [],
    /** A snapshot that holds the head: what it read under it is read again by nothing. */
    held?: Snapshot,
    /** Nothing in the transaction awaits the append (`appendEntries`): it goes with what follows, its COMMIT at the latest. */
    { final = false }: { final?: boolean } = {},
  ): Promise<Appended> {
    const prepared = this.#prepared;
    const head = held?.head ?? undefined;
    await this.#weigh(tx, entries);
    const appended = await appendEntries(tx, prepared.logKey, entries, async (locked) => {
      const rotation = head === undefined ? await store.latestVaultEntry(locked, [KEY_ROTATE]) : head.rotation ?? undefined;
      if (rotation !== undefined && !prepared.logKeys.some((key) => key.keyId === rotation.keyId)) {
        prepared.superseded = `the log moved on to ${rotation.keyId}, a key this vault does not hold: a vault given a newer vault key replaced it, and a replaced key writes nothing more`;
        throw new Error(prepared.superseded);
      }
      for (const check of underLock) await check(locked);
    }, head === undefined ? undefined : { head, last: head.last, at: held!.at }, [], prepared.log015 !== null, { final });
    // The head still held, as this append left it, for the next append of the same transaction: a remote key's intent,
    // then the decision's reports.
    if (head !== undefined) {
      held!.head = { ...head, nextSeq: appended.nextSeq, headHash: appended.headHash, last: { seq: appended.nextSeq - 1n, hash: appended.headHash } };
    }
    return appended;
  }

  // --- keys -------------------------------------------------------------------

  // Raw DEKs are cleared on every path. JSON and base64 leave strings that
  // cannot be wiped, so this is best-effort memory hygiene.
  async unwrap(input: UnwrapInput): Promise<Outcome<Unwrapped>> {
    const { principal } = input;
    const use = input.use === undefined ? null : useEntry(principal, input, input.use);
    validateText(input.purpose);
    if (input.keepsSensitive !== undefined && typeof input.keepsSensitive !== 'boolean') throw new Error('keepsSensitive is true, false or absent');
    if (input.accessRevision !== undefined && typeof input.accessRevision !== 'string') throw new Error('accessRevision names an answer of access, or is absent');
    const vias = input.items.map((item) => validateVia(item.via));
    const throughs = input.items.map((item) => validateThrough(item.through));
    const loaded = await this.#versions(input, 'secret.read', { purpose: input.purpose });
    if (!loaded.ok) return loaded;
    // RPC can preserve shared objects, and two holders can read one source: each item its own secret.
    const items = loaded.versions.map((version) => ({ ...version, secret: { ...version.secret } }));
    validateItems(items, 'wrapped');
    const sealed = await this.#referencesAt(vias);
    // Settled first, as a decision is: a new process learns here whether the log is cut over, and so whether a fork's row
    // is held to its seal (review r1).
    await this.#settled();
    const forks = await store.environmentsById(this.#db, throughs.flatMap((through) => (through === null ? [] : [through])), { seals: this.#checksSeals() });
    // A fork whose row is not as 0.15's log holds it is no place to read through (T159), reported.
    const forkReports: NewEntry[] = [];
    for (const [id, fork] of forks) if (this.#placeFault(id, fork, forkReports) !== null) forks.delete(id);
    await this.#record(forkReports);
    // A reference reads only the current version of the source its entry names.
    const viaOk = items.map((item, i) => vias[i] === null || (sealed[i] !== null && sealed[i]!.source.secretId === item.secret.secretId && item.current));
    // A fork an inherited value is read in is a live environment of the same project as the value's, and not its own,
    // for a read whose reference, if any, holds. Checked once, not again under the log's head: it decides nothing, so a
    // fork archived meanwhile only names a read.
    const throughOk = items.map((item, i) => {
      const through = throughs[i];
      if (through === null) return true;
      if (!viaOk[i]) return false;
      const fork = forks.get(through);
      const decidedAt = sealed[i]?.holder ?? item.secret;
      return fork !== undefined && !fork.deleted && !fork.archived && fork.projectId === decidedAt.projectId && through !== decidedAt.environmentId;
    });
    const versionIds = new Map(items.map((item) => [item.secret, item.id]));
    const viaOf = new Map(items.map((item, i) => [item.secret, { via: vias[i], sealed: sealed[i], through: throughs[i], throughOk: throughOk[i] }]));
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry => {
      const { via, sealed: seal, through, throughOk: ok } = viaOf.get(secret)!;
      return {
        ...keyEntry('secret.read', principal, secret, decision, code, input, {
          purpose: input.purpose,
          ...(via === null ? {} : viaDetail(via, seal)),
          // A fork that failed the check is named, never filed under: its project's log is no place for this read.
          ...(through === null ? {} : ok ? throughDetail(through, forks.get(through), via !== null) : { through: { environmentId: through, refused: true } }),
        }),
        secretVersionId: versionIds.get(secret),
      };
    };
    if (viaOk.includes(false)) {
      return this.#refuseVersions(principal, 'bad_claim', items.map((item) => entry(item.secret, 'deny', 'bad_claim')), { asked: input.accessRevision });
    }
    if (throughOk.includes(false)) {
      return this.#refuseVersions(principal, 'bad_claim', items.map((item) => entry(item.secret, 'deny', 'bad_claim')), { asked: input.accessRevision });
    }
    // The app's record of a use names where the read was, which the vault vouches for once it appends it: the place an
    // item was read at, the fork it is read in, else a reference's holder, else its own, with its project. Another is
    // a claim the read does not bear out, refused and logged as one; no use is appended.
    if (use !== null && (use.environmentId !== null || use.projectId !== null)) {
      const named = items.some((item, i) => {
        const fork = throughs[i] === null ? undefined : forks.get(throughs[i]!);
        const place = fork === undefined ? sealed[i]?.holder ?? item.secret : { projectId: fork.projectId, environmentId: throughs[i]! };
        return (use.environmentId === null || place.environmentId === use.environmentId) && (use.projectId === null || place.projectId === use.projectId);
      });
      if (!named) return this.#refuseVersions(principal, 'bad_claim', items.map((item) => entry(item.secret, 'deny', 'bad_claim')), { asked: input.accessRevision });
    }
    const ends = sealed.flatMap((seal) => (seal === null ? [] : [seal.seq]));
    const remote = items.some(({ wrapped }) => this.#remote(this.#config.keks.providerOf(wrapped)));
    return this.#keys(
      {
        action: 'secret.read',
        principal,
        // The proxy's use opens a value for coffre to use for its reader, never to hand back: `secret.use`. Anything else reads.
        permission: input.purpose === 'use' ? 'secret.use' : 'secret.read',
        secrets: items.map((item) => item.secret),
        // Through a reference, the holder decides, as for any key held there (R71).
        places: sealed.map((seal, i) => seal?.holder ?? items[i]!.secret),
        references: ends,
        vet: ends.length === 0 ? undefined : async (_, reads) => sealed.map((seal) => (seal !== null && reads.ended.has(seal.seq) ? 'ended' : null)),
        remote,
        entry,
        input,
        ...(use === null ? {} : { also: [use] }),
      },
      (contextOf) =>
        items.map(({ secret, wrapped }) => async (operation: KeyOperation) => {
          const key = await this.#open(wrapped, contextOf(secret), operation);
          return key && { key, wipe: () => key.fill(0) };
        }),
      // Each key as text, its buffer left whole: `#keys` wipes it once no attempt of the decision can answer again.
      (opened) => ({
        keys: opened.map(({ key }) => base64(key)),
        // Named back: the read was decided on that answer, which this vault checked.
        ...(input.accessRevision === undefined ? {} : { accessRevision: input.accessRevision }),
        // And the use, appended with the read: the app has nothing left to append.
        ...(use === null ? {} : { used: true as const }),
      }),
    );
  }

  async wrap(input: WrapInput): Promise<Outcome<Wrapped>> {
    const { principal, items } = input;
    validateItems(items, 'key');
    validateText(principal);
    validateCorrelation(input);
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry =>
      keyEntry('key.wrap', principal, secret, decision, code, input);
    return this.#keys(
      {
        action: 'key.wrap',
        principal,
        permission: 'secret.write',
        secrets: items.map((item) => item.secret),
        remote: this.#remote(this.#config.keks.primary),
        entry,
        input,
      },
      (contextOf) =>
        items.map(({ secret, key }) => async (operation: KeyOperation) => {
          const dek = Buffer.from(key, 'base64');
          try {
            return { wrapped: serialisable(await this.#config.keks.wrap(dek, contextOf(secret), operation)), wipe: () => {} };
          } finally {
            dek.fill(0);
          }
        }),
      (done) => ({ wrapped: done.map(({ wrapped }) => wrapped), seqs: [] as number[], sensitive: items.map(({ secret }) => secret.sensitive === true) }),
    );
  }

  async rewrap(input: RewrapInput): Promise<Outcome<Wrapped>> {
    const { principal } = input;
    const loaded = await this.#versions(input, 'key.rewrap');
    if (!loaded.ok) return loaded;
    // RPC can preserve shared objects; each item needs its own source.
    const items = input.items.map((item, i) => ({ secret: { ...item.secret }, wrapped: loaded.versions[i].wrapped }));
    validateItems(items, 'wrapped');
    const sameSecret = (secret: SecretRef, source: SecretRef) =>
      secret.projectId === source.projectId && secret.environmentId === source.environmentId && secret.secretId === source.secretId;
    if (items.some((item, i) => !sameSecret(item.secret, loaded.versions[i].secret))) {
      return this.#refuseVersions(principal, 'bad_claim', loaded.versions.map((source) => ({
        ...keyEntry('key.rewrap', principal, source.secret, 'deny', 'bad_claim', input), secretVersionId: source.id,
      })));
    }
    // A value is made looser only by writing it again: a sensitive value's key, or one of a secret whose newest version
    // is, is never wrapped again as anything but sensitive, so that a person who may not read it never makes it readable.
    // Nor a version whose value was made sensitive since, in place: the newest version of its very ciphertext. But for one:
    // a key's current sensitive value made a secret, in place, by an Owner of its project, who reads it anyway through a
    // service account they give read (R30). Older versions stay as they were held.
    const loosens = items.map((item, i) => item.secret.sensitive !== true && loaded.versions[i].secret.sensitive === true && loaded.versions[i].current);
    const strict = (i: number) => loaded.versions[i].secret.sensitive || loaded.versions[i].heldSensitive || loaded.versions[i].newestSensitive;
    if (items.some((item, i) => !loosens[i] && item.secret.sensitive !== true && strict(i))) {
      return this.#refuseVersions(principal, 'invalid', loaded.versions.map((source) => ({
        ...keyEntry('key.rewrap', principal, source.secret, 'deny', 'invalid', input), secretVersionId: source.id,
      })), { message: LOOSER });
    }
    const sources = new Map(items.map((item, i) => [item.secret, loaded.versions[i]]));
    const loosened = new Set(items.flatMap((item, i) => (loosens[i] ? [item.secret] : [])));
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry => ({
      ...keyEntry('key.rewrap', principal, secret, decision, code, input, { from: sources.get(secret)!.secret.version, ...(loosened.has(secret) ? { was: 'sensitive' } : {}) }),
      secretVersionId: sources.get(secret)!.id,
    });
    const remote =
      this.#remote(this.#config.keks.primary) || items.some(({ wrapped }) => this.#remote(this.#config.keks.providerOf(wrapped)));
    return this.#keys(
      {
        action: 'key.rewrap', principal, permission: 'secret.write', secrets: items.map((item) => item.secret), remote, entry, input,
        // Again in the decision and under the log's head: a sensitive version written since it was loaded is as newest as any,
        // a value made sensitive in place since is so, and a value loosened is still its key's current one.
        vet: async (db) => {
          const newest = await store.newestSensitive(db, items.map(({ secret }) => secret.secretId));
          // Each source again: current as the decision had it, its key's pointer and its newest, and its value as held now.
          const again = new Map((await store.versions(db, items.map(({ secret }) => sources.get(secret)!.id))).map((version) => [version.id, version]));
          return items.map(({ secret }, i) => {
            const now = again.get(sources.get(secret)!.id);
            if (loosens[i]) return now?.current === true ? null : 'invalid';
            return secret.sensitive !== true && (newest.has(secret.secretId) || now?.heldSensitive === true) ? 'invalid' : null;
          });
        },
        owns: loosens,
        // An old value brought back, not the current one, is made live by whoever could have read it: a secret by its
        // readers, a sensitive one, which nobody reads, by those who use it, a plain one by any writer, as it was shown
        // to them. Whatever reads the key next, a reference to it included, then reads what its restorer could. Typing a
        // value, or tightening the current one, takes no more than writing.
        needs: async (db) => {
          const restored = await store.restoredNatures(db, items.map(({ secret }) => ({ secretId: secret.secretId, from: sources.get(secret)!.id })));
          return restored.map((nature) => (nature === 'secret' ? ['secret.read'] as const : nature === 'sensitive' ? ['secret.use'] as const : null));
        },
      },
      (contextOf) =>
        items.map(({ secret, wrapped }) => async (operation: KeyOperation) => {
          // Opened as the source was written, sensitive or not, and wrapped as the new version is.
          const key = await this.#open(wrapped, contextOf(sources.get(secret)!.secret), operation);
          if (key === null) return null;
          try {
            return { wrapped: serialisable(await this.#config.keks.wrap(key, contextOf(secret), operation)), wipe: () => {} };
          } finally {
            key.fill(0);
          }
        }),
      (done) => ({ wrapped: done.map(({ wrapped }) => wrapped), seqs: [] as number[], sensitive: items.map(({ secret }) => secret.sensitive === true) }),
    );
  }

  /** Versions need no lock: they change only by being erased, once their place is archived, and their ids determine the whole batch before any key call. */
  async #versions(
    input: Correlation & { principal: string; items: { secretVersionId: string }[]; accessRevision?: string },
    action: KeyAction,
    detail: Record<string, unknown> = {},
  ): Promise<Outcome<{ versions: store.SecretVersion[] }>> {
    validateText(input.principal);
    validateCorrelation(input);
    const ids = input.items.map((item) => item.secretVersionId);
    for (const id of ids) {
      if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) {
        throw new Error('secret version id must be a lowercase UUID');
      }
    }
    const found = new Map((await store.versions(this.#db, ids)).map((version) => [version.id, version]));
    if ([...found.values()].some((version) => version.deleted)) {
      return this.#refuseVersions(input.principal, 'deleted', [...found.values()].map((version) => ({
        ...keyEntry(action, input.principal, version.secret, 'deny', 'deleted', input, detail), secretVersionId: version.id,
      })), { asked: input.accessRevision });
    }
    if (ids.some((id) => !found.has(id))) {
      return this.#refuseVersions(input.principal, 'bad_claim', ids.map((id) => {
        const version = found.get(id);
        if (version === undefined) return {
          actor: input.principal, action, decision: 'deny', code: 'bad_claim',
          operationId: input.operationId, requestId: input.requestId,
          metadata: JSON.stringify({ ...detail, secretVersionId: id, ...traced(input) }),
        };
        return { ...keyEntry(action, input.principal, version.secret, 'deny', 'bad_claim', input, detail), secretVersionId: id };
      }), { asked: input.accessRevision });
    }
    return { ok: true, versions: ids.map((id) => found.get(id)!) };
  }

  /**
   * Refuse a call for what its versions are, under the principal's row, as
   * any decision: and a read on a kept answer no longer theirs as that, not
   * for its versions, logging no read (`accessRevision`).
   */
  async #refuseVersions(
    principal: string,
    code: 'bad_claim' | 'deleted' | 'invalid',
    entries: NewEntry[],
    { message = REFUSAL_MESSAGES[code], asked }: { message?: string; asked?: string } = {},
  ): Promise<Outcome<never>> {
    return this.#decide([principal], async (d) => {
      if (asked !== undefined) {
        const standing = await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports, d.reads);
        if (this.#revisionOf(standing, d) !== asked) throw new Refused(refusal('access_changed', REFUSAL_MESSAGES.access_changed), []);
      }
      throw new Refused(refusal(code, message), entries);
    }, { reads: true });
  }

  /**
   * The data key, or null when it does not open as this secret's: a claim
   * that is not what it says. A key service that cannot answer is an outage,
   * not a verdict on the claim, and throws.
   */
  async #open(wrapped: WrappedKey, context: SecretContext, operation: KeyOperation): Promise<Buffer | null> {
    try {
      return await this.#config.keks.unwrap(unwrappable(wrapped), context, operation);
    } catch (error) {
      if (error instanceof KekBadClaimError) return null;
      throw error;
    }
  }

  /** Whether a key operation under `kek` leaves the process: a key service, not a key in memory. */
  #remote(kek: KekProvider | undefined): boolean {
    return kek !== undefined && !(kek instanceof LocalKekProvider);
  }

  /**
   * One call's key operations, decided as one. With a key service, the
   * intent commits first; then, under the reader's row, the check, every
   * operation within the budget, and each key's outcome. With a key in
   * memory there is nothing to pair with outside, and it is all one short
   * transaction.
   */
  async #keys<T extends { wipe: () => void }, R>(
    call: {
      action: KeyAction;
      principal: string;
      permission: Permission;
      secrets: readonly SecretRef[];
      /** Where each secret is decided, when not where it is: a reference's holder, by its own key (R71). */
      places?: readonly HeldKey[];
      /** The `reference.create` entries `vet` asks about: read with the decision (`Snapshot`'s `ended`). */
      references?: readonly bigint[];
      /**
       * What else refuses each secret, checked in the decision and again
       * once the log's head is locked, before its entries append: from the
       * decision's reads, or the database.
       */
      vet?: (db: Queryable, reads: Snapshot) => Promise<(RefusalCode | null)[]>;
      /**
       * Any one of which each secret takes besides `permission`, where it
       * is, read in the decision and again under the head; none for null.
       */
      needs?: (db: Queryable) => Promise<(readonly Permission[] | null)[]>;
      /** Each secret that takes besides its reader being an Owner of its project (`ownsProject`): a sensitive value made a secret. */
      owns?: readonly boolean[];
      remote: boolean;
      entry: (secret: SecretRef, decision: 'allow' | 'deny', code: string | null) => NewEntry;
      /** Entries appended with the release, after its own, only once the keys are released: the app's record of a use. */
      also?: readonly NewEntry[];
      input: Correlation & Through & { purpose?: string; keepsSensitive?: boolean; accessRevision?: string };
    },
    /**
     * One per secret; null for a bad claim, an error for an outage or an
     * unexpected fault. `context` is each secret's, as the decision read its
     * environment: a personal config's binds its owner.
     */
    operations: (context: (secret: SecretRef) => SecretContext) => ((operation: KeyOperation) => Promise<T | null>)[],
    result: (done: T[]) => R,
  ): Promise<Outcome<R>> {
    const { action, principal, secrets, entry } = call;
    for (const secret of secrets) entry(secret, 'allow', null);
    // One deadline for the call: the record of the KEK's check, the decisions, the intent's and the keys', and, with a
    // key service, its own budget besides, spent from it too.
    const budget = CALL_DEADLINE_MS + (call.remote ? this.#prepared.options.keyBudgetMs : 0);
    const deadline = Date.now() + budget;
    const wrongKek = await this.#kekMismatch(deadline);
    if (wrongKek !== null) {
      return this.#decide([], async () => {
        throw new Refused(refusal('wrong_kek', wrongKek), secrets.map((secret) => entry(secret, 'deny', 'wrong_kek')));
      }, { reads: true, deadline });
    }
    // Each personal config's owner, hashed, by environment, as the decision read them: what its keys' contexts bind.
    const owners = new Map<string, string>();
    const check = async (d: Decision) => {
      const standing = await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports, d.reads);
      // A read decided on an earlier answer about its reader, only while that is still the answer: nothing read, nothing logged.
      const asked = call.input.accessRevision;
      if (asked !== undefined && this.#revisionOf(standing, d) !== asked) throw new Refused(refusal('access_changed', REFUSAL_MESSAGES.access_changed), []);
      const reader = through(standing, call.input);
      // One read of the environments the decision is about, as the store has them, not as the app sent them:
      // each secret's and, for a read through a reference, its holder's. A grant on one slug in every project
      // matches the slug there, and a place deleted on either side opens for none.
      const at = secrets.map((secret, i) => call.places?.[i] ?? secret);
      // Each a personal config is a config of too, whose read its owner needs (`places`).
      const environments = d.reads.environments;
      // Each as 0.15's log holds its row (T159): its project, its slug, its tombstone, a personal config's owner and parent.
      const decided = [...secrets, ...at].map((place) => place.environmentId);
      this.#placesHold(environments, [...decided, ...decided.flatMap((id) => (environments.get(id)?.owner == null ? [] : [environments.get(id)!.parentId!]))], d.reports);
      owners.clear();
      for (const [id, environment] of environments) if (environment.owner !== null) owners.set(id, ownerKey(environment.owner));
      const needs = call.needs === undefined ? [] : await call.needs(d.tx);
      let codes = keyRefusals(reader, { principal, permission: call.permission, secrets, at, environments, needs, owns: call.owns });
      if (call.vet !== undefined && !codes.some((code) => code !== null)) codes = await call.vet(d.tx, d.reads);
      // `at` is also where each key is held, the secret itself, a fork's parent or a reference's holder, by its own
      // key: what a workload lists, and the project whose Owners give a service its sensitive values (R71).
      codes = useOnlyRefusals(codes, reader, { action, purpose: call.input.purpose, secrets: at });
      codes = sensitiveRefusals(codes, reader, {
        action, principal, purpose: call.input.purpose, keepsSensitive: call.input.keepsSensitive,
        secrets: at.map((place, i) => ({ projectId: place.projectId, sensitive: secrets[i]!.sensitive })),
      });
      let first = codes.find((code) => code !== null) ?? null;
      if (first === null && action === 'secret.read' && this.#overBulkLimit(d)) first = 'bulk_limit';
      if (first !== null) {
        throw new Refused(
          refusal(first, REFUSAL_MESSAGES[first]),
          secrets.map((secret, i) => entry(secret, 'deny', codes[i] ?? first)),
        );
      }
    };

    // Every decision below reads the places it is about with the reader's standing; a read, the reader's releases too.
    const reads: Reads = {
      environments: [...secrets, ...secrets.map((secret, i) => call.places?.[i] ?? secret)].map((place) => place.environmentId),
      references: call.references ?? [],
      ...(action === 'secret.read' ? { released: { principal, keys: secrets.map((secret) => secret.secretId) } } : {}),
    };
    // The intent's own identity; `operationId` is the app's, for the whole action.
    const intentId = call.remote ? randomUUID() : null;
    let intentSeq: bigint | null = null;
    const outcomeEntry = (secret: SecretRef, item: number, decision: 'allow' | 'deny', code: string | null): NewEntry => {
      const outcome = entry(secret, decision, code);
      return intentSeq === null ? outcome : {
        ...outcome,
        relatedSeq: intentSeq,
        metadata: JSON.stringify({
          ...JSON.parse(outcome.metadata ?? '{}'),
          intent: intentId,
          item,
          ...(['key_error', 'kms_uncertain'].includes(code ?? '') ? { uncertain: true } : {}),
        }),
      };
    };
    if (call.remote) {
      const intent = await this.#decide([principal], async (d) => {
        await check(d);
        const at = d.at;
        const appended = await this.#append(d.tx, [{
          actor: principal,
          action: 'key.intent',
          decision: 'allow',
          operationId: call.input.operationId ?? null,
          requestId: call.input.requestId ?? null,
          metadata: JSON.stringify({
            intent: intentId,
            operation: action,
            // When accounting for it is overdue: its outcomes commit by the call's deadline, each of their statements
            // bound by what is left of it (`#decideOnce`, a read's), and the call began before `at` was read, so its
            // whole budget from `at` covers it; the COMMIT after the last statement, which nothing bounds, is given one
            // more call's deadline, a margin, not a measured bound (review r1).
            expiresAt: at + budget + CALL_DEADLINE_MS,
            ...(call.input.purpose === undefined ? {} : { purpose: call.input.purpose }),
            ...traced(call.input),
            // Each key with where its outcome is logged, as `entry` writes it: what a rotation that closes the intent for a
            // vault on a retired key logs it as (`#closeIntents`), so that a place's audit finds it (review r7).
            keys: secrets.map((secret, item) => ({ item, subject: secret.path, secretId: secret.secretId, version: secret.version, logged: loggedAs(entry(secret, 'deny', null)) })),
          }),
        }], [], d.reads);
        return { seq: appended.seqStart };
      }, { asked: reads, reads: true, deadline });
      if (!intent.ok) return intent;
      intentSeq = intent.seq;
    }

    // The check, the key operations, and their outcome. With a key in memory, all in one decision, under the reader's
    // row and the log's head from the start (`#decideOnce`): what the check read stands until the commit, as every change
    // it reads appends under the head, and the head waits on nothing slow. With a key service, nothing waits on it
    // holding a lock, nor a transaction or a connection (R75): the intent's check above, then the key operations, outside
    // any transaction, then the outcome's decision, which takes the reader's row and the head as any read does and
    // decides it all again on what it reads there (formal/Coffre.tla's StandingRecheckUnderHead): a revocation, a
    // removal, a deletion, a reference ended, a policy changed or a bulk count passed while the key service answered is
    // seen, and the keys it opened are withheld (single-database.md, "Releasing a key", superseded by R75).
    const decided = async (d: Decision) => {
      try {
        await check(d);
      } catch (error) {
        // A read on a kept answer no longer the vault's logs no read; but a key service's intent, logged already, is
        // accounted for all the same, each key refused, as after any other refusal.
        if (error instanceof Refused && !(error.refusal.code === 'access_changed' && intentSeq === null)) {
          throw new Refused(error.refusal, secrets.map((secret, item) =>
            outcomeEntry(secret, item, 'deny', error.entries[item]?.code ?? error.refusal.code)));
        }
        throw error;
      }
    };
    // What the key operations came to, decided once the check above has passed in the same decision: each key's outcome.
    const settled = (d: Decision, outcomes: KeyOutcome<T>[], expired: boolean): R => {
      const done = outcomes.flatMap((outcome) => (outcome.ok ? [outcome.value] : []));
      const entries = () => secrets.map((secret, i) =>
        outcomeEntry(secret, i, 'deny', outcomes[i].ok ? 'withheld' : outcomes[i].code));
      const fault = outcomes.find((outcome) => !outcome.ok && outcome.code === 'key_error');
      if (fault !== undefined && !fault.ok) throw new Outage(fault.error, entries());
      const unanswered = outcomes.filter((outcome) => !outcome.ok && outcome.code !== 'bad_claim').length;
      if (unanswered > 0) {
        throw new Outage(
          new KekUnavailableError(`the key service did not answer for ${unanswered} of ${secrets.length} keys`,
            outcomes.some((outcome) => !outcome.ok && outcome.code === 'kms_uncertain')),
          entries(),
        );
      }
      if (expired) throw new Outage(new KekUnavailableError('key operation exceeded its deadline'), entries());
      if (done.length < outcomes.length) {
        throw new Refused(refusal('bad_claim', REFUSAL_MESSAGES.bad_claim), entries());
      }
      const released = secrets.map((secret, i) => outcomeEntry(secret, i, 'allow', null));
      d.log.push(...released, ...(call.also ?? []));
      const answer = result(done);
      // A wrap's answer names its entries, which the app's writes refer to.
      if (action !== 'secret.read') d.after.push((seqOf) => Object.assign(answer as object, { seqs: released.map(seqOf) }));
      return answer;
    };
    const run = () => settle(operations((secret) => context(secret, owners.get(secret.environmentId))), within(deadline, this.#prepared.options.keyBudgetMs));
    const wipe = (outcomes: KeyOutcome<T>[]) => {
      for (const outcome of outcomes) if (outcome.ok) outcome.value.wipe();
    };
    if (!call.remote) {
      return this.#decide([principal], async (d) => {
        await decided(d);
        const { outcomes, expired } = await run();
        try {
          return settled(d, outcomes, expired);
        } finally {
          wipe(outcomes);
        }
      }, { asked: reads, reads: true, deadline });
    }
    // The key service, with nothing held: its contexts as the intent's check read the places.
    const { outcomes, expired } = await run();
    try {
      return await this.#decide([principal], async (d) => {
        await decided(d);
        // A read through a reference: its holder's place too, which a deletion may have taken since the intent.
        const places = secrets.flatMap((secret, i) => [secret, call.places?.[i] ?? secret]);
        if (places.some((place) => d.reads.environments.get(place.environmentId)?.deleted ?? false)) {
          throw new Refused(refusal('deleted', REFUSAL_MESSAGES.deleted), secrets.map((secret, i) => outcomeEntry(secret, i, 'deny', 'deleted')));
        }
        return settled(d, outcomes, expired);
      }, { asked: reads, reads: true, deadline });
    } finally {
      // Once every attempt of the decision is done (`#decideNow` decides again on a row moved): the keys were opened once.
      wipe(outcomes);
    }
  }

  /**
   * Whether this read's keys would take the reader past the bulk limit: the
   * distinct keys released to them in the window, these among them. A key
   * read again exposes nothing new, so it counts once, whatever its version.
   * Counted under the log's head, which every release appends under, so
   * exactly: one reader's reads decide side by side under their row, and
   * each counts the others' releases again once it holds the head (`#keys`).
   */
  #overBulkLimit(d: Decision): boolean {
    return d.reads.released > this.#config.bulkLimit.count;
  }

  // --- references ---------------------------------------------------------------

  /**
   * Make each holder a reference to its source: the actor writes the holder
   * and reads the source, by their own grants, and the vault's
   * `reference.create` entry is the reference. The app's row only points at
   * it; a read through one is checked against the entry (`#referencesAt`).
   */
  async reference(input: ReferenceInput): Promise<Outcome<{ seqs: number[] }>> {
    const { principal, items } = input;
    validateText(principal);
    validateCorrelation(input);
    for (const item of items) {
      if (typeof item.id !== 'string' || !UUID.test(item.id)) throw new Error('a reference id must be a lowercase UUID');
      if (typeof item.source?.secretId !== 'string' || !UUID.test(item.source.secretId)) throw new Error('a source must be named by its secret id');
      checkContext(item.holder);
      validateText(item.holder.path);
    }
    if (new Set(items.map((item) => item.id)).size !== items.length) throw new Error('each reference needs its own id');
    if (items.length === 0) return { ok: true, seqs: [] };
    const [sources, projectOf] = await Promise.all([
      store.secretsByIds(this.#db, items.map((item) => item.source.secretId)),
      store.projectsOfEnvironments(this.#db, items.map((item) => item.holder.environmentId)),
    ]);
    const entry = (item: ReferenceInput['items'][number], decision: 'allow' | 'deny', code: string | null): NewEntry => {
      const source = sources.get(item.source.secretId);
      return {
        actor: principal,
        action: 'reference.create',
        decision,
        code,
        projectId: projectOf.has(item.holder.environmentId) ? item.holder.projectId : null,
        environmentId: projectOf.has(item.holder.environmentId) ? item.holder.environmentId : null,
        operationId: input.operationId ?? null,
        requestId: input.requestId ?? null,
        // A new holder's row is not committed yet: it is named here, as a wrap names its secret.
        metadata: JSON.stringify({
          reference: item.id,
          subject: item.holder.path,
          secretId: item.holder.secretId,
          source: source === undefined ? { secretId: item.source.secretId } : { path: source.path },
          ...(source === undefined ? {} : { also: { projectId: source.projectId, environmentId: source.environmentId, secretId: source.secretId } }),
          ...traced(input),
        }),
      };
    };
    return this.#decide([principal], async (d) => {
      // Under the log's head, which a deletion and every change to the policy take: neither side deleted, nor protected,
      // nor a role narrowed, before this commits.
      const reader = through(await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports, d.reads), input);
      // Each source's nature, its current version's, under the head: what its maker must hold there.
      const natures = await store.natures(d.tx, [...sources.values()].map((source) => source.secretId));
      // Both sides as the store has them: a grant on a slug matches there, and neither side may be deleted.
      const environments = await store.environmentsById(d.tx, items.flatMap((item) => {
        const source = sources.get(item.source.secretId);
        return source === undefined ? [item.holder.environmentId] : [item.holder.environmentId, source.environmentId];
      }), { seals: this.#checksSeals() });
      // Each as 0.15's log holds its row (T159).
      this.#placesHold(environments, environments.keys(), d.reports);
      const codes = items.map((item): RefusalCode | null => {
        const source = sources.get(item.source.secretId);
        // The holder's project as the row this decision checked says it (review r4): the read before only names the entry.
        if (source === undefined || environments.get(item.holder.environmentId)?.projectId !== item.holder.projectId) return 'bad_claim';
        if (source.secretId === item.holder.secretId) return 'invalid';
        return referenceRefusal(reader, item.holder, source, environments, natures.get(source.secretId) ?? 'secret');
      });
      const first = codes.find((code) => code !== null) ?? null;
      if (first !== null) throw new Refused(refusal(first, REFUSAL_MESSAGES[first]), items.map((item, i) => entry(item, 'deny', codes[i] ?? first)));
      const entries = items.map((item) => entry(item, 'allow', null));
      d.log.push(...entries);
      const answer = { seqs: [] as number[] };
      d.after.push((seqOf) => (answer.seqs = entries.map(seqOf)));
      return answer;
    });
  }

  /**
   * End references, each with a `reference.end` naming its creation by
   * `related_seq`, where the next read through it looks. `replaced` takes
   * write on the holder; `broken`, write on the holder or managing the
   * source's project's access. Ending one already ended is refused.
   */
  async endReferences(input: EndReferencesInput): Promise<Outcome<{ seqs: number[] }>> {
    const { principal, reason } = input;
    validateText(principal);
    validateCorrelation(input);
    if (reason !== 'replaced' && reason !== 'broken' && reason !== 'abandoned') throw new Error('a reference ends replaced, broken or abandoned');
    const vias = input.items.map((item) => validateVia(item)!);
    if (vias.some((via) => via === null) || new Set(vias.map((via) => via.seq)).size !== vias.length || new Set(vias.map((via) => via!.reference)).size !== vias.length) {
      throw new Error('each reference to end, once');
    }
    if (vias.length === 0) return { ok: true, seqs: [] };
    const sealed = await this.#referencesAt(vias);
    // A holder's row is committed after its reference is sealed, if the write went through: an end names it only then.
    const holders = await store.secretsByIds(this.#db, sealed.flatMap((seal) => (seal === null ? [] : [seal.holder.secretId])));
    const entry = (via: Via, seal: Sealed | null, decision: 'allow' | 'deny', code: string | null): NewEntry => ({
      actor: principal,
      action: 'reference.end',
      decision,
      code,
      projectId: seal?.holder.projectId ?? null,
      environmentId: seal?.holder.environmentId ?? null,
      // So that the holder key's own log shows the reference ending.
      secretId: seal !== null && holders.has(seal.holder.secretId) ? seal.holder.secretId : null,
      relatedSeq: seal === null ? null : seal.seq,
      operationId: input.operationId ?? null,
      requestId: input.requestId ?? null,
      metadata: JSON.stringify({
        reference: via.reference,
        reason,
        ...(seal === null
          ? { seq: via.seq }
          : {
              subject: seal.holder.path,
              secretId: seal.holder.secretId,
              source: { path: seal.source.path },
              also: { projectId: seal.source.projectId, environmentId: seal.source.environmentId, secretId: seal.source.secretId },
            }),
        ...traced(input),
      }),
    });
    if (sealed.some((seal) => seal === null)) {
      return this.#decide([principal], async () => {
        throw new Refused(refusal('bad_claim', REFUSAL_MESSAGES.bad_claim), vias.map((via, i) => entry(via, sealed[i]!, 'deny', 'bad_claim')));
      });
    }
    const seals = sealed as Sealed[];
    // Ended already: by an authentic end only. A forged one (a row with the vault's name and no valid MAC) refuses a
    // read, the safe side there (`endedReferences`); here it would stop a genuine break, and with 0.15's log leave the
    // holder serving, its end written nowhere (review r9).
    const ended = async (db: Queryable) => {
      const done = new Set((await store.referenceEnds(db, seals.map((seal) => seal.seq))).filter((end) => this.#authentic(end)).map((end) => end.relatedSeq!));
      return seals.map((seal) => (done.has(seal.seq) ? ('ended' as const) : null));
    };
    return this.#decide([principal], async (d) => {
      // Under the log's head: two ends of one reference at once, the second finds the first; and the actor's standing stands.
      const actor = through(await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports, d.reads), input);
      // Ending is allowed in a deleted place: deleting one ends the references into and out of it.
      const environments = await store.environmentsById(d.tx, seals.map((seal) => seal.holder.environmentId), { seals: this.#checksSeals() });
      // Each as 0.15's log holds its row (T159).
      this.#placesHold(environments, environments.keys(), d.reports);
      // Who may end each: write where it is held; for a break, managing the source's project's access too; abandoning,
      // its maker alone, for a write of theirs that stored nothing (the vault never reads the app's rows, so whose
      // seal it is decides, and no one else's end says it).
      const mayEnd = (reader: Reader, places: ReadonlyMap<string, { projectId: string; slug: string }>) => seals.map((seal): RefusalCode | null => {
        const holder = refuses(reader, 'secret.write', placeIn(seal.holder, places), false);
        if (reason === 'abandoned' && seal.createdBy !== principal) return 'not_allowed';
        if (holder === null || reason !== 'broken') return holder;
        return refuses(reader, 'grant.manage', { projectId: seal.source.projectId }, false) === null ? null : holder;
      });
      const codes: (RefusalCode | null)[] = mayEnd(actor, environments);
      // With 0.15's log, also as 0.15 decides it, on sealed objects alone (R53): the actor's principal object, the
      // roles object and each holder environment's object, each as its log has it and checked against its seal
      // (`readerOf`, as a use's reader). 0.14's reader reads rows no seal covers (an environment's slug, a project's
      // tombstone, the protection they make): a writer who swapped one could let a member end what they may not
      // (reviews r10 and r11). An end needs both to allow it, so an unsealed row can only refuse one. An object the log
      // does not bear out refuses the end. Per reference: one whose holder environment, or the actor, 0.14's log alone
      // holds (before the cutover) is 0.14's reader's alone, and no other reference of the call with it (review r12).
      const allowed14 = !codes.some((code) => code !== null);
      if (d.changes !== null && allowed14) {
        const member = await d.changes.held(d.tx, { kind: 'principal', id: principal });
        const roles = await d.changes.held(d.tx, ROLES_REF as Ref & { kind: 'roles' });
        const places = new Map<string, EnvironmentInput>();
        for (const id of new Set(seals.map((seal) => seal.holder.environmentId))) {
          const held = await d.changes.held(d.tx, { kind: 'environment', id });
          if (held.log === 'live' && held.object.kind === 'environment') places.set(id, held.object);
        }
        if (member.log !== 'unlogged') {
          const account = member.log === 'live' && member.object.kind === 'principal' ? member.object : null;
          // The way the actor came in, as a reader takes it: its kind and scope (its generation weighs nothing here).
          const credential: CredentialInput = {
            kind: 'credential', id: principal, principal, caller: input.caller, scope: input.credentialScope ?? null, expiresAt: null, revoked: false, generation: account?.generation ?? 0,
          };
          const reader = readerOf(account, credential, roles.log === 'live' && roles.object.kind === 'roles' ? roles.object : noEdits(), places.values(), d.at);
          mayEnd(reader, places).forEach((code, i) => {
            if (places.has(seals[i]!.holder.environmentId)) codes[i] = code;
          });
        }
      }
      if (!codes.some((code) => code !== null)) (await ended(d.tx)).forEach((code, i) => (codes[i] = code));
      const first = codes.find((code) => code !== null) ?? null;
      if (first !== null) throw new Refused(refusal(first, REFUSAL_MESSAGES[first]), vias.map((via, i) => entry(via, seals[i]!, 'deny', codes[i] ?? first)));
      // With 0.15's log, each reference ended ends in its row, beside 0.14's entry, in this transaction (0029;
      // formal/SealedObjects.tla, EndInRow and EndWithEntry). Decided only on what the vault authenticates (R53): that
      // it has not ended is 0.14's log's (`ended` above), and what its holder reads is the holder's object, as its log
      // has it and checked against its seal (`heldByLog`: ReferenceInObject, LivenessFromLog), never its rows, which
      // a writer may rename, plant or mark archived. A holder whose rows the log does not bear out refuses the end
      // (`tampered`, `stale`).
      // - A holder whose object reads its source through this reference changes: `secret.write`, no source, whose
      //   newest row, this one, `change_input` ends.
      // - Any other ends this row alone, by its id (`end_reference`): an abandoned reference's stored none, and its
      //   end touches no other. A holder with no object has only rows, which decide nothing here: 0.14's alone
      //   before the cutover, which holds each reference row to 0.14's `reference.create` and `reference.end` (plan
      //   PR 9); or archived, whose unarchive restores what its log last sealed (`keptObjects`, T134), never its rows.
      // - So an archived holder whose kept object reads through this reference has that object ended too: written
      //   ended, then deleted again, still no object (EndWhileArchived). Otherwise its unarchive would restore it
      //   live, the row's end cleared by a writer, or refuse an honest one for the end in its rows. Its rows must make
      //   the kept object, as a live holder's must make its sealed one: else the end is refused, reported.
      if (d.changes !== null) {
        const changes = d.changes;
        const rows: string[] = [];
        const staged = new Set<string>();
        const end = (ref: Ref & { kind: 'secret' }, at: { projectId: string; environmentId: string }, archived: boolean) => {
          if (staged.has(ref.id)) return;
          staged.add(ref.id);
          changes.stage(ref, { op: 'secret.write', projectId: at.projectId, environmentId: at.environmentId, version: '', nature: 'secret', key: null, digest: null, source: null, reference: null }, principal);
          if (archived) changes.stage(ref, { op: 'secret.delete' }, principal);
        };
        for (const [i, { holder }] of seals.entries()) {
          const reference = vias[i]!.reference;
          const ref = { kind: 'secret' as const, id: holder.secretId };
          const held = await changes.held(d.tx, ref);
          if (held.log === 'live' && held.object.kind === 'secret' && held.object.reference === reference) {
            end(ref, holder, false);
            continue;
          }
          if (held.log === 'gone') {
            const kept = await changes.kept(d.tx, ref);
            if (kept?.kind === 'secret' && kept.reference === reference) {
              // Its rows must make that object, or its end would write none of them: refused, reported, as a live one's.
              await changes.rowsAsKept(d.tx, ref, kept);
              end(ref, kept, true);
            }
          }
          rows.push(reference);
        }
        if (rows.length > 0) d.writes.push((at) => store.endReferenceRows(d.tx, rows, at));
      }
      const entries = vias.map((via, i) => entry(via, seals[i]!, 'allow', null));
      d.log.push(...entries);
      const answer = { seqs: [] as number[] };
      d.after.push((seqOf) => (answer.seqs = entries.map(seqOf)));
      return answer;
    });
  }

  /**
   * The reference each read names, as the vault's own `reference.create`
   * entry at its seq says it is: an entry of the vault's, allowed, under its
   * MAC, about that reference. Null for an item that names none, and for
   * one that names something else: a row the vault never sealed.
   */
  async #referencesAt(vias: readonly (Via | null)[]): Promise<(Sealed | null)[]> {
    const found = await store.entriesAt(this.#db, vias.flatMap((via) => (via === null ? [] : [BigInt(via.seq)])));
    return vias.map((via) => {
      if (via === null) return null;
      const entry = found.get(BigInt(via.seq));
      if (entry === undefined || entry.author !== 'vault' || entry.action !== 'reference.create' || entry.decision !== 'allow') return null;
      if (!this.#authentic(entry)) return null;
      return sealedReference(entry, via.reference);
    });
  }

  // --- Owners of the whole instance -------------------------------------------------

  /** Whether the deployment names `principal` an Owner of the whole instance (`owners`). */
  #listed(principal: string): boolean {
    return principal.startsWith('user:') && this.#config.owners.includes(principal.slice('user:'.length));
  }

  /**
   * An Owner of the whole instance other than `except`, as their row says
   * and its check holds (`#integrity`), or null when there is none. A row
   * changed around the vault owns nothing, and is reported. Read under the
   * log's head, which every change to a member takes before it writes, the
   * answer stands until the reader commits.
   */
  async #anOwner(db: Queryable, reports: NewEntry[], except: string | null = null): Promise<string | null> {
    for (const row of await store.instanceOwners(db)) {
      if (row.principal === except) continue;
      if ((await this.#integrity(db, row.principal, row, await store.grants(db, row.principal), reports)) === null) return row.principal;
    }
    return null;
  }

  /**
   * Make each of `principals`, people the deployment names (`owners`), an
   * Owner of the whole instance, whoever else is one: asked about all of
   * them at the start of each process (`#convert`), and at `access` about
   * one who owns nothing, which is a new instance's first sign-in, before
   * the vault has written to its log, and the way back for someone whose
   * row was changed around the vault since. An unlocked read of each finds
   * who is one already, the quick way out: a hint, never a report, and
   * never `#record`, which would settle the vault, and so convert, again;
   * one it cannot tell, a row changing under it as another process makes
   * them an Owner, is due. Then one decision, under the others' rows, reads
   * again (`#makeOwner`). One whose row the log never admitted stays as it is,
   * and is asked about again at each of their requests. Whether it ran.
   */
  async #declare(principals: readonly string[], start?: StartReads): Promise<boolean> {
    // Under 0.15's log, no Owner made before the cutover: nothing of the log's precedes its change (AnchorHolds).
    if (!(await this.#cutOverNow(start))) return false;
    // Their rows, grants and the policy in one statement, as `access` reads one member's (T206).
    const reads = await snapshot(this.#db, { principals, members: true, seals: this.#checksSeals() });
    const at = this.#at(reads);
    const due: string[] = [];
    for (const principal of principals) {
      const subject = await this.#standing(this.#db, principal, reads.members.get(principal), at, [], reads).catch((error: unknown) => {
        if (error instanceof Retry) return null;
        throw error;
      });
      if (!(subject?.status === 'active' && ownsInstance(subject.live))) due.push(principal);
    }
    if (due.length === 0) return true;
    const decided = await this.#decideNow(due, async (d) => {
      for (const principal of due) await this.#makeOwner(d, principal, 'owners');
    });
    return decided.ok;
  }

  /**
   * Refuse a change that would leave `principal`, an Owner of the whole
   * instance, no longer one, unless another is. Counted under the log's
   * head, which every decision holds: two changes at once, each demoting or
   * removing a different Owner, lock different rows, and only the head puts
   * one after the other.
   */
  async #keepAnOwner(d: Decision, actor: string, principal: string, refused: (code: RefusalCode, message?: string) => Refused): Promise<void> {
    if ((await this.#anOwner(d.tx, d.reports, principal)) !== null) return;
    throw refused('last_owner', actor === principal
      ? "you're the last Owner of the whole instance: make someone else an Owner first"
      : `${principal.slice('user:'.length)} is the last Owner of the whole instance: make someone else an Owner first`);
  }

  /**
   * Make `principal`, a person, an Owner of the whole instance, as the
   * vault, for `reason`: admitted, brought back, or given the role, the
   * grants they hold kept. One whose row fails its check is started over
   * first, as removing them would; one the log never admitted, whose row was
   * written around the vault, is left as it is. Whether it made them one.
   */
  async #makeOwner(d: Decision, principal: string, reason: 'owners'): Promise<boolean> {
    const row = d.members.get(principal);
    const subject = await this.#standing(d.tx, principal, row, d.at, d.reports, d.reads);
    if (subject.status === 'active' && ownsInstance(subject.live)) return false;
    const tampered = subject.status === 'tampered';
    // Under 0.15's log, no start over (`#startOver`): reported, and left as it is until a reseal.
    if (tampered && (this.#checksSeals() || (await this.#logged(d.tx, principal)) === undefined)) return false;
    const correlation = { operationId: randomUUID() };
    const owner = { role: 'owner' as const, scope: EVERYWHERE };
    d.grants.set(principal, [...subject.stored]);
    d.touched.add(principal);
    if (tampered) await this.#startOver(d, VAULT_ACTOR, principal, row, subject.fault!, correlation, (code, message) => new Refused(refusal(code, message ?? REFUSAL_MESSAGES[code]), []));
    // Started over, their row is one 0.15's log does not hold, and changes nothing there: adoption or a reseal does
    // (plan PR 9). Otherwise, the change the writes below make.
    if (!tampered) {
      const op = row === undefined ? 'member.add' : row.status === 'removed' ? 'member.restore' : 'member.role';
      d.changes?.stage(memberRef(principal), { op, ...asStored(owner.role, owner.scope) }, VAULT_ACTOR);
    }
    if (row === undefined && !tampered) {
      d.log.push(accessEntry(VAULT_ACTOR, 'member.add', principal, 'allow', correlation, { ...owner, reason }));
      d.writes.push((at) => store.insertMember(d.tx, {
        principal, status: 'active', ...owner, generation: 0, createdAt: at, createdBy: VAULT_ACTOR, statusChangedAt: at, statusChangedBy: VAULT_ACTOR, ...UNSEALED,
      }));
    } else if (tampered || row?.status === 'removed') {
      // Coming back keeps the generation a removal, or the start over, moved on to.
      d.log.push(accessEntry(VAULT_ACTOR, 'member.restore', principal, 'allow', correlation, { ...owner, reason }));
      d.writes.push((at) => store.updateMember(d.tx, principal, { status: 'active', ...owner, statusChangedAt: at, statusChangedBy: VAULT_ACTOR }));
    } else {
      d.log.push(accessEntry(VAULT_ACTOR, 'member.role', principal, 'allow', correlation, { ...owner, previousRole: row!.role, previousScope: row!.scope, reason }));
      d.writes.push(() => store.updateMember(d.tx, principal, owner));
    }
    return true;
  }


  // --- who holds what -----------------------------------------------------------

  /**
   * What `principal` holds, their row checked first (`#integrity`): a row
   * that fails holds nothing, and is `tampered`.
   */
  async #standing(db: Queryable, principal: string, row: Member | undefined, at: number, reports: NewEntry[], reads?: Snapshot): Promise<Standing> {
    const none = NOTHING;
    const grants = row === undefined ? [] : reads?.grants.get(principal) ?? (await store.grants(db, principal));
    const log = this.#checksSeals() ? await this.#memberLog(db, principal, reads) : undefined;
    const fault = await this.#integrity(db, principal, row, grants, reports, reads, log === undefined ? undefined : new Map([[principal, log]]));
    if (fault !== null) return { principal, status: 'tampered', live: none, all: none, fault, stored: grants, log };
    if (!PRINCIPAL.test(principal)) return { principal, status: 'unknown', live: none, all: none, fault, stored: grants, log };
    if (row?.status !== 'active') return { principal, status: row?.status ?? 'unknown', live: none, all: none, fault, stored: grants, log };
    // What they hold: their grants but those on a place whose row is not as 0.15's log holds it (T159). Kept as stored.
    const held = (await this.#heldGrants(db, grants, reports, reads?.environments)).map((grant) => ({ ...grant, role: grant.role as Role }));
    const { role, scope } = roleOf(principal, row);
    // Every decision about them reads the policy: their roles as an Owner edited them, and which environments are protected.
    const { policy } = await this.#policyAt(db, reports, at, reads);
    const service = !principal.startsWith('user:');
    return {
      principal,
      status: 'active',
      live: { role, scope, grants: held.filter((grant) => live(grant, at)), policy, service },
      all: { role, scope, grants: held, policy, service },
      fault,
      stored: grants,
      log,
    };
  }

  #access(principal: string, row: Member | undefined, held: readonly GrantRow[], at: number, tampered: boolean, policy: Policy): Access {
    return answerFrom(principal, row, held, at, tampered, policy);
  }

  /** The revision of what `access` would answer about a standing a decision read: none but an active member's matches a kept answer. */
  #revisionOf(standing: Standing, d: Decision): string | null {
    const { policy } = standing.live;
    if (standing.status !== 'active' || policy === undefined) return null;
    // Its grants that hold, as `access` answers them (`#heldGrants`): those `all` keeps.
    const held = standing.stored.filter((grant) => grant.environmentId === null || standing.all.grants.some((kept) => kept.environmentId === grant.environmentId));
    return this.#access(standing.principal, d.members.get(standing.principal), held, d.at, false, policy).revision!;
  }

  /**
   * What `principal` holds now. Read without locks, the fast way; a row that
   * seems to fail its check is read again in one snapshot before anyone is
   * called tampered, since a change committed between two of the reads
   * looks like one. A person the deployment names (`owners`) who owns
   * nothing becomes an Owner of the whole instance first (`#declare`). A
   * vault that holds no key the log's newest entries are under, given the
   * wrong vault key, cannot tell a row it cannot check from one changed
   * around it: it says so, an outage, rather than call the member tampered.
   * A row it can check still answers, so a forged entry that stops it
   * writing leaves the Owners able to sign in and find it.
   */
  async access(principal: string): Promise<Access> {
    const superseded = await this.#settled();
    const access = await this.#read(principal, superseded);
    if (superseded !== null || !this.#listed(principal) || (access.status === 'active' && ownsInstance(access))) return access;
    return (await this.#declare([principal])) ? this.#read(principal, superseded) : access;
  }

  /** `access`, as the rows are now. */
  async #read(principal: string, superseded: string | null): Promise<Access> {
    const read = async (db: Queryable, reports: NewEntry[]) => {
      const reads = await snapshot(db, { principals: [principal], members: true, seals: this.#checksSeals() });
      const [row, held, at] = [reads.members.get(principal), reads.grants.get(principal)!, this.#at(reads)];
      const fault = await this.#integrity(db, principal, row, held, reports, reads);
      // Their grants but those on a place whose row is not as 0.15's log holds it, which hold nothing (T159).
      const holding = fault === null ? await this.#heldGrants(db, held, reports, reads.environments) : held;
      const { policy } = await this.#policyAt(db, reports, at, reads);
      return this.#access(principal, row, holding, at, fault !== null, policy);
    };
    const found: NewEntry[] = [];
    const quick = await read(this.#db, found).catch((error: unknown) => {
      if (error instanceof Retry) return null;
      throw error;
    });
    if (quick !== null && quick.status !== 'tampered') {
      await this.#record(found);
      return quick;
    }
    const reports: NewEntry[] = [];
    const access = await this.#db.transaction((tx) => read(tx, reports), SNAPSHOT);
    if (access.status === 'tampered' && superseded !== null) throw new Error(superseded);
    await this.#record(reports);
    return access;
  }

  /**
   * Every member's row checked as `access` checks it, each finding
   * reported: their newest access entries read in one query, and the slow
   * way only for a row that does not match. Lists of members read the rows
   * without the vault, so this is what finds a row changed around it before
   * its member next asks for anything. The checkpoint runs it in one
   * snapshot: a change committed between two of its reads, such as a lapsed
   * grant cleared, would otherwise pair a row with grants it was never
   * sealed over.
   */
  async #sweep(db: Queryable, reports: NewEntry[]): Promise<void> {
    const rows = await store.allMembers(db);
    const held = await store.grants(db);
    if (this.#checksSeals()) {
      // Once 0.15's log holds the rows: each one's seals and newest access entry in one read, as `#onLog` checks them.
      const logs = await store.memberLogs(db, rows.map((row) => row.principal));
      for (const row of rows) await this.#integrity(db, row.principal, row, held.filter((grant) => grant.principal === row.principal), reports, undefined, logs);
      return;
    }
    const newest = await store.newestAccessEntries(db);
    for (const row of rows) {
      const grants = held.filter((grant) => grant.principal === row.principal);
      const entry = newest.get(row.principal);
      const holds = entry !== undefined && this.#authentic(entry) && this.#sealed(row, grants) && entry.seq === row.accessSeq;
      if (!holds) await this.#integrity(db, row.principal, row, grants, reports);
    }
  }

  // --- changing access ----------------------------------------------------------

  setAccess(input: SetAccessInput): Promise<Outcome<{ changes: AccessChange[]; admitted?: Admitted }>> {
    const { actor, principal } = input;
    const changes = input.changes.map(({ projectId, environmentId, role, expiresAt }) => ({ projectId, environmentId, environmentSlug: null, role, expiresAt }));
    const action = changes.every((change) => change.role === null) ? 'access.revoke' : 'access.grant';
    // One place refused is shown where it is, to whoever reads that place's log; an invalid one may be no place at all.
    const [only] = changes.length === 1 ? changes : [];
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) => {
      const where = only === undefined || code === 'invalid' ? { ids: {}, detail: {} } : located(only);
      return new Refused(refusal(code, message), [{
        ...accessEntry(actor, action, principal, 'deny', input, { changes: input.changes, ...where.detail }, code),
        ...where.ids,
      }]);
    };
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      if (!PRINCIPAL.test(principal)) throw refused('invalid', `not a principal: ${principal}`);
      const places = new Set<string>();
      for (const change of changes) {
        if (grantKind(change) === null) {
          throw refused('invalid', change.projectId === null && change.environmentId === null
            ? 'grants are on a project or an environment: a person reaches every project by their instance role'
            : 'an environment is named in its project');
        }
        const key = placeKey(change);
        if (places.has(key)) throw refused('invalid', 'each place may be changed once per call');
        places.add(key);
        if (change.role !== null && typeof change.role !== 'string') throw refused('invalid', `no such role: ${String(change.role)}`);
        const expiresAt = change.expiresAt === null ? null : Date.parse(change.expiresAt);
        if (Number.isNaN(expiresAt) || (expiresAt !== null && expiresAt <= d.at)) {
          throw refused('invalid', 'an end date must be in the future');
        }
      }
      // A project or an environment must be there, and to be granted, not
      // deleted. Read under the log's head, which a deletion holds while it
      // renames the place, so the place is as it commits.
      // The roles as the policy defines them now, under the head every change to it takes: a role an Owner made is
      // granted as one that ships, and one deleted meanwhile is granted by nobody.
      const { policy } = await this.#policyAt(d.tx, d.reports, d.at, d.reads);
      for (const change of changes) {
        if (change.role !== null && !isRole(change.role, policy)) throw refused('invalid', `no such role: ${change.role}`);
        if (change.role !== null && change.environmentId !== null && !assignableToEnvironment(change.role, policy)) {
          throw refused('invalid', `${change.role} can only be granted on a project`);
        }
      }
      const named = changes.flatMap((change) => (change.environmentId === null ? [] : [change.environmentId]));
      const known = await store.places(d.tx, changes.map((change) => change.projectId!), named, { seals: this.#checksSeals() });
      // Each environment by its project and slug as 0.15's log holds its row (T159): what a grant there is weighed on.
      this.#placesHold(known.environments, named, d.reports);
      const where: Place[] = changes.map(({ projectId, environmentId, role }) => {
        const environment = environmentId === null ? undefined : known.environments.get(environmentId);
        if (!known.projects.has(projectId!) || (environmentId !== null && environment?.projectId !== projectId)) {
          throw refused('invalid', `no such place: ${environmentId === null ? projectId : `${projectId}/${environmentId}`}`);
        }
        // A grant there is refused; a revocation, as a deletion makes, is not.
        if (role !== null && (known.deleted.has(projectId!) || (environmentId !== null && known.deleted.has(environmentId)))) {
          throw refused('deleted');
        }
        // An environment by its slug as the store has it, which scopes match.
        return environmentId === null ? { projectId: projectId! } : { projectId: projectId!, environmentId, environmentSlug: environment!.slug };
      });
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports, d.reads), input);
      if (acting.status === 'tampered') throw refused('tampered');
      // Where they manage access, anything; otherwise only a person to a service account (`givesService`).
      const manages = where.every((place) => mayManageAccess(acting.live, place));
      if (!manages && !(SERVICE.test(principal) && PERSON.test(actor))) throw refused('not_allowed');
      // Managing access never reads a value: nobody gives themselves a role, though they may give one up.
      if (actor === principal && changes.some((change) => change.role !== null)) {
        throw refused('not_allowed', 'nobody grants themselves a role: ask another admin');
      }

      const row = d.members.get(principal);
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports, d.reads);
      if (subject.status === 'tampered') throw refused('tampered', this.#tamperedSubject());
      // A service account admitted with its first grants, as `admit` would: all of it, or none.
      const admitted = input.admit === true && row?.status !== 'active' ? await this.#admitWith(d, acting, principal, row, input) : undefined;
      if (admitted === undefined && row?.status === 'removed') throw refused('removed');
      if (admitted === undefined && row === undefined) throw refused('not_a_member');
      if (!manages) {
        // The setting as of the log's head, which a change to it takes too.
        const setting = (await this.#settingsAt(d.tx, d.reports)).serviceAccounts;
        // One just admitted holds nothing yet, and is theirs.
        const account = admitted !== undefined || row === undefined ? { grants: [], admittedBy: actor } : await this.#account(d.tx, subject, row, d.reads, d.reports);
        // Each place's new role they must hold, and what it held before: taking a grant away is changing it.
        const gives = changes.every((change, i) => {
          const before = subject.live.grants.find((grant) => placeKey({ ...grant, environmentSlug: null }) === placeKey(change));
          return [change.role, before?.role].every((role) => role == null || givesService(acting.live, setting, role, where[i]));
        });
        if (!gives || !managesService(acting.live, setting, actor, account)) throw refused('not_allowed', NOT_THEIRS);
      }
      // The grants the check verified, not a second read: what the decision changes, and seals.
      const held = subject.stored;
      d.grants.set(principal, [...held]);
      const outcomes = changes.map((change) => this.#apply(d, actor, principal, held, change, input));
      if (d.writes.length > 0) d.touched.add(principal);
      return { changes: outcomes, ...(admitted === undefined ? {} : { admitted }) };
    });
  }

  /**
   * Admit a service account that `setAccess` gives its first grants, as
   * `admit` would, its refusals logged as `member.add`'s: someone who does
   * not run the instance sets one up as they would through `admit`.
   */
  async #admitWith(d: Decision, acting: Standing, principal: string, row: Member | undefined, input: SetAccessInput): Promise<Admitted> {
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) =>
      new Refused(refusal(code, message), [accessEntry(acting.principal, 'member.add', principal, 'deny', input, { changes: input.changes }, code)]);
    if (!SERVICE.test(principal)) throw refused('invalid', 'only a service account is admitted with its grants: a person, by an instance role');
    if (!runsInstance(acting.live)) await this.#setsUp(d, acting, true, refused);
    return this.#enlist(d, acting, principal, row, undefined, input, refused);
  }

  /** One place's change, logged when it changes what is live. */
  #apply(
    d: Decision,
    actor: string,
    principal: string,
    held: readonly GrantRow[],
    change: GrantChange & store.Place,
    correlation: Correlation,
  ): AccessChange {
    const existing = held.find((grant) => placeKey(grant) === placeKey(change));
    const current = existing !== undefined && live(existing, d.at) ? existing : undefined;
    const expiresAt = change.expiresAt === null ? null : Date.parse(change.expiresAt);
    const place = { projectId: change.projectId, environmentId: change.environmentId, environmentSlug: change.environmentSlug };
    const where = located(place);
    const entry = (action: string, role: string | null) =>
      d.log.push({
        ...accessEntry(actor, action, principal, 'allow', correlation, {
          role,
          expiresAt: expiresAt === null ? null : iso(expiresAt),
          previousRole: current?.role ?? null,
          ...where.detail,
        }),
        ...where.ids,
      });
    // A lapsed grant is cleared with no entry: it changes nothing anyone holds.
    const clear = () => {
      if (existing === undefined) return;
      d.writes.push(async () => {
        await store.deleteGrant(d.tx, principal, place);
        d.grants.set(principal, d.grants.get(principal)!.filter((grant) => grant !== existing));
      });
    };

    if (change.role === null) {
      clear();
      if (existing !== undefined) d.changes?.stage(memberRef(principal), { op: 'access.revoke', place: placeOf(place) }, actor);
      if (current === undefined) return 'unchanged';
      entry('access.revoke', null);
      return 'revoked';
    }
    if (current !== undefined && current.role === change.role && current.expiresAt === expiresAt) return 'unchanged';
    const role = change.role;
    clear();
    d.writes.push(async (at) => {
      const grant = { principal, ...place, role, expiresAt, grantedAt: at, grantedBy: actor };
      await store.insertGrant(d.tx, grant);
      d.grants.get(principal)!.push(grant);
    });
    // In place of whatever it held there, lapsed or not, as clearing it then inserting this does.
    d.changes?.stage(memberRef(principal), { op: 'access.grant', grant: inputGrant({ ...placeOf(place), role, expiresAt }) }, actor);
    entry('access.grant', role);
    return current === undefined ? 'created' : 'updated';
  }

  admit(input: AdmitInput): Promise<Outcome<Admitted>> {
    const { actor, principal } = input;
    const asked = input.role === undefined ? {} : { role: input.role, scope: input.scope ?? EVERYWHERE };
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) =>
      new Refused(refusal(code, message), [
        accessEntry(actor, 'member.add', principal, 'deny', input, asked, code),
      ]);
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports, d.reads), input);
      if (acting.status === 'tampered') throw refused('tampered');
      // A service account, with no grant yet, any person who could give it one sets up (`setsUpServices`).
      const service = SERVICE.test(principal) && (input.role ?? 'member') === 'member' && input.scope === undefined;
      if (!runsInstance(acting.live)) await this.#setsUp(d, acting, service, refused);
      if (!PRINCIPAL.test(principal)) throw refused('invalid', `not a member: ${shownMember(principal)}`);
      if (input.role !== undefined && !isInstanceRole(input.role)) throw refused('invalid', `no such instance role: ${input.role}`);
      if (input.scope !== undefined && (input.role === undefined || !isScope(input.scope))) throw refused('invalid', 'a scope is a role\'s: { projects, environments }, each all, only or except');
      const wanted = input.role === undefined ? undefined : { role: input.role, scope: input.role === 'member' ? EVERYWHERE : normalScope(input.scope ?? EVERYWHERE) };
      if (wanted !== undefined && wanted.role !== 'member' && !principal.startsWith('user:')) {
        throw refused('invalid', 'service accounts hold project grants only, never an instance role');
      }
      const row = d.members.get(principal);
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports, d.reads);
      if (subject.status === 'tampered') throw refused('tampered', this.#tamperedSubject());
      d.touched.add(principal);
      d.grants.set(principal, [...subject.stored]);

      if (row === undefined || row.status === 'removed') {
        // Added or brought back, as anything but an Owner of the whole instance, one the deployment names would be a listed Member.
        if (this.#listed(principal) && !(wanted !== undefined && ownsInstance(wanted))) throw refused('not_allowed', declaredOwner(principal));
        return this.#enlist(d, acting, principal, row, wanted, input, refused);
      }
      const changed = wanted !== undefined && JSON.stringify(standing(wanted)) !== JSON.stringify(standing(row));
      // One the deployment names stays an Owner of the whole instance, whoever asks: the list says where to change that.
      if (changed && this.#listed(principal) && !ownsInstance(wanted)) throw refused('not_allowed', declaredOwner(principal));
      // Read under both rows' locks: neither the actor's role nor the subject's changes before this commits.
      if (changed && (wanted.role === 'owner' || subject.live.role === 'owner') && !ownsInstance(acting.live)) throw refused('not_allowed', OWNERS_ONLY);
      // Nobody sets their own role, but an Owner of the whole instance, who holds all there is: running the instance never lets anyone widen what they hold themselves.
      if (changed && actor === principal && !ownsInstance(acting.live)) throw refused('not_allowed', 'nobody changes their own instance role: ask another admin');
      if (changed && ownsInstance(subject.live) && !ownsInstance(wanted)) await this.#keepAnOwner(d, actor, principal, refused);
      if (changed) {
        d.log.push(accessEntry(actor, 'member.role', principal, 'allow', input, { role: wanted.role, scope: wanted.scope, previousRole: row.role, previousScope: row.scope }));
        d.writes.push(() => store.updateMember(d.tx, principal, { role: wanted.role, scope: wanted.scope }));
        d.changes?.stage(memberRef(principal), { op: 'member.role', ...asStored(wanted.role, wanted.scope) }, actor);
        return { created: false, ...wanted, generation: row.generation };
      }
      return { created: false, role: row.role, scope: row.scope, generation: row.generation };
    });
  }

  /**
   * Whether `acting`, who does not run the instance, may admit `principal`:
   * only a service account (`service`: one asked for with no role), as a
   * person who could give it a grant somewhere (`setsUpServices`), and one
   * removed only if they removed it themselves, never one someone else
   * took away.
   */
  async #setsUp(d: Decision, acting: Standing, service: boolean, refused: (code: RefusalCode, message?: string) => Refused): Promise<void> {
    const setting = (await this.#settingsAt(d.tx, d.reports)).serviceAccounts;
    if (!service || !PERSON.test(acting.principal) || !setsUpServices(acting.live, setting, placesOf(await this.#livePlaces(d)))) {
      throw refused('not_allowed', SETS_UP_ONLY);
    }
  }

  /**
   * Every live project and its environments, each environment by its
   * project, slug and tombstone as 0.15's log holds its row (T159): one that
   * is not is no place anyone sets a service account up in, nor that a
   * grant on every project of 0.4 becomes one on. Each read once,
   * in the statement whose rows are checked, so what is checked is what is
   * weighed (review r3: a row renamed between two reads, and back).
   */
  async #livePlaces(d: Decision): Promise<Awaited<ReturnType<typeof store.liveProjects>>> {
    const projects = await store.liveProjects(d.tx);
    if (!this.#checksSeals()) return projects;
    const rows = await store.environmentsById(d.tx, 'all', { seals: true });
    const held = [...rows].filter(([id, row]) => this.#placeFault(id, row, d.reports) === null && !row.deleted);
    return projects.map((project) => ({
      id: project.id,
      environments: held.filter(([, row]) => row.projectId === project.id).map(([id, row]) => ({ id, slug: row.slug })).sort((a, b) => (a.id < b.id ? -1 : 1)),
    }));
  }

  /**
   * Admit `principal`, who has no row or a removed one: a fresh start, as a
   * member unless given a role (`wanted`), at the generation a removal
   * moved on. The caller has checked who may, and locked the row.
   */
  #enlist(
    d: Decision,
    acting: Standing,
    principal: string,
    row: Member | undefined,
    wanted: { role: InstanceRole; scope: Scope } | undefined,
    correlation: Correlation,
    refused: (code: RefusalCode, message?: string) => Refused,
  ): Admitted {
    const actor = acting.principal;
    if (row?.status === 'removed' && row.statusChangedBy !== actor && !runsInstance(acting.live)) {
      throw refused('not_allowed', `${shownMember(row.statusChangedBy)} removed this service account: only they, or someone who runs the whole instance, may bring it back`);
    }
    if (wanted?.role === 'owner' && !ownsInstance(acting.live)) throw refused('not_allowed', OWNERS_ONLY);
    const { role, scope } = wanted ?? { role: 'member' as const, scope: EVERYWHERE };
    d.log.push(accessEntry(actor, row === undefined ? 'member.add' : 'member.restore', principal, 'allow', correlation, { role, scope }));
    d.changes?.stage(memberRef(principal), { op: row === undefined ? 'member.add' : 'member.restore', ...asStored(role, scope) }, actor);
    d.writes.push(async (at) => {
      if (row === undefined) {
        await store.insertMember(d.tx, {
          principal,
          status: 'active',
          role,
          scope,
          generation: 0,
          createdAt: at,
          createdBy: actor,
          statusChangedAt: at,
          statusChangedBy: actor,
          ...UNSEALED,
        });
      } else {
        await store.updateMember(d.tx, principal, { status: 'active', role, scope, statusChangedAt: at, statusChangedBy: actor });
      }
    });
    // A removal moved the generation on already; coming back keeps it.
    return { created: true, role, scope, generation: row?.generation ?? 0 };
  }

  remove(input: RemoveInput): Promise<Outcome<{ revoked: Grant[]; generation: number }>> {
    const { actor, principal } = input;
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) =>
      new Refused(refusal(code, message), [accessEntry(actor, 'member.remove', principal, 'deny', input, {}, code)]);
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      if (!PRINCIPAL.test(principal)) throw refused('invalid', `not a member: ${shownMember(principal)}`);
      const row = d.members.get(principal);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports, d.reads), input);
      if (acting.status === 'tampered') throw refused('tampered');
      const holder = acting.live;
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports, d.reads);
      const held = subject.stored;
      if (this.#listed(principal)) throw refused('not_allowed', declaredOwner(principal));
      if (subject.status === 'tampered') {
        if (!runsInstance(holder)) throw refused('not_allowed', 'only admins and owners of the whole instance may remove a member whose record failed its check');
        return this.#startOver(d, actor, principal, row, subject.fault!, input, refused);
      }
      if (!runsInstance(holder)) {
        // A service account its manager removes: they reach everything it holds (`managesService`).
        const theirs = SERVICE.test(principal) && PERSON.test(actor) && row?.status === 'active' &&
          managesService(holder, (await this.#settingsAt(d.tx, d.reports)).serviceAccounts, actor, await this.#account(d.tx, subject, row, d.reads, d.reports));
        if (!theirs) throw refused('not_allowed', 'only admins and owners of the whole instance may remove members, and a service account whoever manages it');
      }
      if (row?.status !== 'active') throw refused(row === undefined ? 'not_a_member' : 'removed');
      if (subject.live.role === 'owner' && !ownsInstance(holder)) throw refused('not_allowed', OWNERS_ONLY);
      if (ownsInstance(subject.live)) await this.#keepAnOwner(d, actor, principal, refused);

      const revoked = held.filter((grant) => live(grant, d.at));
      for (const grant of revoked) {
        const where = located(grant);
        d.log.push({
          ...accessEntry(actor, 'access.revoke', principal, 'allow', input, {
            role: null,
            expiresAt: null,
            previousRole: grant.role,
            ...where.detail,
          }),
          ...where.ids,
        });
      }
      const generation = row.generation + 1;
      d.log.push(accessEntry(actor, 'member.remove', principal, 'allow', input, { revoked: revoked.length, generation }));
      // In 0.15's log, what the writes below do, op by op: every grant revoked, lapsed ones too, the role back to a
      // Member's, then the removal.
      for (const grant of held) d.changes?.stage(memberRef(principal), { op: 'access.revoke', place: placeOf(grant) }, actor);
      if (row.role !== 'member') d.changes?.stage(memberRef(principal), { op: 'member.role', ...asStored('member', EVERYWHERE) }, actor);
      d.changes?.stage(memberRef(principal), { op: 'member.remove' }, actor);
      d.touched.add(principal);
      d.writes.push(async (at) => {
        await store.deleteGrants(d.tx, principal);
        d.grants.set(principal, []);
        await store.updateMember(d.tx, principal, {
          status: 'removed',
          role: 'member',
          scope: EVERYWHERE,
          generation,
          statusChangedAt: at,
          statusChangedBy: actor,
        });
      });
      return { revoked: revoked.map(view), generation };
    });
  }

  /**
   * A service account as `managesService` weighs it: its live grants, each
   * environment by its slug, which the setting's scope matches, and who
   * admitted it, as its row says.
   */
  async #account(db: Queryable, subject: Standing, row: Member, reads: Snapshot, reports: NewEntry[]): Promise<ServiceAccount> {
    // Every place it holds a grant on, lapsed ones too, as 0.15's log holds its row (T159): one that is not holds nothing,
    // and so would leave the account easier to manage, not harder. Refused instead.
    const ids = subject.stored.flatMap((grant) => (grant.environmentId === null ? [] : [grant.environmentId]));
    // The decision's own read of them, their grants' places among it once 0.15's log is cut over (`asked.seals`); else read.
    const missing = ids.filter((id) => !reads.environments.has(id));
    const slugs = missing.length === 0 ? reads.environments : new Map([...reads.environments, ...await store.environmentsById(db, missing, { seals: this.#checksSeals() })]);
    if (this.#checksSeals() && ids.some((id) => !slugs.has(id))) throw new Refused(refusal('tampered', TAMPERED_PLACE), []);
    this.#placesHold(slugs, ids, reports);
    return {
      grants: subject.live.grants.map((grant) => ({
        role: grant.role,
        place: grant.environmentId === null
          ? { projectId: grant.projectId! }
          : { projectId: grant.projectId!, environmentId: grant.environmentId, environmentSlug: slugs.get(grant.environmentId)?.slug ?? null },
      })),
      admittedBy: row.statusChangedBy,
    };
  }

  // --- the instance's settings ------------------------------------------------

  async settings(): Promise<Settings> {
    await this.#settled();
    const reports: NewEntry[] = [];
    const settings = await this.#settingsAt(this.#db, reports);
    await this.#record(reports);
    return settings;
  }

  /**
   * The settings the vault's newest `settings.change` says, by its MAC: one
   * in its name it did not write is passed over, and reported. With such
   * entries and none of its own within reach, the setting is closed, never
   * the default: otherwise whoever can insert rows could open it again.
   */
  async #settingsAt(db: Queryable, reports: NewEntry[], reads?: Snapshot): Promise<Settings> {
    // A snapshot's newest first, when it read it (`asked.settings`); the pages before it, as they are asked.
    const entry = await newestAuthentic(
      (limit, before) => (reads?.newestSettings !== undefined && before === undefined
        ? Promise.resolve(reads.newestSettings === null ? [] : [reads.newestSettings])
        : store.newestVaultEntries(db, SETTINGS, limit, before)),
      this.#check(reports, null),
    );
    if (entry === 'none') return settingsFrom(null);
    return typeof entry === 'string' ? CLOSED_SETTINGS : settingsFrom(entry.metadata);
  }

  // --- the instance's access policy -------------------------------------------

  async policy(): Promise<Policy> {
    await this.#settled();
    const reports: NewEntry[] = [];
    const { policy } = await this.#policyAt(this.#db, reports, await this.#now(this.#db));
    await this.#record(reports);
    return policy;
  }

  /**
   * The policy the vault's newest `policy.change` says, by its MAC, and its
   * edits, as of `at`: one in its name it did not write is passed over, and
   * reported. With such entries and none of its own within reach, the
   * policy is unreadable, and closed: every environment is protected, and
   * no role holds anything but Owner, otherwise whoever can insert rows
   * could unprotect them. Its edits are then unknown, not none.
   */
  async #policyAt(db: Queryable, reports: NewEntry[], at: number, reads?: Snapshot): Promise<{ policy: Policy; edits: PolicyEdits; readable: boolean; seq: bigint | null }> {
    // The snapshot's newest first, with the rows it protects; the pages before it, as they are asked.
    const entry = await newestAuthentic(
      (limit, before) => (reads !== undefined && before === undefined
        ? Promise.resolve(reads.newestPolicy === null ? [] : [reads.newestPolicy])
        : store.newestVaultEntries(db, POLICY, limit, before)),
      this.#check(reports, null),
    );
    if (entry === 'none') return { policy: DEFAULT_POLICY, edits: NO_EDITS, readable: true, seq: null };
    const edits = typeof entry === 'string' ? null : readEdits(JSON.parse(entry.metadata) as { policy?: unknown });
    if (edits === null) return { policy: CLOSED_POLICY, edits: NO_EDITS, readable: false, seq: null };
    const rows = entry === reads?.newestPolicy
      ? reads.environments
      : await store.environmentsById(db, edits.protected.map((place) => place.environmentId), { seals: this.#checksSeals() });
    return { policy: this.#livePolicy(rows, edits, at, reports), edits, readable: true, seq: (entry as StoredEntry).seq };
  }

  changePolicy(input: ChangePolicyInput): Promise<Outcome<{ policy: Policy; seq: number | null }>> {
    const { actor, change, revision } = input;
    if (revision !== undefined && (typeof revision !== 'string' || !POLICY_REVISION.test(revision))) throw new Error('revision names a policy as policyRevision writes it');
    // Where a protection is, once its rows are found: its project, and its one environment if that has a row yet. A fork's,
    // protected before its row is written, is named by the change alone, as the log's columns name only rows.
    const at: { projectId?: string; environmentId?: string } = {};
    const entry = (decision: 'allow' | 'deny', detail: Record<string, unknown>, code: RefusalCode | null = null): NewEntry => ({
      actor,
      action: POLICY,
      decision,
      code,
      operationId: input.operationId ?? null,
      requestId: input.requestId ?? null,
      ...at,
      metadata: JSON.stringify({ ...detail, ...traced(input) }),
    });
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) =>
      new Refused(refusal(code, message), [entry('deny', { change: describeChange(change) }, code)]);
    return this.#decide([actor], async (d) => {
      validateCorrelation(input);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports, d.reads), input);
      if (acting.status === 'tampered') throw refused('tampered');
      if (acting.status !== 'active') throw refused(acting.status === 'removed' ? 'removed' : 'not_a_member');
      // Under the log's head, as the actor's standing above: two changes at once each start from the one before. One the
      // caller weighed from a revision of the policy, its newest change and its protected environments' rows, starts
      // from that one, or is refused, to be asked again: a protected prod renamed since is a policy changed too.
      // The newest change in the vault's name, read with the decision, as the app reads it: by its number, unchecked.
      const newest = d.reads.newestPolicy?.seq ?? null;
      const { policy: before, edits, readable } = await this.#policyAt(d.tx, d.reports, d.at, d.reads);
      if (revision !== undefined && policyRevision(newest, before) !== revision) throw refused('policy_changed');
      const owner = acting.live.credentialScope == null && ownsInstance(acting.live);
      // Unreadable, its edits are unknown: a change made from none would erase every protection and role edit the forged
      // rows hide. An Owner of the whole instance alone writes it again, from the roles as they ship and nothing protected.
      if (!readable && !owner) throw refused('not_allowed', "the vault cannot read its own policy: only an Owner of the whole instance writes it again, from the roles as they ship");
      // Those the policy no longer holds stay out: a deleted environment's id, and an unwritten fork's past its window,
      // neither of which comes back, the window being one a fork writes its row well within.
      // What 0.15's log changes with it: the roles object, or each environment whose protection moves.
      const changes: { ref: Ref & { kind: 'roles' | 'role' | 'environment' }; op: Op }[] = [];
      const next: PolicyEdits = {
        roles: { ...edits.roles },
        instanceRoles: { ...edits.instanceRoles },
        protected: edits.protected.filter((place) => before.protected.includes(place.environmentId)).map((place) => ({ ...place })),
      };
      if (change?.kind === 'role' || change?.kind === 'instance-role') {
        // Roles are the whole instance's: an Owner of all of it alone changes them (R1, R15), never through a scoped credential.
        if (!owner) throw refused('not_allowed', 'only an Owner of the whole instance edits roles');
        const instance = change.kind === 'instance-role';
        const fixed = instance ? FIXED_ROLES.instanceRoles.includes(change.role as InstanceRole) : FIXED_ROLES.roles.includes(change.role);
        if (typeof change.role !== 'string' || fixed) throw refused('invalid', `${change.role} is not edited: it holds ${change.role === 'member' ? 'nothing' : 'everything'}, always`);
        if (instance && !isInstanceRole(change.role)) throw refused('invalid', `no instance role ${change.role}: an Owner makes project roles`);
        if (!instance && !isBuiltinRole(change.role) && !ROLE_ID.test(change.role)) throw refused('invalid', ROLE_ID_RULE);
        const table = instance ? next.instanceRoles as Record<string, RoleDefinition> : next.roles;
        if (change.definition === null) {
          // Put back as it ships, or, one an Owner made, gone: while no grant names it.
          if (!instance && !isBuiltinRole(change.role)) {
            if (table[change.role] === undefined) throw refused('invalid', `no role ${change.role}`);
            const held = await store.grantsNaming(d.tx, change.role);
            if (held > 0) throw refused('invalid', `${held === 1 ? '1 grant names' : `${held} grants name`} ${change.role}: revoke ${held === 1 ? 'it' : 'them'} first`);
          }
          // What it ships as is held to the same rule as any edit: a project-wide permission back on a role granted on environments.
          const shipped = instance ? undefined : isBuiltinRole(change.role) ? ROLES[change.role] : undefined;
          if (shipped !== undefined && shipped.permissions.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission)) && (await store.grantsNaming(d.tx, change.role, { onEnvironments: true })) > 0) {
            throw refused('invalid', `${change.role} is granted on environments: as it ships, it holds a project-wide permission, which would make those grants incoherent`);
          }
          delete table[change.role];
          changes.push(...await this.#roleWrites(d, instance ? 'instanceRoles' : 'roles', change.role, null));
        } else {
          const problem = definitionProblem(change.definition);
          if (problem !== null) throw refused('invalid', problem);
          const definition = normalDefinition(change.definition);
          // A project role granted on an environment keeps no project-wide permission while any grant there names it.
          if (!instance && definition.permissions.some((permission) => PROJECT_ONLY_PERMISSIONS.includes(permission)) && (await store.grantsNaming(d.tx, change.role, { onEnvironments: true })) > 0) {
            throw refused('invalid', `${change.role} is granted on environments: a project-wide permission would make those grants incoherent`);
          }
          const shipped = instance ? INSTANCE_ROLES[change.role as InstanceRole] : isBuiltinRole(change.role) ? ROLES[change.role] : undefined;
          if (shipped !== undefined && JSON.stringify(normalDefinition(shipped)) === JSON.stringify(definition)) delete table[change.role];
          else table[change.role] = definition;
          changes.push(...await this.#roleWrites(d, instance ? 'instanceRoles' : 'roles', change.role, definition));
        }
      } else if (change?.kind === 'protect') {
        if (typeof change.projectId !== 'string' || !UUID.test(change.projectId) || !Array.isArray(change.environmentIds) || change.environmentIds.length === 0
          || change.environmentIds.some((id) => typeof id !== 'string' || !UUID.test(id)) || typeof change.protected !== 'boolean') {
          throw refused('invalid', 'protection names a project and some of its environments, by id, and whether they are protected');
        }
        if (!(await store.projectLive(d.tx, change.projectId))) throw refused('invalid', 'no such project');
        at.projectId = change.projectId;
        // Each a live environment of the project, or none yet: a fork's id, protected before its row is written.
        const found = await store.environmentsById(d.tx, change.environmentIds, { seals: this.#checksSeals() });
        // Each as 0.15's log holds its row (T159, review r1): its project and whether it was deleted decide what changes, and
        // a tombstone set around the log would keep a protection's end from its object. One the log has never held (no
        // seal, no change) is 0.14's alone, which the change path takes as such.
        this.#placesHold(found, [...found].flatMap(([id, row]) => (row.sealed?.seal == null && row.sealed?.newest == null ? [] : [id])), d.reports);
        if ([...found.values()].some((environment) => environment.projectId !== change.projectId)) throw refused('invalid', 'each environment is one of the project\'s');
        if (change.environmentIds.length === 1 && found.has(change.environmentIds[0]!)) at.environmentId = change.environmentIds[0];
        // An environment whose object 0.15's log changes with this: one with a row, not deleted (`environment.protect`).
        const live015 = (id: string) => found.get(id)?.deleted === false;
        if (change.protected) {
          if (!allows(acting.live, 'environment.manage', { projectId: change.projectId })) throw refused('not_allowed', 'protecting an environment takes managing its project\'s environments');
          const known = new Set(next.protected.map((place) => place.environmentId));
          // An id with no row yet, a fork's, is no object of 0.15's log: its creation carries its protection (plan PR 4b).
          // A deleted one changes no more there: 0.14 keeps its id in the edits, which its policy reads past.
          for (const id of change.environmentIds) if (!known.has(id) && live015(id)) changes.push({ ref: { kind: 'environment', id }, op: { op: 'environment.protect', protected: true } });
          next.protected = [...next.protected, ...change.environmentIds.filter((id) => !known.has(id)).map((environmentId) => ({ projectId: change.projectId, environmentId, at: d.at }))]
            .sort((a, b) => (a.environmentId < b.environmentId ? -1 : 1));
        } else {
          // Unprotecting widens what people hold there: an Owner of the project's to do, or of the whole instance's (R30).
          // It takes off only what the project protects: a fork's id, with no row yet, is another project's to unprotect.
          if (!ownsProject(acting.live, change.projectId)) throw refused('not_allowed', 'only an Owner of its project, or of the whole instance, unprotects an environment');
          for (const place of next.protected) {
            if (place.projectId === change.projectId && change.environmentIds.includes(place.environmentId) && live015(place.environmentId)) {
              changes.push({ ref: { kind: 'environment', id: place.environmentId }, op: { op: 'environment.protect', protected: false } });
            }
          }
          next.protected = next.protected.filter((place) => place.projectId !== change.projectId || !change.environmentIds.includes(place.environmentId));
        }
      } else {
        throw refused('invalid', 'a change is to a role, an instance role, or protection');
      }
      // The policy now, and the newest change, which it is as of: this one's, when it changed anything.
      const answer = {
        policy: this.#livePolicy(await store.environmentsById(d.tx, next.protected.map((place) => place.environmentId), { seals: this.#checksSeals() }), next, d.at, d.reports),
        seq: newest === null ? null : Number(newest),
      };
      if (!readable || JSON.stringify(next) !== JSON.stringify(edits)) {
        // With 0.15's log, ordered against the vault's issues in flight, which check the policy under the issue lock shared:
        // exclusive, its rows written, before its append's trigger takes the fence (`holdIssues`).
        if (this.#prepared.log015 !== null) await holdIssues(d.tx);
        const made = entry('allow', { policy: next, change: describeChange(change), before: describeBefore(change, before) });
        d.log.push(made);
        for (const { ref, op } of changes) d.changes?.stage(ref, op, actor);
        d.after.push((seqOf) => {
          for (const { ref } of changes) d.changes?.cite(ref, BigInt(seqOf(made)));
        });
        d.after.push((seqOf) => (answer.seq = seqOf(made)));
      }
      return answer;
    });
  }

  /**
   * What a change of one role writes to 0.15's log, in this order (T178, 0.16; formal/Roles.tla's 0.16 change): the
   * row of each other role brought to what the log's roles object says, sealed, as the vault's start does (EditSyncs:
   * one 0.15.0 changed since is not left behind this one); the role's own row, its object; and the whole object
   * (DualWrite), which 0.16's uses still decide on. Under 0.14's log alone, the whole object's change, which nothing
   * stages. Each staged under the change's actor.
   */
  async #roleWrites(d: Decision, table: RoleTable, role: string, definition: RoleDefinition | null): Promise<{ ref: Ref & { kind: 'roles' | 'role' }; op: Op }[]> {
    const op: Op = { op: 'role.define', table, role, definition };
    const whole = { ref: ROLES_REF as Ref & { kind: 'roles' }, op };
    if (d.changes == null) return [whole];
    const [held, rows] = await Promise.all([d.changes.held(d.tx, ROLES_REF as Ref & { kind: 'roles' }), store.roleRows(d.tx)]);
    const object: RolesInput = held.log === 'live' && held.object.kind === 'roles' ? held.object : noEdits();
    return [...roleChanges(this.#prepared.log015!.seals, object, rows, { table, role }), { ref: roleRef(table, role), op }, whole];
  }

  setSettings(input: SetSettingsInput): Promise<Outcome<{ settings: Settings }>> {
    const { actor } = input;
    const entry = (decision: 'allow' | 'deny', detail: Record<string, unknown>, code: RefusalCode | null = null): NewEntry => ({
      actor,
      action: SETTINGS,
      decision,
      code,
      operationId: input.operationId ?? null,
      requestId: input.requestId ?? null,
      metadata: JSON.stringify({ ...detail, ...traced(input) }),
    });
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) =>
      new Refused(refusal(code, message), [entry('deny', { serviceAccounts: input.settings?.serviceAccounts ?? null }, code)]);
    return this.#decide([actor], async (d) => {
      validateCorrelation(input);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports, d.reads), input);
      if (acting.status === 'tampered') throw refused('tampered');
      if (!runsInstance(acting.live)) throw refused('not_allowed', "only admins and owners of the whole instance change its settings");
      if (!isScope(input.settings?.serviceAccounts)) throw refused('invalid', 'who sets up service accounts is a scope: { projects, environments }, each all, only or except');
      // Under the log's head, so two changes at once each name the one before.
      const previous = await this.#settingsAt(d.tx, d.reports);
      const settings: Settings = { serviceAccounts: normalScope(input.settings.serviceAccounts) };
      if (JSON.stringify(settings) !== JSON.stringify(previous)) d.log.push(entry('allow', { ...settings, previous }));
      return { settings };
    });
  }

  /**
   * Remove a member whose row failed its check, from what the log says of
   * them rather than what the row does: their grants go, whatever they were,
   * and their generation moves past both the row's and the log's, so no
   * session or token from any earlier membership comes back with a row put
   * back. Admitted again, they start from nothing, as any removed member.
   *
   * Under 0.15's log, refused: the log changes no member whose row it does
   * not hold (`Changes`), and a row rewritten here without a change of its
   * own would fail every check of it after (`#onLog`). The member holds
   * nothing meanwhile; a reseal makes their row the log's again (plan PR 9).
   */
  async #startOver(
    d: Decision,
    actor: string,
    principal: string,
    row: Member | undefined,
    fault: Fault,
    correlation: Correlation,
    refused: (code: RefusalCode, message?: string) => Refused,
  ): Promise<{ revoked: Grant[]; generation: number }> {
    if (this.#checksSeals()) throw refused('tampered', START_OVER_015);
    const logged = await this.#logged(d.tx, principal);
    if (logged === undefined) throw refused('not_a_member', 'the log never admitted them: their row was written around the vault');
    const generation = Math.max(row?.generation ?? 0, logged.generation) + 1;
    d.log.push(accessEntry(actor, 'member.remove', principal, 'allow', correlation, { revoked: 0, generation, tampered: fault }));
    d.touched.add(principal);
    d.writes.push(async (at) => {
      await store.deleteGrants(d.tx, principal);
      d.grants.set(principal, []);
      const fresh = {
        status: 'removed' as const,
        role: 'member' as const,
        scope: EVERYWHERE,
        generation,
        createdAt: logged.createdAt,
        createdBy: logged.createdBy,
        statusChangedAt: at,
        statusChangedBy: actor,
      };
      if (row === undefined) await store.insertMember(d.tx, { principal, ...fresh, ...UNSEALED });
      else await store.updateMember(d.tx, principal, fresh);
    });
    return { revoked: [], generation };
  }

  /** `principal` as the log says they are: their authenticated access entries, replayed. */
  async #logged(db: Queryable, principal: string): Promise<LoggedMember | undefined> {
    const state: Replayed = { members: new Map(), held: new Map() };
    const entries = (await store.accessEntriesAbout(db, principal, 100_000)).filter((entry) => this.#authentic(entry));
    for (const entry of entries.reverse()) apply(state, entry);
    return state.members.get(principal);
  }

  // --- the KEKs ----------------------------------------------------------------

  /**
   * Null when every KEK the vault is given opens what it wrapped; otherwise
   * why not, naming the KEK, never its key. Decided once per process, before
   * its first key operation or checkpoint: until then, each call checks for
   * itself, over its own database, and the first verdict is kept. A key
   * service that cannot answer leaves it undecided: the error is thrown,
   * and the next call asks again.
   */
  async #kekMismatch(deadline?: number): Promise<string | null> {
    const prepared = this.#prepared;
    if (!prepared.kekChecked) {
      const wrong = await this.#checkKeks(deadline);
      if (!prepared.kekChecked) {
        prepared.wrongKek = wrong;
        prepared.kekChecked = true;
      }
    }
    return prepared.wrongKek;
  }

  /**
   * Each KEK opens its check value, or, with none recorded yet (a fresh
   * database, a new KEK, data from before checks), opens one of the newest
   * keys it wrapped, if there are any; then its check value is recorded.
   * A KEK that opens neither is not the one that wrapped the data.
   */
  async #checkKeks(deadline?: number): Promise<string | null> {
    // A vault that may not write cannot record a check either; why it may not is the answer.
    const superseded = await this.#settled();
    if (superseded !== null) return superseded;
    const checks = await this.#checkValues(this.#db);
    const budget = this.#prepared.options.keyBudgetMs;
    for (const kek of this.#config.keks.all) {
      // A read's, within what is left of its deadline.
      const spend = within(deadline, budget);
      const operation = { deadline: Date.now() + spend, signal: AbortSignal.timeout(spend) };
      const opens = async (wrapped: WrappedDek, context: SecretContext, expected?: Buffer) => {
        try {
          const key = await kek.unwrap(wrapped, context, operation);
          const right = expected === undefined || (key.length === expected.length && timingSafeEqual(key, expected));
          key.fill(0);
          return right;
        } catch (error) {
          if (error instanceof KekBadClaimError) return false;
          throw error;
        }
      };
      const mismatch = `the vault key ${kek.keyId}${kek.provider === 'local' ? '' : ` (${kek.provider})`}, kek or previousKeks in the vault's config, is not the one that wrapped these values`;
      const check = checks.get(`${kek.provider}:${kek.keyId}`);
      if (check !== undefined) {
        if (!(await opens(unwrappable(check.wrapped), KEY_CHECK_CONTEXT, KEY_CHECK_VALUE))) return mismatch;
        continue;
      }
      const samples = await store.wrappedUnder(this.#db, kek.provider, kek.keyId, KEY_CHECK_SAMPLE);
      let proof: { secretId: string; version: number } | null = null;
      for (const { projectId, environmentId, secretId, version, ...wrapped } of samples) {
        if (await opens(wrapped, { projectId, environmentId, secretId })) {
          proof = { secretId, version };
          break;
        }
      }
      if (samples.length > 0 && proof === null) return mismatch;
      const wrapped = await kek.wrap(Buffer.from(KEY_CHECK_VALUE), KEY_CHECK_CONTEXT, operation);
      // The key it opened, if any, is in the log, as every key the vault opens is. Another call that
      // checked at the same time may have recorded one first: under the log's lock, the first stays.
      await this.#db.transaction(async (tx) => {
        // Once a process, by its first key operation: a read's waits as the read's, within its deadline.
        await store.boundLockWaits(tx, within(deadline, READ_LOCK_TIMEOUT_MS), within(deadline, READ_LOCK_TIMEOUT_MS));
        await lockLogHead(tx);
        if ((await this.#checkValues(tx)).has(`${kek.provider}:${kek.keyId}`)) return;
        await this.#append(tx, [
          { actor: VAULT_ACTOR, action: KEY_CHECK, decision: 'allow', metadata: JSON.stringify({ ...serialisable(wrapped), proof }) },
        ]);
      });
    }
    return null;
  }

  /** Each KEK's recorded check value, by `provider:keyId`, and the entry that holds it. */
  async #checkValues(db: Queryable): Promise<Map<string, { seq: bigint; wrapped: WrappedKey }>> {
    const checks = new Map<string, { seq: bigint; wrapped: WrappedKey }>();
    for (const entry of await store.vaultEntriesOf(db, [KEY_CHECK], -1n, VERIFY_BATCH)) {
      // A check in the vault's name that the vault did not write proves nothing either way.
      if (!this.#authentic(entry)) continue;
      const { kekProvider, kekId, kekVersion, bytes } = JSON.parse(entry.metadata) as WrappedKey;
      checks.set(`${kekProvider}:${kekId}`, { seq: entry.seq, wrapped: { kekProvider, kekId, kekVersion, bytes } });
    }
    return checks;
  }

  // --- checkpoints and the log --------------------------------------------------

  /**
   * Where a walk of the log resumes: the first entry (`start`), a
   * checkpoint's entry that keeps a tally, or the newest such entry, the
   * first entry while there is none. The entry must be the vault's, by its
   * MAC, and its tally whole: the members and grants it keeps, or the
   * earlier checkpoint it names keeps, match the digest it carries.
   *
   * Its signature is left to the walk: the entry comes after the prefix it
   * signs, so a walk from there reads it, as it reads every other.
   */
  async #resume(db: Queryable, from: 'start' | 'newest' | bigint): Promise<Resumed | Broken> {
    if (from === 'start') return FIRST_ENTRY;
    const entry = from === 'newest' ? await store.latestTallied(db) : (await store.entriesAt(db, [from])).get(from);
    if (entry === undefined) return from === 'newest' ? FIRST_ENTRY : { ok: false, failedAtSeq: Number(from), reason: 'no checkpoint at this entry' };
    return (await this.#resumeEach(db, [entry]))[0]!;
  }

  /** `#resume` for each of these checkpoint entries, the entries their members and grants are kept in read at once. */
  async #resumeEach(db: Queryable, entries: readonly StoredEntry[]): Promise<(Resumed | Broken)[]> {
    const reads = entries.map((entry) => this.#tallied(entry));
    const named = reads.flatMap((read) => (typeof read !== 'string' && 'at' in read.tally.access ? [BigInt(read.tally.access.at)] : []));
    const carriers = new Map([...(await store.entriesAt(db, named))].map(([seq, held]) => [seq, this.#tallied(held)]));
    return entries.map((entry, i): Resumed | Broken => {
      const broken = (reason: string): Broken => ({ ok: false, failedAtSeq: Number(entry.seq), reason });
      const read = reads[i]!;
      if (typeof read === 'string') return broken(read);
      let carrier = entry.seq;
      let { access } = read.tally;
      if ('at' in access) {
        carrier = BigInt(access.at);
        const holder = carrier < entry.seq ? carriers.get(carrier) : undefined;
        if (holder === undefined || typeof holder === 'string' || 'at' in holder.tally.access) {
          return broken(`its tally keeps its members and grants in entry ${carrier}, which holds none`);
        }
        access = holder.tally.access;
      }
      const kept = { members: access.members, grants: access.grants, newest: access.newest };
      if (keptDigest(access) !== read.tally.access.digest) return broken("its tally's members and grants do not match their digest");
      return {
        ok: true,
        entry: entry.seq,
        at: { seq: BigInt(read.seq), hash: Buffer.from(read.hash, 'hex') },
        tally: { ...read.tally, access: kept },
        digest: read.tally.access.digest,
        carrier,
        scrub: read.scrub === null ? null : { at: positionOf(read.scrub.at), end: positionOf(read.scrub.end) },
      };
    });
  }

  /** A checkpoint's entry that keeps a tally, as it says, or why it is not one the vault wrote. */
  #tallied(entry: StoredEntry): TalliedCheckpoint | string {
    const not = "not a checkpoint of the vault's that keeps a tally";
    if (entry.author !== 'vault' || entry.action !== CHECKPOINT || entry.decision !== 'allow' || entry.relatedSeq === null) return not;
    const authentic = verifyEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash, keys: this.#keysFor(entry) });
    if (!authentic.ok) return withCause(authentic.reason);
    const read = metadataOf(entry) as Partial<TalliedCheckpoint> | null;
    if (read?.tally?.v !== TALLY_VERSION || read.scrub === undefined || typeof read.seq !== 'number' || BigInt(read.seq) !== entry.relatedSeq) return not;
    return read as TalliedCheckpoint;
  }

  /** Which of `heads` the log still holds where they were, in one read. */
  async #holding(db: Queryable, heads: readonly LogHead[]): Promise<(head: LogHead) => boolean> {
    const hashes = await store.hashesAt(db, [...new Set(heads.filter((head) => head.seq >= 0).map((head) => BigInt(head.seq)))]);
    return (head) => head.hash === GENESIS_HASH.toString('hex') || hashes.get(BigInt(head.seq))?.toString('hex') === head.hash;
  }

  /**
   * Sign the log up to its last entry, from the newest checkpoint's tally.
   *
   * Without the log's lock, so that no append waits on it, and in one short
   * snapshot: every member's row checked, since rows changed around the
   * vault write nothing to the log; the prefix the newest checkpoint signed
   * still there, its hash where it was, which a rewrite chained again
   * changes, and every entry of it, which a cut changes. Then, in no
   * transaction, a batch a statement, the chain recomputed from there, every
   * hash from content and every vault entry by its MAC, no further than one
   * walk (`walks.checkpoint`); and a stretch of the prefixes signed before
   * rehashed (`#scrub`). Then, under the lock, the entries appended since
   * the walk, so that it signs the head.
   *
   * A walk cut short signs where it got to, behind the head: the log after
   * an upgrade from 0.10.0, whose checkpoints kept no tally, is signed again
   * from the first entry, one walk a call, and `/readyz` stays red until the
   * checkpoints reach the newest heartbeat.
   */
  async checkpoint(): Promise<Outcome<{ checkpoint: Checkpoint; warning?: string }>> {
    await this.#settled();
    // A KEK found wrong turns readiness red: the checkpoint is refused. It does no key work of its
    // own, so it writes nothing more and never waits on a key service; a check under way, or none yet, is no verdict.
    const { wrongKek, logKeys } = this.#prepared;
    const { walks } = this.#prepared.options;
    const found: NewEntry[] = [];
    // The newest checkpoint entry, signed or refused, as this call's snapshot found it.
    let seen: StoredEntry | undefined;
    const resumed = await this.#db.transaction(async (tx) => {
      seen = await store.newestCheckpointEntry(tx);
      await this.#sweep(tx, found);
      const from = await this.#resume(tx, 'newest');
      if (!from.ok) return from;
      const signed = headOf(from.at);
      if (!(await this.#holding(tx, [signed]))(signed)) {
        return { ok: false as const, failedAtSeq: null, reason: `the log up to entry ${signed.seq} is not the prefix the last checkpoint signed` };
      }
      const gap = await missingEntry(tx, from.at.seq);
      if (gap !== null) return { ok: false as const, failedAtSeq: Number(gap.found), reason: `sequence gap: expected seq ${gap.expected}, found ${gap.found}` };
      return from;
    }, SNAPSHOT);
    const walked = resumed.ok ? await this.#walkOn(resumed, walks.checkpoint) : resumed;
    // The past rehashed, in a snapshot of its own. The database failing it leaves the stretch for the
    // next call, where it was, and the checkpoint is signed all the same, saying why (`warning`); a bug
    // throws, as anywhere else.
    let scrub: Scrubbed = { ok: true, next: walked.ok ? walked.from.scrub : null };
    let stalled: string | null = null;
    if (walked.ok) {
      try {
        scrub = await this.#db.transaction((tx) => this.#scrub(tx, walked.from), SNAPSHOT);
      } catch (error) {
        // Only the database not answering, or a statement it gave up on: anything else is coffre's to fix.
        if (!isUnavailable(error)) throw error;
        stalled = `the rehash of the past did not run, and goes on where it was next time: ${(error as Error).message}`;
      }
    }
    const decided = await this.#decide([], async (d) => {
      for (const entry of found) if (!d.reports.includes(entry)) d.reports.push(entry);
      // Checkpoints one at a time, each against the one before.
      const head = await lockLogHead(d.tx);
      const latest = await store.latestVaultEntry(d.tx, [CHECKPOINT]);
      const refused = (code: RefusalCode, detail: Record<string, unknown>, message = REFUSAL_MESSAGES[code]) =>
        new Refused(refusal(code, message), [
          { actor: SCHEDULER, action: CHECKPOINT, decision: 'deny', code, metadata: JSON.stringify(detail) },
        ]);
      // Logging the refusal would give the next call something to sign.
      if (head.nextSeq === 0n) throw new Refused(refusal('invalid', 'the log is empty'), []);
      if (wrongKek !== null) throw refused('wrong_kek', { reason: wrongKek }, wrongKek);
      if (!walked.ok) throw refused('log_broken', { failedAtSeq: walked.failedAtSeq, reason: walked.reason });
      if (!scrub.ok) throw refused('log_broken', { failedAtSeq: scrub.failedAtSeq, reason: scrub.reason });
      const newest = latest === undefined ? null : (JSON.parse(latest.metadata) as Checkpoint);
      // Another call checkpointed, or refused to, since this one's snapshot, or this one's rehash of the past
      // could not run: what it would sign over is not what it checked. A refusal for a broken log stands,
      // and a checkpoint signed meanwhile is the newest prefix; the next call starts from them.
      if (stalled !== null || ((await store.newestCheckpointEntry(d.tx))?.seq ?? null) !== (seen?.seq ?? null)) {
        const standing = await this.#standingRefusal(d.tx);
        if (standing !== null) throw refused('log_broken', standing);
        if (stalled === null && newest !== null) return { checkpoint: signedPart(newest) };
      } else if (seen?.decision === 'deny' && walked.ok) {
        // A refusal for a broken log stands since this call's snapshot, of an entry before where its walk began, which
        // it never read: that entry again, as the walk checks each, before anything is signed over it. Still broken,
        // the refusal stands; whole again, the signature clears it (T104).
        const standing = await this.#standingRefusal(d.tx);
        const named = typeof standing?.failedAtSeq === 'number' ? BigInt(standing.failedAtSeq) : null;
        if (named !== null && named <= walked.from.at.seq && !(await this.#entryHolds(d.tx, named))) throw refused('log_broken', standing!);
      }
      // Nothing since the last one, which signed every entry before its own: it is still the newest prefix.
      if (newest !== null && latest!.seq === head.nextSeq - 1n && latest!.relatedSeq === latest!.seq - 1n) return { checkpoint: signedPart(newest) };
      // Under the lock, the rest: the prefix signed last still where it was,
      // and every entry since the walk, unless the walk is catching up,
      // when what it walked must still be there. A rewrite is never signed over.
      if (newest !== null && !(await carries(d.tx, newest))) {
        throw refused('log_broken', { reason: `the log up to entry ${newest.seq} is not the prefix the last checkpoint signed` });
      }
      const walk = new Walk(walked.tally, walked.digest);
      let { at } = walked;
      if (walked.done) {
        // Where the walk ended still has the hash it found there: what follows links to it.
        if (!(await carries(d.tx, headOf(at)))) {
          throw refused('log_broken', { failedAtSeq: Number(at.seq), reason: `the log up to entry ${at.seq} changed while the vault walked it` });
        }
        const rest = await rehash(d.tx, logKeys, at, walk, {});
        if (!rest.ok) throw refused('log_broken', { failedAtSeq: rest.failedAtSeq, reason: rest.reason });
        const unsigned = await this.#checkpointFault(d.tx, walk.checkpoints);
        if (unsigned !== null) throw refused('log_broken', { failedAtSeq: unsigned.failedAtSeq, reason: unsigned.reason });
        at = rest.at;
        // It signs the entry it verified to, which the head, locked, must name.
        if (at.seq !== head.nextSeq - 1n || !at.hash.equals(head.headHash)) {
          throw refused('log_broken', { reason: 'the chain head does not name the last entry' });
        }
      } else if (!(await carries(d.tx, headOf(at)))) {
        throw refused('log_broken', { reason: `the log up to entry ${at.seq} changed while the vault walked it` });
      }
      // Another call signed as far, or further, while this one walked behind the head: that is the newest prefix, never one shorter.
      if (newest !== null && latest!.relatedSeq !== null && latest!.relatedSeq >= at.seq) return { checkpoint: signedPart(newest) };
      this.#prepared.verified = further(this.#prepared.verified, at);
      const tally = walk.tally();
      // Its members and grants once, in the first checkpoint after they change; the others name that one.
      const digest = walk.digest();
      const { from } = walked;
      const access = digest === from.digest && from.carrier !== null ? { digest, at: Number(from.carrier) } : { digest, ...tally.access };
      const signed = { seq: Number(at.seq), hash: at.hash.toString('hex'), signedAt: iso(d.at) };
      const checkpoint = {
        ...signed,
        keyId: this.#prepared.signer.keyId,
        signature: await this.#prepared.signer.sign(checkpointMessage(signed)),
      };
      const lap = scrub.next === null ? null : { at: headOf(scrub.next.at), end: headOf(scrub.next.end) };
      const kept: TalliedCheckpoint = { ...checkpoint, tally: { v: TALLY_VERSION, ...tally, access }, scrub: lap };
      d.log.push({ actor: SCHEDULER, action: CHECKPOINT, decision: 'allow', relatedSeq: at.seq, metadata: JSON.stringify(kept) });
      return stalled === null ? { checkpoint } : { checkpoint, warning: stalled };
    });
    // Then the bulk count's upkeep, which no read waits on, after a checkpoint signed, never instead of a refusal: the
    // releases no window can count again, kept a day and an hour (`RELEASES_KEPT_MS`), longer than any window, up to
    // `RELEASES_PRUNED` of them, in one statement of its own, holding no lock any read takes but the rows it deletes,
    // and none an append holds. What is kept is the database's to say, not the caller's: no login forgets a release a
    // window counts. A failure leaves it to the next checkpoint, and says so.
    if (!decided.ok) return decided;
    const pruned = await store.pruneReleases(this.#db, RELEASES_PRUNED).then(() => null, (error: Error) => `the releases the bulk limit counts were not pruned, and the next checkpoint tries again: ${error.message}`);
    if (pruned === null) return decided;
    return { ...decided, warning: decided.warning === undefined ? pruned : `${decided.warning}; ${pruned}` };
  }

  /**
   * The walk on from where a checkpoint resumes, no further than `limit`
   * entries, outside any transaction: a batch a statement, each linked to
   * the hash it verified last, so that no connection is held while it
   * rehashes, seconds for a long walk. Entries are appended in order, under
   * the head, and never change, so no snapshot keeps them: what it read is
   * held to the log again under the head, before anything is signed over it
   * (`carries`).
   */
  async #walkOn(from: Resumed, limit: number) {
    const { logKeys } = this.#prepared;
    const walk = new Walk(from.tally, from.digest);
    const chain = await rehash(this.#db, logKeys, from.at, walk, { limit });
    if (!chain.ok) return chain;
    const unsigned = await this.#checkpointFault(this.#db, walk.checkpoints);
    if (unsigned !== null) return unsigned;
    return { ok: true as const, from, tally: walk.tally(), digest: walk.digest(), at: chain.at, done: chain.done };
  }

  /**
   * The prefixes signed before, rehashed a stretch at a time, in laps: a lap
   * runs from the first entry to the prefix the newest checkpoint signed
   * when it began, which it keeps (`end`), `walks.scrub` entries a call, each
   * hash recomputed from its entry and each link checked (`relink`); the
   * next lap runs to the prefix signed then. A checkpoint resumes from the
   * newest one's tally and never reads what it signed again, and an entry
   * before it edited in place, its stored hash left as it was, keeps the
   * chain: this is what finds it, within two laps at most, each the length
   * of the log when it began over `walks.scrub` beats, however fast the log
   * grows meanwhile. The lap as it goes on, null between laps.
   */
  async #scrub(db: Queryable, newest: Resumed): Promise<Scrubbed> {
    const lap = newest.scrub ?? { at: START, end: newest.at };
    if (lap.end.seq < 0n) return { ok: true, next: null };
    const relinked = await relink(db, lap.at, lap.end.seq, this.#prepared.options.walks.scrub);
    if (!relinked.ok) return relinked;
    if (relinked.at.seq < lap.end.seq) return { ok: true, next: { at: relinked.at, end: lap.end } };
    // A lap ends at the prefix a checkpoint signed, or it was not the chain the checkpoints signed.
    if (!relinked.at.hash.equals(lap.end.hash)) {
      return { ok: false, failedAtSeq: Number(lap.end.seq), reason: `the log up to entry ${lap.end.seq} is not the prefix a checkpoint signed` };
    }
    return { ok: true, next: null };
  }

  /**
   * Whether entry `seq` is as the walk checks each: there, its hash its
   * own, linked to the entry before, and the vault's under its MAC; and the
   * entry after it, if any, linked to it, for a refusal can name either side
   * of a broken link (`forward`, at the end of a batch).
   */
  async #entryHolds(db: Queryable, seq: bigint): Promise<boolean> {
    const found = await store.entriesAt(db, seq === 0n ? [seq, seq + 1n] : [seq - 1n, seq, seq + 1n]);
    const entry = found.get(seq);
    const before = seq === 0n ? { hash: GENESIS_HASH } : found.get(seq - 1n);
    if (entry === undefined || before === undefined) return false;
    const after = found.get(seq + 1n);
    if (after !== undefined && !after.prevHash.equals(entry.hash)) return false;
    return verifyEntries([entry], { keys: this.#keysFor(entry), chainOnly: ['app'], startSeq: seq, startPrevHash: before.hash }).ok;
  }

  /**
   * The newest refusal for a broken log since the newest checkpoint was
   * signed, by the vault's MAC, as it said: it stands, for every
   * verification and checkpoint, until a checkpoint is signed, which takes
   * the check that found it running again and passing. A refusal of
   * another kind since, a wrong KEK, hides none.
   */
  async #standingRefusal(db: Queryable): Promise<{ failedAtSeq?: number | null; reason?: string } | null> {
    const signed = await store.latestVaultEntry(db, [CHECKPOINT]);
    const refused = await store.newestRefusal(db, CHECKPOINT, 'log_broken', signed?.seq ?? -1n);
    if (refused === undefined || !this.#authentic(refused)) return null;
    return JSON.parse(refused.metadata) as { failedAtSeq?: number | null; reason?: string };
  }

  async about(): Promise<{ checkpointKeys: Record<string, CheckpointKey>; owners: string[]; rootAdmins: []; log?: '0.15'; uses?: true; batchUses?: true; namedBatches?: true; sealing?: true; credentials?: true; issues?: true; writes?: true }> {
    await this.#settled();
    const { signers, since } = this.#prepared;
    // A key it replaced vouches only for prefixes before its first entry under the current one: none, before it has one.
    const until = Number(since ?? 0n);
    return {
      checkpointKeys: Object.fromEntries(signers.map(({ keyId, publicKey }, i) => [keyId, { publicKey, until: i === 0 ? null : until }])),
      owners: [...this.#config.owners],
      // For an app of 0.5 while it runs beside this vault: there are none, and its lists and checks need the field.
      rootAdmins: [],
      // With it, the vault makes sign-ins through bindings and revokes credentials itself (credentials.ts).
      ...(this.#prepared.log015 === null ? {} : { log: '0.15' as const, sealing: true as const, credentials: true as const, issues: true as const, binds: true as const, sweeps: true as const }),
      // 0.15's uses need its log and the hot path's login: the app opens values through them only then (`use`).
      // A request's several keys in one call too (`useMany`, T167), said so that an app newer than its vault asks for it
      // only of a vault that has it.
      // And a request's several keys by name (`useNamedMany`, T165), which reads them with the caller's standing first.
      ...(this.#prepared.log015 === null || this.#hot === undefined ? {} : { uses: true as const, batchUses: true as const, namedBatches: true as const }),
      // A key write decided on one read (`writeKeys`, T179 PR 3), where this vault serves it.
      ...(this.#serveWrites() ? { writes: true as const } : {}),
      ...(this.#serveAdmits() ? { admits: true as const } : {}),
    };
  }

  /**
   * 0.15's cutover from 0.14 (cutover.ts; plan PR 9; formal/Migration015.tla).
   * Done once: the marker read with no lock first, so that each isolate's
   * start stalls nothing once it is. Without `input`, where 0.14's chain is
   * verified from, for the app to check its own entries from there.
   *
   * With it: 0.14's chain walked on from its newest checkpoint, outside any
   * transaction (VerifyChain); then one transaction, under every member's
   * row, 0.14's head, the issue lock shared and the fence (RowFirst,
   * CutoverHeadLock, CutoverIssueFirst, CutoverFence), the marker read again
   * (Marker), the rest of the chain to the head, what the app checked still
   * the chain's and nothing of the app's since (VouchedHeld), every row read
   * and checked (`planCutover`), the places 0.14 deleted made as 0.15 leaves
   * them, each object's genesis, its own 0.14 entry, `log.cutover`, and the
   * cutover's change naming it. Answers once that change is sealed (R51).
   */
  async cutover(input?: CutoverInput | null): Promise<CutoverOutcome> {
    const log015 = this.#log015();
    const prepared = this.#prepared;
    if (prepared.cutover || (await this.#cutoverSealed())) {
      prepared.cutover = true;
      return { ok: true, done: true };
    }
    if (prepared.since === null && prepared.superseded === null) await this.#settle();
    if (prepared.superseded !== null) return { ok: false, refused: 'refused', why: prepared.superseded };
    const from = await this.#resume(this.#db, 'newest');
    if (!from.ok) return this.#cutoverRefused(`0.14's chain does not verify at entry ${from.failedAtSeq}: ${from.reason}`);
    const mark = { seq: from.at.seq.toString(), hash: from.at.hash.toString('hex') };
    // Over RPC or a socket, no input arrives as null.
    if (input == null) return { ok: true, done: false, from: mark };
    // The app checked its entries from where this walk starts, or another checkpoint came since: it checks again.
    if (input.checked?.from?.seq !== mark.seq || input.checked.from.hash !== mark.hash) return { ok: false, refused: 'moved', why: "0.14's newest checkpoint is not the one the app checked from" };
    // 0.14's chain whole, outside any transaction (VerifyChain): the prefix its newest checkpoint signed, rehashed from the
    // first entry, which must come to the hash it signed (an entry edited, deleted or moved before it does not: review
    // r4), each entry there MAC'd when that checkpoint was signed; then the entries since, by the vault's MACs. Once a
    // cutover: hashes alone, no MAC, no tally.
    const signed = await relink(this.#db, START, from.at.seq, Infinity);
    if (!signed.ok) return this.#cutoverRefused(`0.14's chain does not verify at entry ${signed.failedAtSeq}: ${signed.reason}`);
    if (signed.at.seq !== from.at.seq || !signed.at.hash.equals(from.at.hash)) return this.#cutoverRefused(`0.14's chain up to entry ${from.at.seq} is not the prefix its newest checkpoint signed`);
    const walked = await this.#walkOn(from, Infinity);
    if (!walked.ok) return this.#cutoverRefused(`0.14's chain does not verify at entry ${walked.failedAtSeq}: ${walked.reason}`);
    const reports: NewEntry[] = [];
    let number: bigint;
    try {
      number = await this.#db.transaction((tx) => this.#cutOver(tx, input, walked, reports));
    } catch (error) {
      if (error instanceof VouchMoved || error instanceof Retry) return { ok: false, refused: 'moved', why: error instanceof VouchMoved ? error.message : 'a member was admitted meanwhile' };
      if (error instanceof CutoverRefused) return this.#cutoverRefused(error.message);
      throw error;
    }
    this.#reported(reports);
    // Done once sealed (R51), whichever vault's change it is: one found under the locks too.
    await log015.sealThrough(number);
    prepared.cutover = true;
    return { ok: true, done: true };
  }

  /** The cutover's transaction (`cutover`): its change's number, another vault's if it cut over first. */
  async #cutOver(tx: Transaction, input: CutoverInput, walked: Walked, reports: NewEntry[]): Promise<bigint> {
    const log015 = this.#log015();
    const { logKeys } = this.#prepared;
    await store.boundLockWaits(tx, LOCK_WAIT_MS);
    const principals = (await store.allMembers(tx)).map((row) => row.principal);
    const rows = principals.length === 0 ? new Map<string, Member>() : await store.lockMembers(tx, principals);
    const head = await lockLogHead(tx);
    await holdFence(tx);
    const found = await store.cutoverNumber(tx);
    if (found !== null) return found;
    if ((await store.allMembers(tx)).length !== rows.size) throw new Retry();
    // 0.14's chain, to the head it holds: what the walk read still there, and the rest by the vault's MACs.
    if (!(await carries(tx, headOf(walked.at)))) throw new CutoverRefused(`the log up to entry ${walked.at.seq} changed while the vault walked it`);
    const walk = new Walk(walked.tally, walked.digest);
    const rest = await rehash(tx, logKeys, walked.at, walk, {});
    if (!rest.ok) throw new CutoverRefused(`0.14's chain does not verify at entry ${rest.failedAtSeq}: ${rest.reason}`);
    const unsigned = await this.#checkpointFault(tx, walk.checkpoints);
    if (unsigned !== null) throw new CutoverRefused(`0.14's chain does not verify at entry ${unsigned.failedAtSeq}: ${unsigned.reason}`);
    if (rest.at.seq !== head.nextSeq - 1n || !rest.at.hash.equals(head.headHash)) throw new CutoverRefused("0.14's chain head does not name its last entry");
    // What the app checked by its MACs is the chain's, and it wrote nothing since: what it vouched for stands (VouchedHeld).
    const to = { seq: Number(input.checked.to.seq), hash: input.checked.to.hash };
    if (!Number.isSafeInteger(to.seq) || to.seq < -1 || BigInt(to.seq) > rest.at.seq || !(await carries(tx, to))) throw new VouchMoved("the chain the app checked is not 0.14's now");
    if (await store.appEntriesAfter(tx, BigInt(to.seq))) throw new VouchMoved('the app wrote to 0.14\'s log since it vouched for its rows');

    const at = await this.#now(tx);
    const { edits, readable, seq: policySeq } = await this.#policyAt(tx, reports, at);
    if (!readable) throw new CutoverRefused("0.14's newest policy is not the vault's: its roles and protection are not known");
    const logged = await store.loggedObjects(tx);
    const held = new Map<string, GrantRow[]>();
    for (const grant of await store.grants(tx)) held.set(grant.principal, [...(held.get(grant.principal) ?? []), grant]);
    const seals = await store.memberSeals(tx);
    // Each member's newest access entry, all in one read: a row whose MAC holds and names it, the vault's, is as 0.14's
    // `#integrity` takes it; any other is checked by it, one read each, and reported.
    const newest = await store.newestAccessEntries(tx);
    const members = [];
    for (const member of rows.values()) {
      const grants = held.get(member.principal) ?? [];
      const seal = seals.get(member.principal) ?? null;
      // A member 0.15's log holds already is its log's: not checked as 0.14's again.
      const fresh = seal === null && !logged.has(objectKey(memberRef(member.principal)));
      const entry = newest.get(member.principal);
      const plain = entry !== undefined && entry.seq === member.accessSeq && this.#authentic(entry) && this.#sealed(member, grants);
      members.push({ member, grants, seal, genuine: !fresh || plain || (await this.#integrity(tx, member.principal, member, grants, reports)) === null });
    }
    const secrets = await store.everySecret(tx);
    const references = await this.#referencesMade(tx, secrets);
    const plan = planCutover({
      logged,
      config: await store.configRows(tx),
      members,
      edits,
      policySeq,
      bulk: this.#config.bulkLimit,
      projects: await store.everyProject(tx),
      environments: await store.everyEnvironment(tx),
      secrets,
      references,
      input,
      credentials: await store.credentialsAt(tx, input.credentials.map((columns) => columns.id)),
      bindings: await store.bindingsAt(tx, input.bindings.map((columns) => columns.id)),
      connections: await store.connectionsAt(tx, input.connections.map((columns) => columns.id)),
    });
    // Reported as a change refused on them would be (`#notLogged`), once: a member's by their check (`#integrity`).
    for (const { ref, fault } of plan.skipped) if (ref.kind !== 'principal') this.#report(reports, null, fault === 'tampered' ? 'mac' : 'stale', `log.${ref.kind}:${ref.id}`);

    await store.endReferenceRows(tx, plan.ends, at);
    await store.cutoverPlaces(tx, at, plan.rename, plan.archive);
    // Its own entry last, the head its change names (the anchor): the trigger's issue lock and fence held already.
    const appended = await this.#append(tx, [...reports, {
      actor: VAULT_ACTOR, action: CUTOVER, decision: 'allow',
      metadata: JSON.stringify({ from: { seq: walked.from.at.seq.toString(), hash: walked.from.at.hash.toString('hex') }, sealed: plan.genesis.length + plan.bindings.length, skipped: plan.skipped.length }),
    }]);
    const calls = genesisCalls(log015, plan.genesis, at);
    for (let i = 0; i < calls.length; i += GENESIS_BATCH) {
      const numbers = await store.changeInputs(tx, calls.slice(i, i + GENESIS_BATCH));
      if (numbers.some((n) => n === null)) throw new VouchMoved('an object\'s row moved under the cutover\'s locks');
    }
    for (const call of genesisCalls(log015, plan.bindings, at)) {
      if ((await store.sealBinding(tx, call)) === null) throw new VouchMoved(`the binding ${call.ref.id}'s row moved under the cutover's locks`);
    }
    const anchor = { seq: appended.nextSeq - 1n, hash: appended.headHash };
    return store.logCutover(tx, cutoverRow(log015, at, cutoverPayload(anchor, walked.from.at)));
  }

  /**
   * Each key's newest reference row's `reference.create`, by its number:
   * whether it is the vault's, by its MAC, about that row, holder and
   * source; and whether an authentic `reference.end` ended it.
   */
  async #referencesMade(db: Queryable, secrets: readonly store.SecretRead[]): Promise<Map<string, { authentic: boolean; ended: boolean }>> {
    const rows = secrets.flatMap((secret) => (secret.reference === null ? [] : [{ secret, reference: secret.reference }]));
    const made = await store.entriesAt(db, rows.map(({ reference }) => reference.createdSeq));
    // An entry of these the vault's MAC does not hold is damaged history, read under the cutover's locks: refused, never
    // taken for no end (a reference 0.14 holds ended would be sealed live: review r4) nor for no reference.
    const damaged = (entry: StoredEntry) => {
      throw new CutoverRefused(`0.14's ${entry.action} at entry ${entry.seq} does not carry the vault's MAC: its history is damaged`);
    };
    const ends = await store.referenceEnds(db, rows.map(({ reference }) => reference.createdSeq));
    for (const entry of ends) if (!this.#authentic(entry)) damaged(entry);
    const ended = new Set(ends.map((entry) => entry.relatedSeq!.toString()));
    return new Map(rows.map(({ secret, reference }) => {
      const entry = made.get(reference.createdSeq);
      const created = entry !== undefined && entry.author === 'vault' && entry.action === 'reference.create' && entry.decision === 'allow';
      if (created && !this.#authentic(entry)) damaged(entry);
      const sealed = !created ? null : sealedReference(entry, reference.id);
      // The holder where the vault made it: a row moved around it, its id and reference row kept, would read the source
      // from another place, where 0.14's read through it is refused.
      const authentic = sealed !== null && sealed.holder.secretId === secret.id && sealed.holder.projectId === secret.projectId
        && sealed.holder.environmentId === secret.environmentId && sealed.source.secretId === reference.source;
      return [reference.createdSeq.toString(), { authentic, ended: ended.has(reference.createdSeq.toString()) }];
    }));
  }

  /** A cutover refused, recorded once a process (`log.cutover`, denied), and answered. */
  async #cutoverRefused(why: string): Promise<CutoverOutcome> {
    const reports: NewEntry[] = [];
    const key = `cutover|${why}`;
    if (!this.#prepared.reported.has(key)) {
      const entry: NewEntry = { actor: VAULT_ACTOR, action: CUTOVER, decision: 'deny', code: 'log_broken', metadata: JSON.stringify({ reason: why }) };
      REPORTED.set(entry, key);
      reports.push(entry);
    }
    if (reports.length > 0) await this.#db.transaction((tx) => this.#append(tx, reports));
    this.#reported(reports);
    return { ok: false, refused: 'refused', why };
  }

  /**
   * Under 0.15's log, that it is cut over from 0.14 (`cutover`): nothing of
   * 0.15's is decided, changed or used before, so that the cutover's change
   * precedes every other (AnchorHolds) and nothing decides on rows it has
   * not sealed. The marker read once, with no lock, until it is there.
   */
  async #cutOverYet(): Promise<void> {
    if (!(await this.#cutOverNow())) throw new Error(NOT_CUT_OVER);
  }

  /** Whether the vault may serve 0.15's log: kept by 0.14's alone, or cut over, its change sealed (`#cutoverSealed`). */
  async #cutOverNow(start?: StartReads): Promise<boolean> {
    const prepared = this.#prepared;
    if (prepared.log015 === null || prepared.cutover) return true;
    if (!(await this.#cutoverSealed(start))) return false;
    prepared.cutover = true;
    return true;
  }

  /**
   * Whether the log is cut over, its change sealed: the marker read with no
   * lock, then, found, its seal waited for (R51), as the vault that wrote it
   * waits before it answers. Committed and not sealed yet, as when that vault
   * waits or failed before its seal, it serves nothing until it is. Sealed
   * long ago, as it is but in a deployment's first moments, a pair this
   * vault's key signed past it says so (T169): an isolate's first calls, its
   * uses among them, ask no checkpointer, which may be the one thing that
   * does not answer.
   */
  async #cutoverSealed(start?: StartReads): Promise<boolean> {
    const number = await (start?.cutover ?? store.cutoverNumber(this.#db));
    if (number === null) return false;
    if (!(await this.#signedPast(number, start))) await this.#log015().sealThrough(number);
    return true;
  }

  /**
   * Whether the database's newest checkpoint is a pair this vault's key signed in whose changes tree change `number`
   * is proved, as its seal proves it: a pair covering its number may cover a gap a writer moved the change into
   * (review r1). Anything short of that goes to the seal, which alarms on what it refuses.
   */
  async #signedPast(number: bigint, start?: StartReads): Promise<boolean> {
    const store = logStore(this.#db);
    const newest = await (start?.checkpoint ?? store.newest());
    if (newest === null || newest.upto < number) return false;
    const pair = await openPair(newest.notes, (await this.#verifierKeys()).current.verifiers);
    if (pair === null || pair.upto !== newest.upto) return false;
    const proof = await proveIn(store, number, { pair, notes: newest.notes }, { tree: 'changes' }).catch(() => null);
    return proof !== null;
  }

  /**
   * The app's changes, sealed (`prepareChanges`, plan PR 4b): no lock,
   * nothing written, and one read, each object's newest change with its MAC
   * checked (T190), and for an unarchive what its key's log last sealed
   * (`keptFrom`, T134); but the report of a row that is not the vault's, or a
   * newest change whose MAC does not hold, which refuses them all
   * (`tampered`, `stale`), as a decision of its own would. A row that is
   * not, as the app read it, its object's newest change's is `moved`,
   * reported nowhere: the app reads it again.
   */
  async prepare(input: PrepareInput): Promise<Outcome<Prepared>> {
    const log015 = this.#log015();
    if (typeof input?.actor !== 'string' || input.actor.length === 0 || !Array.isArray(input.changes)) throw new Error('prepare takes an actor and the changes the app will write');
    // Before the cutover, a change of 0.14's rows alone, which logs nothing (`prepareChanges`): what the app key's
    // rotation makes as it signs sessions out, which the app's door finishes before it cuts over (review r3). One that
    // makes an object, or changes one the log holds, waits for the cutover.
    if (input.changes.some((change) => change.before === null || change.before.seal !== null)) await this.#cutOverYet();
    try {
      // Each object's newest change, its MAC checked (T190), in one statement: `app_change` holds the row to that
      // change's seal, which SQL compares and cannot authenticate. An unarchive reads the write its archive ended too.
      const refs = [...new Map(input.changes.map((change) => [objectKey({ kind: change.kind, id: change.id }), { kind: change.kind, id: change.id }])).values()];
      const restored = input.changes.flatMap((change) => (change.kind === 'secret' && change.restores === true ? [{ kind: 'secret' as const, id: change.id }] : []));
      const logged = await store.loggedChanges(this.#db, macsOf(log015), refs, restored);
      for (const ref of refs) if (logged.get(objectKey(ref))?.[0]?.holds === false) throw new NotLogged(ref, 'tampered');
      const kept = new Map(restored.map((ref) => [objectKey(ref), keptFrom(log015.seals, ref, logged.get(objectKey(ref)) ?? [])]));
      const changes = prepareChanges(log015, Date.now() + this.#prepared.options.clockOffset(), input.actor, input.changes, kept);
      // Each object's calls go on from its newest change: the change whose MAC holds above (T190, review Fable). Its
      // first call from that change's seal, each after from the seal the one before leaves. `app_change` compares bytes
      // alone, so a row put back with an old seal, read by the app, would pass it once the newest change's seal was
      // forged to match after this read; held to the checked seal here, a forgery needs an honest change of the object
      // to land between this read and that statement (sealed-inputs.md). The calls, not the app's entries: two entries
      // of one object, the first a no-op on the row as the log holds it, the second from a row put back, make one call,
      // from the second's (review r3). A row whose seal is not the vault's was refused above (`tampered`, reported); a
      // mismatch here is also what a write that came between makes, honestly, so nothing is reported, and the app
      // reads again (`moved`), as it does when `app_change` finds a row moved. An object with no call writes nothing.
      const left = new Map<string, Buffer | null>();
      for (const call of changes) {
        // A row read unsealed (0.14's), or a key its log never held, logs nothing: `app_change` holds it to there being
        // no change of its object at all, which no edit of a seal column fakes.
        if (call.requestId === null) continue;
        const from = call.sealFrom === null ? null : Buffer.from(call.sealFrom, 'base64');
        const same = (seal: Buffer | null) => (seal === null ? from === null : from?.equals(seal) ?? false);
        // A first call from no row (made, or restored), or of an object the log has no change of, is `app_change`'s to
        // refuse (stale). A newest change that ended the object (its seal null) counts: its seal column could be made
        // the read row's too.
        const newest = logged.get(call.object)?.[0];
        const held = left.has(call.object) ? same(left.get(call.object)!) : from === null || newest === undefined || same(newest.seal);
        if (!held) {
          return { ok: false, refusal: refusal('moved', `the ${call.kind} ${call.id} is not, as the app read it, its newest change's: read it again`) };
        }
        left.set(call.object, call.seal === null ? null : Buffer.from(call.seal, 'base64'));
      }
      return { ok: true, changes };
    } catch (error) {
      if (!(error instanceof NotLogged)) throw error;
      const reports: NewEntry[] = [];
      const refused = this.#notLogged(reports, error);
      await this.#record(reports);
      return { ok: false, refusal: refused.refusal };
    }
  }

  /**
   * A key write decided on one read (write.ts; T179 PR 3; docs/design/two-trips.md, "A key write"; formal/Writing.tla):
   * `write_request`, one statement, reads what the decision weighs and numbers the request; the decision takes that
   * read alone (`decideWrite`); then each data key is wrapped and each key's change prepared from its object as read,
   * the request and the read's digest in its payload: what records the write, in 0.15's log alone (0.16.0 appends no
   * 0.14 `key.wrap` entry, which needed a transaction of two round trips, its head read before its MAC). The app's
   * transaction holds the same read before it commits (`hold_inputs`). Anything this path does not serve, a refusal
   * among them, answers `served: false`, nothing written but the request's number: the app writes as before, which
   * decides, answers and logs it.
   */
  async writeKeys(input: WriteKeysInput): Promise<WriteKeysOutcome> {
    const unserved = (why: string): WriteKeysOutcome => ({ served: false, why });
    const log015 = this.#prepared.log015;
    if (log015 === null || !this.#serveWrites()) return unserved('vault');
    validateWriteKeys(input);
    if (!(await this.#cutOverNow())) return unserved('vault');
    if ((await this.#kekMismatch(Date.now() + CALL_DEADLINE_MS)) !== null) return unserved('kek');
    const at = Date.now() + this.#prepared.options.clockOffset();
    const read = await callWrite(this.#db, {
      at, tokenHash: Buffer.from(input.tokenHash, 'base64'), project: input.project, environment: input.environment, keys: input.keys.map((key) => key.name),
    });
    if (read.state === 'ahead') return unserved('clock');
    const inputs = parseInputs(read.inputs);
    const decided = decideWrite({ seals: log015.seals, macs: log015.macs, members: (row, grants) => this.#sealed(row, grants) }, inputs, { at, accepts: input.accepts, kinds: WRITE_KINDS, asked: input.keys });
    if (typeof decided === 'string') return unserved(decided);
    // Refused on the read (PR 6): the record prepared, for `recordRefusal` once the app has checked the caller's rows.
    if ('refused' in decided) {
      const { credential, environment } = decided;
      return {
        served: false, why: 'refused', refusal: refusal(decided.refused, decided.message), at, app: read.app, standing: writeStanding(decided, at),
        ticket: writeRefusal(log015.mac, at, {
          code: decided.refused, actor: credential.principal, credential: credential.id, identity: inputs.credential.identityId, read: read.digest,
          operationId: input.operationId ?? null, requestId: input.requestId ?? null, number: read.number,
          projectId: environment.projectId, environmentId: environment.id, path: `${input.project}/${input.environment}`, keys: input.keys.map((key) => key.name),
        }),
      };
    }
    const { credential, environment } = decided;
    const principal = credential.principal;
    const secrets: SecretRef[] = decided.keys.map((key) => ({
      projectId: environment.projectId, environmentId: environment.id, secretId: key.id, version: key.before.version + 1,
      path: `${input.project}/${input.environment}/${key.name}`, ...(key.sensitive ? { sensitive: true } : {}),
    }));
    // Each data key wrapped as its version's context binds it: its ids, and whether it is sensitive (no personal config here).
    const operation = { deadline: Date.now() + CALL_DEADLINE_MS, signal: new AbortController().signal };
    const wrapped = await Promise.all(secrets.map(async (secret, i) => {
      const dek = Buffer.from(input.keys[i]!.key, 'base64');
      try {
        return serialisable(await this.#config.keks.wrap(dek, context(secret), operation));
      } finally {
        dek.fill(0);
      }
    }));
    // Each key's change, from its object as read (none for a key the write makes) to its new version.
    const changes = prepareChanges(log015, at, principal, decided.keys.map((key, i): ObjectChange => ({
      kind: 'secret', id: key.id,
      before: key.created ? null : { columns: secretColumnsOf(key.before), seal: key.before.object.seal!.toString('base64') },
      after: {
        id: key.id, projectId: environment.projectId, environmentId: environment.id, source: null, reference: null,
        version: {
          id: input.keys[i]!.versionId, sensitive: key.sensitive, plaintext: null,
          kekProvider: wrapped[i]!.kekProvider, kekId: wrapped[i]!.kekId, kekVersion: wrapped[i]!.kekVersion, wrappedDek: wrapped[i]!.bytes,
        },
      },
    })), new Map(), {
      number: read.number, credential: credential.id, identity: inputs.credential.identityId, inputs: read.digest,
      operationId: input.operationId ?? null, requestId: input.requestId ?? null,
    });
    return {
      served: true, at, number: read.number.toString(), app: read.app, standing: writeStanding(decided, at), digest: read.digest,
      keys: decided.keys.map((key, i) => ({ name: key.name, id: key.id, created: key.created, version: key.before.version + 1, sensitive: key.sensitive, wrapped: wrapped[i]! })),
      changes,
    };
  }

  /**
   * A member's first add, decided on one read (T179 PR 5; admit.ts): `admit_read`, one statement, no lock; then the
   * decision on that read alone. Served, the add prepared under the vault's MAC (`ticket`), for `admitWrite` once the
   * app has checked the caller's rows the read answered (`app`). Anything else `served: false`, the app adding as before.
   */
  async admitRead(input: AdmitReadInput): Promise<AdmitReadOutcome> {
    const unserved = (why: string): AdmitReadOutcome => ({ served: false, why });
    const log015 = this.#prepared.log015;
    if (log015 === null || !this.#serveAdmits()) return unserved('vault');
    validateAdmitRead(input);
    if ((await this.#settled()) !== null || !(await this.#cutOverNow())) return unserved('vault');
    const at = Date.now() + this.#prepared.options.clockOffset();
    const asked: AdmitAsked = { principal: input.principal, ...(input.role === undefined ? {} : { role: input.role }), ...(input.scope === undefined ? {} : { scope: input.scope }) };
    const slugs = scopeSlugs(asked);
    const read = await callAdmit(this.#db, { at, tokenHash: Buffer.from(input.tokenHash, 'base64'), principal: input.principal, scope: slugs });
    if (read.state === 'ahead') return unserved('clock');
    const inputs = parseAdmitInputs(read.inputs, input.principal);
    const decided = decideAdmit({ seals: log015.seals, macs: log015.macs, members: (row, grants) => this.#sealed(row, grants) }, inputs, { at, accepts: input.accepts, kinds: ADMIT_KINDS, asked, listed: this.#listed(input.principal) });
    if (typeof decided === 'string') return unserved(decided);
    // Refused on the read (PR 6), as a key write's.
    if ('refused' in decided) {
      const { credential } = decided;
      return {
        served: false, why: 'refused', refusal: refusal(decided.refused, decided.message), at, app: read.app, standing: admitStanding(decided, at),
        ticket: addRefusal(log015.mac, at, {
          code: decided.refused, actor: credential.principal, credential: credential.id, identity: inputs.credential.identityId, read: read.digest,
          operationId: input.operationId ?? null, requestId: input.requestId ?? null, principal: input.principal, role: input.role, scope: input.scope,
        }),
      };
    }
    const ticket: AdmitTicket = {
      v: 1, until: at + TICKET_MS, at, digest: read.digest, tokenHash: input.tokenHash, principal: input.principal, scopeSlugs: slugs,
      // Who the add is by, by ids, as the checked read resolved them (ActorFromRead): the write resolves no token.
      actor: decided.credential.principal, credential: decided.credential.id, identity: inputs.credential.identityId, personal: inputs.credential.kind === 'personal',
      role: decided.role, scope: decided.scope, requestId: input.requestId ?? null, operationId: input.operationId ?? null,
    };
    return {
      served: true, at, app: read.app, standing: admitStanding(decided, at), ticket: sealTicket(log015.mac, ticket),
      admitted: { created: true, role: decided.role, scope: decided.scope, generation: 0 },
      projects: inputs.projects.flatMap(({ slug, id }) => (id === null ? [] : [{ id, slug }])),
    };
  }

  /**
   * The add `admitRead` prepared, written in one transaction of one round trip (T179; docs/design/two-trips.md, "A member
   * add"), every statement left to `later` and sent with the COMMIT, in this order: the bound on lock waits, the members'
   * rows (`laterLockMembers`) and 0.14's head, a lock alone (MembersFirst, formal/WriteLocks.tla's AddLocks); the hold
   * (`admit_hold`: the issue lock, the fence, the read again, as decided or `coffre_moved`); the member's row, sealed as
   * `#seal` seals one; and its change (`change_input_strict`, the read's digest and the request's ids in its payload),
   * which records the add, in 0.15's log alone (0.16.0 appends no 0.14 `member.add` entry, whose MAC needed the head
   * read first). Then the seal wait (R51). A hold that fails writes nothing: `moved`, and the app reads again. First,
   * as `admitRead`, this isolate's keys settled and its config's Owners weighed: else `unserved`, today's path.
   */
  async admitWrite(input: AdmitWriteInput): Promise<AdmitWriteOutcome> {
    const log015 = this.#prepared.log015;
    if (log015 === null || !this.#serveAdmits()) throw new Error('this vault writes no prepared add: it does not serve admitRead');
    const opened = openTicket(log015.macs, input?.ticket, Date.now() + this.#prepared.options.clockOffset());
    if (opened === 'expired') return { written: false, why: 'expired' };
    if (opened === null) throw new Error("an add's ticket is the vault's own, as admitRead answered it: this one is not");
    if (!isConfirmation(input.confirmed)) throw new Error('confirmed must name a passkey by its lowercase UUID and when it was touched, ISO 8601');
    const ticket = opened;
    const { principal, actor } = ticket;
    // This isolate's own keys and config, which may not be the reading one's (review r1 of #474): settled as
    // `admitRead` settles them, and an Owner its config names left to today's path, which decides on their row as
    // `admitRead` would have (`listed`). A rollout between the two calls changes neither digest nor ticket.
    if ((await this.#settled()) !== null || this.#listed(principal)) return { written: false, why: 'unserved' };
    const { role, scope } = asStored(ticket.role, ticket.scope);
    let numbers: ChangeNumbers;
    try {
      // Its lock waits retried as a change's are (`retryingLocks`): it commits nothing before its COMMIT, and its ticket
      // holds for `TICKET_MS` (Fable's review of #538).
      numbers = await retryingLocks(() => this.#db.transaction(async (tx) => {
        // One Sync, nothing awaited: the bound, the members' rows, then the head, in that order (as `#decideOnce` takes
        // them), each a lock; then the hold, which every write after it rests on.
        void store.boundLockWaits(tx, LOCK_WAIT_MS, undefined, { final: true });
        store.laterLockMembers(tx, [actor, principal]);
        laterHead(tx);
        holdAdmit(tx, { tokenHash: Buffer.from(ticket.tokenHash, 'base64'), principal, scope: ticket.scopeSlugs, digest: Buffer.from(ticket.digest, 'hex') });
        const at = Date.now() + this.#prepared.options.clockOffset();
        // No 0.14 access entry accounts for the row: its `accessSeq` names none (0, as a row before its first `#seal`),
        // and its change says nothing of one (no `old`). Under 0.15's log nothing weighs the column against an entry
        // (`#onLog` weighs the member's newest access entry against its newest change, and a first add has neither).
        const row = { principal, status: 'active' as const, role, scope, generation: 0, createdAt: at, createdBy: actor, statusChangedAt: at, statusChangedBy: actor, accessSeq: 0n };
        await store.insertMember(tx, { ...row, mac: memberMac(this.#prepared.rowKey, row, []) }, { final: true });
        const after = principalObject({ principal, status: 'active', generation: 0, role, scope }, []);
        return store.laterInputs(tx, [admitChange(log015, {
          at, actor, principal, after, op: { op: 'member.add', role, scope },
          credential: ticket.credential, identity: ticket.identity, inputs: ticket.digest, operationId: ticket.operationId, requestId: ticket.requestId,
          confirmed: input.confirmed ?? null,
        })]);
      }), Date.now() + CALL_DEADLINE_MS);
    } catch (error) {
      // The read moved under it, or another add made the row first: nothing written, and the app reads again.
      if (isMovedChange(error) || isUniqueViolation(error)) return { written: false, why: 'moved' };
      throw error;
    }
    const newest = await newestCommitted(this.#db, numbers);
    if (newest === null) throw new Error("an add's change committed with no number");
    await log015.sealThrough(newest);
    return { written: true, number: newest.toString(), admitted: { created: true, role, scope, generation: 0 } };
  }

  /**
   * The record of a refusal `writeKeys` or `admitRead` decided (PR 6; refusal.ts), once the app has checked the caller's
   * rows (RefusalAfterAuth): one statement (`log_refusal`), then the seal wait (R51, kept for refusals: D165). The
   * record is the vault's, MAC'd here as it is written, its time this isolate's clock now.
   */
  async recordRefusal(input: RecordRefusalInput): Promise<RecordRefusalOutcome> {
    const log015 = this.#prepared.log015;
    if (log015 === null || !(this.#serveWrites() || this.#serveAdmits())) throw new Error('this vault records no refusal: it serves neither writeKeys nor admitRead');
    const now = Date.now() + this.#prepared.options.clockOffset();
    const opened = openRefusal(log015.macs, input?.ticket, now);
    if (opened === 'expired') return { recorded: false, why: 'expired' };
    if (opened === null) throw new Error("a refusal's ticket is the vault's own, as writeKeys or admitRead answered it: this one is not");
    const number = await callRefusal(this.#db, refusalRow(log015.mac, opened, now));
    await log015.sealThrough(number);
    return { recorded: true, number: number.toString() };
  }

  /** Whether this vault serves `admitRead` and `admitWrite`: 0.15's log, on Postgres. */
  #serveAdmits(): boolean {
    return this.#prepared.log015 !== null && engineOf(this.#db) === 'postgres';
  }

  /** Whether this vault serves `writeKeys`: 0.15's log, on Postgres, its key-encryption key in memory (a key service's intent and outcome are records of their own, PR 7). */
  #serveWrites(): boolean {
    return this.#prepared.log015 !== null && engineOf(this.#db) === 'postgres' && !this.#remote(this.#config.keks.primary);
  }

  /**
   * A sign-in through a trust binding, made by the vault (credentials.ts, T149), then the seal wait (R51). `sign_in`
   * holds the account's and the binding's rows to their objects' newest seals, which SQL cannot authenticate, so the
   * vault checks those changes' MACs first (T190), else an account removed or a binding ended, put back with its newest
   * change's seal written to match, signs a run in. The changes the app read beside the binding (T192), when they
   * hold: one statement, `sign_in`'s, which holds each newest change to the one checked, whole (ChangePinsChecked,
   * ChangePinsWhole), so that a seal column edited in place once the check is done, or an old change handed back under
   * the newest's number, is `moved`. Otherwise, and on
   * `moved`, the vault reads them itself, one statement more. Three tries in all, as a key write's (two-trips.md,
   * "Retries"), then `busy`, asked again shortly: a churn fails fast (R44).
   */
  async signIn(input: SignInInput): Promise<SignInOutcome> {
    const log015 = this.#log015();
    await this.#cutOverYet();
    const at = Date.now() + this.#prepared.options.clockOffset();
    // The proof, verified here on the sealed binding (D148): what the credential is held to comes of the token, not the app.
    const proven = await this.#proven(log015, input, at);
    if ('refused' in proven) return proven;
    const binding: Ref = { kind: 'binding', id: proven.binding.columns.id };
    // The seal `#proven` checked over the binding's columns, which must be its newest change's (review r3): else an
    // ended binding put back, its old seal valid, would pass, its end's seal column written to match.
    const bindingSeal = Buffer.from(proven.binding.seal!, 'base64');
    let pins = givenPins(log015.macs, input, bindingSeal);
    for (let tries = 1; ; tries += 1) {
      if (pins === null) {
        let found: Map<string, CheckedChange[]>;
        try {
          found = await changesHold(log015, this.#db, [{ kind: 'principal', id: proven.principal }, binding]);
        } catch (error) {
          if (!(error instanceof NotLogged)) throw error;
          const reports: NewEntry[] = [];
          this.#notLogged(reports, error);
          await this.#record(reports);
          return { ok: false, refused: 'unbound' };
        }
        // Nothing reported for a binding's seal other than its newest change's: an end that came between makes it so.
        pins = readPins(found, proven, bindingSeal);
        if (pins === null) return { ok: false, refused: 'unbound' };
      }
      const answer = await signIn(this.#db, log015, at, proven, pins);
      if (answer.state === 'moved') {
        if (tries === SIGN_IN_TRIES) return { ok: false, refused: 'busy' };
        pins = null;
        continue;
      }
      if (answer.number == null) return { ok: false, refused: answer.state as Exclude<SignInRefusal, 'proof'> };
      const sealed = await log015.sealThrough(BigInt(answer.number));
      return { ok: true, number: answer.number, witnessed: sealed.witnessed ?? null };
    }
  }

  /**
   * A credential revoked by the vault (credentials.ts, T149): one statement,
   * then the seal wait. A row whose seal is not the vault's, or not its
   * object's newest change's, is reported, as `prepare` reports one; one
   * whose policy moved since its revoke was weighed is refused, nothing
   * reported.
   *
   * Unlike `prepare`, `signIn` and an issue, it does not check its newest
   * change's MAC first (T190), on purpose: a revoke only ends, so the most a
   * writer who forged that change's seal gets is the credential revoked from
   * the row it put back, which is revoked all the same; refusing it would
   * let a forged log keep a credential live. `changeBindings`' ends and the
   * credentials they sweep go ahead so too.
   */
  async revokeCredential(input: RevokeCredentialInput): Promise<RevokeCredentialOutcome> {
    const log015 = this.#log015();
    await this.#cutOverYet();
    const notLogged = async (error: NotLogged) => {
      const reports: NewEntry[] = [];
      this.#notLogged(reports, error);
      await this.#record(reports);
      return { ok: false as const, refused: error.fault };
    };
    let answer: Answer;
    try {
      answer = await revokeCredential(this.#db, log015, Date.now() + this.#prepared.options.clockOffset(), input);
    } catch (error) {
      if (error instanceof NotLogged) return notLogged(error);
      throw error;
    }
    if (answer.state === 'stale') return notLogged(new NotLogged({ kind: 'credential', id: input.before.columns.id }, 'stale'));
    if (answer.state === 'moved' || answer.state === 'busy' || answer.state === 'policy') return { ok: false, refused: answer.state };
    if (answer.number == null) throw new Error('revoke_credential answered neither a change nor why it made none');
    const sealed = await log015.sealThrough(BigInt(answer.number));
    return { ok: true, number: answer.number, witnessed: sealed.witnessed ?? null };
  }

  /**
   * What of a sign-in the vault checks itself (D148, PR 3b; formal/Lifecycle.tla's
   * VaultVerifiesToken, AudienceSealed, Fetched), asking no one: only on a
   * binding whose seal is its own (BindingSealed: the issuer, keys, audience
   * and claims it trusts are the ones a manager made it with); a workload's
   * DPoP proof, whose key's thumbprint names the session's key, the
   * credential's `jkt` and, where its platform lets the caller choose the
   * token's audience, that audience, never the app's; and, when the sealed
   * binding carries its issuer's keys, the token, on those keys
   * (`verifyRunToken`), the sign-in's spend, times and run then taken from
   * it. A binding of keys its issuer publishes, which the vault does not
   * fetch, and a proof that is no ID token (an AWS signed request) take the
   * app's word for the token, as their binding's seal says.
   */
  async #proven(log015: NonNullable<PreparedVault['log015']>, input: SignInInput, at: number): Promise<SignInInput | { ok: false; refused: 'unsealed' } | { ok: false; refused: 'proof'; reason: string; message: string; kid: string | null }> {
    const binding = checkBinding(input?.binding?.columns);
    const seal = typeof input.binding.seal === 'string' ? Buffer.from(input.binding.seal, 'base64') : null;
    if (seal === null || binding.revoked || binding.principal !== input.principal || !sealedObject(log015.seals, { kind: 'binding', id: binding.id }, bindingObject(binding), seal)) {
      return { ok: false, refused: 'unsealed' };
    }
    const refuse = (reason: string, message: string, kid: string | null = null) => ({ ok: false as const, refused: 'proof' as const, reason, message, kid });
    const { idToken, dpop } = input;
    if ((idToken !== null && (typeof idToken?.token !== 'string' || typeof idToken.jwks !== 'string')) || (dpop !== null && typeof dpop !== 'string')) {
      throw new Error('a sign-in names the run\'s ID token and its binding\'s uploaded keys, or neither, and a DPoP proof or none');
    }
    const workload = input.credential.kind === 'workload';
    // A workload's key: the one its DPoP proof is signed by, for this instance's sign-in, by the binding's own origin.
    let jkt: string | null = null;
    if (workload) {
      if (dpop === null) return refuse('dpop', 'a DPoP header, a proof signed by the key the session will be bound to, comes with the sign-in');
      const proof = await verifyProof(dpop, { method: 'POST', url: `${new URL(binding.origin).origin}${WORKLOAD_SIGN_IN_PATH}`, skewSeconds: EXCHANGE_SKEW_SECONDS, now: at });
      if (!proof.ok) return refuse('dpop', `the DPoP proof does not hold: ${proof.message}`);
      jkt = proof.jkt;
      if (input.credential.jkt !== jkt) return refuse('dpop', 'the session is bound to the key its DPoP proof is signed by, no other');
    } else if (dpop !== null) {
      return refuse('malformed', 'a CI run\'s sign-in takes no DPoP proof');
    }
    // The token the vault verifies itself only on keys its binding's seal digests: it fetches none (Lifecycle.tla's Fetched).
    if (!binding.jwksUri.startsWith(UPLOADED_KEYS)) {
      if (idToken !== null) return refuse('malformed', 'a binding of keys its issuer publishes takes the app\'s word for its token, which the vault does not verify');
      return input;
    }
    if (idToken === null) return refuse('malformed', 'a sign-in through a binding of uploaded keys comes with its token, for the vault to verify');
    let proven: RunProof;
    try {
      const run = { profile: binding.profile as WorkloadProfile, issuer: binding.issuer, origin: binding.origin, jwksUri: binding.jwksUri, jwks: idToken.jwks, claims: binding.claims, policy: binding.policy };
      proven = await verifyRunToken(idToken.token, run, { now: new Date(at), workload: jkt === null ? null : { jkt } });
    } catch (error) {
      if (error instanceof RunProofRefused) return refuse(error.reason, error.message, error.kid);
      throw error;
    }
    if (workload && proven.notAfter !== null && input.credential.notAfter !== null && input.credential.notAfter > proven.notAfter) {
      return refuse('expired', 'the session ends no later than the token it was signed in with');
    }
    return {
      ...input,
      spent: proven.spent === null ? null : proven.spent.toString('base64'),
      validUntil: proven.validUntil,
      record: { ...input.record, issuer: binding.issuer, run: proven.run },
    };
  }

  /**
   * A token issued by the vault (credentials.ts, T149 PR 2; formal/Lifecycle.tla's
   * IssueRead, IssueRows): what it is weighed on read, the issuer and the
   * account in one snapshot and the credential the request came in on
   * beside it, each row checked as `access` checks it; the issue weighed
   * with the app's own rules on those reads (`weighIssue`); then one
   * statement that holds the rows as read, and the seal wait. Nothing is
   * held between the read and the statement. A row that moved in between
   * (IssuerCAS) has it read and weighed again, as the model's IssueCheck
   * does, up to three times; then `moved`, and the app asks again.
   */
  async issueToken(input: IssueTokenInput): Promise<IssueTokenOutcome> {
    const log015 = this.#log015();
    await this.#settled();
    await this.#cutOverYet();
    const scope = checkIssue(input);
    for (let tries = 0; ; tries += 1) {
      const outcome = await this.#issueOnce(log015, input, scope);
      if (outcome.ok || outcome.refused !== 'moved' || tries === 2) return outcome;
    }
  }

  async #issueOnce(log015: NonNullable<PreparedVault['log015']>, input: IssueTokenInput, scope: CredentialScope): Promise<IssueTokenOutcome> {
    const read = await this.#issuerRead(log015, { ...input, scope, service: input.credential.kind === 'service' });
    if ('refused' in read) return read;
    const why = weighIssue(input, scope, read.holder, read.places, read.via?.columns ?? null, read.issue.at, read.service, this.#config.deployment.services.tokenMaxDays);
    if (why !== null) {
      await this.#record(read.reports);
      return { ok: false, refused: 'refused', why };
    }
    await this.#record(read.reports);
    const answer = await issueToken(this.#db, issueCall(log015, input, read.issue));
    if (answer.number == null) return { ok: false, refused: answer.state === 'expired' ? 'refused' : answer.state as IssueTokenRefusal, ...(answer.state === 'expired' ? { why: 'its end is past' } : {}) };
    const sealedAt = await log015.sealThrough(BigInt(answer.number));
    return { ok: true, number: answer.number, witnessed: sealedAt.witnessed ?? null };
  }

  /**
   * What a grant to `principal` by `actor` is weighed on, read and checked
   * as `access` checks each row (a token's issue, PR 2; a binding's, PR 3a):
   * the members, their grants, the policy, a service's setting and the
   * places in one snapshot, the credential the request came in on beside it;
   * then the issuer's standing through that credential, the account's, and
   * the scope's places. A refusal records what the reads reported; else the
   * caller records them before it writes.
   */
  async #issuerRead(
    log015: NonNullable<PreparedVault['log015']>,
    input: Pick<IssueTokenInput, 'actor' | 'via' | 'principal' | 'generation' | 'actorAccess' | 'policy'> & { scope: CredentialScope; service: boolean },
  ): Promise<{ ok: false; refused: IssueTokenRefusal; why?: string } | {
    issue: IssueRead; holder: Holdings; places: (Place | null)[]; via: Awaited<ReturnType<typeof store.issuingCredential>>;
    service: { setting: ServiceSetting | null; account: ServiceAccount } | null; reports: NewEntry[];
  }> {
    const { actor, principal, scope } = input;
    const environmentIds = [...new Set([
      ...scope.flatMap((grant) => (grant.environmentId == null ? [] : [grant.environmentId])),
      ...input.policy.protected.map(({ environmentId }) => environmentId),
    ])];
    const reports: NewEntry[] = [];
    // The members, their grants, the policy, the setting and the places in one statement; the credential beside it.
    const [reads, via] = await Promise.all([
      snapshot(this.#db, { principals: [...new Set([actor, principal])], members: true, settings: input.service, environments: environmentIds, seals: this.#checksSeals() }),
      input.via === null ? Promise.resolve(null) : store.issuingCredential(this.#db, input.via, macsOf(log015)),
    ]);
    // The settings from the snapshot's newest entry; the pages before it read only when it fails its check.
    const settings = input.service ? await this.#settingsAt(this.#db, reports, reads) : null;
    const at = this.#at(reads);
    const refuse = async (refused: IssueTokenRefusal, why?: string) => {
      await this.#record(reports);
      return { ok: false as const, refused, ...(why === undefined ? {} : { why }) };
    };
    // Each environment read, as 0.15's log holds its row (T159): a protected one that is not stays protected, its slug
    // unknown, as `access` answers it (`#livePolicy`); one the scope names refuses the issue; a member's grant on one
    // holds nothing (`#standing`), and the account's refuses whoever manages it (`#account`).
    const faulty = new Set([...reads.environments].flatMap(([id, row]) => (this.#placeFault(id, row, reports) === null ? [] : [id])));
    // The policy the app weighed the scope on, as `policyStill` holds a write to it: one moved since says so, first.
    const newestPolicy = reads.newestPolicy === null ? null : String(reads.newestPolicy.seq);
    const renamed = input.policy.protected.some(({ environmentId, slug }) => {
      const environment = reads.environments.get(environmentId);
      return (environment === undefined || faulty.has(environmentId) || environment.deleted ? null : environment.slug) !== slug;
    });
    if (newestPolicy !== input.policy.seq || renamed) return refuse('policy');
    const actorRow = reads.members.get(actor);
    const acting = await this.#standing(this.#db, actor, actorRow, at, reports, reads);
    if (acting.status !== 'active' || actorRow === undefined) return refuse('ended');
    if (input.actorAccess !== null && actorRow.accessSeq.toString() !== input.actorAccess) return refuse('access');
    // The credential the request came in on: the log's (its seal the vault's, and its object's newest change's), live, its issuer's.
    let viaScope: CredentialScope | null = null;
    if (input.via !== null) {
      if (via === null) return refuse('ended');
      // One 0.14 made, which the log never held, has nothing the vault can authenticate: the app issues on it as before.
      if (via.seal === null && via.newest === null) return refuse('unlogged');
      // Its newest change's MAC first (T190): `issue_token` and `change_bindings` hold the row to that change's seal
      // in SQL, which cannot authenticate it, so a revoked credential put back, the seal written to match, issues.
      if (via.newest !== null && !via.newest.holds) {
        this.#notLogged(reports, new NotLogged({ kind: 'credential', id: input.via }, 'tampered'));
        return refuse('ended');
      }
      const object = credentialObject(via.columns);
      const logged = via.seal !== null && via.newest?.seal != null && via.newest.seal.equals(via.seal) && sealedObject(log015.seals, { kind: 'credential', id: input.via }, object, via.seal);
      if (!logged || via.columns.principal !== actor || via.columns.revoked || (via.columns.expiresAt ?? Infinity) <= at || via.columns.generation !== actorRow.generation) {
        return refuse('ended');
      }
      viaScope = object.scope;
    }
    const caller = actor.startsWith('user:') ? 'person' as const : via?.columns.kind === 'workload' ? 'workload' as const : 'bearer' as const;
    const holder = through(acting, { credentialScope: viaScope, caller }).live;
    const principalRow = reads.members.get(principal);
    const subject = principal === actor ? acting : await this.#standing(this.#db, principal, principalRow, at, reports, reads);
    if (subject.status !== 'active' || principalRow === undefined || principalRow.generation !== input.generation) {
      // A service account whose row the log does not hold is no gone account: say which, as a grant to it would.
      if (principal !== actor && subject.status === 'tampered') return refuse('refused', this.#tamperedSubject());
      return refuse(principal === actor ? 'ended' : 'gone');
    }
    if (scope.some((grant) => grant.environmentId != null && faulty.has(grant.environmentId))) return refuse('refused', TAMPERED_PLACE);
    // Each place by its environment's slug, which scopes match: one deleted, or of another project, is no place. The
    // protected ones' slugs are held to the policy under the issue lock (`issue_token`), but those whose rows are not as
    // the log holds them, which it weighed with none: no slug moves that.
    const places = scope.map((grant): Place | null => {
      if (grant.environmentId == null) return { projectId: grant.projectId! };
      const environment = reads.environments.get(grant.environmentId);
      return environment === undefined || environment.deleted || environment.projectId !== grant.projectId
        ? null
        : { projectId: grant.projectId!, environmentId: grant.environmentId, environmentSlug: environment.slug };
    });
    let service: { setting: ServiceSetting | null; account: ServiceAccount } | null = null;
    try {
      if (settings !== null) service = { setting: settings.serviceAccounts, account: await this.#account(this.#db, subject, principalRow, reads, reports) };
    } catch (error) {
      if (error instanceof Refused) return refuse('refused', error.refusal.message);
      throw error;
    }
    return {
      holder, places, via, service, reports,
      issue: {
        at,
        actor: { generation: actorRow.generation, accessSeq: actorRow.accessSeq },
        principal: { generation: principalRow.generation, accessSeq: principalRow.accessSeq },
        via: via === null ? null : { columns: via.columns, seal: via.seal },
        // The protected environments' slugs, and the scope's as weighed: none moves before the number (Fable on PR 2).
        slugs: weighed([
          ...input.policy.protected.filter(({ environmentId }) => !faulty.has(environmentId)),
          ...places.flatMap((place) => (place?.environmentId == null ? [] : [{ environmentId: place.environmentId, slug: place.environmentSlug ?? null }])),
          // The places of the account's grants, by whose slugs `#account` weighed who manages it (review r2).
          ...(service === null ? [] : subject.live.grants.flatMap((grant) => {
            const row = grant.environmentId === null ? undefined : reads.environments.get(grant.environmentId);
            return row === undefined ? [] : [{ environmentId: grant.environmentId!, slug: row.deleted ? null : row.slug }];
          })),
        ]),
      },
    };
  }


  /**
   * A service's bindings changed by the vault (credentials.ts, T149 PR 3a;
   * formal/Lifecycle.tla's bind, as an issue, and unbind): a binding made is
   * weighed as a service token's issue is, on the same reads (`#issuerRead`,
   * `weighService`), and those it ends, with every credential they issued,
   * must be the log's (their seals the vault's). One statement, which holds
   * all of it as read (`change_bindings`), then the seal wait. A row that
   * moved meanwhile answers `moved`: the app reads again, as the rows it
   * ends are its reads.
   */
  async changeBindings(input: ChangeBindingsInput): Promise<ChangeBindingsOutcome> {
    const log015 = this.#log015();
    await this.#settled();
    await this.#cutOverYet();
    checkChangeBindings(input);
    const { actor, make } = input;
    let read: IssueRead | null = null;
    let reports: NewEntry[] = [];
    if (make !== null) {
      const scope = readScope(make.scope);
      if (scope === null || scope.length === 0) throw new Error('a binding made reaches what its scope names, at least one place');
      const weighed = await this.#issuerRead(log015, {
        actor, via: input.via, principal: make.principal, generation: make.generation, actorAccess: input.actorAccess, policy: input.policy, scope, service: true,
      });
      if ('refused' in weighed) return weighed;
      const why = make.createdBy !== actor.slice(actor.indexOf(':') + 1) ? 'a binding names who made it, its maker'
        : weighed.places.some((place) => place === null) ? 'a place the binding names is no longer there'
        : weighService(actor, make.principal, scope, weighed.holder, weighed.places as Place[], weighed.service);
      if (why !== null) {
        await this.#record(weighed.reports);
        return { ok: false, refused: 'refused', why };
      }
      read = weighed.issue;
      reports = weighed.reports;
    }
    const call = bindingsCall(log015, input, read?.at ?? Date.now() + this.#prepared.options.clockOffset(), read);
    await this.#record(reports);
    if ('refused' in call) return { ok: false, refused: call.refused };
    const answer = await changeBindings(this.#db, call);
    if (answer.number == null) return { ok: false, refused: answer.state as ChangeBindingsRefusal };
    // Only rows the log never held were ended: no change of the log's to wait for. A sweep waits for no seal either: the
    // end that follows it waits for its own, which seals the log's prefix, these changes with it (R51; Unbinding.tla). But
    // one that makes a replacement's binding, which its request answers made, waits for that.
    if (answer.number === '0' || (call.sweep && call.make === null)) return { ok: true, number: answer.number, witnessed: null };
    const sealedAt = await log015.sealThrough(BigInt(answer.number));
    return { ok: true, number: answer.number, witnessed: sealedAt.witnessed ?? null };
  }

  /** Once entry `number` is sealed and witnessed, or its witnesses past their 2 s (R51): what a change the app made waits for. */
  async waitSealed(input: { number: string }): Promise<Outcome<{ witnessed: boolean | null }>> {
    const log015 = this.#log015();
    if (typeof input?.number !== 'string' || !/^[1-9][0-9]{0,18}$/.test(input.number)) throw new Error('waitSealed takes an entry\'s number, in decimal');
    const sealed = await log015.sealThrough(BigInt(input.number));
    return { ok: true, witnessed: sealed.witnessed ?? null };
  }

  /**
   * 0.15's log checked (verifier.ts): the newest pair and every entry above
   * it, held to the pairs held outside. With 0.14's log alone, there is
   * none to check. The signer remembers a pair before the database has it
   * (RememberFirst), so a check that lands in between finds the database
   * behind (`Verdict.behind`): it is checked again 50 ms later, then a
   * tick later (reviews r4, r5). A rollback is still behind then.
   */
  // --- proxy definitions written in the UI (0.16, T186) ---------------------

  /**
   * An environment's proxy definitions, from its sealed object, and the
   * reserved names (docs/design/proxy-ui.md, section 8, "Reading the tab"):
   * each checked as a use would, its row against its seal and that seal its
   * newest change's. A forged object shows as `tampered`, with no item: an
   * Owner who edited or copied one would seal a forgery as their own. Who may
   * read it is the app's to say: its definitions are no secret (R6). No item
   * carries the holdings its save froze.
   */
  async proxy(input: ProxyInput): Promise<ProxyView> {
    const keys = this.#log015();
    if (!UUID.test(String(input?.projectId)) || !UUID.test(String(input?.environmentId))) throw new Error('an environment is named by its project\'s id and its own');
    await this.#settled();
    // The row and its newest change, read apart: a save that commits between them makes them disagree for that read
    // alone, so a disagreement is read once more before it is shown as one. The seal shown is the one the items were
    // checked against, which a save names.
    const read = async <K extends 'proxy' | 'proxy-reserved'>(ref: Ref & { kind: K }) => {
      for (let attempt = 0; ; attempt += 1) {
        const [row, newest] = await Promise.all([store.readObject(this.#db, ref), store.newestChange(this.#db, ref, macsOf(keys))]);
        try {
          const held = heldFrom(keys.seals, ref, row, newest);
          return { object: held.log === 'live' ? (held.object as Extract<Input, { kind: K }>) : null, seal: newest?.seal ?? null, state: 'ok' as const };
        } catch (error) {
          if (!(error instanceof NotLogged)) throw error;
          if (attempt === 0) continue;
          return { object: null, seal: newest?.seal ?? null, state: error.fault };
        }
      }
    };
    const held = (ref: Ref & { kind: ReadKind }) => heldByLog(keys, this.#db, ref);
    const [proxy, reserved, chain] = await Promise.all([read({ kind: 'proxy', id: input.environmentId }), read(RESERVED_REF), this.#chain(held, input.environmentId)]);
    // Each item that would not route now, marked: what the tab says an Owner must save again (decision 5).
    // A fork's inherited items too, nearest parent first, each decided here: where this environment's use resolves
    // their keys (its own value over a parent's) and for its chain, not the parent's (decision 6).
    if (chain[0]?.projectId !== input.projectId) return proxyView({ id: input.environmentId, projectId: input.projectId }, proxy, reserved, new Map());
    const lenient = (ref: Ref & { kind: ReadKind }) => held(ref).catch(notLogged);
    const parents = await Promise.all(chain.slice(1).map((environment) => lenient({ kind: 'proxy', id: environment.id })));
    const own = Object.values(proxy.object?.items ?? {});
    const taken = new Set(own.map((item) => item.definition.name));
    const inherited: ProxyItem[] = [];
    for (const parent of parents) {
      if (parent.log !== 'live' || parent.object.kind !== 'proxy') continue;
      for (const item of Object.values(parent.object.items)) {
        if (taken.has(item.definition.name)) continue;
        taken.add(item.definition.name);
        inherited.push(item);
      }
    }
    const marks = await this.#marks(this.#db, lenient, chain, [...own, ...inherited], Date.now());
    const view = proxyView({ id: input.environmentId, projectId: input.projectId }, proxy, reserved, marks);
    const uncleared = Object.fromEntries(inherited.flatMap((item) => {
      const mark = marks.get(item.definition.name);
      return mark == null ? [] : [[item.definition.name, mark]];
    }));
    return { ...view, inheritedNotCleared: uncleared };
  }

  /**
   * An environment's proxy definitions saved (`proxy.save`; docs/design/proxy-ui.md,
   * sections 2 and 8), decided on the vault's sealed objects alone (R53): the
   * editor's principal, the roles, the environment and its fork parents, the
   * reserved set and each key an item sends. A person on a session of theirs,
   * holding `proxy.edit` there; never at a personal config (decision 7), nor
   * a reserved name. Each changed item's keys are resolved by name here,
   * inherited and referenced ones included, and cleared for its editor, whose
   * holdings the item freezes; a key the place does not have yet is decided
   * at each use. The page names the seal it loaded: another change since is
   * `proxy_changed`. A forged object is replaced whole, by an Owner of the
   * project, or not at all.
   */
  saveProxy(input: SaveProxyInput): Promise<Outcome<{ view: ProxyView }>> {
    const keys = this.#log015();
    const { actor, projectId, environmentId } = input;
    if (typeof actor !== 'string' || !UUID.test(String(projectId)) || !UUID.test(String(environmentId))) throw new Error('a save names its editor, and an environment by its project\'s id and its own');
    const ref = { kind: 'proxy' as const, id: environmentId };
    const entry = (decision: 'allow' | 'deny', detail: Record<string, unknown>, code: RefusalCode | null = null): NewEntry => ({
      actor, action: PROXY_SAVE, decision, code, projectId, environmentId,
      operationId: input.operationId ?? null, requestId: input.requestId ?? null,
      metadata: JSON.stringify({ ...detail, ...traced(input) }),
    });
    const named = typeof input.items === 'object' && input.items !== null && !Array.isArray(input.items) ? Object.keys(input.items) : null;
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) => new Refused(refusal(code, message), [entry('deny', { names: named ?? [] }, code)]);
    return this.#decide([actor], async (d) => {
      const changes = d.changes!;
      validateCorrelation(input);
      // What it asks, before anything is read: every definition as the vault keeps it, at most MAX_PROXY_ITEMS named.
      if (named === null || named.length > MAX_PROXY_ITEMS) throw refused('invalid', `a save names at most ${MAX_PROXY_ITEMS} items, each its definition or null`);
      if (input.seal !== null && (typeof input.seal !== 'string' || Buffer.from(input.seal, 'base64').length !== 16)) throw refused('invalid', 'a save names the seal its page loaded, or null for none');
      const asked = new Map<string, ProxyDefinition | null>();
      for (const name of named) {
        const given = input.items[name];
        if (given === null) {
          asked.set(name, null);
          continue;
        }
        const problem = proxyDefinitionProblem(given, { insecureUpstreams: input.insecureUpstreams === true });
        if (problem !== null) throw refused('invalid', problem);
        const definition = canonicalDefinition(given, { insecureUpstreams: input.insecureUpstreams === true });
        if (definition.name !== name) throw refused('invalid', `${name}: an item is filed under its own name, not ${definition.name}`);
        asked.set(name, definition);
      }
      // A person, signed in as themselves (a browser's session, or `coffre login`'s): no token or handle edits a route.
      if (input.caller !== 'person' || input.credentialScope != null || !actor.startsWith('user:')) throw refused('not_allowed', 'a person edits proxy definitions, signed in as themselves');
      // The objects it weighs, each as its log has it (`held`: a forged one refuses it), and the newest change of the
      // environment's proxy object, which its page must have loaded.
      // The object it changes among them, as its log has it: a forged one only replaced whole, which reads none of it. And
      // the keys any item asked for names, where the environment itself holds them: a fork's parents are read after.
      const askedKeys = [...new Set([...asked.values()].flatMap((definition) => (definition === null ? [] : definitionKeys(definition))))];
      const [member, roles, reserved, place, newest, current, own] = await Promise.all([
        changes.held(d.tx, { kind: 'principal', id: actor }),
        changes.held(d.tx, ROLES_REF as Ref & { kind: 'roles' }),
        changes.held(d.tx, RESERVED_REF),
        changes.held(d.tx, { kind: 'environment', id: environmentId }),
        store.newestChange(d.tx, ref, macsOf(keys)),
        // A replace weighs none of it: read only for the audit's `removed`, the items its log had.
        changes.held(d.tx, ref).catch((error: unknown) => {
          if (error instanceof NotLogged) return error;
          throw error;
        }),
        store.secretsNamed(d.tx, [environmentId], askedKeys),
      ]);
      if (place.log !== 'live' || place.object.kind !== 'environment' || place.object.projectId !== projectId) throw refused('invalid', 'no such environment');
      const chain = [place.object];
      for (let parent = place.object.parentId; parent !== null && chain.length <= MAX_PARENTS; ) {
        const held = await changes.held(d.tx, { kind: 'environment', id: parent });
        if (held.log !== 'live' || held.object.kind !== 'environment') break;
        chain.push(held.object);
        parent = held.object.parentId;
      }
      const account = member.log === 'live' && member.object.kind === 'principal' ? member.object : null;
      const credential: CredentialInput = { kind: 'credential', id: actor, principal: actor, caller: 'person', scope: null, expiresAt: null, revoked: false, generation: account?.generation ?? 0 };
      const reader = readerOf(account, credential, roles.log === 'live' && roles.object.kind === 'roles' ? roles.object : noEdits(), chain, d.at);
      const environment = place.object;
      const places = new Map(chain.map((each) => [each.id, each]));
      const code = refuses(reader, 'proxy.edit', placeIn({ projectId, environmentId }, places), environment.deleted);
      if (code !== null) throw refused(code, code === 'no_grant' || code === 'expired' ? 'editing proxy definitions takes proxy.edit there: Owners hold it' : REFUSAL_MESSAGES[code]);
      if (environment.owner !== null) throw refused('invalid', "a personal config takes no proxy definitions of its own: they are its environment's");
      if (environment.archived || environment.projectArchived) throw refused('not_allowed', "an archived environment's proxy definitions stay as they are");
      if (input.replace === true && !ownsProject(reader.live, projectId)) throw refused('not_allowed', "replacing an environment's proxy definitions whole takes an Owner of its project");
      // CAS on the object's newest change, never its row: a forged row's seal is no change anyone loaded.
      if ((newest?.seal?.toString('base64') ?? null) !== input.seal) throw refused('proxy_changed');
      const names = reserved.log === 'live' && reserved.object.kind === 'proxy-reserved' ? reserved.object.names : [];
      const taken = [...asked].find(([name, definition]) => definition !== null && names.includes(name));
      if (taken !== undefined) throw refused('reserved', `${taken[0]} is reserved by the deployment's code: an instance Owner may release it`);
      if (current instanceof NotLogged && input.replace !== true) {
        throw refused('tampered', current.fault === 'stale'
          ? "this environment's proxy definitions are not their newest change's (stale): an Owner of its project replaces them whole"
          : "this environment's proxy definitions failed the vault's integrity check: an Owner of its project replaces them whole");
      }
      const logged: ProxyObject | null = !(current instanceof NotLogged) && current.log === 'live' && current.object.kind === 'proxy' ? current.object : null;
      const before = input.replace === true ? null : logged;
      // What changes: each item the save names is saved again, under its editor's standing now (a re-save is how an
      // Owner clears a route an earlier editor can no longer), unless its definition, editor and standing are the ones
      // it holds: then nothing changes and nothing is logged.
      const holdings = frozenHoldings(reader);
      const saved = new Map<string, ProxyDefinition | null>();
      for (const [name, definition] of asked) {
        const was = before?.items[name] ?? null;
        if (definition === null ? was === null && input.replace !== true : was !== null && was.savedBy === actor && canonical(was.definition) === canonical(definition) && canonical(was.holdings) === canonical(holdings)) continue;
        saved.set(name, definition);
      }
      const kept = input.replace === true ? 0 : Object.keys(before?.items ?? {}).filter((name) => !saved.has(name)).length;
      if (kept + [...saved.values()].filter((definition) => definition !== null).length > MAX_PROXY_ITEMS) throw refused('invalid', `an environment holds at most ${MAX_PROXY_ITEMS} proxy definitions`);
      // Each changed item's keys, resolved by name where the use will find them: the nearest place of the fork chain
      // that holds one, its value's nature a reference's source's; and cleared for the editor.
      const sending = [...new Set([...saved.values()].flatMap((definition) => (definition === null ? [] : definitionKeys(definition))))];
      const resolved = await this.#proxyKeys(d.tx, (ref) => changes.held(d.tx, ref), chain, sending, own);
      const cleared = new Map<string, string[]>();
      for (const key of resolved.values()) {
        const why = routeRefusal(reader, key, chain);
        if (why !== null) throw refused('route_not_cleared', `${why}: it cannot be routed by ${actor.slice('user:'.length)}`);
      }
      const items: Record<string, ProxyItem | null> = {};
      for (const [name, definition] of saved) {
        if (definition === null) {
          items[name] = null;
          continue;
        }
        const sent = definitionKeys(definition);
        cleared.set(name, sent.filter((key) => resolved.get(key)?.nature === 'sensitive'));
        items[name] = { definition, keys: sent, savedBy: actor, savedAt: d.at, holdings };
      }
      const op: Op = { op: 'proxy.save', items, replace: input.replace === true, loaded: input.seal };
      const after = applyOp(before, ref, op);
      if (after === undefined || after === null || after.kind !== 'proxy') throw refused('invalid', 'not a save the rules allow');
      // No clearance marks: they take reads no change should hold its locks for. The tab reads them after (`proxy`).
      const view = proxyView({ id: environmentId, projectId }, { object: after, seal: sealOf(keys.seals[0]!, ref, after), state: 'ok' }, { object: reserved.log === 'live' && reserved.object.kind === 'proxy-reserved' ? reserved.object : null, state: 'ok' });
      if (saved.size === 0 && input.replace !== true) return { view: { ...view, seal: input.seal } };
      changes.stage(ref, op, actor);
      // The audit page's diff: each item saved, where it sends which keys, and the sensitive ones it routes (R66).
      d.log.push(entry('allow', {
        proxy: {
          replace: input.replace === true,
          saved: [...saved].flatMap(([name, definition]) => (definition === null ? [] : [{ name, kind: definition.kind, ...(definition.kind === 'route' ? { upstream: definition.upstream } : {}), keys: definitionKeys(definition), routesSensitive: cleared.get(name) ?? [] }])),
          removed: input.replace === true ? Object.keys(logged?.items ?? {}).filter((name) => saved.get(name) == null) : [...saved].flatMap(([name, definition]) => (definition === null ? [name] : [])),
        },
      }));
      return { view };
    });
  }

  /**
   * Each key name's nearest holder in a fork chain, nearest first, as a use
   * finds it (values inherit, up to three parents), its object as its log
   * has it, and a reference's source's nature. A key no place
   * holds, or one archived, is left out: decided at each use.
   */
  async #proxyKeys(
    db: Queryable, held: (ref: Ref & { kind: 'secret' }) => Promise<Held>, chain: readonly EnvironmentInput[], names: readonly string[], own: readonly { id: string; environmentId: string; key: string }[],
  ): Promise<Map<string, ResolvedKey>> {
    if (names.length === 0) return new Map();
    const parents = chain.slice(1).map((environment) => environment.id);
    const found = [...own.filter((row) => names.includes(row.key)), ...(parents.length === 0 ? [] : await store.secretsNamed(db, parents, names))];
    const nearest = new Map<string, { id: string; holder: EnvironmentInput }>();
    for (const holder of chain) {
      for (const row of found) if (row.environmentId === holder.id && !nearest.has(row.key)) nearest.set(row.key, { id: row.id, holder });
    }
    const resolved = new Map<string, ResolvedKey>();
    await Promise.all([...nearest].map(async ([name, { id, holder }]) => {
      const read = await held({ kind: 'secret', id });
      if (read.log !== 'live' || read.object.kind !== 'secret') return;
      let secret: SecretInput = read.object;
      if (secret.source !== null) {
        const source = await held({ kind: 'secret', id: secret.source });
        if (source.log !== 'live' || source.object.kind !== 'secret') return;
        secret = source.object;
      }
      resolved.set(name, { name, holder, nature: secret.nature });
    }));
    return resolved;
  }

  /**
   * Each of these items, its own or inherited, that would not route now in
   * the chain's first environment, by name, and why (`notCleared`, decision
   * 5): its keys resolved where a use there finds
   * them, decided for what its save froze and for its editor as they stand,
   * from the objects `held` reads (the log's, never a row's columns). What
   * cannot be read marks nothing: the use decides it, failing closed.
   */
  async #marks(
    db: Queryable, held: (ref: Ref & { kind: ReadKind }) => Promise<Held>, chain: readonly EnvironmentInput[], items: readonly ProxyItem[], at: number,
  ): Promise<Map<string, NonNullable<ProxyItemView['notCleared']> | null>> {
    if (items.length === 0) return new Map();
    const environmentId = chain[0]!.id;
    const names = [...new Set(items.flatMap((item) => item.keys))];
    const editors = [...new Set(items.map((item) => item.savedBy))];
    const [roles, own, ...members] = await Promise.all([
      held(ROLES_REF as Ref & { kind: 'roles' }),
      store.secretsNamed(db, [environmentId], names),
      ...editors.map((editor) => held({ kind: 'principal', id: editor })),
    ]);
    const policy = roles.log === 'live' && roles.object.kind === 'roles' ? roles.object : noEdits();
    const resolved = await this.#proxyKeys(db, held, chain, names, own);
    const readers = new Map(editors.map((editor, i) => {
      const member = members[i]!;
      const account = member.log === 'live' && member.object.kind === 'principal' ? member.object : null;
      const credential: CredentialInput = { kind: 'credential', id: editor, principal: editor, caller: 'person', scope: null, expiresAt: null, revoked: false, generation: account?.generation ?? 0 };
      return [editor, readerOf(account, credential, policy, chain, at)] as const;
    }));
    return new Map(items.map((item) => [item.definition.name, notCleared(item, readers.get(item.savedBy)!, resolved, chain)]));
  }

  /** An environment and the parents of its fork, nearest first, as the log has them; the first not live ends the chain. */
  async #chain(held: (ref: Ref & { kind: 'environment' }) => Promise<Held>, environmentId: string): Promise<EnvironmentInput[]> {
    const chain: EnvironmentInput[] = [];
    for (let id: string | null = environmentId; id !== null && chain.length <= MAX_PARENTS; ) {
      const read = await held({ kind: 'environment', id });
      if (read.log !== 'live' || read.object.kind !== 'environment') break;
      chain.push(read.object);
      id = read.object.parentId;
    }
    return chain;
  }

  /**
   * The UI items `member` saved, in every environment (decision 5's
   * offboarding preview): the rows that name them found by their JSON, each
   * object then held by the log, so a forged row lists nothing.
   */
  async proxySavedBy(input: { member: string }): Promise<{ items: SavedProxyItem[] }> {
    const keys = this.#log015();
    if (typeof input?.member !== 'string' || !/^(user|token):/.test(input.member)) throw new Error('a member is named user:<email> or token:<name>');
    await this.#settled();
    const found = await store.proxiesSavedBy(this.#db, input.member);
    const objects = await Promise.all(found.map((id) => heldByLog(keys, this.#db, { kind: 'proxy', id }).catch(notLogged)));
    const items = objects.flatMap((held, i) => held.log !== 'live' || held.object.kind !== 'proxy' ? [] : Object.values(held.object.items)
      .filter((item) => item.savedBy === input.member)
      .map((item) => ({ environmentId: found[i]!, name: item.definition.name, kind: item.definition.kind, keys: [...item.keys] })));
    return { items };
  }

  /**
   * The names the deployment's code defines, reserved (`proxy.code`;
   * docs/design/proxy-ui.md, section 6): each name new to the instance's set
   * added, and each UI item of such a name deleted, in every environment, each
   * whole in its entry, so that the log restores it. One transaction under
   * the fence; two first isolates racing, the second finds its names in and
   * writes nothing. An environment whose object fails its seal is passed
   * over: it serves nothing (R64), and its item, should a writer put it back,
   * stays shadowed by the name, which no deploy drops.
   */
  async reserveProxy(input: ReserveProxyInput): Promise<Outcome<{ reserved: string[]; cleared: ClearedItem[] }>> {
    const keys = this.#log015();
    const problem = reservedProblem(input?.names);
    if (problem !== null) throw new Error(problem);
    const wanted = [...new Set(input.names)].sort();
    // Every isolate's call after the deploy that added its names finds them reserved, and writes nothing (Routing.tla's
    // LogCode, its ELSE): the object read as the log holds it says so, first in the decision's transaction, before the
    // head. A read that cannot say, unsealed, torn by a change between its two statements or short of a name, decides
    // under the head.
    //
    // The gate keeps no pending call, so the deploy that adds a name sends every isolate's first requests here at once,
    // each finding it missing. Each deciding in turn under the head, 3,080 no-op decisions queued 200 s in #467's bench
    // at 1,000 a second, and every use behind them; each reading in one turn of a Node deployment's pool (8) and
    // deciding in another, the first call's decision waited behind 780 calls' reads, and the last answered after 15 s.
    // So the read and the decision take one turn, and only one call waits for the head, in the code's one place in line;
    // the others, refused that place at once (`HeadBusy`), try again after a pause, and read the names it wrote. On
    // SQLite, whose every transaction queues for the file's one writer (`WriteQueue`) and a plain read not, the read
    // comes before the transaction, as its own statement (review r15 of #467).
    const reads = (await this.#settled()) === null && (await this.#cutOverNow());
    const sqlite = engineOf(this.#db) === 'sqlite';
    const first = reads && !sqlite ? (tx: Transaction) => this.#reservedAlready(tx, keys, wanted) : undefined;
    // One bound for the call: each attempt's lock waits within what is left of it (review r14 of #467), a call that
    // took the place late never waiting the whole bound again. A no-op attempt, every call of a deploy's herd but one,
    // waits for nothing else; the one that writes waits, after the head, for the issue lock and the fence, each within
    // what was left when its attempt began, as every change waits for each lock it takes.
    const deadline = Date.now() + this.#prepared.options.codeWaitMs;
    for (let pause = LOCK_PAUSE_MS; ; pause = Math.min(2 * pause, LOCK_PAUSE_MAX_MS)) {
      if (reads && sqlite) {
        const found = await this.#reservedAlready(this.#db, keys, wanted);
        if (found !== null) return { ok: true, ...found };
      }
      try {
        return await this.#decide([], (d) => this.#reserve(d, wanted, input), { queue: CODE_QUEUE, deadline, ...(first === undefined ? {} : { first }) });
      } catch (error) {
        if (!(error instanceof HeadBusy)) throw error;
        const wait = pause * (0.5 + Math.random());
        if (Date.now() + wait >= deadline) throw error;
        await new Promise((resolve) => setTimeout(resolve, wait));
      }
    }
  }

  /**
   * `wanted` reserved, as the sealed set read before the head says, or null: it cannot say, or a name is missing.
   * A set its log does not bear out says nothing, not "none": it decides under the head, which reports it and
   * refuses, an empty ask's (a deployment of UI routes alone) as much as any (review r12 of #467). So does a set whose
   * newest change's MAC does not hold (T190): a row put back with a forged seal never stands for names reserved.
   */
  async #reservedAlready(db: Queryable, keys: ChangeKeys, wanted: readonly string[]): Promise<{ reserved: string[]; cleared: ClearedItem[] } | null> {
    const held = await heldByLog(keys, db, RESERVED_REF).catch((error: unknown) => {
      if (error instanceof NotLogged) return null;
      throw error;
    });
    if (held === null) return null;
    const names = held.log === 'live' && held.object.kind === 'proxy-reserved' ? held.object.names : [];
    return wanted.every((name) => names.includes(name)) ? { reserved: [...names], cleared: [] } : null;
  }

  /** `reserveProxy`'s decision, under the head: the names missing added, and the UI items of those names deleted. */
  async #reserve(d: Decision, wanted: readonly string[], input: ReserveProxyInput): Promise<{ reserved: string[]; cleared: ClearedItem[] }> {
    const changes = d.changes!;
    const reserved = await changes.held(d.tx, RESERVED_REF);
    const names = reserved.log === 'live' && reserved.object.kind === 'proxy-reserved' ? reserved.object.names : [];
    const adding = wanted.filter((name) => !names.includes(name));
    if (adding.length === 0) return { reserved: [...names], cleared: [] };
    changes.stage(RESERVED_REF, { op: 'proxy.code', names: adding }, CODE_ACTOR);
    const cleared: ClearedItem[] = [];
    for (const environmentId of await store.proxiesNaming(d.tx, adding)) {
      const ref = { kind: 'proxy' as const, id: environmentId };
      const held = await changes.held(d.tx, ref).catch((error: unknown) => {
        if (error instanceof NotLogged) return null;
        throw error;
      });
      if (held?.log !== 'live' || held.object.kind !== 'proxy') continue;
      const { items } = held.object;
      const gone = Object.fromEntries(adding.filter((name) => Object.hasOwn(items, name)).map((name) => [name, items[name]!]));
      if (Object.keys(gone).length === 0) continue;
      changes.stage(ref, { op: 'proxy.code', names: adding, cleared: gone }, CODE_ACTOR);
      cleared.push(...Object.keys(gone).map((name) => ({ environmentId, name })));
    }
    d.log.push({
      actor: CODE_ACTOR, action: PROXY_CODE, decision: 'allow', code: null,
      operationId: input.operationId ?? null, requestId: input.requestId ?? null,
      metadata: JSON.stringify({ proxy: { reserved: adding, cleared } }),
    });
    return { reserved: [...new Set([...names, ...adding])].sort(), cleared };
  }

  /**
   * A reserved name freed, instance-wide (`proxy.release`), by an Owner of
   * the whole instance on a session of theirs: it frees the name in every
   * environment of every project. Whether an older deployment still serving
   * defines it is the app's to warn of: no code is an input of the log.
   */
  releaseProxy(input: ReleaseProxyInput): Promise<Outcome<{ reserved: string[] }>> {
    this.#log015();
    const { actor, name } = input;
    if (typeof actor !== 'string') throw new Error('a release names who asks');
    const entry = (decision: 'allow' | 'deny', code: RefusalCode | null = null): NewEntry => ({
      actor, action: PROXY_RELEASE, decision, code,
      operationId: input.operationId ?? null, requestId: input.requestId ?? null,
      metadata: JSON.stringify({ proxy: { released: String(name) }, ...traced(input) }),
    });
    const refused = (code: RefusalCode, message = REFUSAL_MESSAGES[code]) => new Refused(refusal(code, message), [entry('deny', code)]);
    return this.#decide([actor], async (d) => {
      const changes = d.changes!;
      validateCorrelation(input);
      if (typeof name !== 'string' || !CREDENTIAL_NAME.test(name)) throw refused('invalid', 'a release names one reserved name');
      if (input.caller !== 'person' || input.credentialScope != null || !actor.startsWith('user:')) throw refused('not_allowed', 'an Owner of the whole instance releases a name, signed in as themselves');
      const [member, reserved] = await Promise.all([changes.held(d.tx, { kind: 'principal', id: actor }), changes.held(d.tx, RESERVED_REF)]);
      const account = member.log === 'live' && member.object.kind === 'principal' ? member.object : null;
      if (account === null || account.status !== 'active') throw refused(account === null ? 'not_a_member' : 'removed');
      if (!ownsInstance(account)) throw refused('not_allowed', 'a released name is free in every project: only an Owner of the whole instance releases one');
      const names = reserved.log === 'live' && reserved.object.kind === 'proxy-reserved' ? reserved.object.names : [];
      if (!names.includes(name)) throw refused('invalid', `${name} is not reserved`);
      changes.stage(RESERVED_REF, { op: 'proxy.release', name }, actor);
      d.log.push(entry('allow'));
      return { reserved: names.filter((each) => each !== name) };
    });
  }

  /** Whether 0.15's checkpointer seals (T169): what `/readyz` asks. Under 0.14's log alone, nothing waits on one. */
  async sealing(): Promise<Sealing> {
    const log015 = this.#prepared.log015;
    if (log015 === null) return { ok: true };
    try {
      return await log015.sealing();
    } catch (error) {
      return { ok: false, reason: (error as Error).message };
    }
  }

  async verifyTrees(): Promise<TreeVerification> {
    await this.#settled();
    if (this.#prepared.log015 === null) return { kept: false };
    const anchors = await this.#prepared.log015.heldOutside();
    const keys = await this.#verifierKeys();
    const walk = () => verifyTrees(this.#db, keys, { anchors });
    let walked = await walk();
    // The signer's write lands a moment after it remembers: asked again soon, then once more a tick later, for a write
    // that failed and is made again at the next tick (PR 8 review r5).
    for (const wait of [50, TICK_MS + 250]) {
      if (!walked.behind) break;
      await new Promise((resolve) => setTimeout(resolve, wait));
      walked = await walk();
    }
    // What crosses to the app: the verdict, never the retry's signal.
    const { behind: _behind, ...verdict } = walked;
    return verdict;
  }

  /**
   * The entries of 0.15's log, as an audit page read them, whose MAC holds
   * under no key that vouches at their number over the columns it shows
   * (T166): forged, or edited, around coffre. A malformed one is named too.
   * The current key vouches for any; a key it replaced, only below its
   * rotation (T168, keyring.ts, R41), whose bounds are read, in one
   * statement, only when an entry fails the current key and the vault holds
   * a replaced one, and kept by no isolate (a restore moves them).
   * Otherwise pure CPU: about 3 µs an entry, `VOUCHED_AT_ONCE` at most.
   */
  async vouch(input: VouchInput): Promise<{ forged: string[] }> {
    const entries: unknown = (input as { entries?: unknown } | undefined)?.entries;
    if (!Array.isArray(entries) || entries.length > VOUCHED_AT_ONCE) throw new Error(`vouch takes up to ${VOUCHED_AT_ONCE} entries`);
    const keys = await this.#verifierKeys();
    const asked = entries.map((entry: VouchedEntry): { named: string; holds: (ring: Keyring) => boolean } => {
      const named = typeof entry?.number === 'string' ? entry.number : '?';
      if (entry?.tree === 'cursor') {
        const at = typeof entry.through === 'string' && /^[0-9]{1,19}$/.test(entry.through) && typeof entry.pair === 'string' && /^[0-9]{1,19}$/.test(entry.pair) && Number.isSafeInteger(entry.at);
        const mac = entry.mac === null ? null : typeof entry.mac === 'string' && /^[0-9a-f]{32}$/.test(entry.mac) ? Buffer.from(entry.mac, 'hex') : undefined;
        const cursor = at && mac !== undefined ? { through: BigInt(entry.through), pair: BigInt(entry.pair), at: entry.at, mac } : null;
        return { named, holds: (ring) => cursor !== null && cursorVouched(ring, cursor) };
      }
      if (entry?.tree === 'reads') {
        const read = vouchedRead(entry);
        return { named, holds: (ring) => read !== null && readVouched(ring, read) };
      }
      const logged = vouchedEntry(entry as Exclude<VouchedEntry, { tree: 'reads' | 'cursor' }>);
      return { named, holds: (ring) => logged !== null && entryVouched(ring, logged) === 'held' };
    });
    const failing = asked.filter((a) => !a.holds(alone(keys)));
    if (failing.length === 0 || keys.previous.length === 0) return { forged: failing.map((a) => a.named) };
    const ring = await keyringOf(keys, logStore(this.#db));
    return { forged: failing.filter((a) => !a.holds(ring)).map((a) => a.named) };
  }

  /**
   * A stretch of the reads' check (reads.ts, `checkReads`): from `start`, or
   * a stretch's `next` (a pair's number), in a snapshot of its own. Flat:
   * a checkpoint's range, whatever the log's length.
   */
  async verifyReads(input: { from: string }): Promise<ReadsVerification> {
    await this.#settled();
    if (this.#prepared.log015 === null) return { kept: false };
    const from = (input as { from?: unknown } | undefined)?.from;
    const at = typeof from === 'string' ? /^(?:start|([0-9]{1,19}))$/.exec(from) : null;
    if (at === null) throw new Error('verifyReads starts at start, or at a stretch\'s next');
    const keys = await this.#verifierKeys();
    const checked = await this.#db.transaction((tx) => checkReads(logStore(tx as unknown as Database), keys, at[1] === undefined ? 0n : BigInt(at[1])), SNAPSHOT);
    return {
      kept: true,
      ok: checked.problems.length === 0,
      problems: checked.problems,
      through: String(checked.through),
      listed: String(checked.listed),
      next: checked.next === null ? null : String(checked.next),
    };
  }

  async #verifierKeys(): Promise<VerifierKeys> {
    return (this.#prepared.verifier ??= await verifierKeys(this.#config.signingKeys));
  }

  #log015(): NonNullable<PreparedVault['log015']> {
    const log015 = this.#prepared.log015;
    if (log015 === null) throw new Error("this vault keeps 0.14's log: the app writes its rows as 0.14 does (`about().log`)");
    return log015;
  }

  async keyChecks(): Promise<KeyChecks> {
    // A vault key with no check yet gets one first, as before the first key operation.
    await this.#kekMismatch();
    const { provider, keyId } = this.#config.keks.primary;
    const checks = [...(await this.#checkValues(this.#db)).values()]
      .sort((a, b) => (a.seq < b.seq ? 1 : -1))
      .map(({ seq, wrapped }) => ({ ...wrapped, seq: Number(seq) }));
    return { current: { kekProvider: provider, kekId: keyId }, checks };
  }

  /**
   * The log from a checkpoint's tally, in one snapshot: the vault's
   * entries since, each by its MAC, the keys it moved through, and what the
   * other checks need of it (`Walk`); then every checkpoint walked, the
   * heads that must still be there, and, for a walk that ends at the
   * present, the key batches accounted for and the members and grants
   * replayed against their rows.
   *
   * With `upTo`, the head the app verified to, the links and hashes of the
   * chain are the app's to recompute, as it just has, over its own
   * snapshot, through that head; holding `upTo` ties this snapshot to that
   * one. So the vault reads only its own entries, each checked against its
   * own hash and MAC over the link it names. Without `upTo`, nobody else
   * recomputed the chain: the vault reads it all, and rehashes every link,
   * no further than one walk (`walks.verify`).
   */
  async verifyLog(input: VerifyLogInput): Promise<LogVerification> {
    await this.#settled();
    const upTo = input.upTo ?? null;
    const { logKeys } = this.#prepared;
    const { walks } = this.#prepared.options;
    return this.#db.transaction(async (tx): Promise<LogVerification> => {
      const remembered = this.#prepared.verified;
      const from = await this.#resume(tx, input.from === undefined ? 'newest' : input.from === 'start' ? 'start' : BigInt(input.from));
      if (!from.ok) return from;
      // Where a stretch ends, the last entry its checkpoint names: that checkpoint, and each it passes on the
      // way, are held to the walk as it gets there, so a fault on the way is named where it is.
      const to = input.to === undefined ? null : BigInt(input.to);
      const ends = to === null ? null : (await store.entriesAt(tx, [to])).get(to)?.relatedSeq ?? -1n;
      if (ends !== null && (ends <= from.at.seq || (upTo !== null && BigInt(upTo.seq) !== ends))) {
        return { ok: false, failedAtSeq: Number(to), reason: 'not a checkpoint after the one the walk starts from, whose prefix ends where the app verified to' };
      }
      // The prefix the walk starts from still there, as it was signed, and whole: a rewrite chained again
      // changes its hash, and a cut its count.
      if (!(await this.#holding(tx, [headOf(from.at)]))(headOf(from.at))) {
        return { ok: false, failedAtSeq: Number(from.entry), reason: `the log up to entry ${from.at.seq} is not the prefix this checkpoint signed: it was rewritten` };
      }
      const gap = await missingEntry(tx, from.at.seq);
      if (gap !== null) return { ok: false, failedAtSeq: Number(gap.found), reason: `sequence gap: expected seq ${gap.expected}, found ${gap.found}` };
      // Every checkpoint after it whose prefix the walk may pass, a stretch's end among them, signed while
      // the app walked or not: each tally is held to the walk where it gets there (`Walk.expect`).
      const walk = new Walk(from.tally, from.digest);
      const later = await store.talliedAfter(tx, from.entry ?? -1n, walks.verify);
      const passed = later.filter(({ seq }) => to === null || seq <= to);
      if (to !== null && passed.at(-1)?.seq !== to) {
        return { ok: false, failedAtSeq: Number(to), reason: `a stretch passes no more than ${walks.verify} checkpoints: end one sooner` };
      }
      // Each one's tally as what the walk must come to, a few at a time, so that members and grants kept whole
      // in many of them are never all in memory: the digest it keeps of them stands for them.
      // Each one's members and grants are as its digest says, kept whole in it or in the earlier checkpoint it
      // names, each such checkpoint read once: what a walk resuming from it would find.
      const holding = new Map<bigint, string | null>();
      const carried = async (carrier: bigint): Promise<string | null> => {
        if (!holding.has(carrier)) {
          const entry = (await store.entriesAt(tx, [carrier])).get(carrier);
          const read = entry === undefined ? 'missing' : this.#tallied(entry);
          holding.set(carrier, typeof read === 'string' || 'at' in read.tally.access ? null : keptDigest(read.tally.access));
        }
        return holding.get(carrier)!;
      };
      const expected: Expected[] = [];
      // The hash the stretch's own checkpoint signed, as it is read among the others.
      let endSigned: string | null = null;
      for (let after = from.entry ?? -1n, last = passed.at(-1)?.seq; last !== undefined && after < last; ) {
        const batch = await store.talliedWithin(tx, after, last, walks.verify + 1);
        if (batch.length === 0) break;
        for (const entry of batch) {
          const read = this.#tallied(entry);
          const point = { entry: entry.seq, through: entry.relatedSeq! };
          if (typeof read === 'string') {
            expected.push({ ...point, unreadable: read });
            continue;
          }
          if (entry.seq === to) endSigned = read.hash;
          const { access } = read.tally;
          if (!('at' in access)) holding.set(entry.seq, keptDigest(access));
          const kept = 'at' in access ? (BigInt(access.at) < entry.seq ? await carried(BigInt(access.at)) : null) : holding.get(entry.seq)!;
          expected.push(kept === access.digest
            ? { ...point, key: expectedKey(read.tally) }
            : { ...point, unreadable: kept === null ? `its tally keeps its members and grants in entry ${'at' in access ? access.at : entry.seq}, which holds none` : "its tally's members and grants do not match their digest" });
        }
        after = batch.at(-1)!.seq;
      }
      walk.expect(expected);
      // How far the walk got, the hash there, and whether that is the present: the rows and the key batches
      // are held to the log only when the walk read every entry of the vault's there is.
      let through = from.at.seq;
      let reached = headOf(from.at).hash;
      let present = false;
      if (upTo === null) {
        const chain = await rehash(tx, logKeys, from.at, walk, ends === null ? { limit: walks.verify } : { to: ends });
        if (!chain.ok) return chain;
        [through, reached, present] = [chain.at.seq, headOf(chain.at).hash, chain.done && ends === null];
        this.#prepared.verified = further(this.#prepared.verified, chain.at);
      } else {
        // On past the app's head, to the vault's last entry in this snapshot: the rows are as they are at
        // this one's. The app's head bounds what is verified; the vault's own walk, what the rows meet.
        const own = await ownEntries(tx, logKeys, from.at.seq, walk, ends === null ? { limit: walks.verify } : { to: ends });
        if (!own.ok) return own;
        // An app older than 0.10.1 names no `from`, and takes an ok for the whole of `upTo`: it gets one only for that.
        if (!own.done && input.from === undefined) {
          return { ok: false, failedAtSeq: null, reason: `the vault verifies no more than ${walks.verify} of its entries a call, and its checkpoints are catching up: update the app` };
        }
        // Short of its own last entry, it has not held the rows to the log: never say it verified all the app did.
        const short = own.at < BigInt(upTo.seq) ? own.at : BigInt(upTo.seq) - 1n;
        [through, reached, present] = [own.done ? BigInt(upTo.seq) : short, upTo.hash, own.done && ends === null];
      }
      walk.finish(ends ?? through);
      // Each head the log must still hold, in one read: the app's, every
      // checkpoint's walked, and the last this vault rehashed.
      const rememberedHead = remembered.seq >= 0n ? headOf(remembered) : null;
      const heads = [...(upTo === null ? [] : [upTo]), ...(rememberedHead === null ? [] : [rememberedHead])];
      const holds = await this.#holding(tx, [...heads, ...walk.checkpoints.map(({ checkpoint }) => checkpoint)]);
      if (upTo !== null && !holds(upTo)) {
        return { ok: false, failedAtSeq: upTo.seq, reason: 'not the entry the app verified up to: the log changed between the two checks' };
      }
      const unsigned = await this.#checkpointFault(tx, walk.checkpoints, holds);
      if (unsigned !== null) return unsigned;
      // What this vault last verified must still be there: whoever holds
      // its key can seal a rewrite, but cannot put back the head it saw. A
      // checkpoint names an earlier break, so it is reported first.
      if (rememberedHead !== null && !holds(rememberedHead)) {
        return { ok: false, failedAtSeq: rememberedHead.seq, reason: 'changed since the vault last verified it' };
      }
      if (walk.mismatch !== null) return { ok: false, failedAtSeq: Number(walk.mismatch.entry), reason: walk.mismatch.reason };
      if (ends !== null) {
        // The walk ends at the prefix the stretch's checkpoint signed, by its hash too: a chain made again from before it is not.
        if ((upTo === null && through !== ends) || endSigned !== reached) {
          return { ok: false, failedAtSeq: Number(to), reason: `the log up to entry ${ends} is not the prefix this checkpoint signed: it was rewritten` };
        }
        return { ok: true, entries: walk.entries, through: Number(ends) };
      }
      // A checkpoint refused since the newest was signed, for a broken log: what it found, the stretch of the
      // past it rehashed among it, which no walk from a tally reads again.
      const standing = await this.#standingRefusal(tx);
      if (standing !== null) {
        return { ok: false, failedAtSeq: standing.failedAtSeq ?? null, reason: `the last checkpoint was refused: ${standing.reason ?? 'the log is broken'}` };
      }
      const verified = { ok: true as const, entries: walk.entries, through: Number(through) };
      if (!present) return verified;
      const at = await this.#now(tx);
      const accounting = walk.accounting.result(at);
      if (!accounting.ok) return accounting;
      const [rows, held, fast] = await Promise.all([store.allMembers(tx), store.grants(tx), this.#checksSeals() ? store.fastAdded(tx) : new Set<string>()]);
      const fault = fast.size === 0
        ? this.#unsealed(rows, held, walk.newestAccess) ?? walk.replayFault ?? replayFault(walk.replayed, rows, held, at)
        : await this.#partlyReplayed(tx, walk, rows, held, fast, at);
      if (fault !== null) return { ok: false, failedAtSeq: null, reason: describeAccessFault(fault), fault };
      return accounting.pending === 0 ? verified : { ...verified, pending: accounting.pending };
    }, SNAPSHOT);
  }

  /**
   * Every checkpoint walked, not only the newest: each signed by the key
   * whose log key wrote its entry, over a prefix the log still holds,
   * entry for entry, which one that keeps a tally names as related. Its
   * entry's MAC is checked by now, and one under a key the vault replaced
   * comes before the rotation.
   */
  async #checkpointFault(
    db: Queryable,
    checkpoints: Walk['checkpoints'],
    known?: (head: LogHead) => boolean,
  ): Promise<Broken | null> {
    if (checkpoints.length === 0) return null;
    const holds = known ?? (await this.#holding(db, checkpoints.map(({ checkpoint }) => checkpoint)));
    const { logKeys, signers } = this.#prepared;
    // Each signer's key imported once, for this check only.
    const verifiers = new Map<string, Promise<(checkpoint: Checkpoint) => Promise<boolean>>>();
    const signed = (checkpoint: Checkpoint, by: Signer) => {
      let verifier = verifiers.get(by.keyId);
      if (verifier === undefined) verifiers.set(by.keyId, (verifier = checkpointVerifier(by.publicKey)));
      return verifier.then((verify) => verify(checkpoint));
    };
    for (let from = 0; from < checkpoints.length; from += SIGNATURES_AT_ONCE) {
      const chunk = checkpoints.slice(from, from + SIGNATURES_AT_ONCE);
      // The signatures of a chunk at once, where crypto runs beside the code; the first fault, in the log's order.
      const faults = await Promise.all(chunk.map(async ({ entry, checkpoint }) => {
        const by = signers[logKeys.findIndex((key) => key.keyId === entry.keyId)];
        if (by?.keyId !== checkpoint.keyId) return `a checkpoint signed under ${checkpoint.keyId}, in an entry written under ${entry.keyId}: each key signs only its own`;
        if (!(await signed(checkpoint, by))) return 'a checkpoint the vault did not sign';
        if (BigInt(checkpoint.seq) >= entry.seq || !holds(checkpoint) || (entry.relatedSeq !== null && entry.relatedSeq !== BigInt(checkpoint.seq))) {
          return `the log up to entry ${checkpoint.seq} is not the prefix this checkpoint signed: it was rewritten`;
        }
        return null;
      }));
      const at = faults.findIndex((fault) => fault !== null);
      if (at !== -1) return { ok: false, failedAtSeq: Number(chunk[at]!.entry.seq), reason: faults[at]! };
    }
    return null;
  }

  /**
   * The rows held to the log once a first add down the two-trip path wrote
   * no 0.14 entry (T179, since 0.16.0): `fast`, whom such adds added, are
   * people 0.14's replay never admitted. Every row still names the newest
   * 0.14 access entry about them (`#unsealed`; none, 0, for one added so
   * and changed no further). Everyone else is replayed as before, unless
   * the replay stopped at a change of one of `fast` (an `unadmitted-change`:
   * the walk applies nothing after its first fault, a tally keeps it, and a
   * tally follows from 0.14's log alone): it can say nothing after. Whom it
   * cannot replay, `fast`, and every row past a stopped replay, are held to
   * 0.15's log, as `#sweep` holds them (`#integrity`, then `#onLog`: the
   * 0.4 MAC, the row's seal against its object's newest change, that
   * change's MAC, and no 0.14 access entry past the one it accounts for),
   * with no row too (deleted, unless the log says so).
   * Nothing reported: a verification only says.
   */
  async #partlyReplayed(
    db: Queryable, walk: Walk, rows: readonly Member[], held: readonly GrantRow[], fast: ReadonlySet<string>, at: number,
  ): Promise<AccessFault | null> {
    const newest = new Map(walk.newestAccess);
    for (const principal of fast) if (!newest.has(principal)) newest.set(principal, 0n);
    const unsealed = this.#unsealed(rows, held, newest);
    if (unsealed !== null) return unsealed;
    const stopped = walk.replayFault !== null && walk.replayFault.kind === 'unadmitted-change' && fast.has(walk.replayFault.principal);
    if (!stopped) {
      if (walk.replayFault !== null) return walk.replayFault;
      const replayed: Replayed = {
        members: new Map([...walk.replayed.members].filter(([principal]) => !fast.has(principal))),
        held: new Map([...walk.replayed.held].filter(([principal]) => !fast.has(principal))),
      };
      const others = replayFault(replayed, rows.filter((row) => !fast.has(row.principal)), held.filter((grant) => !fast.has(grant.principal)), at);
      if (others !== null) return others;
    }
    const byPrincipal = new Map(rows.map((row) => [row.principal, row]));
    // Past a stopped replay, everyone: each row, and each the walk saw an access entry about (it keeps their newest
    // after a fault), whose row deleted the replay no longer says.
    const principals = [...new Set([...(stopped ? [...byPrincipal.keys(), ...walk.newestAccess.keys()] : []), ...fast])].sort();
    const logs = await store.memberLogs(db, principals);
    for (const principal of principals) {
      const why = await this.#integrity(db, principal, byPrincipal.get(principal), held.filter((grant) => grant.principal === principal), [], undefined, logs);
      if (why !== null) return { kind: 'tampered-member', principal, why };
    }
    return null;
  }

  /**
   * The first member whose row fails its MAC, or names an older access
   * entry than the log's newest about them (`newest`, from the walk, where
   * each entry's MAC was checked, on from the tally).
   */
  #unsealed(rows: readonly Member[], held: readonly GrantRow[], newest: ReadonlyMap<string, bigint>): AccessFault | null {
    for (const row of rows) {
      const grants = held.filter((grant) => grant.principal === row.principal);
      if (!this.#sealed(row, grants)) return { kind: 'tampered-member', principal: row.principal, why: 'mac' };
      if (newest.get(row.principal) !== row.accessSeq) return { kind: 'tampered-member', principal: row.principal, why: 'stale' };
    }
    return null;
  }
}

type Broken = Extract<LogVerification, { ok: false }>;

/** 0.14's chain as the cutover walked it from its newest checkpoint, outside any transaction (`#walkOn`). */
type Walked = { from: Resumed; tally: Tally; digest: string; at: Position };

/**
 * Where a walk of the log resumes: the checkpoint's entry (null for the
 * first entry), the end of the prefix it signed, the tally through there,
 * its members and grants' digest and the entry that keeps them, and where
 * the background rehash goes on from (`#scrub`).
 */
type Resumed = {
  ok: true;
  entry: bigint | null;
  at: Position;
  tally: Tally;
  digest: string;
  carrier: bigint | null;
  scrub: Lap | null;
};

/** A lap of the rehash of the past: the last entry rehashed, and the prefix it rehashes to, signed when it began. */
type Lap = { at: Position; end: Position };

/** Where the next rehash of the past goes on from, null for the first entry; or what it found. */
type Scrubbed = { ok: true; next: Lap | null } | Broken;

const FIRST_ENTRY: Resumed = { ok: true, entry: null, at: START, tally: EMPTY_TALLY, digest: accessDigest(EMPTY_TALLY.access), carrier: null, scrub: null };

/** How far one call walks the log, in entries: a checkpoint's walk from the last, its rehash of the past, and a verification's own walk. */
export type Walks = { checkpoint: number; scrub: number; verify: number };

/**
 * A walk rehashes, MACs and replays some 40 µs of CPU an entry, and 95
 * with V8's optimizer off, as on a cold isolate: 10,000 entries is a beat
 * of catching up, about a second, and a team's instance writes fewer than
 * a thousand a day. The rehash of the past is a hash an entry, 14 µs warm
 * and 55 cold, beside two reads: 100 entries keep it near 6 ms a beat.
 */
const WALKS: Walks = { checkpoint: 10_000, scrub: 100, verify: 10_000 };

/** The digest of the members and grants a checkpoint keeps whole, beside the digest it says they have. */
function keptDigest({ members, grants, newest }: AccessTally): string {
  return accessDigest({ members, grants, newest });
}

/** Each checkpoint entry's metadata, parsed once however many times it is asked about: one may hold every member and grant. */
const parsed = new WeakMap<StoredEntry, unknown>();
function metadataOf(entry: StoredEntry): unknown {
  if (!parsed.has(entry)) parsed.set(entry, JSON.parse(entry.metadata));
  return parsed.get(entry);
}

/** A head, as an entry keeps it, as a walk goes on from it. */
function positionOf(head: LogHead): Position {
  return { seq: BigInt(head.seq), hash: Buffer.from(head.hash, 'hex') };
}

/** A position as the log's heads are named, in hex. */
function headOf(position: Position): LogHead {
  return { seq: Number(position.seq), hash: position.hash.toString('hex') };
}

/** What a checkpoint's signature covers, and nothing it keeps beside it. */
function signedPart({ seq, hash, signedAt, keyId, signature }: Checkpoint): Checkpoint {
  return { seq, hash, signedAt, keyId, signature };
}

/** Checkpoint signatures checked at once. */
const SIGNATURES_AT_ONCE = 256;

/** Settle every operation before releasing the member lock, including cancelled requests. */
async function settle<T extends { wipe: () => void }>(
  operations: ((operation: KeyOperation) => Promise<T | null>)[],
  budgetMs: number,
): Promise<{ outcomes: KeyOutcome<T>[]; expired: boolean }> {
  const controller = new AbortController();
  const operation = { deadline: Date.now() + budgetMs, signal: controller.signal };
  const timer = setTimeout(() => controller.abort(), budgetMs);
  try {
    const outcomes = await Promise.all(operations.map(async (work): Promise<KeyOutcome<T>> => {
      try {
        if (operation.signal.aborted || Date.now() >= operation.deadline) throw new KekCancelledError();
        const value = await work(operation);
        return value === null ? { ok: false, code: 'bad_claim' } : { ok: true, value };
      } catch (error) {
        if (error instanceof KekUnavailableError) {
          return { ok: false, code: error.uncertain ? 'kms_uncertain' : error instanceof KekCancelledError ? 'cancelled' : 'kms_unavailable' };
        }
        return { ok: false, code: 'key_error', error };
      }
    }));
    return { outcomes, expired: controller.signal.aborted || Date.now() >= operation.deadline };
  } finally {
    clearTimeout(timer);
  }
}

function validateText(value: string): void {
  if (typeof value !== 'string' || /[\uD800-\uDFFF]/u.test(value)) throw new Error('key request strings must be well-formed Unicode');
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The app's `credential.use` entry, as the vault appends it beside a read
 * (`UnwrapInput.use`): what the app wrote, checked to be what an entry
 * holds, in its reader's name. The app wrote it under the head itself
 * before 0.14.5; it describes the read, and decides nothing.
 */
function useEntry(principal: string, correlation: Correlation, use: UseRecord): NewEntry {
  const id = (value: unknown, name: string) => {
    if (value !== null && (typeof value !== 'string' || !UUID.test(value))) throw new Error(`a use's ${name} must be a lowercase UUID or null`);
    return value;
  };
  // The bound first: nothing past it is read.
  if (typeof use.metadata !== 'string' || use.metadata.length > USE_METADATA_LENGTH) {
    throw new Error(`a use's metadata must be a JSON object of at most ${USE_METADATA_LENGTH} characters`);
  }
  if (use.sourceIp !== null) validateText(use.sourceIp);
  validateText(use.metadata);
  let metadata: unknown;
  try {
    metadata = JSON.parse(use.metadata);
  } catch {
    metadata = undefined;
  }
  if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
    throw new Error(`a use's metadata must be a JSON object of at most ${USE_METADATA_LENGTH} characters`);
  }
  return {
    actor: principal,
    action: 'credential.use',
    decision: 'allow',
    projectId: id(use.projectId, 'projectId'),
    environmentId: id(use.environmentId, 'environmentId'),
    operationId: correlation.operationId ?? null,
    requestId: correlation.requestId ?? null,
    sourceIp: use.sourceIp,
    metadata: use.metadata,
  };
}

/** The caller's ids go into the log as they are: a request id is text, an operation id a lowercase UUID. */
function validateCorrelation(input: Correlation): void {
  if (input.requestId != null) validateText(input.requestId);
  if (input.operationId != null && (typeof input.operationId !== 'string' || !UUID.test(input.operationId))) {
    throw new Error(`operationId must be a lowercase UUID, got: ${String(input.operationId)}`);
  }
  if (input.credentialId != null && (typeof input.credentialId !== 'string' || !UUID.test(input.credentialId))) {
    throw new Error(`credentialId must be a lowercase UUID, got: ${String(input.credentialId)}`);
  }
  if (!isConfirmation(input.confirmed)) throw new Error('confirmed must name a passkey by its lowercase UUID and when it was touched, ISO 8601');
}

/** Validate the entire batch before any provider sees a key. */
function validateItems(items: readonly { secret: SecretRef; key?: string; wrapped?: WrappedKey }[], field: 'key' | 'wrapped'): void {
  for (const { secret, key, wrapped } of items) {
    if (field === 'key' && typeof key !== 'string') throw new Error('DEK must be base64');
    if (field === 'wrapped' && (wrapped === undefined || wrapped === null)) throw new Error('wrapped key is required');
    checkContext(context(secret));
    if (secret.sensitive !== undefined && typeof secret.sensitive !== 'boolean') throw new Error('a secret is sensitive or not: true, false or absent');
    if (!Number.isSafeInteger(secret.version) || secret.version < 1) throw new Error('secret version must be a positive integer');
    if (typeof secret.path !== 'string' || /[\uD800-\uDFFF]/u.test(secret.path)) throw new Error('secret path must be a well-formed string');
    if (key !== undefined) {
      const dek = Buffer.from(key, 'base64');
      try {
        if (dek.length !== DEK_BYTES) throw new Error(`DEK must be ${DEK_BYTES} bytes, got ${dek.length}`);
        if (base64(dek) !== key) throw new Error('DEK must be canonical base64');
      } finally {
        dek.fill(0);
      }
    }
    if (wrapped !== undefined) {
      for (const field of [wrapped.kekProvider, wrapped.kekId, wrapped.kekVersion]) {
        if (typeof field !== 'string' || field.length === 0 || /[\uD800-\uDFFF]/u.test(field)) throw new Error('wrapped key metadata must be nonempty well-formed strings');
      }
      const bytes = Buffer.from(wrapped.bytes, 'base64');
      if (bytes.length === 0 || base64(bytes) !== wrapped.bytes) throw new Error('wrapped key must be nonempty canonical base64');
    }
  }
}

/** A reference as its `reference.create` entry seals it. */
type Sealed = {
  reference: string;
  seq: bigint;
  holder: { projectId: string; environmentId: string; secretId: string; path: string };
  source: { projectId: string; environmentId: string; secretId: string; path: string };
  createdBy: string;
  createdAt: number;
};

/** What a genuine `reference.create` entry seals, if it is about `reference`; null if not, or malformed. */
function sealedReference(entry: StoredEntry, reference: string): Sealed | null {
  let detail: { reference?: unknown; subject?: unknown; secretId?: unknown; source?: { path?: unknown }; also?: Record<string, unknown> };
  try {
    detail = JSON.parse(entry.metadata) as typeof detail;
  } catch {
    return null;
  }
  const text = (value: unknown): value is string => typeof value === 'string' && value !== '';
  const also = detail.also ?? {};
  if (detail.reference !== reference || entry.projectId === null || entry.environmentId === null) return null;
  if (!text(detail.subject) || !text(detail.secretId) || !text(detail.source?.path)) return null;
  if (!text(also.projectId) || !text(also.environmentId) || !text(also.secretId)) return null;
  return {
    reference,
    seq: entry.seq,
    holder: { projectId: entry.projectId, environmentId: entry.environmentId, secretId: detail.secretId, path: detail.subject },
    source: { projectId: also.projectId, environmentId: also.environmentId, secretId: also.secretId, path: detail.source!.path as string },
    createdBy: entry.actor,
    createdAt: entry.occurredAt,
  };
}

/** A read's reference, checked for shape: null for none. */
function validateVia(via: Via | null | undefined): Via | null {
  if (via === undefined || via === null) return null;
  if (typeof via.reference !== 'string' || !UUID.test(via.reference)) throw new Error('a reference id must be a lowercase UUID');
  if (!Number.isSafeInteger(via.seq) || via.seq < 0) throw new Error("a reference's seq must be a whole number");
  return { reference: via.reference, seq: via.seq };
}

/** A read's fork, checked for shape: null for none. */
function validateThrough(through: string | null | undefined): string | null {
  if (through === undefined || through === null) return null;
  if (typeof through !== 'string' || !UUID.test(through)) throw new Error("a fork's id must be a lowercase UUID");
  return through;
}

/**
 * How a read of an inherited value is logged: the fork it was read in,
 * `through`, and as `also`, which puts it in the fork's log too, unless it
 * was read through the parent's reference. The fork decides nothing: the
 * reader's grants where the value is held do, as for any read.
 */
function throughDetail(through: string, fork: { projectId: string; slug: string } | undefined, viaReference: boolean): Record<string, unknown> {
  return {
    through: { environmentId: through, ...(fork === undefined ? {} : { slug: fork.slug }) },
    // Through a reference, the entry is the source's, in another project perhaps, and stays filed where references
    // file theirs: the source and the holder, the parent. A fork's own log would show a reader of the fork alone
    // what the parent's reference reads, which is the parent's to tell.
    ...(viaReference ? {} : { also: { projectId: fork?.projectId ?? null, environmentId: through } }),
  };
}

/**
 * How a read through a reference is logged: the way in, and `also`, the
 * holder's place, which puts the read in the holder's project's log too.
 */
function viaDetail(via: Via, seal: Sealed | null): Record<string, unknown> {
  if (seal === null) return { via: { reference: via.reference, seq: via.seq } };
  return {
    via: { reference: via.reference, seq: via.seq, path: seal.holder.path, createdBy: seal.createdBy, createdAt: iso(seal.createdAt) },
    also: { projectId: seal.holder.projectId, environmentId: seal.holder.environmentId, secretId: seal.holder.secretId },
  };
}

/**
 * An entry about a key. A new secret's row is not committed when its key is
 * wrapped, so a wrap names the secret in its payload; the others name it.
 */
/** Where a key's outcome is logged, as its intent keeps it for a rotation to log it as (`#closeIntents`). */
type Logged = { projectId: string | null; environmentId: string | null; secretId: string | null; secretVersionId: string | null; detail: Record<string, unknown> };

function loggedAs(entry: NewEntry): Logged {
  return {
    projectId: entry.projectId ?? null, environmentId: entry.environmentId ?? null, secretId: entry.secretId ?? null,
    secretVersionId: entry.secretVersionId ?? null, detail: JSON.parse(entry.metadata ?? '{}') as Record<string, unknown>,
  };
}

function keyEntry(
  action: KeyAction,
  principal: string,
  secret: SecretRef,
  decision: 'allow' | 'deny',
  code: string | null,
  correlation: Correlation,
  detail: Record<string, unknown> = {},
): NewEntry {
  return {
    actor: principal,
    action,
    decision,
    code,
    projectId: secret.projectId,
    environmentId: secret.environmentId,
    secretId: action === 'key.wrap' ? null : secret.secretId,
    operationId: correlation.operationId ?? null,
    requestId: correlation.requestId ?? null,
    metadata: JSON.stringify({
      subject: secret.path,
      ...(action === 'key.wrap' ? { secretId: secret.secretId } : {}),
      version: secret.version,
      ...detail,
      ...traced(correlation),
    }),
  };
}

/** What every secret of one read at a place shares, said once in its entry rather than in each of its `secrets`. */
const READ_SHARED = ['purpose', 'intent', 'credentialId', 'through'] as const;

/**
 * A decision's `secret.read` entries, made one per secret, as the log keeps
 * them: one per place it was decided at, the environment read and, through
 * a reference, the holder's, or the fork that inherits it (`also`,
 * `through`). An entry about several secrets lists
 * them in `secrets`, each with what its own entry would have said: its
 * `secretId`, `secretVersionId`, `subject`, `version`, and its `via`, holder
 * (`also.secretId`) and intent `item` when it has them. An entry about one
 * secret is as it always was. A `coffre run` of a hundred keys is one entry,
 * not a hundred; what it decided, and for which keys, is the same. Other
 * entries pass through, in order.
 */
function readsByPlace(entries: readonly NewEntry[]): NewEntry[] {
  const groups = new Map<string, NewEntry[]>();
  const out: (NewEntry | NewEntry[])[] = [];
  for (const entry of entries) {
    if (entry.action !== 'secret.read') {
      out.push(entry);
      continue;
    }
    const { also, through } = JSON.parse(entry.metadata ?? '{}') as { also?: { projectId?: string; environmentId?: string }; through?: unknown };
    const place = JSON.stringify([
      entry.actor, entry.decision, entry.code ?? null, entry.projectId ?? null, entry.environmentId ?? null,
      entry.operationId ?? null, entry.requestId ?? null, String(entry.relatedSeq ?? null), also?.projectId ?? null, also?.environmentId ?? null,
      through ?? null,
    ]);
    const group = groups.get(place);
    if (group !== undefined) {
      group.push(entry);
      continue;
    }
    const fresh = [entry];
    groups.set(place, fresh);
    out.push(fresh);
  }
  return out.map((item) => (Array.isArray(item) ? oneRead(item) : item));
}

/** Entries of one read at one place as one entry: `readsByPlace`. */
function oneRead(group: NewEntry[]): NewEntry {
  const [first] = group as [NewEntry];
  if (group.length === 1) return first;
  const details = group.map((entry) => JSON.parse(entry.metadata ?? '{}') as Record<string, unknown>);
  const shared = Object.fromEntries(READ_SHARED.flatMap((field) => (details[0]![field] === undefined ? [] : [[field, details[0]![field]]])));
  // The place on the other side, which the group shares: a reference's holder, or the fork reading.
  const beside = details[0]!.also as { projectId: string | null; environmentId: string } | undefined;
  const secrets = group.map((entry, i) => {
    const own = Object.fromEntries(Object.entries(details[i]!).filter(([field]) => !(READ_SHARED as readonly string[]).includes(field) && field !== 'also'));
    // A reference's holder is its own; a fork's `also` names only the fork, which the entry says once.
    const holder = (details[i]!.also as { secretId?: string } | undefined)?.secretId;
    return {
      ...(entry.secretId == null ? {} : { secretId: entry.secretId }),
      ...(entry.secretVersionId == null ? {} : { secretVersionId: entry.secretVersionId }),
      ...own,
      ...(holder === undefined ? {} : { also: { secretId: holder } }),
    };
  });
  return {
    ...first,
    secretId: null,
    secretVersionId: null,
    metadata: JSON.stringify({
      ...shared,
      ...(beside === undefined ? {} : { also: { projectId: beside.projectId, environmentId: beside.environmentId } }),
      secrets,
    }),
  };
}

/** Whether `entry` changes a member's access: what their row's `access_seq` names. */
function isAccessEntry(entry: NewEntry): boolean {
  return (
    entry.decision === 'allow' &&
    entry.subjectPrincipal !== undefined &&
    entry.subjectPrincipal !== null &&
    (ACCESS_ACTIONS as readonly string[]).includes(entry.action)
  );
}

/** An entry about a member's access. */
function accessEntry(
  actor: string,
  action: string,
  principal: string,
  decision: 'allow' | 'deny',
  correlation: Correlation,
  detail: Record<string, unknown>,
  code: RefusalCode | null = null,
): NewEntry {
  return {
    actor,
    action,
    decision,
    code,
    // A refusal may be about something that is no principal at all.
    subjectPrincipal: PRINCIPAL.test(principal) ? principal : null,
    operationId: correlation.operationId ?? null,
    requestId: correlation.requestId ?? null,
    metadata: JSON.stringify(PRINCIPAL.test(principal) ? { ...detail, ...traced(correlation) } : { subject: principal, ...detail, ...traced(correlation) }),
  };
}

/**
 * Where an entry about a grant says it is: its project and environment; or,
 * for a grant on every project of 0.4, neither, and the place as a path in
 * its payload, `*`, or `*` and the slug, as 0.4 wrote it.
 */
function located(place: store.Place): { ids: Pick<NewEntry, 'projectId' | 'environmentId'>; detail: { place?: string } } {
  return place.projectId === null && place.environmentId === null
    ? { ids: {}, detail: { place: place.environmentSlug === null ? '*' : `*/${place.environmentSlug}` } }
    : { ids: { projectId: place.projectId, environmentId: place.environmentId }, detail: {} };
}

/** One key per place a member can hold a grant at, by what the grant names first: its environment, its project, or neither, on every project of 0.4. */
/** Every project there is now and each of its environments, as a permission check names them. */
function placesOf(projects: readonly { id: string; environments: readonly { id: string; slug: string }[] }[]): Place[] {
  return projects.flatMap((project) => [
    { projectId: project.id },
    ...project.environments.map((environment) => ({ projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug })),
  ]);
}

function placeKey(place: store.Place): string {
  if (place.environmentId !== null) return `environment:${place.environmentId}`;
  return place.projectId !== null ? `project:${place.projectId}` : `every-project:${place.environmentSlug ?? ''}`;
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** A change, as its entry names it. */
function describeChange(change: PolicyChange | undefined): Record<string, unknown> | null {
  if (change === undefined || change === null || typeof change !== 'object') return null;
  if (change.kind === 'protect') return { kind: 'protect', projectId: change.projectId, environmentIds: change.environmentIds, protected: change.protected };
  return { kind: change.kind, role: change.role, definition: change.definition };
}

/** What a change changed, as it was: the role's definition, or which environments were protected. */
function describeBefore(change: PolicyChange, before: Policy): Record<string, unknown> {
  if (change.kind === 'protect') return { protected: change.environmentIds.filter((id) => before.protected.includes(id)) };
  const table = change.kind === 'instance-role' ? before.instanceRoles as Record<string, RoleDefinition> : before.roles;
  return { definition: Object.hasOwn(table, change.role) ? table[change.role] : null };
}

/** A secret's binding context: its ids, a personal config's owner, hashed, as the decision read it, and whether it is sensitive. */
function context(secret: SecretRef, owner?: string): SecretContext {
  return {
    projectId: secret.projectId,
    environmentId: secret.environmentId,
    secretId: secret.secretId,
    ...(owner === undefined ? {} : { owner }),
    ...(secret.sensitive === true ? { sensitive: true as const } : {}),
  };
}

function unwrappable(wrapped: WrappedKey) {
  return { ...wrapped, bytes: Buffer.from(wrapped.bytes, 'base64') };
}

function serialisable(wrapped: { kekProvider: string; kekId: string; kekVersion: string; bytes: Buffer }): WrappedKey {
  return { ...wrapped, bytes: base64(wrapped.bytes) };
}

/**
 * Bytes as base64. Through `Buffer.from`, a view of the same memory, because
 * Workers' types declare their own `Buffer` and a bare one loses its
 * `toString(encoding)` to them.
 */
function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}

/** An entry as `vouch` was given it, as the trees take it; null for one of no shape a row has. */
function vouchedEntry(entry: Exclude<VouchedEntry, { tree: 'reads' | 'cursor' }>): LogEntry | null {
  const hex = (value: unknown) => (typeof value === 'string' && /^(?:[0-9a-f]{2})*$/.test(value) ? Buffer.from(value, 'hex') : null);
  const text = (value: unknown) => typeof value === 'string';
  if (typeof entry !== 'object' || entry === null || !text(entry.number) || !/^[0-9]{1,19}$/.test(entry.number) || !Number.isSafeInteger(entry.at) || !text(entry.requestId)) return null;
  const mac = hex(entry.mac);
  if (mac === null) return null;
  const number = BigInt(entry.number);
  if (entry.tree === 'changes') {
    const seal = entry.seal === null ? null : hex(entry.seal);
    if (!text(entry.object) || !text(entry.actor) || !text(entry.payload) || (entry.seal !== null && seal === null)) return null;
    return changeEntry({ number, at: entry.at, requestId: entry.requestId, object: entry.object, actor: entry.actor, payload: entry.payload, seal, mac });
  }
  if (entry.tree !== 'uses' || !/^[0-9]{1,19}$/.test(entry.requestId) || !text(entry.credential) || !text(entry.secret) || !Number.isSafeInteger(entry.purpose)
    || (entry.place !== null && !text(entry.place)) || (entry.route != null && !text(entry.route))) return null;
  return usedEntry({ number, at: entry.at, requestId: BigInt(entry.requestId), credential: entry.credential, secret: entry.secret, purpose: entry.purpose, place: entry.place, route: entry.route ?? null, mac });
}

/** A read as `vouch` was given it (`log_reads`, T166); null for one of no shape the projector writes. */
function vouchedRead(entry: Extract<VouchedEntry, { tree: 'reads' }>): ReadRow | null {
  const id = (value: unknown) => typeof value === 'string' && value.length > 0;
  const maybe = (value: unknown): value is string | null => value === null || id(value);
  const mac = typeof entry.mac === 'string' && /^[0-9a-f]{32}$/.test(entry.mac) ? Buffer.from(entry.mac, 'hex') : null;
  if (mac === null || typeof entry.number !== 'string' || !/^[0-9]{1,19}$/.test(entry.number) || !Number.isSafeInteger(entry.at) || !Number.isSafeInteger(entry.purpose)
    || !id(entry.credential) || !id(entry.principal) || !id(entry.secret) || !id(entry.environment) || !id(entry.project)
    || !maybe(entry.place) || !maybe(entry.source) || !maybe(entry.sourceEnvironment) || !maybe(entry.sourceProject) || !maybe(entry.version)) return null;
  return { ...entry, number: BigInt(entry.number), mac };
}
