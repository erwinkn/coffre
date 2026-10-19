import { randomUUID, timingSafeEqual } from 'node:crypto';

import {
  allows,
  assignableToEnvironment,
  DEFAULT_POLICY,
  definitionProblem,
  EVERY_ENVIRONMENT,
  EVERYWHERE,
  FIXED_ROLES,
  givesService,
  guarded,
  grantKind,
  INSTANCE_ROLES,
  isBuiltinRole,
  isCredentialScope,
  isInstanceRole,
  isRole,
  isScope,
  managesService,
  mayManageAccess,
  normalDefinition,
  normalScope,
  NOTHING,
  ownsInstance,
  PROJECT_ONLY_PERMISSIONS,
  ROLE_ID,
  ROLES,
  runsInstance,
  setsUpServices,
  UNWRITTEN_FORK_MS,
  type Holdings,
  type InstanceRole,
  type Permission,
  type Place,
  type Policy,
  type Role,
  type RoleDefinition,
  type Scope,
  type ServiceAccount,
  withinCredential,
} from '@coffre/core/access';
import { GENESIS_HASH, verifyEntries, type LogKey, type StoredEntry } from '@coffre/core/audit';
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
  checkpointVerifier,
  describeAccessFault,
  handsBack,
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
  type Purpose,
  type ReferenceInput,
  type Refusal,
  type RefusalCode,
  type RemoveInput,
  type RewrapInput,
  type SecretRef,
  type SetAccessInput,
  type SetSettingsInput,
  type Settings,
  type Through,
  type UnwrapInput,
  type Wrapped,
  type Vault,
  type Via,
  type VerifyLogInput,
  type WrapInput,
  type WrappedKey,
} from '@coffre/core/vault';
import type { Database, Queryable, Transaction } from '@coffre/db';
import { isUniqueViolation, SNAPSHOT } from '@coffre/db/dialect';
import { everyProjectConversion, newestAccess, reportStands } from '@coffre/db/grants';
import { appendEntries, LOOK_BACK, lockLogHead, newestAuthentic, newestVaultSeq, type Appended, type Authenticity, type Newest, type NewEntry } from '@coffre/db/log';

import { KeyAccounting } from './accounting.ts';
import { signer, type Signer } from './checkpoint.ts';
import type { ResolvedVaultConfig } from './config.ts';
import { carries, forward, further, UNVERIFIED, vaultLogKey, VERIFY_BATCH, verifyChain, withCause, type Anchor } from './log.ts';
import { apply, replayFault, type LoggedMember, type Replayed } from './replay.ts';
import { memberMac, rowKey, sameGrants, sealed, standing } from './rows.ts';
import * as store from './store.ts';
import { ACCESS_ACTIONS, type GrantRow, type Member } from './store.ts';

export type VaultOptions = {
  /**
   * How long every key operation of one call may take, in milliseconds;
   * 5 seconds unless set. Past it, a call fails as an outage.
   */
  keyBudgetMs?: number;
  /** Milliseconds added to the database's clock where the vault decides by it. Tests move time with it. */
  clockOffset?: () => number;
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
  options: Required<VaultOptions>;
  /** How far the log is verified; `verifyChain` in log.ts. The furthest any call got to. */
  verified: Anchor;
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
};

export async function prepareVault(config: ResolvedVaultConfig, options: VaultOptions = {}): Promise<PreparedVault> {
  return {
    config,
    ...(await keysOf(config.signingKeys)),
    options: { keyBudgetMs: options.keyBudgetMs ?? KEY_BUDGET_MS, clockOffset: options.clockOffset ?? (() => 0) },
    verified: UNVERIFIED,
    reported: new Set(),
    since: null,
    superseded: null,
    kekChecked: false,
    wrongKek: null,
    converted: false,
  };
}

/** The vault's own keys, from each of its signing keys, the one it signs with first. */
async function keysOf(seeds: readonly Uint8Array[]) {
  const signers = await Promise.all(seeds.map((seed) => signer(seed)));
  const logKeys = seeds.map((seed) => vaultLogKey(seed));
  const rowKeys = seeds.map((seed) => rowKey(seed));
  return { signer: signers[0], signers, logKey: logKeys[0], logKeys, rowKey: rowKeys[0], rowKeys };
}

/** The vault over `db`. Cheap: on Workers, one per call, over that call's connections. */
export function openVault(db: Database, prepared: PreparedVault): Vault {
  return new VaultService(db, prepared);
}

/** Every key operation of one call, together: a removal waits at most this long for a read at KMS. */
const KEY_BUDGET_MS = 5_000;

/** How long a decision waits for a lock: above the key budget, so a removal outwaits a read in flight. */
const LOCK_TIMEOUT_MS = 15_000;

/** A member: `user:<email>` or `token:<name>`. */
const PRINCIPAL = /^(user|token):[^\s:][^\s]*$/;

/** A person, and a service account: only a person sets one up (`givesService`). */
const PERSON = /^user:/;
const SERVICE = /^token:/;

/** Who acts for the vault itself, as when it makes an Owner its deployment names. */
const VAULT_ACTOR = 'system:vault';

// A KEK's check: a known value, the size of a data key, wrapped under it in
// a context no secret has (the nil UUID), and kept in a `key.check` entry
// (@coffre/core/kek). Opening it again tells the vault its KEK is the one
// that wrapped the data, without opening any data; `coffre verify keys`
// holds an escrowed key to it the same way.

/** How many stored keys a KEK with no check yet is tried on: one that opens proves it. */
const KEY_CHECK_SAMPLE = 3;

/** The vault's first entry under a new key, which the keys it replaced count only before (`#settle`). */
const KEY_ROTATE = 'key.rotate';

/** A new member row, before the decision seals it (`#seal`). */
const UNSEALED = { accessSeq: 0n, mac: Buffer.alloc(32) };

/** Why a change to a tampered member is refused. */
const TAMPERED_SUBJECT = "this member's record failed the vault's integrity check: remove them to start over";

/** The action of the vault's entry that signs a prefix of the log. */
const CHECKPOINT = 'audit.checkpoint';

/** The action of the vault's entry that holds the instance's settings, and changes them (`settings`). */
const SETTINGS = 'settings.change';

/** The settings before anyone changed them: people set up service accounts anywhere they hold access. */
const DEFAULT_SETTINGS: Settings = { serviceAccounts: EVERYWHERE };

/** The action of the vault's entry that holds the instance's access policy, and changes it (`policy`). */
const POLICY = 'policy.change';

/**
 * What a `policy.change` entry keeps: the roles an Owner edited or made,
 * each whole, and the protected environments. A role as it ships is kept by
 * none, so a release that changes a default changes it where nobody edited it.
 */
type PolicyEdits = { roles: Record<string, RoleDefinition>; instanceRoles: Partial<Record<InstanceRole, RoleDefinition>>; protected: ProtectedPlace[] };

/**
 * A protected environment, with its project's id, what a grant on the whole
 * project reaches of it, and when it was protected, by the vault's clock:
 * an id with no row an hour later is a fork that was never written.
 */
type ProtectedPlace = { projectId: string; environmentId: string; at: number };


const NO_EDITS: PolicyEdits = { roles: {}, instanceRoles: {}, protected: [] };

/** A role holding nothing, which every role but Owner is under the closed policy. */
const NOTHING_HELD = (definition: RoleDefinition): RoleDefinition => ({ ...definition, permissions: [], protected: [] });

/**
 * The policy when the log has some, but none the vault wrote within reach:
 * whoever inserted rows may have hidden an Owner's narrowing, so no role
 * holds anything, a service account's neither, but Owner, which holds
 * everything always and so may write the policy again.
 */
const CLOSED_POLICY: Policy = {
  roles: Object.fromEntries(Object.entries(ROLES).map(([id, definition]) => [id, id === 'owner' ? definition : NOTHING_HELD(definition)])),
  instanceRoles: Object.fromEntries(Object.entries(INSTANCE_ROLES).map(([id, definition]) => [id, id === 'owner' ? definition : NOTHING_HELD(definition)])) as Policy['instanceRoles'],
  protected: [EVERY_ENVIRONMENT],
  protectedIn: {},
};

/** The settings when the log has some, but none the vault wrote within reach: people set up no service accounts. */
const CLOSED_SETTINGS: Settings = { serviceAccounts: { projects: { only: [] }, environments: 'all' } };

/** Why a change to who is an Owner, scoped or not, is refused to anyone else: Owners make and unmake Owners. */
const OWNERS_ONLY = 'only an Owner of the whole instance makes someone an Owner, or changes or removes one';

/** Why nobody demotes or removes a person the deployment names (`owners`), themselves included. */
function declaredOwner(principal: string): string {
  return `the deployment names ${principal.slice('user:'.length)} an Owner (owners, in the vault's configuration): take them off that list and deploy first`;
}

/** Why a person's change to a service account is refused. */
const NOT_THEIRS = 'a person gives a service account at most what they hold, where the instance lets them set one up, and only to one whose every grant they hold';

/** Who asks for checkpoints: the app's scheduled job. */
const SCHEDULER = 'system:coffre-scheduler';

/**
 * How often a checkpoint recomputes the chain from its first entry: the
 * first of each hour, by the vault's clock. The others resume from the
 * prefix the last one signed (`#recompute`).
 */
const FULL_RECOMPUTE_MS = 60 * 60 * 1000;

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
const LOOSER = 'a value is made less sensitive only by writing it again: an old version comes back, and a key is made stricter, as sensitive as its newest version or more';

function refusal(code: RefusalCode, message: string): Refusal {
  return { code, message };
}

const MESSAGES: Record<RefusalCode, string> = {
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
  not_allowed: 'not allowed to change this',
  last_owner: 'the last Owner of the whole instance stays one: make someone else an Owner first',
  invalid: 'not something the rules allow',
  policy_changed: "the instance's roles or protected environments changed while this was asked: try again",
  log_broken: 'the vault log does not hold from the last checkpoint',
  wrong_kek: "this vault's key does not open the data it holds",
  tampered: "this member's record failed the vault's integrity check",
};

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
};

/** The actions of the entries the vault writes about keys. */
type KeyAction = 'secret.read' | 'key.wrap' | 'key.rewrap';

/** What ties an entry to the app's request, and to the one action it is part of. */
type Correlation = { requestId?: string | null; operationId?: string | null; credentialId?: string | null };

/**
 * What the one asking holds through the credential their request came in
 * on: no more than its scope (`allows`). A scope that is not one is a bug
 * of the app's, which fails the call.
 */
function through(standing: Standing, { credentialScope }: Through): Standing {
  if (credentialScope == null) return standing;
  if (!isCredentialScope(credentialScope)) throw new Error('credentialScope must be a list of grants, one a place');
  return { ...standing, live: { ...standing.live, credentialScope }, all: { ...standing.all, credentialScope } };
}

/** The credential a CI run's request came in on, as its entries record it: copied, never decided on. */
function traced(correlation: Correlation): { credentialId?: string } {
  return correlation.credentialId == null ? {} : { credentialId: correlation.credentialId };
}

/** Why a member's row is not the one the vault last wrote; rows.ts. */
type Fault = 'mac' | 'stale';

/**
 * What someone holds, read once per decision; `fault` when their row fails
 * its check, and they hold nothing. `stored` is the grants as read, which
 * the check verified when `fault` is null.
 */
type Standing = { principal: string; status: Access['status']; live: Holdings; all: Holdings; fault: Fault | null; stored: GrantRow[] };

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

  constructor(db: Database, prepared: PreparedVault) {
    this.#db = db;
    this.#prepared = prepared;
    this.#config = prepared.config;
  }

  async #now(db: Queryable): Promise<number> {
    return (await store.now(db)) + this.#prepared.options.clockOffset();
  }

  /**
   * Decide in one transaction, with `principals`' rows locked first, then
   * the log's head. A `Refused` or an `Outage` rolls back all but its own
   * entries, which commit on their own: then the refusal is the answer, and
   * the outage fails the call.
   *
   * Every change to the policy, the settings, a member or a place appends
   * under the head, so whatever the decision reads of them stands until it
   * commits: no decision acts on a policy read before it. A key operation
   * alone takes the head later (`late`), once its key service has answered,
   * which it must not wait on holding it, and decides again then (`#keys`).
   */
  async #decide<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>, late = false): Promise<Outcome<T>> {
    const superseded = await this.#settled();
    if (superseded !== null) return { ok: false, refusal: refusal('wrong_kek', superseded) };
    return this.#decideNow(principals, decide, late);
  }

  /** `#decide`, once the vault is settled. */
  async #decideNow<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>, late = false): Promise<Outcome<T>> {
    const reports: NewEntry[] = [];
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.#decideOnce(principals, decide, reports, late);
      } catch (error) {
        // A member who had no row when this decision locked theirs, and has
        // one now: another decision admitted them meanwhile. Again, with it.
        if (attempt < 3 && (error instanceof Retry || isUniqueViolation(error))) continue;
        throw error;
      }
    }
  }

  async #decideOnce<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>, reports: NewEntry[], late: boolean): Promise<Outcome<T>> {
    try {
      const result = await this.#db.transaction(async (tx) => {
        await store.boundLockWaits(tx, LOCK_TIMEOUT_MS);
        const members = principals.length === 0 ? new Map<string, Member>() : await store.lockMembers(tx, principals);
        if (!late) await lockLogHead(tx);
        const d: Decision = {
          tx, members, at: await this.#now(tx), log: [], writes: [], touched: new Set(), grants: new Map(), reports, after: [], underLock: [],
        };
        const result = await decide(d);
        // A read is logged once per place, whichever way it ends (`readsByPlace`).
        const entries = [...reports, ...readsByPlace(d.log)];
        let at = d.at;
        // Each member's newest access entry, which their row names (rows.ts).
        const accessSeq = new Map<string, bigint>();
        if (entries.length > 0) {
          const appended = await this.#append(tx, entries, d.underLock);
          at = appended.occurredAt;
          entries.forEach((entry, i) => {
            if (isAccessEntry(entry)) accessSeq.set(entry.subjectPrincipal!, appended.seqStart + BigInt(i));
          });
          const seqs = new Map(entries.map((entry, i) => [entry, Number(appended.seqStart) + i]));
          for (const then of d.after) then((entry) => seqs.get(entry)!);
        }
        for (const write of d.writes) await write(at);
        for (const principal of new Set([...d.touched, ...accessSeq.keys()])) {
          await this.#seal(d, principal, accessSeq.get(principal));
        }
        return result;
      });
      this.#reported(reports);
      return { ok: true, ...result };
    } catch (error) {
      if (!(error instanceof Refused || error instanceof Outage)) throw error;
      const entries = [...reports, ...readsByPlace(error.entries)];
      if (entries.length > 0) {
        await this.#db.transaction(async (tx) => {
          await store.boundLockWaits(tx, LOCK_TIMEOUT_MS);
          await this.#append(tx, entries);
        });
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
   * rather than sealed in.
   */
  async #seal(d: Decision, principal: string, accessSeq: bigint | undefined): Promise<void> {
    const row = await store.member(d.tx, principal);
    if (row === undefined) return;
    const decided = d.grants.get(principal);
    if (decided === undefined) throw new Error(`sealing ${principal} without the grants this decision verified`);
    if (!sameGrants(await store.grants(d.tx, principal), decided)) {
      this.#report(d.reports, principal, 'mac', row.mac.toString('hex'));
      throw new Refused(refusal('tampered', MESSAGES.tampered), []);
    }
    const next = { ...row, accessSeq: accessSeq ?? row.accessSeq };
    await store.updateMember(d.tx, principal, { accessSeq: next.accessSeq, mac: memberMac(this.#prepared.rowKey, next, decided) });
  }

  /**
   * Whether `row`, with these grants, is the row the vault last wrote: its
   * MAC holds, and it names the newest access entry the log has about the
   * member. A genuine row put back from before a later change passes the
   * first and fails the second. Entries in the vault's name that fail their
   * MAC are passed over, and reported: otherwise whoever can insert a row
   * could lock any member out.
   */
  async #integrity(db: Queryable, principal: string, row: Member | undefined, grants: readonly GrantRow[], reports: NewEntry[]): Promise<Fault | null> {
    if (row !== undefined && !this.#sealed(row, grants)) {
      this.#report(reports, principal, 'mac', row.mac.toString('hex'));
      return 'mac';
    }
    const newest = await this.#newestAccess(db, principal, reports);
    // No row, and no entry of the vault's own: someone never admitted. No
    // row, but one: one deleted, unless it was admitted since the row was
    // read. Too many forged to see past: neither a row nor the lack of one holds.
    const seq = typeof newest !== 'string' ? newest.seq : newest === 'unreached' ? undefined : null;
    if (row === undefined ? seq === null : seq === row.accessSeq) return null;
    if (row === undefined && (await store.member(db, principal)) !== undefined) throw new Retry();
    this.#report(reports, principal, 'stale', `${row?.accessSeq ?? 'none'}<${seq ?? newest}`);
    return 'stale';
  }

  /** The newest access entry about `principal` that carries the vault's MAC (`newestAccess` in @coffre/db/grants). */
  #newestAccess(db: Queryable, principal: string, reports: NewEntry[]): Promise<Newest> {
    return newestAccess(db, principal, this.#check(reports, principal));
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
    const { logKeys, since } = this.#prepared;
    const keys = since !== null && entry.seq >= since ? logKeys.slice(0, 1) : logKeys;
    return verifyEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash, keys }).ok;
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

  /** A `vault.tampered` entry, once per process for each thing found: `#reported` marks it once committed. */
  #report(reports: NewEntry[], principal: string | null, code: Fault | 'forged_entry', detail: string, relatedSeq: bigint | null = null): void {
    const key = `${principal}|${code}|${detail}`;
    if (this.#prepared.reported.has(key) || reports.some((entry) => REPORTED.get(entry) === key)) return;
    const entry: NewEntry = {
      actor: VAULT_ACTOR,
      action: 'vault.tampered',
      decision: 'deny',
      code,
      subjectPrincipal: principal,
      relatedSeq,
      metadata: '{}',
    };
    REPORTED.set(entry, key);
    reports.push(entry);
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
    // Each call that finds it unsettled reads for itself, over its own
    // database; calls that race settle it alike, and a rotation they race
    // to write goes in once (`#rotate`).
    if (prepared.since === null && prepared.superseded === null) await this.#settle();
    // A log with no entry of the vault's holds nothing to convert, and stays empty until someone acts.
    if (prepared.superseded === null && prepared.since !== null && !prepared.converted) await this.#convert();
    return prepared.superseded;
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
  async #convert(): Promise<void> {
    for (const principal of await store.everyProjectHolders(this.#db)) {
      await this.#decideNow([principal], (d) => this.#replaceEveryProject(d, principal));
    }
    this.#prepared.converted = await this.#declare(this.#config.owners.map((email) => `user:${email}`));
  }

  async #replaceEveryProject(d: Decision, principal: string): Promise<void> {
    const row = d.members.get(principal);
    const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
    if (row === undefined || subject.status !== 'active') return;
    const everyProject = subject.stored.filter((grant) => grant.projectId === null && grant.environmentId === null);
    if (everyProject.length === 0) return;
    if (await reportStands(d.tx, principal, this.#check(d.reports, principal))) return;
    // The projects there are now, read under the log's head, which a deletion holds.
    const before = roleOf(principal, row);
    const conversion = everyProjectConversion(principal, before.role, subject.stored, d.at, await store.liveProjects(d.tx));
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
  async #settle(): Promise<void> {
    const prepared = this.#prepared;
    const current = prepared.logKey.keyId;
    for (let attempt = 1; ; attempt += 1) {
      const rotation = await store.latestVaultEntry(this.#db, [KEY_ROTATE]);
      if (rotation?.keyId === current && this.#authentic(rotation)) {
        prepared.since = rotation.seq;
        return;
      }
      const [newest] = await store.vaultPage(this.#db, undefined, 1);
      // A log the vault has not written to: nothing to settle until it does.
      if (newest === undefined) return;
      const first = await store.firstVaultEntryUnder(this.#db, current);
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
    const since = await this.#db.transaction(async (tx) => {
      await store.boundLockWaits(tx, LOCK_TIMEOUT_MS);
      const principals = (await store.allMembers(tx)).map((row) => row.principal);
      const rows = principals.length === 0 ? new Map<string, Member>() : await store.lockMembers(tx, principals);
      await lockLogHead(tx);
      const [newest] = await store.vaultPage(tx, undefined, 1);
      if (newest?.keyId !== from || (await store.allMembers(tx)).length !== rows.size) throw new Retry();
      const held = await store.grants(tx);
      for (const row of rows.values()) {
        const grants = held.filter((grant) => grant.principal === row.principal);
        // A row that fails is reported, and left under the key it was sealed with, which fails it from now on.
        if ((await this.#integrity(tx, row.principal, row, grants, reports)) === null) {
          await store.updateMember(tx, row.principal, { mac: memberMac(this.#prepared.rowKey, row, grants) });
        }
      }
      const rotated = { actor: VAULT_ACTOR, action: KEY_ROTATE, decision: 'allow' as const, metadata: JSON.stringify({ from }) };
      return (await this.#append(tx, [rotated, ...reports])).seqStart;
    });
    this.#reported(reports);
    return since;
  }

  /**
   * Append under the vault's current key, unless the log's newest rotation
   * is to a key it does not hold: a vault given a newer KEK has replaced
   * this one, which writes nothing more. Checked under the head's lock, so
   * that an instance still running with the replaced KEK, as during a
   * deploy, cannot write after the rotation.
   */
  #append(tx: Transaction, entries: readonly NewEntry[], underLock: readonly ((locked: Queryable) => Promise<void>)[] = []): Promise<Appended> {
    const prepared = this.#prepared;
    return appendEntries(tx, prepared.logKey, entries, async (locked) => {
      const rotation = await store.latestVaultEntry(locked, [KEY_ROTATE]);
      if (rotation !== undefined && !prepared.logKeys.some((key) => key.keyId === rotation.keyId)) {
        prepared.superseded = `the log moved on to ${rotation.keyId}, a key this vault does not hold: a vault given a newer vault key replaced it, and a replaced key writes nothing more`;
        throw new Error(prepared.superseded);
      }
      for (const check of underLock) await check(locked);
    });
  }

  // --- keys -------------------------------------------------------------------

  // Raw DEKs are cleared on every path. JSON and base64 leave strings that
  // cannot be wiped, so this is best-effort memory hygiene.
  async unwrap(input: UnwrapInput): Promise<Outcome<{ keys: string[] }>> {
    const { principal } = input;
    validateText(input.purpose);
    if (input.keepsSensitive !== undefined && typeof input.keepsSensitive !== 'boolean') throw new Error('keepsSensitive is true, false or absent');
    const vias = input.items.map((item) => validateVia(item.via));
    const throughs = input.items.map((item) => validateThrough(item.through));
    const loaded = await this.#versions(input, 'secret.read', { purpose: input.purpose });
    if (!loaded.ok) return loaded;
    // RPC can preserve shared objects, and two holders can read one source: each item its own secret.
    const items = loaded.versions.map((version) => ({ ...version, secret: { ...version.secret } }));
    validateItems(items, 'wrapped');
    const sealed = await this.#referencesAt(vias);
    const forks = await store.environmentsById(this.#db, throughs.flatMap((through) => (through === null ? [] : [through])));
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
      return this.#refuseVersions(principal, 'bad_claim', items.map((item) => entry(item.secret, 'deny', 'bad_claim')));
    }
    if (throughOk.includes(false)) {
      return this.#refuseVersions(principal, 'bad_claim', items.map((item) => entry(item.secret, 'deny', 'bad_claim')));
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
        // Through a reference, the reader's grants on the holder's environment decide.
        places: sealed.map((seal, i) => seal?.holder ?? items[i]!.secret),
        vet: ends.length === 0 ? undefined : async (db) => {
          const ended = await store.endedReferences(db, ends);
          return sealed.map((seal) => (seal !== null && ended.has(seal.seq) ? 'ended' : null));
        },
        remote,
        entry,
        input,
      },
      (contextOf) =>
        items.map(({ secret, wrapped }) => async (operation: KeyOperation) => {
          const key = await this.#open(wrapped, contextOf(secret), operation);
          return key && { key, wipe: () => key.fill(0) };
        }),
      (opened) => ({
        keys: opened.map(({ key }) => {
          try {
            return base64(key);
          } finally {
            key.fill(0);
          }
        }),
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
    // A value is made looser only by writing it again: a sensitive version's key, or one of a secret whose newest is,
    // is never wrapped again as anything but sensitive, so that a person who may not read it never makes it readable.
    if (items.some((item, i) => item.secret.sensitive !== true && (loaded.versions[i].secret.sensitive || loaded.versions[i].newestSensitive))) {
      return this.#refuseVersions(principal, 'invalid', loaded.versions.map((source) => ({
        ...keyEntry('key.rewrap', principal, source.secret, 'deny', 'invalid', input), secretVersionId: source.id,
      })), LOOSER);
    }
    const sources = new Map(items.map((item, i) => [item.secret, loaded.versions[i]]));
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry => ({
      ...keyEntry('key.rewrap', principal, secret, decision, code, input, { from: sources.get(secret)!.secret.version }),
      secretVersionId: sources.get(secret)!.id,
    });
    const remote =
      this.#remote(this.#config.keks.primary) || items.some(({ wrapped }) => this.#remote(this.#config.keks.providerOf(wrapped)));
    return this.#keys(
      {
        action: 'key.rewrap', principal, permission: 'secret.write', secrets: items.map((item) => item.secret), remote, entry, input,
        // Again in the decision and under the log's head: a sensitive version written since it was loaded is as newest as any.
        vet: async (db) => {
          const newest = await store.newestSensitive(db, items.map(({ secret }) => secret.secretId));
          return items.map(({ secret }) => (secret.sensitive !== true && newest.has(secret.secretId) ? 'invalid' : null));
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
    input: Correlation & { principal: string; items: { secretVersionId: string }[] },
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
      })));
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
      }));
    }
    return { ok: true, versions: ids.map((id) => found.get(id)!) };
  }

  async #refuseVersions(principal: string, code: 'bad_claim' | 'deleted' | 'invalid', entries: NewEntry[], message = MESSAGES[code]): Promise<Outcome<never>> {
    return this.#decide([principal], async () => {
      throw new Refused(refusal(code, message), entries);
    });
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
      /** Where each secret's permission is checked, when not where it is: a reference's holder. */
      places?: readonly SecretPlace[];
      /**
       * What else refuses each secret, checked in the decision and again
       * once the log's head is locked, before its entries append.
       */
      vet?: (db: Queryable) => Promise<(RefusalCode | null)[]>;
      remote: boolean;
      entry: (secret: SecretRef, decision: 'allow' | 'deny', code: string | null) => NewEntry;
      input: Correlation & Through & { purpose?: string; keepsSensitive?: boolean };
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
    const wrongKek = await this.#kekMismatch();
    if (wrongKek !== null) {
      return this.#decide([], async () => {
        throw new Refused(refusal('wrong_kek', wrongKek), secrets.map((secret) => entry(secret, 'deny', 'wrong_kek')));
      });
    }
    // Each personal config's owner, hashed, by environment, as the decision read them: what its keys' contexts bind.
    const owners = new Map<string, string>();
    const check = async (d: Decision) => {
      const reader = through(await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports), call.input);
      // One read of the environments the decision is about, as the store has them, not as the app sent them:
      // each secret's and, for a read through a reference, its holder's. A grant on one slug in every project
      // matches the slug there, and a place deleted on either side opens for none.
      const at = secrets.map((secret, i) => call.places?.[i] ?? secret);
      const environments = await store.environmentsById(d.tx, [...secrets, ...at].map((place) => place.environmentId));
      // A personal config's parent, whose read its owner needs.
      const parents = [...environments.values()].flatMap((environment) => (environment.owner === null || environment.parentId === null ? [] : [environment.parentId]));
      for (const [id, parent] of await store.environmentsById(d.tx, parents)) environments.set(id, parent);
      const gone = (place: SecretPlace) => environments.get(place.environmentId)?.deleted ?? false;
      owners.clear();
      for (const [id, environment] of environments) if (environment.owner !== null) owners.set(id, ownerKey(environment.owner));
      const codes: (RefusalCode | null)[] = secrets.map((secret, i) => {
        const personal = personalRefusal(reader, principal, call.permission, secret, at[i]!, environments);
        if (personal !== undefined) return personal;
        const held = refuses(reader, call.permission, placeIn(at[i]!, environments), gone(secret) || gone(at[i]!));
        // Through a reference into a protected environment, a person holds their protected column at its source too: one
        // made before prod was protected lends prod's values to nobody who reads the holder. A service account reads on.
        const source = placeIn(secret, environments);
        return held ?? (at[i] !== secret && guarded(reader.live, source) ? refuses(reader, call.permission, source, false) : null);
      });
      if (call.vet !== undefined && !codes.some((code) => code !== null)) {
        (await call.vet(d.tx)).forEach((code, i) => (codes[i] = code));
      }
      // A sensitive value is only ever used for a person, never handed back, by whatever credential of theirs asks. And
      // a fork copies one, for anyone, a service account too, only where its app says it keeps it sensitive: an app of
      // 0.9, mid-deploy, would write the copy as a secret its people read.
      const copying = action === 'secret.read' && call.input.purpose === 'copy';
      const handedBack = action === 'secret.read' && principal.startsWith('user:') && handsBack({ purpose: call.input.purpose ?? '', keepsSensitive: call.input.keepsSensitive === true });
      if (handedBack || (copying && call.input.keepsSensitive !== true)) {
        secrets.forEach((secret, i) => {
          if (codes[i] === null && secret.sensitive === true) codes[i] = 'sensitive';
        });
      }
      let first = codes.find((code) => code !== null) ?? null;
      if (first === null && action === 'secret.read' && (await this.#overBulkLimit(d, principal, secrets.length))) first = 'bulk_limit';
      if (first !== null) {
        throw new Refused(
          refusal(first, MESSAGES[first]),
          secrets.map((secret, i) => entry(secret, 'deny', codes[i] ?? first)),
        );
      }
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
        const at = await this.#now(d.tx);
        const appended = await this.#append(d.tx, [{
          actor: principal,
          action: 'key.intent',
          decision: 'allow',
          operationId: call.input.operationId ?? null,
          requestId: call.input.requestId ?? null,
          metadata: JSON.stringify({
            intent: intentId,
            operation: action,
            // Member and outcome locks can each wait before accounting is overdue.
            expiresAt: at + this.#prepared.options.keyBudgetMs + 2 * LOCK_TIMEOUT_MS,
            ...(call.input.purpose === undefined ? {} : { purpose: call.input.purpose }),
            ...traced(call.input),
            keys: secrets.map((secret, item) => ({ item, subject: secret.path, secretId: secret.secretId, version: secret.version })),
          }),
        }]);
        return { seq: appended.seqStart };
      });
      if (!intent.ok) return intent;
      intentSeq = intent.seq;
    }

    return this.#decide([principal], async (d) => {
      try {
        await check(d);
      } catch (error) {
        if (error instanceof Refused) {
          throw new Refused(error.refusal, secrets.map((secret, item) =>
            outcomeEntry(secret, item, 'deny', error.entries[item].code ?? error.refusal.code)));
        }
        throw error;
      }
      // A reference ended while this decided refuses it, rather than a read logged after its end.
      const { vet } = call;
      if (vet !== undefined) {
        d.underLock.push(async (locked) => {
          const codes = await vet(locked);
          const first = codes.find((code) => code !== null);
          if (first === undefined || first === null) return;
          throw new Refused(refusal(first, MESSAGES[first]), secrets.map((secret, item) => outcomeEntry(secret, item, 'deny', codes[item] ?? first)));
        });
      }
      const { outcomes, expired } = await settle(operations((secret) => context(secret, owners.get(secret.environmentId))), this.#prepared.options.keyBudgetMs);
      const done = outcomes.flatMap((outcome) => (outcome.ok ? [outcome.value] : []));
      try {
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
          throw new Refused(refusal('bad_claim', MESSAGES.bad_claim), entries());
        }
        // Again under the log's head, the append's, taken a statement early: a
        // deletion renames its place under it, so one that committed since the
        // check above is seen here, and nothing is released after it.
        // A read through a reference: its holder's place too, which a deletion may have taken.
        await lockLogHead(d.tx);
        // And as the policy is now, under the head every change to it takes: an environment protected, or a role narrowed,
        // since the check above is seen here, and nothing it refuses now is released.
        try {
          await check(d);
        } catch (error) {
          if (error instanceof Refused) {
            throw new Refused(error.refusal, secrets.map((secret, item) => outcomeEntry(secret, item, 'deny', error.entries[item].code ?? error.refusal.code)));
          }
          throw error;
        }
        const places = secrets.flatMap((secret, i) => [secret, call.places?.[i] ?? secret]);
        const now = await store.environmentsById(d.tx, places.map((place) => place.environmentId));
        if (places.some((place) => now.get(place.environmentId)?.deleted ?? false)) {
          throw new Refused(refusal('deleted', MESSAGES.deleted), secrets.map((secret, i) => outcomeEntry(secret, i, 'deny', 'deleted')));
        }
        const released = secrets.map((secret, i) => outcomeEntry(secret, i, 'allow', null));
        d.log.push(...released);
        const answer = result(done);
        // A wrap's answer names its entries, which the app's writes refer to.
        if (action !== 'secret.read') d.after.push((seqOf) => Object.assign(answer as object, { seqs: released.map(seqOf) }));
        return answer;
      } finally {
        for (const value of done) value.wipe();
      }
    }, true);
  }

  /** Whether `n` more keys would take `principal` past the bulk limit; counted under their row's lock, so exactly. */
  async #overBulkLimit(d: Decision, principal: string, n: number): Promise<boolean> {
    const { count, windowMs } = this.#config.bulkLimit;
    return (await store.releasesSince(d.tx, principal, d.at - windowMs)) + n > count;
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
      const reader = through(await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports), input);
      // Both sides as the store has them: a grant on a slug matches there, and neither side may be deleted.
      const environments = await store.environmentsById(d.tx, items.flatMap((item) => {
        const source = sources.get(item.source.secretId);
        return source === undefined ? [item.holder.environmentId] : [item.holder.environmentId, source.environmentId];
      }));
      const gone = (place: SecretPlace) => environments.get(place.environmentId)?.deleted ?? false;
      const codes = items.map((item): RefusalCode | null => {
        const source = sources.get(item.source.secretId);
        if (source === undefined || projectOf.get(item.holder.environmentId) !== item.holder.projectId) return 'bad_claim';
        if (source.secretId === item.holder.secretId) return 'invalid';
        // A personal config's values are bound to its owner: no reference holds one, nor reads one.
        if (environments.get(item.holder.environmentId)?.owner != null || environments.get(source.environmentId)?.owner != null) return 'personal';
        return refuses(reader, 'secret.write', placeIn(item.holder, environments), gone(item.holder))
          ?? refuses(reader, 'secret.read', placeIn(source, environments), gone(source));
      });
      const first = codes.find((code) => code !== null) ?? null;
      if (first !== null) throw new Refused(refusal(first, MESSAGES[first]), items.map((item, i) => entry(item, 'deny', codes[i] ?? first)));
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
    if (vias.some((via) => via === null) || new Set(vias.map((via) => via.seq)).size !== vias.length) throw new Error('each reference to end, once');
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
        throw new Refused(refusal('bad_claim', MESSAGES.bad_claim), vias.map((via, i) => entry(via, sealed[i]!, 'deny', 'bad_claim')));
      });
    }
    const seals = sealed as Sealed[];
    const ended = async (db: Queryable) => {
      const done = await store.endedReferences(db, seals.map((seal) => seal.seq));
      return seals.map((seal) => (done.has(seal.seq) ? ('ended' as const) : null));
    };
    return this.#decide([principal], async (d) => {
      // Under the log's head: two ends of one reference at once, the second finds the first; and the actor's standing stands.
      const actor = through(await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports), input);
      // Ending is allowed in a deleted place: deleting one ends the references into and out of it.
      const environments = await store.environmentsById(d.tx, seals.map((seal) => seal.holder.environmentId));
      const codes: (RefusalCode | null)[] = seals.map((seal) => {
        const holder = refuses(actor, 'secret.write', placeIn(seal.holder, environments), false);
        // Abandoning is its maker's alone, for a write of theirs that stored nothing: the vault
        // never reads the app's rows, so whose seal it is decides, and no one else's end says it.
        if (reason === 'abandoned' && seal.createdBy !== principal) return 'not_allowed';
        // Replacing or abandoning is the holder's side: write where it is held.
        if (holder === null || reason !== 'broken') return holder;
        return refuses(actor, 'grant.manage', { projectId: seal.source.projectId }, false) === null ? null : holder;
      });
      if (!codes.some((code) => code !== null)) (await ended(d.tx)).forEach((code, i) => (codes[i] = code));
      const first = codes.find((code) => code !== null) ?? null;
      if (first !== null) throw new Refused(refusal(first, MESSAGES[first]), vias.map((via, i) => entry(via, seals[i]!, 'deny', codes[i] ?? first)));
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
  async #declare(principals: readonly string[]): Promise<boolean> {
    const at = await this.#now(this.#db);
    const due: string[] = [];
    for (const principal of principals) {
      const subject = await this.#standing(this.#db, principal, await store.member(this.#db, principal), at, []).catch((error: unknown) => {
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
    const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
    if (subject.status === 'active' && ownsInstance(subject.live)) return false;
    const tampered = subject.status === 'tampered';
    if (tampered && (await this.#logged(d.tx, principal)) === undefined) return false;
    const correlation = { operationId: randomUUID() };
    const owner = { role: 'owner' as const, scope: EVERYWHERE };
    d.grants.set(principal, [...subject.stored]);
    d.touched.add(principal);
    if (tampered) await this.#startOver(d, VAULT_ACTOR, principal, row, subject.fault!, correlation, (code, message) => new Refused(refusal(code, message ?? MESSAGES[code]), []));
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
  async #standing(db: Queryable, principal: string, row: Member | undefined, at: number, reports: NewEntry[]): Promise<Standing> {
    const none = NOTHING;
    const grants = row === undefined ? [] : await store.grants(db, principal);
    const fault = await this.#integrity(db, principal, row, grants, reports);
    if (fault !== null) return { principal, status: 'tampered', live: none, all: none, fault, stored: grants };
    if (!PRINCIPAL.test(principal)) return { principal, status: 'unknown', live: none, all: none, fault, stored: grants };
    if (row?.status !== 'active') return { principal, status: row?.status ?? 'unknown', live: none, all: none, fault, stored: grants };
    const held = grants.map((grant) => ({ ...grant, role: grant.role as Role }));
    const { role, scope } = roleOf(principal, row);
    // Every decision about them reads the policy: their roles as an Owner edited them, and which environments are protected.
    const { policy } = await this.#policyAt(db, reports, at);
    const service = !principal.startsWith('user:');
    return {
      principal,
      status: 'active',
      live: { role, scope, grants: held.filter((grant) => live(grant, at)), policy, service },
      all: { role, scope, grants: held, policy, service },
      fault,
      stored: grants,
    };
  }

  #access(principal: string, row: Member | undefined, held: readonly GrantRow[], at: number, tampered: boolean, policy: Policy): Access {
    const active = PRINCIPAL.test(principal) && !tampered && row?.status === 'active';
    return {
      principal,
      status: tampered ? 'tampered' : !PRINCIPAL.test(principal) ? 'unknown' : (row?.status ?? 'unknown'),
      generation: row?.generation ?? 0,
      ...(active ? roleOf(principal, row) : { role: 'member', scope: EVERYWHERE }),
      grants: active ? held.filter((grant) => live(grant, at) && grantKind(grant) !== null).map(view) : [],
      since: row ? iso(row.statusChangedAt) : null,
      by: row?.statusChangedBy ?? null,
      policy,
    };
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
      const [row, held, at] = await Promise.all([store.member(db, principal), store.grants(db, principal), this.#now(db)]);
      const fault = await this.#integrity(db, principal, row, held, reports);
      const { policy } = await this.#policyAt(db, reports, at);
      return this.#access(principal, row, held, at, fault !== null, policy);
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
    const refused = (code: RefusalCode, message = MESSAGES[code]) => {
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
      const { policy } = await this.#policyAt(d.tx, d.reports, d.at);
      for (const change of changes) {
        if (change.role !== null && !isRole(change.role, policy)) throw refused('invalid', `no such role: ${change.role}`);
        if (change.role !== null && change.environmentId !== null && !assignableToEnvironment(change.role, policy)) {
          throw refused('invalid', `${change.role} can only be granted on a project`);
        }
      }
      const known = await store.places(
        d.tx,
        changes.map((change) => change.projectId!),
        changes.flatMap((change) => (change.environmentId === null ? [] : [change.environmentId])),
      );
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
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports), input);
      if (acting.status === 'tampered') throw refused('tampered');
      // Where they manage access, anything; otherwise only a person to a service account (`givesService`).
      const manages = where.every((place) => mayManageAccess(acting.live, place));
      if (!manages && !(SERVICE.test(principal) && PERSON.test(actor))) throw refused('not_allowed');
      // Managing access never reads a value: nobody gives themselves a role, though they may give one up.
      if (actor === principal && changes.some((change) => change.role !== null)) {
        throw refused('not_allowed', 'nobody grants themselves a role: ask another admin');
      }

      const row = d.members.get(principal);
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
      if (subject.status === 'tampered') throw refused('tampered', TAMPERED_SUBJECT);
      // A service account admitted with its first grants, as `admit` would: all of it, or none.
      const admitted = input.admit === true && row?.status !== 'active' ? await this.#admitWith(d, acting, principal, row, input) : undefined;
      if (admitted === undefined && row?.status === 'removed') throw refused('removed');
      if (admitted === undefined && row === undefined) throw refused('not_a_member');
      if (!manages) {
        // The setting as of the log's head, which a change to it takes too.
        const setting = (await this.#settingsAt(d.tx, d.reports)).serviceAccounts;
        // One just admitted holds nothing yet, and is theirs.
        const account = admitted !== undefined || row === undefined ? { grants: [], admittedBy: actor } : await this.#account(d.tx, subject, row);
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
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
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
    entry('access.grant', role);
    return current === undefined ? 'created' : 'updated';
  }

  admit(input: AdmitInput): Promise<Outcome<Admitted>> {
    const { actor, principal } = input;
    const asked = input.role === undefined ? {} : { role: input.role, scope: input.scope ?? EVERYWHERE };
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [
        accessEntry(actor, 'member.add', principal, 'deny', input, asked, code),
      ]);
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports), input);
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
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
      if (subject.status === 'tampered') throw refused('tampered', TAMPERED_SUBJECT);
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
    if (!service || !PERSON.test(acting.principal) || !setsUpServices(acting.live, setting, placesOf(await store.liveProjects(d.tx)))) {
      throw refused('not_allowed', 'only admins and owners of the whole instance may add people or set their roles, and a service account takes access somewhere the instance lets people set one up');
    }
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
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [accessEntry(actor, 'member.remove', principal, 'deny', input, {}, code)]);
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      if (!PRINCIPAL.test(principal)) throw refused('invalid', `not a member: ${shownMember(principal)}`);
      const row = d.members.get(principal);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports), input);
      if (acting.status === 'tampered') throw refused('tampered');
      const holder = acting.live;
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
      const held = subject.stored;
      if (this.#listed(principal)) throw refused('not_allowed', declaredOwner(principal));
      if (subject.status === 'tampered') {
        if (!runsInstance(holder)) throw refused('not_allowed', 'only admins and owners of the whole instance may remove a member whose record failed its check');
        return this.#startOver(d, actor, principal, row, subject.fault!, input, refused);
      }
      if (!runsInstance(holder)) {
        // A service account its manager removes: they reach everything it holds (`managesService`).
        const theirs = SERVICE.test(principal) && PERSON.test(actor) && row?.status === 'active' &&
          managesService(holder, (await this.#settingsAt(d.tx, d.reports)).serviceAccounts, actor, await this.#account(d.tx, subject, row));
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
  async #account(db: Queryable, subject: Standing, row: Member): Promise<ServiceAccount> {
    const slugs = await store.environmentsById(db, subject.live.grants.flatMap((grant) => (grant.environmentId === null ? [] : [grant.environmentId])));
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
  async #settingsAt(db: Queryable, reports: NewEntry[]): Promise<Settings> {
    const entry = await newestAuthentic(
      (before) => store.newestVaultEntries(db, SETTINGS, LOOK_BACK.page, before),
      this.#check(reports, null),
    );
    if (entry === 'none') return DEFAULT_SETTINGS;
    if (typeof entry === 'string') return CLOSED_SETTINGS;
    const { serviceAccounts } = JSON.parse(entry.metadata) as { serviceAccounts?: unknown };
    return isScope(serviceAccounts) ? { serviceAccounts } : CLOSED_SETTINGS;
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
  async #policyAt(db: Queryable, reports: NewEntry[], at: number): Promise<{ policy: Policy; edits: PolicyEdits; readable: boolean }> {
    const entry = await newestAuthentic(
      (before) => store.newestVaultEntries(db, POLICY, LOOK_BACK.page, before),
      this.#check(reports, null),
    );
    if (entry === 'none') return { policy: DEFAULT_POLICY, edits: NO_EDITS, readable: true };
    const edits = typeof entry === 'string' ? null : readEdits(JSON.parse(entry.metadata) as { policy?: unknown });
    return edits === null ? { policy: CLOSED_POLICY, edits: NO_EDITS, readable: false } : { policy: await livePolicy(db, edits, at), edits, readable: true };
  }

  changePolicy(input: ChangePolicyInput): Promise<Outcome<{ policy: Policy; seq: number | null }>> {
    const { actor, change, policySeq } = input;
    if (policySeq !== undefined && policySeq !== null && !Number.isSafeInteger(policySeq)) throw new Error('policySeq names a policy.change by its number');
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
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [entry('deny', { change: describeChange(change) }, code)]);
    return this.#decide([actor], async (d) => {
      validateCorrelation(input);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports), input);
      if (acting.status === 'tampered') throw refused('tampered');
      if (acting.status !== 'active') throw refused(acting.status === 'removed' ? 'removed' : 'not_a_member');
      // Under the log's head, as the actor's standing above: two changes at once each start from the one before. One the
      // caller weighed from the policy as of a change it names starts from that one, or is refused, to be asked again.
      const newest = await newestVaultSeq(d.tx, POLICY);
      if (policySeq !== undefined && newest !== (policySeq === null ? null : BigInt(policySeq))) {
        throw refused('policy_changed');
      }
      const { policy: before, edits, readable } = await this.#policyAt(d.tx, d.reports, d.at);
      const owner = acting.live.credentialScope == null && ownsInstance(acting.live);
      // Unreadable, its edits are unknown: a change made from none would erase every protection and role edit the forged
      // rows hide. An Owner of the whole instance alone writes it again, from the roles as they ship and nothing protected.
      if (!readable && !owner) throw refused('not_allowed', "the vault cannot read its own policy: only an Owner of the whole instance writes it again, from the roles as they ship");
      const next: PolicyEdits = { roles: { ...edits.roles }, instanceRoles: { ...edits.instanceRoles }, protected: edits.protected.map((place) => ({ ...place })) };
      if (change?.kind === 'role' || change?.kind === 'instance-role') {
        // Roles are the whole instance's: an Owner of all of it alone changes them (R1, R15), never through a scoped credential.
        if (!owner) throw refused('not_allowed', 'only an Owner of the whole instance edits roles');
        const instance = change.kind === 'instance-role';
        const fixed = instance ? FIXED_ROLES.instanceRoles.includes(change.role as InstanceRole) : FIXED_ROLES.roles.includes(change.role);
        if (typeof change.role !== 'string' || fixed) throw refused('invalid', `${change.role} is not edited: it holds ${change.role === 'member' ? 'nothing' : 'everything'}, always`);
        if (instance && !isInstanceRole(change.role)) throw refused('invalid', `no instance role ${change.role}: an Owner makes project roles`);
        if (!instance && !isBuiltinRole(change.role) && !ROLE_ID.test(change.role)) throw refused('invalid', 'a role is named by lowercase letters, digits and dashes, 2 to 32, starting with a letter');
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
        }
      } else if (change?.kind === 'protect') {
        if (typeof change.projectId !== 'string' || !UUID.test(change.projectId) || !Array.isArray(change.environmentIds) || change.environmentIds.length === 0
          || change.environmentIds.some((id) => typeof id !== 'string' || !UUID.test(id)) || typeof change.protected !== 'boolean') {
          throw refused('invalid', 'protection names a project and some of its environments, by id, and whether they are protected');
        }
        if (!(await store.projectLive(d.tx, change.projectId))) throw refused('invalid', 'no such project');
        at.projectId = change.projectId;
        // Each a live environment of the project, or none yet: a fork's id, protected before its row is written.
        const found = await store.environmentsById(d.tx, change.environmentIds);
        if ([...found.values()].some((environment) => environment.projectId !== change.projectId)) throw refused('invalid', 'each environment is one of the project\'s');
        if (change.environmentIds.length === 1 && found.has(change.environmentIds[0]!)) at.environmentId = change.environmentIds[0];
        if (change.protected) {
          if (!allows(acting.live, 'environment.manage', { projectId: change.projectId })) throw refused('not_allowed', 'protecting an environment takes managing its project\'s environments');
          const known = new Set(next.protected.map((place) => place.environmentId));
          next.protected = [...next.protected, ...change.environmentIds.filter((id) => !known.has(id)).map((environmentId) => ({ projectId: change.projectId, environmentId, at: d.at }))]
            .sort((a, b) => (a.environmentId < b.environmentId ? -1 : 1));
        } else {
          // Unprotecting widens what people hold there: an Owner of the whole instance's to do (R15).
          if (!owner) throw refused('not_allowed', 'only an Owner of the whole instance unprotects an environment');
          next.protected = next.protected.filter((place) => !change.environmentIds.includes(place.environmentId));
        }
      } else {
        throw refused('invalid', 'a change is to a role, an instance role, or protection');
      }
      // The policy now, and the newest change, which it is as of: this one's, when it changed anything.
      const answer = { policy: await livePolicy(d.tx, next, d.at), seq: newest === null ? null : Number(newest) };
      if (!readable || JSON.stringify(next) !== JSON.stringify(edits)) {
        const made = entry('allow', { policy: next, change: describeChange(change), before: describeBefore(change, before) });
        d.log.push(made);
        d.after.push((seqOf) => (answer.seq = seqOf(made)));
      }
      return answer;
    });
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
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [entry('deny', { serviceAccounts: input.settings?.serviceAccounts ?? null }, code)]);
    return this.#decide([actor], async (d) => {
      validateCorrelation(input);
      const acting = through(await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports), input);
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
  async #kekMismatch(): Promise<string | null> {
    const prepared = this.#prepared;
    if (!prepared.kekChecked) {
      const wrong = await this.#checkKeks();
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
  async #checkKeks(): Promise<string | null> {
    // A vault that may not write cannot record a check either; why it may not is the answer.
    const superseded = await this.#settled();
    if (superseded !== null) return superseded;
    const checks = await this.#checkValues(this.#db);
    const budget = this.#prepared.options.keyBudgetMs;
    for (const kek of this.#config.keks.all) {
      const operation = { deadline: Date.now() + budget, signal: AbortSignal.timeout(budget) };
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

  /** The last checkpoint the vault signed, and the entry that holds it: its newest allowed `audit.checkpoint`. */
  async #latest(db: Queryable): Promise<{ checkpoint: Checkpoint; seq: bigint; keyId: string } | null> {
    const row = await store.latestVaultEntry(db, [CHECKPOINT]);
    return row === undefined ? null : { checkpoint: JSON.parse(row.metadata) as Checkpoint, seq: row.seq, keyId: row.keyId };
  }

  /**
   * The chain recomputed to its last entry, for a checkpoint to sign: from
   * its first entry at the first checkpoint of each hour, and otherwise from
   * the prefix the last checkpoint signed, if that one was signed this hour.
   *
   * Resuming never signs what the vault did not recompute. The vault
   * recomputed the last checkpoint's prefix itself, from entry 0 at the
   * hour's first checkpoint and onward at each one since, and the entry
   * that holds it is the first one checked again, by its MAC. The next
   * signature extends that same chain.
   *
   * What resuming does not do is recompute the rows of that prefix again.
   * They can change while the hash stored at its end stays, so it first
   * checks the two things that are cheap: that hash is still there, which a
   * prefix rewritten and chained again changes, and every entry of the
   * prefix is, which a cut changes. Either failing, it recomputes from entry
   * 0, which names what broke. An entry edited in place, its hash left as
   * it was, is the one change left to the next full pass, within the hour.
   *
   * It resumes only from a checkpoint under the key the vault writes with
   * now: once the log reaches that key, no other writes again (`forward`).
   * After a rotation, the next pass is full.
   */
  async #recompute(tx: Queryable): Promise<{ verification: LogVerification; anchor: Anchor }> {
    const { logKeys } = this.#prepared;
    const latest = await this.#latest(tx);
    const hour = (ms: number) => Math.floor(ms / FULL_RECOMPUTE_MS);
    const resumable =
      latest !== null &&
      latest.keyId === logKeys[0].keyId &&
      latest.seq === BigInt(latest.checkpoint.seq) + 1n &&
      hour(Date.parse(latest.checkpoint.signedAt)) === hour(await this.#now(tx)) &&
      (await carries(tx, latest.checkpoint)) &&
      (await store.complete(tx, BigInt(latest.checkpoint.seq)));
    if (!resumable) return verifyChain(tx, logKeys, [], UNVERIFIED);
    const { seq, hash } = latest.checkpoint;
    const signed: Anchor = { nextSeq: BigInt(seq) + 1n, hash: Buffer.from(hash, 'hex'), vaultEntries: 0, vaultKeys: [logKeys[0].keyId] };
    return verifyChain(tx, logKeys, [], signed);
  }

  async checkpoint(): Promise<Outcome<{ checkpoint: Checkpoint }>> {
    await this.#settled();
    // A KEK found wrong turns readiness red: the checkpoint is refused. It does no key work of its
    // own, so it writes nothing more and never waits on a key service; a check under way, or none yet, is no verdict.
    const { wrongKek } = this.#prepared;
    // Then, in one snapshot and without the log's lock, so that no append
    // waits on it: every member's row checked, since rows changed around the
    // vault write nothing to the log; and the chain recomputed, every hash
    // from content and every vault entry by its MAC, from the first entry
    // once an hour, since an entry cut from the middle leaves the hashes
    // around a later checkpoint as they were (`#recompute`).
    const found: NewEntry[] = [];
    const whole = await this.#db.transaction(async (tx) => {
      await this.#sweep(tx, found);
      return this.#recompute(tx);
    }, SNAPSHOT);
    return this.#decide([], async (d) => {
      for (const entry of found) if (!d.reports.includes(entry)) d.reports.push(entry);
      // Checkpoints one at a time, each against the one before.
      const head = await lockLogHead(d.tx);
      const latest = await this.#latest(d.tx);
      const refused = (code: RefusalCode, detail: Record<string, unknown>, message = MESSAGES[code]) =>
        new Refused(refusal(code, message), [
          { actor: SCHEDULER, action: CHECKPOINT, decision: 'deny', code, metadata: JSON.stringify(detail) },
        ]);
      // Logging the refusal would give the next call something to sign.
      if (head.nextSeq === 0n) throw new Refused(refusal('invalid', 'the log is empty'), []);
      if (wrongKek !== null) throw refused('wrong_kek', { reason: wrongKek }, wrongKek);
      if (!whole.verification.ok) {
        throw refused('log_broken', { failedAtSeq: whole.verification.failedAtSeq, reason: whole.verification.reason });
      }
      // Nothing since the last one: it is still the newest prefix.
      if (latest !== null && latest.seq === head.nextSeq - 1n) return { checkpoint: latest.checkpoint };
      // Under the lock, the rest: the prefix signed last still where it was,
      // and every entry since the snapshot. A rewrite is never signed over.
      if (latest !== null && !(await carries(d.tx, latest.checkpoint))) {
        throw refused('log_broken', { reason: `the log up to entry ${latest.checkpoint.seq} is not the prefix the last checkpoint signed` });
      }
      const { verification: held, anchor: verified } = await verifyChain(d.tx, this.#prepared.logKeys, [], whole.anchor);
      if (!held.ok) throw refused('log_broken', { failedAtSeq: held.failedAtSeq, reason: held.reason });
      // It signs the entry it verified to, which the head, locked, must name.
      if (verified.nextSeq !== head.nextSeq || !verified.hash.equals(head.headHash)) {
        throw refused('log_broken', { reason: 'the chain head does not name the last entry' });
      }
      const signed = { seq: Number(verified.nextSeq - 1n), hash: verified.hash.toString('hex'), signedAt: iso(d.at) };
      const checkpoint = {
        ...signed,
        keyId: this.#prepared.signer.keyId,
        signature: await this.#prepared.signer.sign(checkpointMessage(signed)),
      };
      d.log.push({ actor: SCHEDULER, action: CHECKPOINT, decision: 'allow', metadata: JSON.stringify(checkpoint) });
      return { checkpoint };
    });
  }

  async about(): Promise<{ checkpointKeys: Record<string, CheckpointKey>; owners: string[]; rootAdmins: [] }> {
    await this.#settled();
    const { signers, since } = this.#prepared;
    // A key it replaced vouches only for prefixes before its first entry under the current one: none, before it has one.
    const until = Number(since ?? 0n);
    return {
      checkpointKeys: Object.fromEntries(signers.map(({ keyId, publicKey }, i) => [keyId, { publicKey, until: i === 0 ? null : until }])),
      owners: [...this.#config.owners],
      // For an app of 0.5 while it runs beside this vault: there are none, and its lists and checks need the field.
      rootAdmins: [],
    };
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

  verifyLog(input: VerifyLogInput): Promise<LogVerification> {
    return this.#verifyAll(input.upTo ?? null);
  }

  /**
   * The whole log, in one snapshot and one pass over the vault's entries:
   * each by its MAC, the keys it moved through, and what the other checks
   * need of it, gathered as it goes (`Findings`); then every checkpoint, the
   * heads that must still be there, the key batches accounted for, and the
   * members and grants replayed.
   *
   * With `upTo`, the head the app verified to, the links and hashes of the
   * chain are the app's to recompute, as it just has, over its own snapshot,
   * through that head; `carries(upTo)` ties this snapshot to that one. So
   * the vault reads only its own entries, each checked against its own hash
   * and MAC over the link it names. Without `upTo`, nobody else recomputed
   * the chain: the vault reads it all, and rehashes every link.
   */
  async #verifyAll(upTo: LogHead | null): Promise<LogVerification> {
    await this.#settled();
    return this.#db.transaction(async (tx) => {
      const remembered = this.#prepared.verified;
      const findings = new Findings();
      const read = upTo === null ? await this.#rehashed(tx, findings) : await this.#ownEntries(tx, findings);
      if (!read.ok) return read;
      // Each head the log must still hold, in one read: the app's, every checkpoint's, and the last this vault rehashed.
      const heads: LogHead[] = [...(upTo === null ? [] : [upTo]), ...findings.checkpoints.map(({ checkpoint }) => checkpoint)];
      const rememberedHead = remembered.nextSeq > 0n ? { seq: Number(remembered.nextSeq - 1n), hash: remembered.hash.toString('hex') } : null;
      if (rememberedHead !== null) heads.push(rememberedHead);
      const hashes = await store.hashesAt(tx, [...new Set(heads.map((head) => BigInt(head.seq)))]);
      const holds = (head: LogHead) => head.hash === GENESIS_HASH.toString('hex') || hashes.get(BigInt(head.seq))?.toString('hex') === head.hash;
      if (upTo !== null && !holds(upTo)) {
        return { ok: false, failedAtSeq: upTo.seq, reason: 'not the entry the app verified up to: the log changed between the two checks' };
      }
      const unsigned = await this.#checkpointFault(findings, holds);
      if (unsigned !== null) return unsigned;
      // What this vault last verified must still be there: whoever holds
      // its key can seal a rewrite, but cannot put back the head it saw. A
      // checkpoint names an earlier break, so it is reported first.
      if (rememberedHead !== null && !holds(rememberedHead)) {
        return { ok: false, failedAtSeq: rememberedHead.seq, reason: 'changed since the vault last verified it' };
      }
      const at = await this.#now(tx);
      const accounting = findings.accounting.result(at);
      if (!accounting.ok) return accounting;
      const [rows, held] = await Promise.all([store.allMembers(tx), store.grants(tx)]);
      const fault = this.#unsealed(rows, held, findings.newestAccess) ?? findings.replayFault ?? replayFault(findings.replayed, rows, held, at);
      if (fault !== null) return { ok: false, failedAtSeq: null, reason: describeAccessFault(fault), fault };
      const verified = { ok: true as const, entries: findings.entries };
      return accounting.pending === 0 ? verified : { ...verified, pending: accounting.pending };
    }, SNAPSHOT);
  }

  /**
   * The vault's own entries, oldest first: each against its own hash, and by
   * its MAC, over the link it names, which the app checked; and the vault's
   * keys moving only forward through them.
   */
  async #ownEntries(tx: Queryable, findings: Findings): Promise<{ ok: true } | Extract<LogVerification, { ok: false }>> {
    const { logKeys } = this.#prepared;
    let keys: readonly string[] = [];
    for (let after = -1n; ; ) {
      const batch = await store.vaultEntriesAfter(tx, after, VERIFY_BATCH);
      if (batch.length === 0) return { ok: true };
      for (const entry of batch) {
        const result = verifyEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash, keys: logKeys });
        if (!result.ok) return { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: withCause(result.reason) };
      }
      const moved = forward(batch, keys, logKeys[0]!.keyId);
      if ('failedAtSeq' in moved) return { ok: false, failedAtSeq: Number(moved.failedAtSeq), reason: moved.reason };
      keys = moved.keys;
      for (const entry of batch) findings.add(entry);
      after = batch[batch.length - 1]!.seq;
    }
  }

  /** The whole chain from its first entry: every link and hash, the vault's MACs; the furthest verified is kept for checkpoints. */
  async #rehashed(tx: Queryable, findings: Findings): Promise<{ ok: true } | Extract<LogVerification, { ok: false }>> {
    const { verification, anchor } = await verifyChain(tx, this.#prepared.logKeys, [], UNVERIFIED, (batch) => {
      for (const entry of batch) if (entry.author === 'vault') findings.add(entry);
    });
    if (!verification.ok) return verification;
    this.#prepared.verified = further(this.#prepared.verified, anchor);
    return { ok: true };
  }

  /**
   * Every checkpoint, not only the newest: each signed by the key whose log
   * key wrote its entry, over a prefix the log still holds (`holds`), entry
   * for entry. Its entry's MAC is checked by now, and one under a key the
   * vault replaced comes before the rotation.
   */
  async #checkpointFault(findings: Findings, holds: (head: LogHead) => boolean): Promise<Extract<LogVerification, { ok: false }> | null> {
    const { logKeys, signers } = this.#prepared;
    // Each signer's key imported once, for this check only.
    const verifiers = new Map<string, Promise<(checkpoint: Checkpoint) => Promise<boolean>>>();
    const signed = (checkpoint: Checkpoint, by: Signer) => {
      let verifier = verifiers.get(by.keyId);
      if (verifier === undefined) verifiers.set(by.keyId, (verifier = checkpointVerifier(by.publicKey)));
      return verifier.then((verify) => verify(checkpoint));
    };
    const { checkpoints } = findings;
    for (let from = 0; from < checkpoints.length; from += SIGNATURES_AT_ONCE) {
      const chunk = checkpoints.slice(from, from + SIGNATURES_AT_ONCE);
      // The signatures of a chunk at once, where crypto runs beside the code; the first fault, in the log's order.
      const faults = await Promise.all(chunk.map(async ({ entry, checkpoint }) => {
        const by = signers[logKeys.findIndex((key) => key.keyId === entry.keyId)];
        if (by?.keyId !== checkpoint.keyId) return `a checkpoint signed under ${checkpoint.keyId}, in an entry written under ${entry.keyId}: each key signs only its own`;
        if (!(await signed(checkpoint, by))) return 'a checkpoint the vault did not sign';
        if (BigInt(checkpoint.seq) >= entry.seq || !holds(checkpoint)) {
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
   * The first member whose row fails its MAC, or names an older access
   * entry than the log's newest about them (`newest`, from the full check's
   * pass, where each entry's MAC was checked).
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

/**
 * What one pass over the vault's entries gathers for the other checks of a
 * full verification, so that the log is read once: the key batches, the
 * access entries replayed, each member's newest, and the checkpoints. Each
 * entry comes after its MAC was checked.
 */
class Findings {
  readonly accounting = new KeyAccounting();
  readonly replayed: Replayed = { members: new Map(), held: new Map() };
  /** The first access entry the replay could not apply. */
  replayFault: AccessFault | null = null;
  /** Each member's newest allowed access entry, by seq. */
  readonly newestAccess = new Map<string, bigint>();
  /** Every allowed checkpoint, with its entry's seq and key: tens of thousands a year, so nothing more of it. */
  readonly checkpoints: { entry: { seq: bigint; keyId: string }; checkpoint: Checkpoint }[] = [];
  /** The vault's entries read. */
  entries = 0;

  add(entry: StoredEntry): void {
    this.entries += 1;
    this.accounting.add(entry);
    if (entry.decision !== 'allow') return;
    if (ACCESS.has(entry.action)) {
      this.replayFault ??= apply(this.replayed, entry);
      if (entry.subjectPrincipal !== null) this.newestAccess.set(entry.subjectPrincipal, entry.seq);
    } else if (entry.action === CHECKPOINT) {
      this.checkpoints.push({ entry: { seq: entry.seq, keyId: entry.keyId }, checkpoint: JSON.parse(entry.metadata) as Checkpoint });
    }
  }
}

const ACCESS = new Set<string>(ACCESS_ACTIONS);

/** Checkpoint signatures checked at once, in a full verification. */
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

/** The caller's ids go into the log as they are: a request id is text, an operation id a lowercase UUID. */
function validateCorrelation(input: Correlation): void {
  if (input.requestId != null) validateText(input.requestId);
  if (input.operationId != null && (typeof input.operationId !== 'string' || !UUID.test(input.operationId))) {
    throw new Error(`operationId must be a lowercase UUID, got: ${String(input.operationId)}`);
  }
  if (input.credentialId != null && (typeof input.credentialId !== 'string' || !UUID.test(input.credentialId))) {
    throw new Error(`credentialId must be a lowercase UUID, got: ${String(input.credentialId)}`);
  }
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

/** An environment a secret is in, or that holds a reference to one. */
type SecretPlace = { projectId: string; environmentId: string };

/**
 * Where a decision checks a permission: an environment, with its slug as
 * the store has it when it was read and is in the project claimed;
 * otherwise none, which no grant on a slug matches.
 */
function placeIn(place: SecretPlace, environments: ReadonlyMap<string, { projectId: string; slug: string }>): Place {
  const environment = environments.get(place.environmentId);
  const slug = environment?.projectId === place.projectId ? environment.slug : null;
  return { projectId: place.projectId, environmentId: place.environmentId, environmentSlug: slug };
}

/**
 * Why `reader` may not do `permission` at `where`, or null if they may. A
 * deleted place is refused before any grant is asked, so no kind of grant,
 * on the project, the environment or every project, can reach into one.
 */
/**
 * A key of a personal config is its owner's alone (docs/design/forking.md,
 * section 4): no grant or role opens or wraps it, an Owner's included,
 * only its owner, while they read the environment it is a config of,
 * whatever the call is. Nor does any reference reach into or out of one.
 * Undefined for a key of any other environment, decided as ever.
 */
function personalRefusal(
  reader: Standing,
  principal: string,
  permission: Permission,
  secret: SecretPlace,
  at: SecretPlace,
  environments: ReadonlyMap<string, store.EnvironmentRow>,
): RefusalCode | null | undefined {
  const own = environments.get(secret.environmentId);
  const held = at.environmentId === secret.environmentId ? own : environments.get(at.environmentId);
  if (own?.owner == null && held?.owner == null) return undefined;
  if (own !== held || principal !== own?.owner || own.parentId === null) return 'personal';
  const parent = placeIn({ projectId: secret.projectId, environmentId: own.parentId }, environments);
  // Its owner reads what they wrote while they read or use the environment it configures (R8).
  const gone = own.deleted || (environments.get(own.parentId)?.deleted ?? true);
  const refused = refuses(reader, 'secret.use', parent, gone) === null ? null : refuses(reader, 'secret.read', parent, gone);
  if (refused !== null) return refused;
  // The credential's scope caps the owner still: their viewer token on the parent reads, and wraps no key. Reading their
  // own values takes use there: a Contributor's handle reads what its owner wrote, and nothing of the parent's.
  return withinCredential(reader.live, permission === 'secret.read' ? 'secret.use' : permission, parent) ? null : 'no_grant';
}

function refuses(reader: Standing, permission: Permission, where: Place, deleted: boolean): RefusalCode | null {
  if (reader.status === 'tampered') return 'tampered';
  if (reader.status === 'removed') return 'removed';
  if (reader.status === 'unknown') return 'not_a_member';
  if (deleted) return 'deleted';
  if (allows(reader.live, permission, where)) return null;
  // Would a grant that has lapsed have covered it?
  return allows(reader.all, permission, where) ? 'expired' : 'no_grant';
}

/**
 * An entry about a key. A new secret's row is not committed when its key is
 * wrapped, so a wrap names the secret in its payload; the others name it.
 */
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

function live(grant: GrantRow, at: number): boolean {
  return grant.expiresAt === null || grant.expiresAt > at;
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

/** A member's instance role, as their row has it: service accounts are members, whatever a row says. */
function roleOf(principal: string, row: Member): { role: InstanceRole; scope: Scope } {
  return principal.startsWith('user:') ? { role: row.role, scope: row.scope } : { role: 'member', scope: EVERYWHERE };
}

function view(grant: GrantRow): Grant {
  return {
    projectId: grant.projectId,
    environmentId: grant.environmentId,
    role: grant.role as Role,
    expiresAt: grant.expiresAt === null ? null : iso(grant.expiresAt),
    grantedAt: iso(grant.grantedAt),
    grantedBy: grant.grantedBy,
  };
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** A policy entry's edits, checked as the vault wrote them, or null for any that does not hold. */
function readEdits(stored: { policy?: unknown }): PolicyEdits | null {
  const edits = stored.policy as Partial<PolicyEdits> | undefined;
  if (typeof edits !== 'object' || edits === null) return null;
  const { roles, instanceRoles, protected: protectedIds } = edits;
  if (typeof roles !== 'object' || roles === null || typeof instanceRoles !== 'object' || instanceRoles === null || !Array.isArray(protectedIds)) return null;
  const defined = (table: object) => Object.values(table).every((definition) => definitionProblem(definition as RoleDefinition) === null);
  if (!defined(roles) || !defined(instanceRoles) || Object.keys(instanceRoles).some((role) => !isInstanceRole(role))) return null;
  if (protectedIds.some((place) => typeof place !== 'object' || place === null || !UUID.test((place as ProtectedPlace).projectId) || !UUID.test((place as ProtectedPlace).environmentId)
    || !Number.isSafeInteger((place as ProtectedPlace).at))) return null;
  return { roles: roles as Record<string, RoleDefinition>, instanceRoles: instanceRoles as PolicyEdits['instanceRoles'], protected: protectedIds as ProtectedPlace[] };
}

/**
 * The policy `edits` say as of `at`: the roles as they ship, each edited
 * one replaced and each made one added; and the protected environments, but
 * for those deleted since, the project around one's included: a deleted
 * prod protects nothing, and holds nobody back from giving a service
 * account a role on all of its project (`givesService`). A fork's id with
 * no row yet stays, protected before it is written, for an hour: one with
 * none after that is a fork refused or abandoned, never written. Each
 * keeps its slug, which a scoped instance role's filters read. The edits
 * keep them all: no write is needed.
 */
async function livePolicy(db: Queryable, edits: PolicyEdits, at: number): Promise<Policy> {
  const rows = await store.environmentsById(db, edits.protected.map((place) => place.environmentId));
  const live = edits.protected.filter((place) => {
    const row = rows.get(place.environmentId);
    return row === undefined ? at - place.at < UNWRITTEN_FORK_MS : !row.deleted;
  });
  const slugOf = (place: ProtectedPlace) => rows.get(place.environmentId)?.slug ?? null;
  return {
    roles: { ...ROLES, ...edits.roles },
    instanceRoles: { ...INSTANCE_ROLES, ...edits.instanceRoles },
    protected: live.map((place) => place.environmentId),
    protectedIn: live.reduce<Record<string, { environmentId: string; slug: string | null }[]>>(
      (byProject, place) => ({ ...byProject, [place.projectId]: [...(byProject[place.projectId] ?? []), { environmentId: place.environmentId, slug: slugOf(place) }] }),
      {},
    ),
  };
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
