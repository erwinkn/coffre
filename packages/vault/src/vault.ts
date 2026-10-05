import { randomUUID, timingSafeEqual } from 'node:crypto';

import {
  allows,
  assignableToEnvironment,
  everyProjectPath,
  grantKind,
  isRole,
  mayManageAccess,
  type GrantPlace,
  type Holdings,
  type Permission,
  type Place,
  type Role,
} from '@coffre/core/access';
import { GENESIS_HASH, verifyEntries, type LogKey, type StoredEntry } from '@coffre/core/audit';
import { checkContext, type SecretContext } from '@coffre/core/envelope';
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
  type Access,
  type AccessChange,
  type AccessFault,
  type AdmitInput,
  type Checkpoint,
  type CheckpointKey,
  type Grant,
  type GrantChange,
  type KeyChecks,
  type LogHead,
  type LogVerification,
  type Outcome,
  type Refusal,
  type RefusalCode,
  type RemoveInput,
  type RewrapInput,
  type SecretRef,
  type SetAccessInput,
  type UnwrapInput,
  type Vault,
  type VerifyLogInput,
  type WrapInput,
  type WrappedKey,
} from '@coffre/core/vault';
import type { Database, Queryable, Transaction } from '@coffre/db';
import { isUniqueViolation, SNAPSHOT } from '@coffre/db/dialect';
import { appendEntries, lockLogHead, type Appended, type NewEntry } from '@coffre/db/log';

import { KeyAccounting } from './accounting.ts';
import { signer, type Signer } from './checkpoint.ts';
import type { ResolvedVaultConfig } from './config.ts';
import { carries, forward, further, UNVERIFIED, vaultLogKey, VERIFY_BATCH, verifyChain, withCause, type Anchor } from './log.ts';
import { apply, replayFault, type LoggedMember, type Replayed } from './replay.ts';
import { memberMac, rowKey, sameGrants, sealed } from './rows.ts';
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
  /** Root admins known to have a member row; rows are never deleted. */
  rooted: Set<string>;
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
};

export async function prepareVault(config: ResolvedVaultConfig, options: VaultOptions = {}): Promise<PreparedVault> {
  return {
    config,
    ...(await keysOf(config.signingKeys)),
    options: { keyBudgetMs: options.keyBudgetMs ?? KEY_BUDGET_MS, clockOffset: options.clockOffset ?? (() => 0) },
    verified: UNVERIFIED,
    rooted: new Set(),
    reported: new Set(),
    since: null,
    superseded: null,
    kekChecked: false,
    wrongKek: null,
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

// Historical principals remain valid audit subjects and sealed rows.
const PRINCIPAL = /^(user|token|sync):[^\s:][^\s]*$/;
const LIVE_PRINCIPAL = /^(user|token):[^\s:][^\s]*$/;

/** Who acts for the vault itself, as when it gives a root admin a member row. */
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
  not_allowed: 'not allowed to change this',
  root_admin: 'root admins are set in the vault configuration',
  invalid: 'not something the rules allow',
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
};

/** The actions of the entries the vault writes about keys. */
type KeyAction = 'secret.read' | 'key.wrap' | 'key.rewrap';

/** What ties an entry to the app's request, and to the one action it is part of. */
type Correlation = { requestId?: string | null; operationId?: string | null; credentialId?: string | null };

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
   * Decide in one transaction, with `principals`' rows locked first. A
   * `Refused` or an `Outage` rolls back all but its own entries, which
   * commit on their own: then the refusal is the answer, and the outage
   * fails the call.
   */
  async #decide<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>): Promise<Outcome<T>> {
    const superseded = await this.#settled();
    if (superseded !== null) return { ok: false, refusal: refusal('wrong_kek', superseded) };
    const reports: NewEntry[] = [];
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.#decideOnce(principals, decide, reports);
      } catch (error) {
        // A member who had no row when this decision locked theirs, and has
        // one now: another decision admitted them meanwhile. Again, with it.
        if (attempt < 3 && (error instanceof Retry || isUniqueViolation(error))) continue;
        throw error;
      }
    }
  }

  async #decideOnce<T>(principals: readonly string[], decide: (d: Decision) => Promise<T>, reports: NewEntry[]): Promise<Outcome<T>> {
    try {
      const result = await this.#db.transaction(async (tx) => {
        await store.boundLockWaits(tx, LOCK_TIMEOUT_MS);
        const members = principals.length === 0 ? new Map<string, Member>() : await store.lockMembers(tx, principals);
        const d: Decision = {
          tx, members, at: await this.#now(tx), log: [], writes: [], touched: new Set(), grants: new Map(), reports, after: [],
        };
        const result = await decide(d);
        const entries = [...reports, ...d.log];
        let at = d.at;
        // Each member's newest access entry, which their row names (rows.ts).
        const accessSeq = new Map<string, bigint>();
        if (entries.length > 0) {
          const appended = await this.#append(tx, entries);
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
      const entries = [...reports, ...error.entries];
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
    const newest = await this.#newestAccessSeq(db, principal, reports);
    // No row, and no entry: someone never admitted. No row, but entries: one
    // deleted, unless it was admitted since the row was read.
    if (row === undefined ? newest === null : newest === row.accessSeq) return null;
    if (row === undefined && (await store.member(db, principal)) !== undefined) throw new Retry();
    this.#report(reports, principal, 'stale', `${row?.accessSeq ?? 'none'}<${newest}`);
    return 'stale';
  }

  /** The seq of the newest access entry about `principal` that carries the vault's MAC, or null. */
  async #newestAccessSeq(db: Queryable, principal: string, reports: NewEntry[]): Promise<bigint | null> {
    for (const entry of await store.accessEntriesAbout(db, principal, 32)) {
      if (this.#authentic(entry)) return entry.seq;
      this.#report(reports, principal, 'forged_entry', String(entry.seq), entry.seq);
    }
    return null;
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
  #report(reports: NewEntry[], principal: string, code: Fault | 'forged_entry', detail: string, relatedSeq: bigint | null = null): void {
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
    return prepared.superseded;
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
  #append(tx: Transaction, entries: readonly NewEntry[]): Promise<Appended> {
    const prepared = this.#prepared;
    return appendEntries(tx, prepared.logKey, entries, async (locked) => {
      const rotation = await store.latestVaultEntry(locked, [KEY_ROTATE]);
      if (rotation === undefined || prepared.logKeys.some((key) => key.keyId === rotation.keyId)) return;
      prepared.superseded = `the log moved on to ${rotation.keyId}, a key this vault does not hold: a vault given a newer vault key replaced it, and a replaced key writes nothing more`;
      throw new Error(prepared.superseded);
    });
  }

  // --- keys -------------------------------------------------------------------

  // Raw DEKs are cleared on every path. JSON and base64 leave strings that
  // cannot be wiped, so this is best-effort memory hygiene.
  async unwrap(input: UnwrapInput): Promise<Outcome<{ keys: string[] }>> {
    const { principal } = input;
    validateText(input.purpose);
    const loaded = await this.#versions(input, 'secret.read', { purpose: input.purpose });
    if (!loaded.ok) return loaded;
    const items = loaded.versions;
    validateItems(items, 'wrapped');
    const versionIds = new Map(items.map((item) => [item.secret, item.id]));
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry => ({
      ...keyEntry('secret.read', principal, secret, decision, code, input, { purpose: input.purpose }),
      secretVersionId: versionIds.get(secret),
    });
    const remote = items.some(({ wrapped }) => this.#remote(this.#config.keks.providerOf(wrapped)));
    return this.#keys(
      { action: 'secret.read', principal, permission: 'secret.read', secrets: items.map((item) => item.secret), remote, entry, input },
      () =>
        items.map(({ secret, wrapped }) => async (operation: KeyOperation) => {
          const key = await this.#open(wrapped, secret, operation);
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

  async wrap(input: WrapInput): Promise<Outcome<{ wrapped: WrappedKey[]; seqs: number[] }>> {
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
      () =>
        items.map(({ secret, key }) => async (operation: KeyOperation) => {
          const dek = Buffer.from(key, 'base64');
          try {
            return { wrapped: serialisable(await this.#config.keks.wrap(dek, context(secret), operation)), wipe: () => {} };
          } finally {
            dek.fill(0);
          }
        }),
      (done) => ({ wrapped: done.map(({ wrapped }) => wrapped), seqs: [] as number[] }),
    );
  }

  async rewrap(input: RewrapInput): Promise<Outcome<{ wrapped: WrappedKey[]; seqs: number[] }>> {
    const { principal } = input;
    const loaded = await this.#versions(input, 'key.rewrap');
    if (!loaded.ok) return loaded;
    // RPC can preserve shared objects; each item needs its own source.
    const items = input.items.map((item, i) => ({ secret: { ...item.secret }, wrapped: loaded.versions[i].wrapped }));
    validateItems(items, 'wrapped');
    const sameSecret = (secret: SecretRef, source: SecretRef) =>
      secret.projectId === source.projectId && secret.environmentId === source.environmentId && secret.secretId === source.secretId;
    if (items.some((item, i) => !sameSecret(item.secret, loaded.versions[i].secret))) {
      return this.#badVersions(principal, loaded.versions.map((source) => ({
        ...keyEntry('key.rewrap', principal, source.secret, 'deny', 'bad_claim', input), secretVersionId: source.id,
      })));
    }
    const sources = new Map(items.map((item, i) => [item.secret, loaded.versions[i]]));
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry => ({
      ...keyEntry('key.rewrap', principal, secret, decision, code, input, { from: sources.get(secret)!.secret.version }),
      secretVersionId: sources.get(secret)!.id,
    });
    const remote =
      this.#remote(this.#config.keks.primary) || items.some(({ wrapped }) => this.#remote(this.#config.keks.providerOf(wrapped)));
    return this.#keys(
      { action: 'key.rewrap', principal, permission: 'secret.write', secrets: items.map((item) => item.secret), remote, entry, input },
      () =>
        items.map(({ secret, wrapped }) => async (operation: KeyOperation) => {
          const key = await this.#open(wrapped, secret, operation);
          if (key === null) return null;
          try {
            return { wrapped: serialisable(await this.#config.keks.wrap(key, context(secret), operation)), wipe: () => {} };
          } finally {
            key.fill(0);
          }
        }),
      (done) => ({ wrapped: done.map(({ wrapped }) => wrapped), seqs: [] as number[] }),
    );
  }

  /** Immutable versions need no lock; their ids determine the whole batch before any key call. */
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
    if (ids.some((id) => !found.has(id))) {
      return this.#badVersions(input.principal, ids.map((id) => {
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

  async #badVersions(principal: string, entries: NewEntry[]): Promise<Outcome<never>> {
    if (this.#isRootAdmin(principal)) await this.#rootRow(principal);
    return this.#decide([principal], async () => {
      throw new Refused(refusal('bad_claim', MESSAGES.bad_claim), entries);
    });
  }

  /**
   * The data key, or null when it does not open as this secret's: a claim
   * that is not what it says. A key service that cannot answer is an outage,
   * not a verdict on the claim, and throws.
   */
  async #open(wrapped: WrappedKey, secret: SecretRef, operation: KeyOperation): Promise<Buffer | null> {
    try {
      return await this.#config.keks.unwrap(unwrappable(wrapped), context(secret), operation);
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
      remote: boolean;
      entry: (secret: SecretRef, decision: 'allow' | 'deny', code: string | null) => NewEntry;
      input: Correlation & { purpose?: string };
    },
    /** One per secret; null for a bad claim, an error for an outage or an unexpected fault. */
    operations: () => ((operation: KeyOperation) => Promise<T | null>)[],
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
    if (this.#isRootAdmin(principal)) await this.#rootRow(principal);
    const check = async (d: Decision) => {
      const reader = await this.#standing(d.tx, principal, d.members.get(principal), d.at, d.reports);
      // A grant on one slug in every project matches the environment's slug as the store has it, not the path the app sent.
      const bySlug = reader.all.grants.some((grant) => grant.environmentSlug !== null);
      const environments = bySlug ? await store.environmentsById(d.tx, secrets.map((secret) => secret.environmentId)) : new Map();
      const codes = secrets.map((secret) => refuses(reader, call.permission, placeOfSecret(secret, environments)));
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
        await lockLogHead(d.tx);
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
      const { outcomes, expired } = await settle(operations(), this.#prepared.options.keyBudgetMs);
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
        const released = secrets.map((secret, i) => outcomeEntry(secret, i, 'allow', null));
        d.log.push(...released);
        const answer = result(done);
        // A wrap's answer names its entries, which the app's writes refer to.
        if (action !== 'secret.read') d.after.push((seqOf) => Object.assign(answer as object, { seqs: released.map(seqOf) }));
        return answer;
      } finally {
        for (const value of done) value.wipe();
      }
    });
  }

  /** Whether `n` more keys would take `principal` past the bulk limit; counted under their row's lock, so exactly. */
  async #overBulkLimit(d: Decision, principal: string, n: number): Promise<boolean> {
    const { count, windowMs } = this.#config.bulkLimit;
    return (await store.releasesSince(d.tx, principal, d.at - windowMs)) + n > count;
  }

  // --- who holds what -----------------------------------------------------------

  #isRootAdmin(principal: string): boolean {
    return principal.startsWith('user:') && this.#config.rootAdmins.includes(principal.slice('user:'.length));
  }

  /**
   * Give a root admin a member row the first time anyone asks about them:
   * the app's sign-ins and sessions point at it, and their reads queue on
   * it like anyone's. Logged, and made in a transaction of its own, under
   * the log's lock: a decision that held the head and then waited for a
   * member row would take the locks out of order. The row never makes
   * anyone a root admin; the configuration does. Rows are never deleted, so
   * one read finds it made already, as on every fresh isolate but the first,
   * without queueing on the log's lock.
   */
  async #rootRow(principal: string): Promise<void> {
    if (this.#prepared.rooted.has(principal) || (await this.#settled()) !== null) return;
    if ((await store.member(this.#db, principal)) !== undefined) {
      this.#prepared.rooted.add(principal);
      return;
    }
    await this.#db.transaction(async (tx) => {
      await lockLogHead(tx);
      if ((await store.member(tx, principal)) !== undefined) return;
      const appended = await this.#append(tx, [
        {
          actor: VAULT_ACTOR,
          action: 'member.add',
          decision: 'allow',
          subjectPrincipal: principal,
          metadata: JSON.stringify({ owner: false, rootAdmin: true }),
        },
      ]);
      const { occurredAt: at, seqStart } = appended;
      const row = {
        principal,
        status: 'active' as const,
        owner: false,
        generation: 0,
        createdAt: at,
        createdBy: VAULT_ACTOR,
        statusChangedAt: at,
        statusChangedBy: VAULT_ACTOR,
        accessSeq: seqStart,
      };
      await store.insertMember(tx, { ...row, mac: memberMac(this.#prepared.rowKey, row, []) });
    });
    this.#prepared.rooted.add(principal);
  }

  /**
   * What `principal` holds, their row checked first (`#integrity`): a row
   * that fails holds nothing, and is `tampered`. A root admin's come from the
   * configuration, which no row can change.
   */
  async #standing(db: Queryable, principal: string, row: Member | undefined, at: number, reports: NewEntry[]): Promise<Standing> {
    const none = { isRootAdmin: false, isOwner: false, grants: [] };
    if (this.#isRootAdmin(principal)) {
      const root = { isRootAdmin: true, isOwner: true, grants: [] };
      return { principal, status: 'active', live: root, all: root, fault: null, stored: [] };
    }
    const grants = row === undefined ? [] : await store.grants(db, principal);
    const fault = await this.#integrity(db, principal, row, grants, reports);
    if (fault !== null) return { principal, status: 'tampered', live: none, all: none, fault, stored: grants };
    if (!LIVE_PRINCIPAL.test(principal)) return { principal, status: 'unknown', live: none, all: none, fault, stored: grants };
    if (row?.status !== 'active') return { principal, status: row?.status ?? 'unknown', live: none, all: none, fault, stored: grants };
    const held = grants.map((grant) => ({ ...grant, role: grant.role as Role }));
    const isOwner = row.owner && principal.startsWith('user:');
    return {
      principal,
      status: 'active',
      live: { isRootAdmin: false, isOwner, grants: held.filter((grant) => live(grant, at)) },
      all: { isRootAdmin: false, isOwner, grants: held },
      fault,
      stored: grants,
    };
  }

  #access(principal: string, row: Member | undefined, held: readonly GrantRow[], at: number, tampered: boolean): Access {
    if (this.#isRootAdmin(principal)) {
      return { principal, status: 'active', generation: row?.generation ?? 0, isRootAdmin: true, isOwner: true, grants: [], since: null, by: null };
    }
    const active = LIVE_PRINCIPAL.test(principal) && !tampered && row?.status === 'active';
    return {
      principal,
      status: tampered ? 'tampered' : !LIVE_PRINCIPAL.test(principal) ? 'unknown' : (row?.status ?? 'unknown'),
      generation: row?.generation ?? 0,
      isRootAdmin: false,
      isOwner: active && row.owner && principal.startsWith('user:'),
      grants: active ? held.filter((grant) => live(grant, at)).map(view) : [],
      since: row ? iso(row.statusChangedAt) : null,
      by: row?.statusChangedBy ?? null,
    };
  }

  /**
   * What `principal` holds now. Read without locks, the fast way; a row that
   * seems to fail its check is read again in one snapshot before anyone is
   * called tampered, since a change committed between two of the reads
   * looks like one.
   */
  async access(principal: string): Promise<Access> {
    await this.#settled();
    if (this.#isRootAdmin(principal)) await this.#rootRow(principal);
    const read = async (db: Queryable, reports: NewEntry[]) => {
      const [row, held, at] = await Promise.all([store.member(db, principal), store.grants(db, principal), this.#now(db)]);
      const fault = this.#isRootAdmin(principal) ? null : await this.#integrity(db, principal, row, held, reports);
      return this.#access(principal, row, held, at, fault !== null);
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
      if (this.#isRootAdmin(row.principal)) continue;
      const grants = held.filter((grant) => grant.principal === row.principal);
      const entry = newest.get(row.principal);
      const holds = entry !== undefined && this.#authentic(entry) && this.#sealed(row, grants) && entry.seq === row.accessSeq;
      if (!holds) await this.#integrity(db, row.principal, row, grants, reports);
    }
  }

  // --- changing access ----------------------------------------------------------

  setAccess(input: SetAccessInput): Promise<Outcome<{ changes: AccessChange[] }>> {
    const { actor, principal } = input;
    const changes = input.changes.map((change) => ({ ...change, environmentSlug: change.environmentSlug ?? null }));
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
    const onProjects = changes.flatMap(({ projectId, environmentId }) => (projectId === null ? [] : [{ projectId, environmentId }]));
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      if (!LIVE_PRINCIPAL.test(principal)) throw refused('invalid', `not a principal: ${principal}`);
      if (this.#isRootAdmin(principal)) throw refused('root_admin');
      const places = new Set<string>();
      for (const change of changes) {
        const shape = placeShape(change);
        if (shape !== null) throw refused('invalid', shape);
        const key = placeKey(change);
        if (places.has(key)) throw refused('invalid', 'each place may be changed once per call');
        places.add(key);
        if (change.role !== null && !isRole(change.role)) throw refused('invalid', `no such role: ${change.role}`);
        if (change.role !== null && (change.environmentId !== null || change.environmentSlug !== null) && !assignableToEnvironment(change.role)) {
          throw refused('invalid', `${change.role} can only be granted on a project, or on every project`);
        }
        const expiresAt = change.expiresAt === null ? null : Date.parse(change.expiresAt);
        if (Number.isNaN(expiresAt) || (expiresAt !== null && expiresAt <= d.at)) {
          throw refused('invalid', 'an end date must be in the future');
        }
      }
      if (changes.some((change) => grantKind(change) === 'every-project') && !(await store.canGrantEveryProject(d.tx))) {
        throw refused('invalid', "grants on every project need this release's database migration: an owner runs `coffre migrate`");
      }
      // Every project is always there; a project or an environment must be.
      const known = await store.places(
        d.tx,
        onProjects.map((change) => change.projectId),
        onProjects.flatMap((change) => (change.environmentId === null ? [] : [change.environmentId])),
      );
      for (const { projectId, environmentId } of onProjects) {
        if (!known.projects.has(projectId) || (environmentId !== null && known.environments.get(environmentId) !== projectId)) {
          throw refused('invalid', `no such place: ${environmentId === null ? projectId : `${projectId}/${environmentId}`}`);
        }
      }
      const acting = await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports);
      if (acting.status === 'tampered') throw refused('tampered');
      if (!changes.every((change) => mayManageAccess(acting.live, change))) throw refused('not_allowed');

      const row = d.members.get(principal);
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
      if (subject.status === 'tampered') throw refused('tampered', TAMPERED_SUBJECT);
      if (row?.status === 'removed') throw refused('removed');
      if (row === undefined) throw refused('not_a_member');
      // The grants the check verified, not a second read: what the decision changes, and seals.
      const held = subject.stored;
      d.grants.set(principal, [...held]);
      const outcomes = changes.map((change) => this.#apply(d, actor, principal, held, change, input));
      if (d.writes.length > 0) d.touched.add(principal);
      return { changes: outcomes };
    });
  }

  /** One place's change, logged when it changes what is live. */
  #apply(
    d: Decision,
    actor: string,
    principal: string,
    held: readonly GrantRow[],
    change: GrantChange & GrantPlace,
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

  admit(input: AdmitInput): Promise<Outcome<{ created: boolean; owner: boolean; generation: number }>> {
    const { actor, principal } = input;
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [
        accessEntry(actor, 'member.add', principal, 'deny', input, { owner: input.owner ?? null }, code),
      ]);
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      const acting = await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports);
      if (acting.status === 'tampered') throw refused('tampered');
      if (!acting.live.isOwner) throw refused('not_allowed', 'only owners may add or restore members');
      if (!LIVE_PRINCIPAL.test(principal)) throw refused('invalid', `not a member: ${principal}`);
      if (this.#isRootAdmin(principal)) throw refused('root_admin');
      if (input.owner === true && !principal.startsWith('user:')) {
        throw refused('invalid', 'service accounts cannot be owners');
      }
      const row = d.members.get(principal);
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
      if (subject.status === 'tampered') throw refused('tampered', TAMPERED_SUBJECT);
      d.touched.add(principal);
      d.grants.set(principal, [...subject.stored]);
      const entry = (action: string, owner: boolean) =>
        d.log.push(accessEntry(actor, action, principal, 'allow', input, { owner }));

      if (row === undefined || row.status === 'removed') {
        // Coming back is a fresh start: no owner role unless given again.
        const owner = input.owner ?? false;
        entry(row === undefined ? 'member.add' : 'member.restore', owner);
        d.writes.push(async (at) => {
          if (row === undefined) {
            await store.insertMember(d.tx, {
              principal,
              status: 'active',
              owner,
              generation: 0,
              createdAt: at,
              createdBy: actor,
              statusChangedAt: at,
              statusChangedBy: actor,
              ...UNSEALED,
            });
          } else {
            await store.updateMember(d.tx, principal, { status: 'active', owner, statusChangedAt: at, statusChangedBy: actor });
          }
        });
        // A removal moved the generation on already; coming back keeps it.
        return { created: true, owner, generation: row?.generation ?? 0 };
      }
      const owner = input.owner ?? row.owner;
      if (owner !== row.owner) {
        entry('member.owner', owner);
        d.writes.push(() => store.updateMember(d.tx, principal, { owner }));
      }
      return { created: false, owner, generation: row.generation };
    });
  }

  remove(input: RemoveInput): Promise<Outcome<{ revoked: Grant[]; generation: number }>> {
    const { actor, principal } = input;
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [accessEntry(actor, 'member.remove', principal, 'deny', input, {}, code)]);
    return this.#decide([actor, principal], async (d) => {
      validateCorrelation(input);
      if (!LIVE_PRINCIPAL.test(principal)) throw refused('invalid', `not a member: ${principal}`);
      if (this.#isRootAdmin(principal)) throw refused('root_admin');
      const row = d.members.get(principal);
      const acting = await this.#standing(d.tx, actor, d.members.get(actor), d.at, d.reports);
      if (acting.status === 'tampered') throw refused('tampered');
      const holder = acting.live;
      const subject = await this.#standing(d.tx, principal, row, d.at, d.reports);
      const held = subject.stored;
      if (subject.status === 'tampered') {
        if (!holder.isOwner) throw refused('not_allowed', 'only owners may remove a member whose record failed its check');
        return this.#startOver(d, actor, principal, row, subject.fault!, input, refused);
      }
      if (!holder.isOwner) throw refused('not_allowed', 'only owners may remove members');
      if (row?.status !== 'active') throw refused(row === undefined ? 'not_a_member' : 'removed');

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
          owner: false,
          generation,
          statusChangedAt: at,
          statusChangedBy: actor,
        });
      });
      return { revoked: revoked.map(view), generation };
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
        owner: false,
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

  async about(): Promise<{ checkpointKeys: Record<string, CheckpointKey>; rootAdmins: string[] }> {
    await this.#settled();
    const { signers, since } = this.#prepared;
    // A key it replaced vouches only for prefixes before its first entry under the current one: none, before it has one.
    const until = Number(since ?? 0n);
    return {
      checkpointKeys: Object.fromEntries(signers.map(({ keyId, publicKey }, i) => [keyId, { publicKey, until: i === 0 ? null : until }])),
      rootAdmins: this.#config.rootAdmins.map((email) => `user:${email}`),
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
      for (const entry of batch) {
        const result = verifyEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash, keys: logKeys });
        if (!result.ok) return { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: withCause(result.reason) };
      }
      const moved = forward(batch, keys, logKeys[0]!.keyId);
      if ('failedAtSeq' in moved) return { ok: false, failedAtSeq: Number(moved.failedAtSeq), reason: moved.reason };
      keys = moved.keys;
      for (const entry of batch) findings.add(entry);
      if (batch.length < VERIFY_BATCH) return { ok: true };
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

/**
 * Where a secret is, for a decision: its environment's slug as the store
 * has it, when it was read and the environment is in the project claimed;
 * otherwise none, which no grant on a slug matches.
 */
function placeOfSecret(secret: SecretRef, environments: ReadonlyMap<string, { projectId: string; slug: string }>): Place {
  const environment = environments.get(secret.environmentId);
  const slug = environment?.projectId === secret.projectId ? environment.slug : null;
  return { projectId: secret.projectId, environmentId: secret.environmentId, environmentSlug: slug };
}

/** Why `reader` may not do `permission` at `where`, or null if they may. */
function refuses(reader: Standing, permission: Permission, where: Place): RefusalCode | null {
  if (reader.status === 'tampered') return 'tampered';
  if (reader.status === 'removed') return 'removed';
  if (reader.status === 'unknown') return 'not_a_member';
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
 * on every project, neither, and the place as a path in its payload. Only a
 * grant that names no place at all is on every project (`grantKind`).
 */
function located(place: GrantPlace): { ids: Pick<NewEntry, 'projectId' | 'environmentId'>; detail: { place?: string } } {
  return grantKind(place) === 'every-project'
    ? { ids: {}, detail: { place: everyProjectPath(place.environmentSlug) } }
    : { ids: { projectId: place.projectId, environmentId: place.environmentId }, detail: {} };
}

/** One key per place a member can hold a grant at, by what the grant names first: its environment, its project, or neither. */
function placeKey(place: GrantPlace): string {
  if (place.environmentId !== null) return `environment:${place.environmentId}`;
  return place.projectId !== null ? `project:${place.projectId}` : everyProjectPath(place.environmentSlug);
}

/** Why a change's place is not one a grant can be at, or null when it is. */
function placeShape(place: GrantPlace): string | null {
  const kind = grantKind(place);
  if (kind === null) return place.projectId === null ? 'an environment is named in its project' : 'a slug names environments on every project, not in one';
  if (kind === 'every-project' && place.environmentSlug !== null && !SLUG.test(place.environmentSlug)) {
    return `not an environment slug: ${place.environmentSlug}`;
  }
  return null;
}

/** An environment's slug, as the schema has it. */
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

function view(grant: GrantRow): Grant {
  return {
    projectId: grant.projectId,
    environmentId: grant.environmentId,
    environmentSlug: grant.environmentSlug,
    role: grant.role as Role,
    expiresAt: grant.expiresAt === null ? null : iso(grant.expiresAt),
    grantedAt: iso(grant.grantedAt),
    grantedBy: grant.grantedBy,
  };
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function context(secret: SecretRef): SecretContext {
  return { projectId: secret.projectId, environmentId: secret.environmentId, secretId: secret.secretId };
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
