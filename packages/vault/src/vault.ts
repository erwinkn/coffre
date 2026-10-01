import {
  allows,
  assignableToEnvironment,
  isRole,
  isSyncPrincipal,
  mayManageAccess,
  type Holdings,
  type Permission,
  type Role,
} from '@coffre/core/access';
import type { LogKey, StoredEntry } from '@coffre/core/audit';
import type { SecretContext } from '@coffre/core/envelope';
import { KekUnavailableError, LocalKekProvider, type KekProvider } from '@coffre/core/kek';
import {
  checkpointMessage,
  describeAccessFault,
  type Access,
  type AccessChange,
  type AdmitInput,
  type Checkpoint,
  type CheckpointInput,
  type Grant,
  type GrantChange,
  type LogHead,
  type LogInput,
  type LogPage,
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
import { SNAPSHOT } from '@coffre/db/dialect';
import { appendEntries, lockLogHead, type NewEntry } from '@coffre/db/log';

import { signer, type Signer } from './checkpoint.ts';
import type { ResolvedVaultConfig } from './config.ts';
import { carries, entryView, further, headOf, UNVERIFIED, vaultLogKey, verifyChain, type Anchor } from './log.ts';
import { replay } from './replay.ts';
import * as store from './store.ts';
import type { GrantRow, Member } from './store.ts';

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
 * the log. Everything else is in the database, so any number of instances
 * share one set of members, one log and one bulk count.
 */
export type PreparedVault = {
  config: ResolvedVaultConfig;
  signer: Signer;
  logKey: LogKey;
  options: Required<VaultOptions>;
  /** How far the log is verified; `verifyChain` in log.ts. The furthest any call got to. */
  verified: Anchor;
  /** Root admins known to have a member row; rows are never deleted. */
  rooted: Set<string>;
};

export async function prepareVault(config: ResolvedVaultConfig, options: VaultOptions = {}): Promise<PreparedVault> {
  return {
    config,
    signer: await signer(config.signingKey),
    logKey: vaultLogKey(config.signingKey),
    options: { keyBudgetMs: options.keyBudgetMs ?? KEY_BUDGET_MS, clockOffset: options.clockOffset ?? (() => 0) },
    verified: UNVERIFIED,
    rooted: new Set(),
  };
}

/** The vault over `db`. Cheap: on Workers, one per call, over that call's connections. */
export function openVault(db: Database, prepared: PreparedVault): Vault {
  return new VaultService(db, prepared);
}

/** Every key operation of one call, together: a removal waits at most this long for a read at KMS. */
const KEY_BUDGET_MS = 5_000;

/** How long a decision waits for a lock: above the key budget, so a removal outwaits a read in flight. */
const LOCK_TIMEOUT_MS = 15_000;

const PRINCIPAL = /^(user|token|sync):[^\s:][^\s]*$/;

/** Who acts for the vault itself, as when it gives a root admin a member row. */
const VAULT_ACTOR = 'system:vault';

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

/** A key service that did not answer, and the entries that record what it did do. */
class Outage {
  readonly error: Error;
  readonly entries: NewEntry[];

  constructor(error: Error, entries: NewEntry[]) {
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
  checkpoint_diverged: 'the audit log does not extend the last checkpoint',
  log_broken: 'the vault log does not hold from the last checkpoint',
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
};

/** What a reader holds, read once per decision. */
type Standing = { principal: string; status: Access['status']; live: Holdings; all: Holdings };

/**
 * How one key operation of a call came out: its value; or a bad claim, a
 * key that does not open as the secret it was presented as; or no answer
 * from the key service.
 */
type KeyOutcome<T> = { ok: true; value: T } | { ok: false; outage: boolean };

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
    try {
      const result = await this.#db.transaction(async (tx) => {
        await store.boundLockWaits(tx, LOCK_TIMEOUT_MS);
        const members = principals.length === 0 ? new Map<string, Member>() : await store.lockMembers(tx, principals);
        const d: Decision = { tx, members, at: await this.#now(tx), log: [], writes: [] };
        const result = await decide(d);
        const at = d.log.length === 0 ? d.at : (await appendEntries(tx, this.#prepared.logKey, d.log)).occurredAt;
        for (const write of d.writes) await write(at);
        return result;
      });
      return { ok: true, ...result };
    } catch (error) {
      if (!(error instanceof Refused || error instanceof Outage)) throw error;
      await this.#db.transaction((tx) => appendEntries(tx, this.#prepared.logKey, error.entries));
      if (error instanceof Outage) throw error.error;
      return { ok: false, refusal: error.refusal };
    }
  }

  // --- keys -------------------------------------------------------------------

  // Raw DEKs are cleared on every path. JSON and base64 leave strings that
  // cannot be wiped, so this is best-effort memory hygiene.
  async unwrap(input: UnwrapInput): Promise<Outcome<{ keys: string[] }>> {
    const { principal, items } = input;
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry =>
      keyEntry('unwrap', principal, secret, decision, code, input.requestId, { purpose: input.purpose });
    const remote = items.some(({ wrapped }) => this.#remote(this.#config.keks.providerOf(wrapped)));
    return this.#keys(
      { action: 'unwrap', principal, permission: 'secret.read', secrets: items.map((item) => item.secret), remote, entry, input },
      () =>
        items.map(({ secret, wrapped }) => async () => {
          const key = await this.#open(wrapped, secret);
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

  async wrap(input: WrapInput): Promise<Outcome<{ wrapped: WrappedKey[] }>> {
    const { principal, items } = input;
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry =>
      keyEntry('wrap', principal, secret, decision, code, input.requestId);
    return this.#keys(
      {
        action: 'wrap',
        principal,
        permission: 'secret.write',
        secrets: items.map((item) => item.secret),
        remote: this.#remote(this.#config.keks.primary),
        entry,
        input,
      },
      () =>
        items.map(({ secret, key }) => async () => {
          const dek = Buffer.from(key, 'base64');
          try {
            return { wrapped: serialisable(await this.#config.keks.wrap(dek, context(secret))), wipe: () => {} };
          } finally {
            dek.fill(0);
          }
        }),
      (done) => ({ wrapped: done.map(({ wrapped }) => wrapped) }),
    );
  }

  async rewrap(input: RewrapInput): Promise<Outcome<{ wrapped: WrappedKey[] }>> {
    const { principal, items } = input;
    const from = new Map(items.map((item) => [item.secret, item.from]));
    const entry = (secret: SecretRef, decision: 'allow' | 'deny', code: string | null): NewEntry =>
      keyEntry('rewrap', principal, secret, decision, code, input.requestId, { from: from.get(secret) });
    const remote =
      this.#remote(this.#config.keks.primary) || items.some(({ wrapped }) => this.#remote(this.#config.keks.providerOf(wrapped)));
    return this.#keys(
      { action: 'rewrap', principal, permission: 'secret.write', secrets: items.map((item) => item.secret), remote, entry, input },
      () =>
        items.map(({ secret, wrapped }) => async () => {
          const key = await this.#open(wrapped, secret);
          if (key === null) return null;
          try {
            return { wrapped: serialisable(await this.#config.keks.wrap(key, context(secret))), wipe: () => {} };
          } finally {
            key.fill(0);
          }
        }),
      (done) => ({ wrapped: done.map(({ wrapped }) => wrapped) }),
    );
  }

  /**
   * The data key, or null when it does not open as this secret's: a claim
   * that is not what it says. A key service that cannot answer is an outage,
   * not a verdict on the claim, and throws.
   */
  async #open(wrapped: WrappedKey, secret: SecretRef): Promise<Buffer | null> {
    try {
      return await this.#config.keks.unwrap(unwrappable(wrapped), context(secret));
    } catch (error) {
      if (error instanceof KekUnavailableError) throw error;
      return null;
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
      action: 'unwrap' | 'wrap' | 'rewrap';
      principal: string;
      permission: Permission;
      secrets: readonly SecretRef[];
      remote: boolean;
      entry: (secret: SecretRef, decision: 'allow' | 'deny', code: string | null) => NewEntry;
      input: { requestId?: string | null; purpose?: string };
    },
    /** One per secret; each resolves to null for a bad claim, and throws `KekUnavailableError` for no answer. */
    operations: () => (() => Promise<T | null>)[],
    result: (done: T[]) => R,
  ): Promise<Outcome<R>> {
    const { action, principal, secrets, entry } = call;
    if (this.#isRootAdmin(principal)) await this.#rootRow(principal);
    const check = async (d: Decision) => {
      const reader = await this.#standing(d.tx, principal, d.members.get(principal), d.at);
      const codes = secrets.map((secret) => refuses(reader, call.permission, secret));
      let first = codes.find((code) => code !== null) ?? null;
      if (first === null && action === 'unwrap' && (await this.#overBulkLimit(d, principal, secrets.length))) first = 'bulk_limit';
      if (first !== null) {
        throw new Refused(
          refusal(first, MESSAGES[first]),
          secrets.map((secret, i) => entry(secret, 'deny', codes[i] ?? first)),
        );
      }
    };

    if (call.remote) {
      const intent = await this.#decide([principal], async (d) => {
        await check(d);
        d.log.push({
          actor: principal,
          action: 'key.intent',
          decision: 'allow',
          requestId: call.input.requestId ?? null,
          metadata: JSON.stringify({
            operation: action,
            ...(call.input.purpose === undefined ? {} : { purpose: call.input.purpose }),
            keys: secrets.map((secret) => ({ subject: secret.path, secretId: secret.secretId, version: secret.version })),
          }),
        });
        return {};
      });
      if (!intent.ok) return intent;
    }

    return this.#decide([principal], async (d) => {
      await check(d);
      const outcomes = await settle(operations(), this.#prepared.options.keyBudgetMs);
      const done = outcomes.flatMap((outcome) => (outcome.ok ? [outcome.value] : []));
      try {
        const unanswered = outcomes.filter((outcome) => !outcome.ok && outcome.outage).length;
        if (unanswered > 0) {
          // The call fails as an outage, not a verdict on the claim, but
          // what the key service did is on the record first: each key it
          // opened and the vault withheld, each it did not answer for.
          const code = (outcome: KeyOutcome<T>) => (outcome.ok ? 'withheld' : outcome.outage ? 'kms_unavailable' : 'bad_claim');
          throw new Outage(
            new KekUnavailableError(`the key service did not answer for ${unanswered} of ${secrets.length} keys`),
            secrets.map((secret, i) => entry(secret, 'deny', code(outcomes[i]))),
          );
        }
        if (done.length < outcomes.length) {
          throw new Refused(
            refusal('bad_claim', MESSAGES.bad_claim),
            secrets.map((secret) => entry(secret, 'deny', 'bad_claim')),
          );
        }
        d.log.push(...secrets.map((secret) => entry(secret, 'allow', null)));
        return result(done);
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
   * anyone a root admin; the configuration does.
   */
  async #rootRow(principal: string): Promise<void> {
    if (this.#prepared.rooted.has(principal)) return;
    await this.#db.transaction(async (tx) => {
      await lockLogHead(tx);
      if ((await store.member(tx, principal)) !== undefined) return;
      const { occurredAt } = await appendEntries(tx, this.#prepared.logKey, [
        {
          actor: VAULT_ACTOR,
          action: 'principal.admit',
          decision: 'allow',
          subjectPrincipal: principal,
          metadata: JSON.stringify({ owner: false, rootAdmin: true }),
        },
      ]);
      await store.insertMember(tx, {
        principal,
        status: 'active',
        owner: false,
        generation: 0,
        createdAt: occurredAt,
        createdBy: VAULT_ACTOR,
        statusChangedAt: occurredAt,
        statusChangedBy: VAULT_ACTOR,
      });
    });
    this.#prepared.rooted.add(principal);
  }

  async #standing(db: Queryable, principal: string, row: Member | undefined, at: number): Promise<Standing> {
    const status = this.#isRootAdmin(principal) ? 'active' : (row?.status ?? 'unknown');
    if (this.#isRootAdmin(principal)) {
      const root = { isRootAdmin: true, isOwner: true, grants: [] };
      return { principal, status, live: root, all: root };
    }
    if (row?.status !== 'active') {
      const none = { isRootAdmin: false, isOwner: false, grants: [] };
      return { principal, status, live: none, all: none };
    }
    const held = (await store.grants(db, principal)).map((grant) => ({ ...grant, role: grant.role as Role }));
    const isOwner = row.owner && principal.startsWith('user:');
    return {
      principal,
      status,
      live: { isRootAdmin: false, isOwner, grants: held.filter((grant) => live(grant, at)) },
      all: { isRootAdmin: false, isOwner, grants: held },
    };
  }

  #access(principal: string, row: Member | undefined, held: readonly GrantRow[], at: number): Access {
    if (this.#isRootAdmin(principal)) {
      return { principal, status: 'active', generation: row?.generation ?? 0, isRootAdmin: true, isOwner: true, grants: [], since: null, by: null };
    }
    const active = row?.status === 'active';
    return {
      principal,
      status: row?.status ?? 'unknown',
      generation: row?.generation ?? 0,
      isRootAdmin: false,
      isOwner: active && row.owner && principal.startsWith('user:'),
      grants: active ? held.filter((grant) => live(grant, at)).map(view) : [],
      since: row ? iso(row.statusChangedAt) : null,
      by: row?.statusChangedBy ?? null,
    };
  }

  async access(principal: string): Promise<Access> {
    if (this.#isRootAdmin(principal)) await this.#rootRow(principal);
    const [row, held, at] = await Promise.all([
      store.member(this.#db, principal),
      store.grants(this.#db, principal),
      this.#now(this.#db),
    ]);
    return this.#access(principal, row, held, at);
  }

  async members(): Promise<Access[]> {
    const [rows, held, at] = await Promise.all([store.allMembers(this.#db), store.grants(this.#db), this.#now(this.#db)]);
    const byPrincipal = new Map(rows.map((row) => [row.principal, row]));
    const everyone = new Set([...this.#config.rootAdmins.map((email) => `user:${email}`), ...byPrincipal.keys()]);
    return [...everyone]
      .sort()
      .map((principal) => this.#access(principal, byPrincipal.get(principal), held.filter((grant) => grant.principal === principal), at));
  }

  // --- changing access ----------------------------------------------------------

  setAccess(input: SetAccessInput): Promise<Outcome<{ changes: AccessChange[] }>> {
    const { actor, principal } = input;
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [
        accessEntry(actor, 'grant.set', principal, 'deny', input.requestId, { changes: input.changes }, code),
      ]);
    return this.#decide([actor, principal], async (d) => {
      if (!PRINCIPAL.test(principal)) throw refused('invalid', `not a principal: ${principal}`);
      if (this.#isRootAdmin(principal)) throw refused('root_admin');
      const places = new Set<string>();
      for (const change of input.changes) {
        const key = `${change.projectId}/${change.environmentId ?? ''}`;
        if (places.has(key)) throw refused('invalid', 'each place may be changed once per call');
        places.add(key);
        if (change.role !== null && !isRole(change.role)) throw refused('invalid', `no such role: ${change.role}`);
        if (change.role !== null && change.environmentId !== null && !assignableToEnvironment(change.role)) {
          throw refused('invalid', `${change.role} can only be granted on a project`);
        }
        const expiresAt = change.expiresAt === null ? null : Date.parse(change.expiresAt);
        if (Number.isNaN(expiresAt) || (expiresAt !== null && expiresAt <= d.at)) {
          throw refused('invalid', 'an end date must be in the future');
        }
      }
      const known = await store.places(
        d.tx,
        input.changes.map((change) => change.projectId),
        input.changes.flatMap((change) => (change.environmentId === null ? [] : [change.environmentId])),
      );
      for (const { projectId, environmentId } of input.changes) {
        if (!known.projects.has(projectId) || (environmentId !== null && known.environments.get(environmentId) !== projectId)) {
          throw refused('invalid', `no such place: ${environmentId === null ? projectId : `${projectId}/${environmentId}`}`);
        }
      }
      const holder = (await this.#standing(d.tx, actor, d.members.get(actor), d.at)).live;
      if (!input.changes.every((change) => mayManageAccess(holder, principal, change))) throw refused('not_allowed');

      const row = d.members.get(principal);
      if (row?.status === 'removed') throw refused('removed');
      if (row === undefined) {
        // A sync is a member from its first grant; anyone else is admitted first.
        if (!isSyncPrincipal(principal) || input.changes.every((change) => change.role === null)) {
          throw refused('not_a_member');
        }
        d.log.push(accessEntry(actor, 'principal.admit', principal, 'allow', input.requestId, { owner: false }));
        d.writes.push(async (at) => {
          await store.insertMember(d.tx, {
            principal,
            status: 'active',
            owner: false,
            generation: 0,
            createdAt: at,
            createdBy: actor,
            statusChangedAt: at,
            statusChangedBy: actor,
          });
        });
      }
      const held = row === undefined ? [] : await store.grants(d.tx, principal);
      const changes = input.changes.map((change) => this.#apply(d, actor, principal, held, change, input.requestId));
      return { changes };
    });
  }

  /** One place's change, logged when it changes what is live. */
  #apply(
    d: Decision,
    actor: string,
    principal: string,
    held: readonly GrantRow[],
    change: GrantChange,
    requestId: string | null | undefined,
  ): AccessChange {
    const existing = held.find((grant) => grant.projectId === change.projectId && grant.environmentId === change.environmentId);
    const current = existing !== undefined && live(existing, d.at) ? existing : undefined;
    const expiresAt = change.expiresAt === null ? null : Date.parse(change.expiresAt);
    const place = { projectId: change.projectId, environmentId: change.environmentId };
    const entry = (action: string, role: string | null) =>
      d.log.push({
        ...accessEntry(actor, action, principal, 'allow', requestId, {
          role,
          expiresAt: expiresAt === null ? null : iso(expiresAt),
          previousRole: current?.role ?? null,
        }),
        ...place,
      });
    // A lapsed grant is cleared with no entry: it changes nothing anyone holds.
    const clear = () => {
      if (existing !== undefined) d.writes.push(() => store.deleteGrant(d.tx, principal, place));
    };

    if (change.role === null) {
      clear();
      if (current === undefined) return 'unchanged';
      entry('grant.revoke', null);
      return 'revoked';
    }
    if (current !== undefined && current.role === change.role && current.expiresAt === expiresAt) return 'unchanged';
    const role = change.role;
    clear();
    d.writes.push((at) => store.insertGrant(d.tx, { principal, ...place, role, expiresAt, grantedAt: at, grantedBy: actor }));
    entry(current === undefined ? 'grant.create' : 'grant.update', role);
    return current === undefined ? 'created' : 'updated';
  }

  admit(input: AdmitInput): Promise<Outcome<{ created: boolean; owner: boolean }>> {
    const { actor, principal } = input;
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [
        accessEntry(actor, 'principal.admit', principal, 'deny', input.requestId, { owner: input.owner ?? null }, code),
      ]);
    return this.#decide([actor, principal], async (d) => {
      const holder = (await this.#standing(d.tx, actor, d.members.get(actor), d.at)).live;
      if (!holder.isOwner) throw refused('not_allowed', 'only owners may add or restore members');
      if (!PRINCIPAL.test(principal) || isSyncPrincipal(principal)) throw refused('invalid', `not a member: ${principal}`);
      if (this.#isRootAdmin(principal)) throw refused('root_admin');
      if (input.owner === true && !principal.startsWith('user:')) {
        throw refused('invalid', 'service accounts cannot be owners');
      }
      const row = d.members.get(principal);
      const entry = (action: string, owner: boolean) =>
        d.log.push(accessEntry(actor, action, principal, 'allow', input.requestId, { owner }));

      if (row === undefined || row.status === 'removed') {
        // Coming back is a fresh start: no owner role unless given again.
        const owner = input.owner ?? false;
        entry(row === undefined ? 'principal.admit' : 'principal.restore', owner);
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
            });
          } else {
            await store.updateMember(d.tx, principal, { status: 'active', owner, statusChangedAt: at, statusChangedBy: actor });
          }
        });
        return { created: true, owner };
      }
      const owner = input.owner ?? row.owner;
      if (owner !== row.owner) {
        entry('principal.owner', owner);
        d.writes.push(() => store.updateMember(d.tx, principal, { owner }));
      }
      return { created: false, owner };
    });
  }

  remove(input: RemoveInput): Promise<Outcome<{ revoked: Grant[] }>> {
    const { actor, principal } = input;
    const refused = (code: RefusalCode, message = MESSAGES[code]) =>
      new Refused(refusal(code, message), [accessEntry(actor, 'principal.remove', principal, 'deny', input.requestId, {}, code)]);
    return this.#decide([actor, principal], async (d) => {
      if (this.#isRootAdmin(principal)) throw refused('root_admin');
      const row = d.members.get(principal);
      const held = row === undefined ? [] : await store.grants(d.tx, principal);
      const holder = (await this.#standing(d.tx, actor, d.members.get(actor), d.at)).live;
      // Owners remove anyone. Removing a sync only takes access away, so
      // whoever may take away one of its grants, or manage it at its
      // source, may remove it, and anyone may remove one that holds nothing.
      const places = input.source === undefined ? held : [...held, input.source];
      const may =
        holder.isOwner ||
        (isSyncPrincipal(principal) &&
          (held.length === 0 || places.some((place) => mayManageAccess(holder, principal, { ...place, role: null }))));
      if (!may) throw refused('not_allowed', 'only owners may remove members');
      if (row?.status !== 'active') throw refused(row === undefined ? 'not_a_member' : 'removed');

      const revoked = held.filter((grant) => live(grant, d.at));
      for (const grant of revoked) {
        d.log.push({
          ...accessEntry(actor, 'grant.revoke', principal, 'allow', input.requestId, {
            role: null,
            expiresAt: null,
            previousRole: grant.role,
          }),
          projectId: grant.projectId,
          environmentId: grant.environmentId,
        });
      }
      d.log.push(accessEntry(actor, 'principal.remove', principal, 'allow', input.requestId, { revoked: revoked.length }));
      d.writes.push(async (at) => {
        await store.deleteGrants(d.tx, principal);
        await store.updateMember(d.tx, principal, {
          status: 'removed',
          owner: false,
          generation: row.generation + 1,
          statusChangedAt: at,
          statusChangedBy: actor,
        });
      });
      return { revoked: revoked.map(view) };
    });
  }

  // --- checkpoints and the log --------------------------------------------------

  /** The last checkpoint the vault signed: its newest allowed `checkpoint` entry. */
  async #latest(db: Queryable): Promise<Checkpoint | null> {
    const row = await store.latestVaultEntry(db, ['checkpoint']);
    if (row === undefined) return null;
    const { subject: _, ...checkpoint } = JSON.parse(row.metadata) as Checkpoint & { subject: string };
    return checkpoint;
  }

  checkpoint(input: CheckpointInput): Promise<Outcome<{ checkpoint: Checkpoint }>> {
    return this.#decide([], async (d) => {
      // Checkpoints one at a time, each against the one before.
      await lockLogHead(d.tx);
      const latest = await this.#latest(d.tx);
      // Signing the same head twice is one checkpoint.
      if (latest !== null && latest.seq === input.seq && latest.headHash === input.headHash) return { checkpoint: latest };
      const refused = (code: RefusalCode, detail: Record<string, unknown>) =>
        new Refused(refusal(code, MESSAGES[code]), [
          {
            actor: SCHEDULER,
            action: 'checkpoint',
            decision: 'deny',
            code,
            metadata: JSON.stringify({ subject: 'audit', seq: input.seq, headHash: input.headHash, ...detail }),
          },
        ]);
      const extends_ =
        latest === null
          ? input.previous === null
          : input.previous !== null &&
            input.previous.seq === latest.seq &&
            input.previous.hash === latest.headHash &&
            input.seq > latest.seq;
      if (!extends_) throw refused('checkpoint_diverged', { previous: input.previous, latest });
      // The vault's entries too: the log still holds the head signed last,
      // and is whole from there. So a rewrite is never signed over, and the
      // app's record of the head signed before shows it.
      const { verification: held } = await verifyChain(d.tx, this.#prepared.logKey, [], anchorAt(latest?.vault ?? null));
      if (!held.ok) throw refused('log_broken', { failedAtSeq: held.failedAtSeq, reason: held.reason });
      const vault = headOf((await store.vaultPage(d.tx, undefined, 1))[0]);
      const signedAt = iso(d.at);
      const signed = { seq: input.seq, headHash: input.headHash, vault, signedAt };
      const checkpoint = {
        ...signed,
        keyId: this.#prepared.signer.keyId,
        signature: await this.#prepared.signer.sign(checkpointMessage(signed)),
      };
      d.log.push({
        actor: SCHEDULER,
        action: 'checkpoint',
        decision: 'allow',
        metadata: JSON.stringify({ subject: 'audit', ...checkpoint }),
      });
      return { checkpoint };
    });
  }

  async latestCheckpoint(): Promise<{ checkpoint: Checkpoint | null; publicKey: string }> {
    return { checkpoint: await this.#latest(this.#db), publicKey: this.#prepared.signer.publicKey };
  }

  async log(input: LogInput): Promise<Outcome<LogPage>> {
    if (!this.#isRootAdmin(input.actor)) {
      const refused = await this.#decide([], async () => {
        throw new Refused(refusal('not_allowed', 'only root admins may read the vault log'), [
          {
            actor: input.actor,
            action: 'log.read',
            decision: 'deny',
            code: 'not_allowed',
            metadata: JSON.stringify({ subject: 'vault' }),
          },
        ]);
      });
      return refused as Outcome<LogPage>;
    }
    const limit = Math.min(Math.max(Math.trunc(input.limit ?? 50), 1), 200);
    const shown = await store.vaultPage(this.#db, input.before === undefined ? undefined : BigInt(input.before), limit);
    const verification =
      input.full === true ? await this.#verifyAll(shown, null, null) : await this.#verify(this.#db, shown, this.#prepared.verified);
    return { ok: true, entries: shown.map(entryView), verification };
  }

  verifyLog(input: VerifyLogInput): Promise<LogVerification> {
    return this.#verifyAll([], input.through, input.upTo ?? null);
  }

  /** `shown`, and the chain from `anchor`; the furthest verified is kept for the next view. */
  async #verify(db: Queryable, shown: readonly StoredEntry[], anchor: Anchor): Promise<LogVerification> {
    const { verification, anchor: reached } = await verifyChain(db, this.#prepared.logKey, shown, anchor);
    if (verification.ok) this.#prepared.verified = further(this.#prepared.verified, reached);
    return verification;
  }

  /**
   * `shown`, and the chain from its first entry, in one snapshot: every
   * link and hash, the vault's MACs; then the heads that must still be
   * there: the one the app verified up to (`upTo`), so both authors are
   * checked over the same entries, the one the app last recorded from a
   * checkpoint (`through`), and the last checkpoint's; and the members and
   * grants replayed from it.
   */
  #verifyAll(shown: readonly StoredEntry[], through: LogHead | null, upTo: LogHead | null): Promise<LogVerification> {
    return this.#db.transaction(async (tx) => {
      const verification = await this.#verify(tx, shown, UNVERIFIED);
      if (!verification.ok) return verification;
      if (upTo !== null && !(await carries(tx, upTo))) {
        return { ok: false, failedAtSeq: upTo.seq, reason: 'not the entry the app verified up to: the log changed between the two checks' };
      }
      const signed = (await this.#latest(tx))?.vault ?? null;
      for (const [kept, by] of [[through, 'a checkpoint the app recorded'], [signed, 'the last checkpoint']] as const) {
        if (kept === null || (await carries(tx, kept))) continue;
        return { ok: false, failedAtSeq: kept.seq, reason: `not the entry ${by} signed: the log was rewritten or cut back` };
      }
      const fault = await replay(tx, await this.#now(tx));
      return fault === null ? verification : { ok: false, failedAtSeq: null, reason: describeAccessFault(fault), fault };
    }, SNAPSHOT);
  }
}

/**
 * Run a call's key operations at once and wait for every one, within the
 * budget: settled, all of them, so a failure never leaves the others
 * unseen. One that has not answered by then counts as an outage, and what
 * it answers later is wiped. Any other error is a fault, thrown once
 * everything that answered is wiped.
 */
async function settle<T extends { wipe: () => void }>(
  operations: (() => Promise<T | null>)[],
  budgetMs: number,
): Promise<KeyOutcome<T>[]> {
  const outcomes: (KeyOutcome<T> | undefined)[] = operations.map(() => undefined);
  const faults: unknown[] = [];
  let over = false;
  const all = Promise.all(
    operations.map(async (operation, i) => {
      try {
        const value = await operation();
        if (over) value?.wipe();
        else outcomes[i] = value === null ? { ok: false, outage: false } : { ok: true, value };
      } catch (error) {
        if (over) return;
        if (error instanceof KekUnavailableError) outcomes[i] = { ok: false, outage: true };
        else faults.push(error);
      }
    }),
  );
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([all, new Promise((resolve) => (timer = setTimeout(resolve, budgetMs)))]);
  clearTimeout(timer);
  over = true;
  if (faults.length > 0) {
    for (const outcome of outcomes) if (outcome?.ok) outcome.value.wipe();
    throw faults[0];
  }
  return outcomes.map((outcome) => outcome ?? { ok: false, outage: true });
}

/** Why `reader` may not do `permission` on `secret`, or null if they may. */
function refuses(reader: Standing, permission: Permission, secret: SecretRef): RefusalCode | null {
  if (reader.status === 'removed') return 'removed';
  if (reader.status === 'unknown') return 'not_a_member';
  const where = { projectId: secret.projectId, environmentId: secret.environmentId };
  if (allows(reader.live, permission, where)) return null;
  // Would a grant that has lapsed have covered it?
  return allows(reader.all, permission, where) ? 'expired' : 'no_grant';
}

/**
 * An entry about a key. A new secret's row is not committed when its key is
 * wrapped, so a wrap names the secret in its payload; the others name it.
 */
function keyEntry(
  action: 'unwrap' | 'wrap' | 'rewrap',
  principal: string,
  secret: SecretRef,
  decision: 'allow' | 'deny',
  code: string | null,
  requestId: string | null | undefined,
  detail: Record<string, unknown> = {},
): NewEntry {
  return {
    actor: principal,
    action,
    decision,
    code,
    projectId: secret.projectId,
    environmentId: secret.environmentId,
    secretId: action === 'wrap' ? null : secret.secretId,
    requestId: requestId ?? null,
    metadata: JSON.stringify({
      subject: secret.path,
      ...(action === 'wrap' ? { secretId: secret.secretId } : {}),
      version: secret.version,
      ...detail,
    }),
  };
}

/** An entry about a member's access. */
function accessEntry(
  actor: string,
  action: string,
  principal: string,
  decision: 'allow' | 'deny',
  requestId: string | null | undefined,
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
    requestId: requestId ?? null,
    metadata: JSON.stringify(PRINCIPAL.test(principal) ? detail : { subject: principal, ...detail }),
  };
}

/** Where to verify from to check that the log still holds `head`: right after it. */
function anchorAt(head: LogHead | null): Anchor {
  if (head === null || head.hash === UNVERIFIED.hash.toString('hex')) return UNVERIFIED;
  return { nextSeq: BigInt(head.seq) + 1n, hash: Buffer.from(head.hash, 'hex'), vaultEntries: 0 };
}

function live(grant: GrantRow, at: number): boolean {
  return grant.expiresAt === null || grant.expiresAt > at;
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
