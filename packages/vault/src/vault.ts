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
import type { SecretContext } from '@coffre/core/envelope';
import { KekUnavailableError } from '@coffre/core/kek';
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

import { signer, type Signer } from './checkpoint.ts';
import type { BulkLimit, ResolvedVaultConfig } from './config.ts';
import { append, carries, entry, head, logKey, UNVERIFIED, verify, type Anchor, type Appended } from './log.ts';
import { replay } from './replay.ts';
import type { Sqlite } from './sqlite.ts';
import { openStore, type GrantRow, type LogRow, type Store } from './store.ts';

export type VaultOptions = {
  /** The clock, in milliseconds; tests move it. */
  now?: () => number;
};

/** The vault over `db`, migrated and ready. */
export async function openVault(db: Sqlite, config: ResolvedVaultConfig, options: VaultOptions = {}): Promise<Vault> {
  return new VaultService(openStore(db), config, await signer(config.signingKey), options.now ?? Date.now);
}

const PRINCIPAL = /^(user|token|sync):[^\s:][^\s]*$/;

/** A refusal and the entries that record it. */
class Refused {
  readonly refusal: Refusal;
  readonly entries: Appended[];

  constructor(refusal: Refusal, entries: Appended[]) {
    this.refusal = refusal;
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
 * The one implementation of `Vault`. Every decision reads and writes the
 * store in one synchronous transaction, logging as it goes. Key operations,
 * which may be asynchronous (a KMS), run before it, and only for a call the
 * rules allow: a KMS logs each one, and should never show a key opened for a
 * read coffre refused. Calls run one at a time, as they would in a Durable
 * Object, so nothing interleaves between that check, the key operations and
 * the decision, which comes to the same answer.
 */
class VaultService implements Vault {
  readonly #store: Store;
  readonly #config: ResolvedVaultConfig;
  readonly #signer: Signer;
  /** What the log is chained with; `logKey` in log.ts. */
  readonly #logKey: Buffer;
  readonly #now: () => number;
  /** How far the log is verified; `verify` in log.ts. In memory only: the store cannot vouch for itself. */
  #verified: Anchor = UNVERIFIED;
  #queue: Promise<unknown> = Promise.resolve();

  constructor(store: Store, config: ResolvedVaultConfig, signer: Signer, now: () => number) {
    this.#store = store;
    this.#config = config;
    this.#signer = signer;
    this.#logKey = logKey(config.signingKey);
    this.#now = now;
  }

  #serial<T>(work: () => Promise<T>): Promise<T> {
    const next = this.#queue.then(work, work);
    this.#queue = next.catch(() => undefined);
    return next;
  }

  /** Decide and log in one transaction; a `Refused` rolls back all but its own entries. */
  #decide<T>(at: number, decision: (log: Appended[]) => T): Outcome<T> {
    try {
      return this.#store.transaction(() => {
        const log: Appended[] = [];
        const result = decision(log);
        append(this.#store, this.#logKey, at, log);
        return { ok: true as const, ...result };
      });
    } catch (error) {
      if (!(error instanceof Refused)) throw error;
      this.#store.transaction(() => append(this.#store, this.#logKey, at, error.entries));
      return { ok: false, refusal: error.refusal };
    }
  }

  // --- keys ---------------------------------------------------------------

  // Clear raw DEKs on every path. JSON/base64 transport leaves strings we
  // cannot wipe, so this is best-effort memory hygiene.
  unwrap(input: UnwrapInput): Promise<Outcome<{ keys: string[] }>> {
    return this.#serial(async () => {
      const at = this.#now();
      const allowed =
        this.#mayAll(input.principal, 'secret.read', input.items, at) &&
        !this.#overBulkLimit(input.principal, input.items.length, at);
      const keys = allowed
        ? await Promise.all(
            input.items.map(async ({ secret, wrapped }) => {
              const key = await this.#open(wrapped, secret);
              if (key === null) return null;
              try {
                return base64(key);
              } finally {
                key.fill(0);
              }
            }),
          )
        : [];
      const entry = (secret: SecretRef, outcome: 'allow' | 'refuse', code: RefusalCode | null): Appended => ({
        actor: input.principal,
        action: 'unwrap',
        outcome,
        code,
        subject: secret.path,
        detail: { ...place(secret), purpose: input.purpose, requestId: input.requestId ?? null },
      });
      return this.#decide(at, (log) => {
        const codes = input.items.map(({ secret }, i) =>
          this.#refuses(input.principal, 'secret.read', secret, at) ?? (keys[i] === null ? 'bad_claim' : null),
        );
        let first = codes.find((code) => code !== null) ?? null;
        if (first === null && this.#overBulkLimit(input.principal, input.items.length, at)) first = 'bulk_limit';
        if (first !== null) {
          throw new Refused(
            refusal(first, MESSAGES[first]),
            input.items.map(({ secret }, i) => entry(secret, 'refuse', codes[i] ?? first)),
          );
        }
        log.push(...input.items.map(({ secret }) => entry(secret, 'allow', null)));
        return { keys: keys as string[] };
      });
    });
  }

  wrap(input: WrapInput): Promise<Outcome<{ wrapped: WrappedKey[] }>> {
    return this.#serial(async () => {
      const at = this.#now();
      const wrapped = this.#mayAll(input.principal, 'secret.write', input.items, at)
        ? await Promise.all(
            input.items.map(async ({ secret, key }) => {
              const dek = Buffer.from(key, 'base64');
              try {
                return serialisable(await this.#config.keks.wrap(dek, context(secret)));
              } finally {
                dek.fill(0);
              }
            }),
          )
        : [];
      return this.#decide(at, (log) => {
        this.#requireWrite(input.principal, 'wrap', input.items.map(({ secret }) => ({ secret })), at, input.requestId);
        log.push(
          ...input.items.map(({ secret }) => ({
            actor: input.principal,
            action: 'wrap',
            outcome: 'allow' as const,
            subject: secret.path,
            detail: { ...place(secret), requestId: input.requestId ?? null },
          })),
        );
        return { wrapped };
      });
    });
  }

  rewrap(input: RewrapInput): Promise<Outcome<{ wrapped: WrappedKey[] }>> {
    return this.#serial(async () => {
      const at = this.#now();
      const wrapped = this.#mayAll(input.principal, 'secret.write', input.items, at)
        ? await Promise.all(
            input.items.map(async ({ secret, wrapped }) => {
              const key = await this.#open(wrapped, secret);
              if (key === null) return null;
              try {
                return serialisable(await this.#config.keks.wrap(key, context(secret)));
              } finally {
                key.fill(0);
              }
            }),
          )
        : [];
      return this.#decide(at, (log) => {
        this.#requireWrite(
          input.principal,
          'rewrap',
          input.items.map(({ secret, from }, i) => ({ secret, from, bad: wrapped[i] === null })),
          at,
          input.requestId,
        );
        log.push(
          ...input.items.map(({ secret, from }) => ({
            actor: input.principal,
            action: 'rewrap',
            outcome: 'allow' as const,
            subject: secret.path,
            detail: { ...place(secret), from, requestId: input.requestId ?? null },
          })),
        );
        return { wrapped: wrapped as WrappedKey[] };
      });
    });
  }

  /**
   * The data key, or null when it does not open as this secret's: a claim
   * that is not what it says. A key service that cannot answer is an outage,
   * not a verdict on the claim, so it fails the call rather than refusing it.
   */
  async #open(wrapped: WrappedKey, secret: SecretRef): Promise<Buffer | null> {
    try {
      return await this.#config.keks.unwrap(unwrappable(wrapped), context(secret));
    } catch (error) {
      if (error instanceof KekUnavailableError) throw error;
      return null;
    }
  }

  /** Whether `principal` may do `permission` on every item's secret: the check before any key operation. */
  #mayAll(principal: string, permission: Permission, items: readonly { secret: SecretRef }[], at: number): boolean {
    return items.every(({ secret }) => this.#refuses(principal, permission, secret, at) === null);
  }

  /** Refuse, with every item logged, unless `principal` may write each secret. */
  #requireWrite(
    principal: string,
    action: string,
    items: { secret: SecretRef; from?: number; bad?: boolean }[],
    at: number,
    requestId: string | null | undefined,
  ): void {
    const codes = items.map(
      ({ secret, bad }) => this.#refuses(principal, 'secret.write', secret, at) ?? (bad ? 'bad_claim' : null),
    );
    const first = codes.find((code) => code !== null);
    if (first === undefined || first === null) return;
    throw new Refused(
      refusal(first, MESSAGES[first]),
      items.map(({ secret, from }, i) => ({
        actor: principal,
        action,
        outcome: 'refuse',
        code: codes[i] ?? first,
        subject: secret.path,
        detail: { ...place(secret), ...(from === undefined ? {} : { from }), requestId: requestId ?? null },
      })),
    );
  }

  /** Why `principal` may not do `permission` on `secret`, or null if they may. */
  #refuses(principal: string, permission: Permission, secret: SecretRef, at: number): RefusalCode | null {
    const status = this.#status(principal);
    if (status === 'removed') return 'removed';
    if (status === 'unknown') return 'not_a_member';
    const where = { projectId: secret.projectId, environmentId: secret.environmentId };
    if (allows(this.#holdings(principal, at), permission, where)) return null;
    // Would a grant that has lapsed have covered it?
    return allows(this.#holdings(principal, null), permission, where) ? 'expired' : 'no_grant';
  }

  /** Whether `n` more unwraps would take `principal` past the limit. */
  #overBulkLimit(principal: string, n: number, at: number): boolean {
    const { count: limit, windowMs }: BulkLimit = this.#config.bulkLimit;
    return this.#store.unwrapsSince(principal, at - windowMs) + n > limit;
  }

  // --- who holds what -----------------------------------------------------

  #isRootAdmin(principal: string): boolean {
    return principal.startsWith('user:') && this.#config.rootAdmins.includes(principal.slice('user:'.length));
  }

  #status(principal: string): Access['status'] {
    if (this.#isRootAdmin(principal)) return 'active';
    return this.#store.member(principal)?.status ?? 'unknown';
  }

  /** What `principal` holds at `at`, or with lapsed grants too when `at` is null. */
  #holdings(principal: string, at: number | null): Holdings {
    if (this.#isRootAdmin(principal)) return { isRootAdmin: true, isOwner: true, grants: [] };
    const row = this.#store.member(principal);
    if (row?.status !== 'active') return { isRootAdmin: false, isOwner: false, grants: [] };
    return {
      isRootAdmin: false,
      isOwner: row.owner && principal.startsWith('user:'),
      grants: this.#store.grants(principal)
        .filter((grant) => at === null || live(grant, at))
        .map((grant) => ({ ...grant, role: grant.role as Role })),
    };
  }

  #access(principal: string, at: number): Access {
    if (this.#isRootAdmin(principal)) {
      return { principal, status: 'active', generation: 0, isRootAdmin: true, isOwner: true, grants: [], since: null, by: null };
    }
    const row = this.#store.member(principal);
    const active = row?.status === 'active';
    return {
      principal,
      status: row?.status ?? 'unknown',
      generation: row?.generation ?? 0,
      isRootAdmin: false,
      isOwner: active && row.owner && principal.startsWith('user:'),
      grants: active ? this.#store.grants(principal).filter((grant) => live(grant, at)).map(view) : [],
      since: row ? iso(row.since) : null,
      by: row?.by ?? null,
    };
  }

  access(principal: string): Promise<Access> {
    return this.#serial(async () => this.#access(principal, this.#now()));
  }

  members(): Promise<Access[]> {
    return this.#serial(async () => {
      const at = this.#now();
      const rootAdmins = this.#config.rootAdmins.map((email) => `user:${email}`);
      const everyone = new Set([...rootAdmins, ...this.#store.memberNames()]);
      return [...everyone].sort().map((principal) => this.#access(principal, at));
    });
  }

  // --- changing access ----------------------------------------------------

  setAccess(input: SetAccessInput): Promise<Outcome<{ changes: AccessChange[] }>> {
    return this.#serial(async () => {
      const at = this.#now();
      const { actor, principal } = input;
      const refused = (code: RefusalCode, message = MESSAGES[code]) =>
        new Refused(refusal(code, message), [
          {
            actor,
            action: 'grant.set',
            outcome: 'refuse',
            code,
            subject: principal,
            detail: { changes: input.changes, requestId: input.requestId ?? null },
          },
        ]);
      return this.#decide(at, (log) => {
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
          if (Number.isNaN(expiresAt) || (expiresAt !== null && expiresAt <= at)) {
            throw refused('invalid', 'an end date must be in the future');
          }
        }
        const holder = this.#holdings(actor, at);
        if (!input.changes.every((change) => mayManageAccess(holder, principal, change))) throw refused('not_allowed');

        const status = this.#status(principal);
        if (status === 'removed') throw refused('removed');
        if (status === 'unknown') {
          // A sync is a member from its first grant; anyone else is admitted first.
          if (!isSyncPrincipal(principal) || input.changes.every((change) => change.role === null)) {
            throw refused('not_a_member');
          }
          this.#store.putMember({ principal, status: 'active', owner: false, generation: 0, since: at, by: actor });
          log.push({
            actor,
            action: 'principal.admit',
            outcome: 'allow',
            subject: principal,
            detail: { owner: false, requestId: input.requestId ?? null },
          });
        }
        const changes = input.changes.map((change) => this.#apply(actor, principal, change, at, log, input.requestId));
        return { changes };
      });
    });
  }

  /** One place's change, logged when it changes what is live. */
  #apply(
    actor: string,
    principal: string,
    change: GrantChange,
    at: number,
    log: Appended[],
    requestId: string | null | undefined,
  ): AccessChange {
    const existing = this.#store.grant(principal, change);
    const current = existing !== undefined && live(existing, at) ? existing : undefined;
    const expiresAt = change.expiresAt === null ? null : Date.parse(change.expiresAt);
    const entry = (action: string, role: string | null) =>
      log.push({
        actor,
        action,
        outcome: 'allow',
        subject: principal,
        detail: {
          projectId: change.projectId,
          environmentId: change.environmentId,
          role,
          expiresAt: expiresAt === null ? null : iso(expiresAt),
          previousRole: current?.role ?? null,
          requestId: requestId ?? null,
        },
      });

    if (change.role === null) {
      if (existing !== undefined) this.#store.deleteGrant(principal, change);
      if (current === undefined) return 'unchanged';
      entry('grant.revoke', null);
      return 'revoked';
    }
    if (current !== undefined && current.role === change.role && current.expiresAt === expiresAt) return 'unchanged';
    this.#store.putGrant({
      principal,
      projectId: change.projectId,
      environmentId: change.environmentId,
      role: change.role,
      expiresAt,
      grantedAt: at,
      grantedBy: actor,
    });
    entry(current === undefined ? 'grant.create' : 'grant.update', change.role);
    return current === undefined ? 'created' : 'updated';
  }

  admit(input: AdmitInput): Promise<Outcome<{ created: boolean; owner: boolean }>> {
    return this.#serial(async () => {
      const at = this.#now();
      const { actor, principal } = input;
      const refused = (code: RefusalCode, message = MESSAGES[code]) =>
        new Refused(refusal(code, message), [
          {
            actor,
            action: 'principal.admit',
            outcome: 'refuse',
            code,
            subject: principal,
            detail: { owner: input.owner ?? null, requestId: input.requestId ?? null },
          },
        ]);
      return this.#decide(at, (log) => {
        if (!this.#holdings(actor, at).isOwner) throw refused('not_allowed', 'only owners may add or restore members');
        if (!PRINCIPAL.test(principal) || isSyncPrincipal(principal)) throw refused('invalid', `not a member: ${principal}`);
        if (this.#isRootAdmin(principal)) throw refused('root_admin');
        if (input.owner === true && !principal.startsWith('user:')) {
          throw refused('invalid', 'service accounts cannot be owners');
        }
        const row = this.#store.member(principal);
        const entry = (action: string, owner: boolean) =>
          log.push({ actor, action, outcome: 'allow', subject: principal, detail: { owner, requestId: input.requestId ?? null } });

        if (row === undefined || row.status === 'removed') {
          // Coming back is a fresh start: no owner role unless given again.
          const owner = input.owner ?? false;
          this.#store.putMember({ principal, status: 'active', owner, generation: row?.generation ?? 0, since: at, by: actor });
          entry(row === undefined ? 'principal.admit' : 'principal.restore', owner);
          return { created: true, owner };
        }
        const owner = input.owner ?? row.owner;
        if (owner !== row.owner) {
          this.#store.setOwner(principal, owner);
          entry('principal.owner', owner);
        }
        return { created: false, owner };
      });
    });
  }

  remove(input: RemoveInput): Promise<Outcome<{ revoked: Grant[] }>> {
    return this.#serial(async () => {
      const at = this.#now();
      const { actor, principal } = input;
      const refused = (code: RefusalCode, message = MESSAGES[code]) =>
        new Refused(refusal(code, message), [
          {
            actor,
            action: 'principal.remove',
            outcome: 'refuse',
            code,
            subject: principal,
            detail: { requestId: input.requestId ?? null },
          },
        ]);
      return this.#decide(at, (log) => {
        if (this.#isRootAdmin(principal)) throw refused('root_admin');
        const held = this.#store.grants(principal);
        const holder = this.#holdings(actor, at);
        // Owners remove anyone. Removing a sync only takes access away, so
        // whoever may take away one of its grants, or manage it at its
        // source, may remove it, and anyone may remove one that holds nothing.
        const places = input.source === undefined ? held : [...held, input.source];
        const may =
          holder.isOwner ||
          (isSyncPrincipal(principal) &&
            (held.length === 0 || places.some((place) => mayManageAccess(holder, principal, { ...place, role: null }))));
        if (!may) throw refused('not_allowed', 'only owners may remove members');
        const status = this.#status(principal);
        if (status !== 'active') throw refused(status === 'removed' ? 'removed' : 'not_a_member');

        this.#store.deleteGrants(principal);
        this.#store.putMember({ principal, status: 'removed', owner: false, generation: this.#store.member(principal)!.generation + 1, since: at, by: actor });
        const revoked = held.filter((grant) => live(grant, at));
        for (const grant of revoked) {
          log.push({
            actor,
            action: 'grant.revoke',
            outcome: 'allow',
            subject: principal,
            detail: {
              projectId: grant.projectId,
              environmentId: grant.environmentId,
              role: null,
              expiresAt: null,
              previousRole: grant.role,
              requestId: input.requestId ?? null,
            },
          });
        }
        log.push({
          actor,
          action: 'principal.remove',
          outcome: 'allow',
          subject: principal,
          detail: { revoked: revoked.length, requestId: input.requestId ?? null },
        });
        return { revoked: revoked.map(view) };
      });
    });
  }

  // --- checkpoints and the log -------------------------------------------

  #latest(): Checkpoint | null {
    const row = this.#store.latestCheckpoint();
    if (row === undefined) return null;
    const { vaultSeq, vaultHash, signedAt, ...rest } = row;
    return { ...rest, vault: { seq: vaultSeq, hash: vaultHash }, signedAt: iso(signedAt) };
  }

  checkpoint(input: CheckpointInput): Promise<Outcome<{ checkpoint: Checkpoint }>> {
    return this.#serial(async () => {
      const at = this.#now();
      const latest = this.#latest();
      // Signing the same head twice is one checkpoint.
      if (latest !== null && latest.seq === input.seq && latest.headHash === input.headHash) {
        return { ok: true, checkpoint: latest };
      }
      const extends_ =
        latest === null
          ? input.previous === null
          : input.previous !== null &&
            input.previous.seq === latest.seq &&
            input.previous.hash === latest.headHash &&
            input.seq > latest.seq;
      // This log too: still the one signed last, and whole from there. So a
      // rewrite of it is never signed over, and the app's record of the head
      // signed before shows it.
      const { verification: held } = verify(this.#store, this.#logKey, [], latest?.vault ?? UNVERIFIED, false);
      const vault = head(this.#store);
      const signedAt = iso(at);
      const signature =
        extends_ && held.ok
          ? await this.#signer.sign(checkpointMessage({ seq: input.seq, headHash: input.headHash, vault, signedAt }))
          : '';
      return this.#decide(at, () => {
        const refused = (code: RefusalCode, detail: Record<string, unknown>) =>
          new Refused(refusal(code, MESSAGES[code]), [
            {
              actor: 'app',
              action: 'checkpoint',
              outcome: 'refuse',
              code,
              subject: 'audit',
              detail: { seq: input.seq, headHash: input.headHash, ...detail },
            },
          ]);
        if (!extends_) throw refused('checkpoint_diverged', { previous: input.previous, latest });
        if (!held.ok) throw refused('log_broken', { failedAtSeq: held.failedAtSeq, reason: held.reason });
        const checkpoint = {
          seq: input.seq,
          headHash: input.headHash,
          vault,
          signedAt,
          keyId: this.#signer.keyId,
          signature,
        };
        this.#store.addCheckpoint({
          ...checkpoint,
          vaultSeq: vault.seq,
          vaultHash: vault.hash,
          signedAt: at,
        });
        return { checkpoint };
      });
    });
  }

  latestCheckpoint(): Promise<{ checkpoint: Checkpoint | null; publicKey: string }> {
    return this.#serial(async () => ({ checkpoint: this.#latest(), publicKey: this.#signer.publicKey }));
  }

  log(input: LogInput): Promise<Outcome<LogPage>> {
    return this.#serial(async () => {
      const at = this.#now();
      return this.#decide(at, () => {
        if (!this.#isRootAdmin(input.actor)) {
          throw new Refused(refusal('not_allowed', 'only root admins may read the vault log'), [
            { actor: input.actor, action: 'log.read', outcome: 'refuse', code: 'not_allowed', subject: 'vault' },
          ]);
        }
        const limit = Math.min(Math.max(Math.trunc(input.limit ?? 50), 1), 200);
        const shown = this.#store.logPage(input.before, limit);
        const verification = input.full === true ? this.#verifyAll(shown, null, at) : this.#verifyNew(shown);
        return { entries: shown.map(entry), verification };
      });
    });
  }

  verifyLog(input: VerifyLogInput): Promise<LogVerification> {
    return this.#serial(async () => this.#verifyAll([], input.through, this.#now()));
  }

  /** `shown`, and the chain since it was last verified; `verify` in log.ts. */
  #verifyNew(shown: readonly LogRow[]): LogVerification {
    const { verification, anchor } = verify(this.#store, this.#logKey, shown, this.#verified, false);
    this.#verified = anchor;
    return verification;
  }

  /**
   * `shown`, the chain from its first entry, the heads the app and the last
   * checkpoint say it carries, and the members and grants replayed from it.
   */
  #verifyAll(shown: readonly LogRow[], through: LogHead | null, at: number): LogVerification {
    const { verification, anchor } = verify(this.#store, this.#logKey, shown, this.#verified, true);
    this.#verified = anchor;
    if (!verification.ok) return verification;
    const signed = this.#latest()?.vault ?? null;
    for (const [kept, by] of [[through, 'a checkpoint the app recorded'], [signed, 'the last checkpoint']] as const) {
      if (kept === null || carries(this.#store, kept)) continue;
      return { ok: false, failedAtSeq: kept.seq, reason: `not the entry ${by} signed: the log was rewritten or cut back` };
    }
    const fault = replay(this.#store, at);
    return fault === null ? verification : { ok: false, failedAtSeq: null, reason: describeAccessFault(fault), fault };
  }
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

function place(secret: SecretRef) {
  return { ...context(secret), version: secret.version };
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
