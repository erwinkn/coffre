import { randomUUID } from 'node:crypto';

import { mayManageAccess, type Permission } from '../../../core/src/access.ts';
import type { AuditEntry } from '../../../db/src/audit.ts';
import type { Database, Queryable, Transaction } from '../../../db/src/database.ts';
import {
  findSyncs,
  insert,
  lock,
  resolvePath,
  update,
  upsert,
  type SyncRow,
} from '../../../db/src/queries.ts';
import { syncKeys, syncs } from '../../../db/src/schema.ts';
import {
  getProvider,
  SyncConfigError,
  SyncProviderError,
  type SyncApplyResult,
  type SyncProvider,
} from '../../../sync/src/index.ts';
import type { GrantChange, Vault } from '../../../vault/src/types.ts';
import type { SyncTiming } from '../config.ts';
import { can } from './caller.ts';
import { allowed, audited, denied, missing, Refusal, vaultRefusal, type ApiContext } from './context.ts';
import { badRequest, conflict, forbidden, notFound } from './errors.ts';
import { openValues } from './keys.ts';
import { formatMember, formatPath, parsePath } from './paths.ts';
import { currentEnvelopes } from './secrets.ts';

/**
 * Syncs: coffre pushing one environment's secrets into a service that needs
 * them, such as GitHub Actions or Vercel, so nobody copies values by hand.
 *
 * A sync is a source environment, a destination, and the credential coffre
 * uses to write there. The credential is an ordinary coffre secret named by
 * path (`ops/sync/GITHUB_TOKEN`), so it is encrypted, versioned and audited
 * like everything else, and rotating it is just writing a new version.
 *
 * What was pushed is recorded per key as the secret version it came from
 * (`sync_keys`), so deciding what to push compares ids and decrypts nothing:
 *
 *   secrets now          recorded as pushed     plan
 *   API_KEY  v7          API_KEY  v6            upsert API_KEY (v7)
 *   DB_URL   v3          DB_URL   v3            -
 *   NEW_FLAG v1          -                      upsert NEW_FLAG
 *   -                    OLD_KEY  v2            delete OLD_KEY
 *
 * Only the keys that changed are decrypted, and each one gets a `sync.push`
 * audit row before its value leaves. Deletion only ever touches keys coffre
 * itself pushed; whatever else lives at the destination is left alone.
 *
 * A sync reads as a principal of its own, `sync:<id>`, which the vault
 * grants `viewer` on the source environment, and on the credential's when
 * that is elsewhere, as the sync is added. Every value a run opens goes
 * through the vault in that name, so revoking the grant stops the sync, and
 * archiving the sync removes the principal.
 *
 * Runs are triggered three ways: right after a secret in the environment
 * changes, by someone pressing "Run now", and by the scheduler, which picks up
 * anything missed and checks each destination hourly for keys that went
 * missing there. A lease on the row keeps two runs of one sync from
 * overlapping.
 */

export type SyncStatus = 'ok' | 'partial' | 'failed';
export type SyncTrigger = 'create' | 'change' | 'manual' | 'scheduled';

/** What survives JSON, as a stored destination config always has. */
export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

export type SyncView = {
  id: string;
  provider: string;
  providerLabel: string;
  /** One line naming the destination, e.g. "erwinkn/app · environment production". */
  destination: string;
  config: { [key: string]: Json };
  /** `project/environment/KEY` of the secret holding the destination's token. */
  credential: string;
  createdAt: string;
  createdBy: string;
  paused: boolean;
  running: boolean;
  lastRunAt: string | null;
  lastStatus: SyncStatus | null;
  lastError: string | null;
  /** Keys whose current version is at the destination. */
  synced: number;
  /** Keys waiting to be pushed or removed. */
  pending: number;
  /** Keys the destination cannot hold, and why. */
  skipped: { key: string; reason: string }[];
};

/** A sync somewhere on the instance, with where it lives. */
export type PlacedSyncView = SyncView & { project: string; environment: string };

export type RunOutcome =
  | { status: 'busy' }
  | {
      status: SyncStatus;
      upserted: string[];
      deleted: string[];
      failed: { key: string; operation: 'upsert' | 'delete'; message: string }[];
      error: string | null;
    };

export type SyncDeps = {
  db: Database;
  vault: Vault;
  chainKey: Buffer;
  /** Injected by tests; defaults to the built-in providers. */
  resolveProvider?: (kind: string) => SyncProvider<unknown> | null;
  /** Injected by tests; defaults to the global fetch. */
  fetch?: typeof fetch;
  /** The deployment's `syncs` settings; the defaults below unless set. */
  timing?: SyncTiming;
};

const MINUTE = 60_000;
/** A run abandoned mid-way (the Worker was stopped) is picked up again after this. */
const LEASE_MS = 5 * MINUTE;
/** The whole run's budget, inside the lease. */
const RUN_TIMEOUT_MS = 4 * MINUTE;
const DEFAULT_TIMING: SyncTiming = { driftCheckMs: 60 * MINUTE, retryAfterMs: 15 * MINUTE };
/** A run that keeps finding new changes when it finishes stops after this many passes. */
const MAX_PASSES = 3;
const MAX_ERROR_LENGTH = 1000;

// --- planning -----------------------------------------------------------------

export type DesiredKey = { key: string; secretId: string; versionId: string };
export type RecordedKey = { key: string; versionId: string | null };

export type SyncPlanIds = {
  upsert: DesiredKey[];
  /** Pushed by coffre, no longer wanted, and present at the destination. */
  delete: string[];
  /** Pushed by coffre, no longer wanted, and already gone from the destination. */
  forget: string[];
  skipped: { key: string; reason: string }[];
  /** Keys whose current version is already at the destination. */
  inSync: number;
};

/**
 * Decide what a run does, from version ids alone.
 *
 * `remote` is the destination's key list when the run fetched it. With it,
 * a key coffre pushed that has since disappeared there is pushed again; without
 * it (when only counting what is pending), the record is trusted.
 */
export function planSync(input: {
  desired: readonly DesiredKey[];
  recorded: readonly RecordedKey[];
  checkKey: (key: string) => { ok: true } | { ok: false; reason: string };
  remote?: ReadonlySet<string>;
}): SyncPlanIds {
  const recorded = new Map(input.recorded.map((row) => [row.key, row.versionId]));
  const wanted = new Set<string>();
  const plan: SyncPlanIds = { upsert: [], delete: [], forget: [], skipped: [], inSync: 0 };

  for (const entry of input.desired) {
    const check = input.checkKey(entry.key);
    if (!check.ok) {
      plan.skipped.push({ key: entry.key, reason: check.reason });
      continue;
    }
    wanted.add(entry.key);
    const missingThere = input.remote !== undefined && !input.remote.has(entry.key);
    if (recorded.get(entry.key) !== entry.versionId || missingThere) plan.upsert.push(entry);
    else plan.inSync += 1;
  }

  for (const key of recorded.keys()) {
    if (wanted.has(key)) continue;
    if (input.remote === undefined || input.remote.has(key)) plan.delete.push(key);
    else plan.forget.push(key);
  }

  return plan;
}

// --- reads --------------------------------------------------------------------

/**
 * Lock one sync's row, and read it with its place. Two runs racing for the
 * lease, or a run and a pause, queue here. Only the sync's own row is locked,
 * not the secrets and environments it joins.
 */
async function lockSync(tx: Transaction, syncId: string): Promise<SyncRow | null> {
  await lock(tx, syncs, { id: syncId });
  const [row] = await findSyncs(tx, { id: syncId });
  return row ?? null;
}

/** Syncs that serve: not archived, in a live project and environment. */
function serves(row: SyncRow): boolean {
  return row.archivedAt === null && row.environmentArchivedAt === null && row.projectArchivedAt === null;
}

/** The principal a sync reads as. */
export const syncPrincipal = (syncId: string) => `sync:${syncId}`;

const credentialPath = (row: SyncRow) => `${row.credential.project}/${row.credential.environment}/${row.credential.key}`;

// --- runner -------------------------------------------------------------------

type Actor = Pick<AuditEntry, 'actorType' | 'actorId' | 'requestId' | 'sourceIp'>;

/** Runs nobody pressed a button for are the sync's own doing. */
function systemActor(syncId: string): Actor {
  return { actorType: 'system', actorId: syncPrincipal(syncId) };
}

/**
 * Everything that runs syncs, in a request or not: after a change, on the
 * scheduler, or when someone presses "Run now".
 */
export class SyncRunner {
  readonly #deps: SyncDeps;

  constructor(deps: SyncDeps) {
    this.#deps = deps;
  }

  provider(kind: string): SyncProvider<unknown> | null {
    return (this.#deps.resolveProvider ?? getProvider)(kind);
  }

  /** After a secret changed: push it everywhere its environment syncs to. Never throws. */
  async runForEnvironment(environmentId: string): Promise<void> {
    try {
      const rows = (await findSyncs(this.#deps.db, { environmentId })).filter(
        (row) => row.archivedAt === null && row.pausedAt === null,
      );
      const results = await Promise.allSettled(
        rows.map((row) => this.runSettled(row.id, 'change', systemActor(row.id))),
      );
      for (const result of results) {
        if (result.status === 'rejected') console.error('sync after change failed', result.reason);
      }
    } catch (error) {
      console.error('sync after change failed', error);
    }
  }

  /**
   * The scheduler's pass: run whatever has changes waiting, retry what failed,
   * and check healthy destinations hourly for keys that disappeared there.
   */
  async reconcile(): Promise<{ ran: number }> {
    const now = Date.now();
    const { driftCheckMs, retryAfterMs } = this.#deps.timing ?? DEFAULT_TIMING;
    const rows = (await findSyncs(this.#deps.db, {})).filter(
      (row) => serves(row) && row.pausedAt === null && (row.leaseUntil === null || row.leaseUntil.getTime() < now),
    );
    const views = await this.views(this.#deps.db, rows);
    const toRun = rows
      .filter((row, index) => {
        const lastRun = row.lastRunAt?.getTime() ?? null;
        const due = lastRun === null || lastRun < now - driftCheckMs;
        const backingOff =
          (row.lastStatus === 'failed' || row.lastStatus === 'partial') &&
          lastRun !== null &&
          lastRun > now - retryAfterMs;
        return !backingOff && (due || views[index].pending > 0);
      })
      .map((row) => row.id);

    const results = await Promise.allSettled(toRun.map((id) => this.runSettled(id, 'scheduled', systemActor(id))));
    for (const result of results) {
      if (result.status === 'rejected') console.error('scheduled sync failed', result.reason);
    }
    return { ran: toRun.length };
  }

  async view(syncId: string): Promise<SyncView> {
    const rows = await findSyncs(this.#deps.db, { id: syncId });
    if (rows.length === 0) throw notFound('unknown sync');
    const [view] = await this.views(this.#deps.db, rows);
    return view;
  }

  /** Views of syncs, with what each would do next. */
  async views(db: Queryable, rows: readonly SyncRow[]): Promise<SyncView[]> {
    const plans = await this.#plans(db, rows);
    const now = Date.now();
    return rows.map((row) => {
      const plan = plans.get(row.id);
      const provider = this.provider(row.provider);
      const config = JSON.parse(row.config) as unknown;
      let destination = row.provider;
      if (provider) {
        try {
          destination = provider.describe(provider.parseConfig(config));
        } catch {
          // A config an older version accepted still lists; its next run reports why it fails.
        }
      }
      return {
        id: row.id,
        provider: row.provider,
        providerLabel: provider?.label ?? row.provider,
        destination,
        // Stored as JSON text from an object the create call checked.
        config: config as SyncView['config'],
        credential: credentialPath(row),
        createdAt: row.createdAt.toISOString(),
        createdBy: row.createdBy,
        paused: row.pausedAt !== null,
        running: row.leaseUntil !== null && row.leaseUntil.getTime() > now,
        lastRunAt: row.lastRunAt?.toISOString() ?? null,
        lastStatus: row.lastStatus as SyncStatus | null,
        lastError: row.lastError,
        synced: plan?.inSync ?? 0,
        pending: plan ? plan.upsert.length + plan.delete.length : 0,
        skipped: plan?.skipped ?? [],
      };
    });
  }

  /** What each sync would do if it ran now, going by the record alone. Decrypts nothing. */
  async #plans(
    db: Queryable,
    rows: readonly SyncRow[],
  ): Promise<Map<string, SyncPlanIds>> {
    const desiredByEnvironment = new Map<string, DesiredKey[]>();
    const plans = new Map<string, SyncPlanIds>();
    for (const row of rows) {
      const provider = this.provider(row.provider);
      if (provider === null) continue;
      let desired = desiredByEnvironment.get(row.environmentId);
      if (desired === undefined) {
        desired = (await currentEnvelopes(db, row.environmentId)).map((entry) => ({
          key: entry.key,
          secretId: entry.secretId,
          versionId: entry.secretVersionId,
        }));
        desiredByEnvironment.set(row.environmentId, desired);
      }
      plans.set(
        row.id,
        planSync({
          desired: desired.filter((entry) => entry.secretId !== row.credentialSecretId),
          recorded: row.recorded,
          checkKey: provider.checkKey,
        }),
      );
    }
    return plans;
  }

  /**
   * Run until nothing is left to do. A secret written while a run is in
   * flight finds the lease taken and leaves the change to that run, so the
   * run looks again when it finishes.
   */
  async runSettled(syncId: string, trigger: SyncTrigger, actor: Actor): Promise<RunOutcome> {
    let outcome: RunOutcome = { status: 'busy' };
    for (let pass = 0; pass < MAX_PASSES; pass++) {
      const next = await this.#run(syncId, pass === 0 ? trigger : 'change', actor);
      if (next.status === 'busy') return pass === 0 ? next : outcome;
      outcome = next;
      if (next.status === 'failed') break;
      // Keys that just failed would only fail again; anything else is new.
      const failed = new Set(next.failed.map((failure) => failure.key));
      const pending = await this.#pendingKeys(syncId);
      if (!pending.some((key) => !failed.has(key))) break;
    }
    return outcome;
  }

  async #pendingKeys(syncId: string): Promise<string[]> {
    const rows = (await findSyncs(this.#deps.db, { id: syncId })).filter(
      (row) => row.archivedAt === null && row.pausedAt === null,
    );
    const plan = (await this.#plans(this.#deps.db, rows)).get(syncId);
    return plan ? [...plan.upsert.map((entry) => entry.key), ...plan.delete] : [];
  }

  /** Take the lease, unless the sync is gone, paused, or already running. */
  async #lease(syncId: string): Promise<SyncRow | null> {
    return this.#deps.db.transaction(async (tx) => {
      const row = await lockSync(tx, syncId);
      const now = Date.now();
      if (row === null || !serves(row) || row.pausedAt !== null) return null;
      if (row.leaseUntil !== null && row.leaseUntil.getTime() >= now) return null;
      await update(tx, syncs, { id: syncId }, { leaseUntil: new Date(now + LEASE_MS) });
      return row;
    });
  }

  /** One run: lease, open the credential, list, plan, audit, push, record. */
  async #run(syncId: string, trigger: SyncTrigger, actor: Actor): Promise<RunOutcome> {
    const sync = await this.#lease(syncId);
    if (sync === null) return { status: 'busy' };
    const scope = { projectId: sync.projectId, environmentId: sync.environmentId };
    const sourcePath = `${sync.project}/${sync.environment}`;
    const runId = randomUUID();
    const { db, chainKey, vault } = this.#deps;
    const asking = { principal: syncPrincipal(syncId), requestId: actor.requestId ?? null, purpose: 'sync' as const };
    /** The vault said no: log it here too, and fail the run with its reason. */
    const refused = (refusal: { code: string; message: string }, place: object) =>
      new Refusal(new SyncFailure(`the vault refused: ${refusal.message}`), {
        ...actor,
        action: 'sync.run',
        decision: 'deny',
        ...place,
        bundleId: runId,
        metadata: { syncId, source: sourcePath, trigger, reason: `vault_${refusal.code}` },
      });

    let outcome: Exclude<RunOutcome, { status: 'busy' }> = {
      status: 'failed',
      upserted: [],
      deleted: [],
      failed: [],
      error: null,
    };
    // The versions this run pushed, so the record names exactly what left.
    const pushedVersions = new Map<string, string>();
    let forget: string[] = [];

    try {
      const provider = this.provider(sync.provider);
      if (provider === null) throw new SyncFailure(`coffre no longer knows the destination "${sync.provider}"`);
      const config = provider.parseConfig(JSON.parse(sync.config));
      const destination = provider.describe(config);
      const signal = AbortSignal.timeout(RUN_TIMEOUT_MS);

      // Opening the credential is a use of a secret, so it is audited as the
      // run itself, in the same transaction as the read.
      const token = await audited({ db, chainKey }, async (tx, log) => {
        const [credential] = await currentEnvelopes(tx, sync.credential.environmentId, sync.credentialSecretId);
        if (credential === undefined) {
          throw new SyncFailure(`${credentialPath(sync)} is archived; restore it or point this sync at another secret`);
        }
        const where = { projectId: sync.credential.projectId, environmentId: sync.credential.environmentId };
        const opened = await openValues(vault, asking, [{
          secret: { ...where, secretId: credential.secretId, version: credential.version, path: credentialPath(sync) },
          envelope: credential.envelope,
        }]);
        if (!opened.ok) throw refused(opened.refusal, where);
        log.push({
          ...actor,
          action: 'sync.run',
          decision: 'allow',
          // Filed under the credential, which is the secret this row reads.
          projectId: sync.credential.projectId,
          environmentId: sync.credential.environmentId,
          secretId: credential.secretId,
          bundleId: runId,
          metadata: { syncId, source: sourcePath, provider: provider.kind, destination, trigger, version: credential.version },
        });
        return opened.values[0];
      });
      const ctx = { token, fetch: this.#deps.fetch, signal };

      const remote = new Set(await provider.listKeys(ctx, config));

      // Plan and decrypt in one transaction, and write a row per key before
      // any value leaves. If the push then fails, the log says more left than
      // did, never less.
      const plan = await audited({ db, chainKey }, async (tx, log) => {
        const current = (await currentEnvelopes(tx, sync.environmentId)).filter(
          (entry) => entry.secretId !== sync.credentialSecretId,
        );
        // Read with the lease: only this run writes the record until it lets go.
        const ids = planSync({
          desired: current.map((entry) => ({ key: entry.key, secretId: entry.secretId, versionId: entry.secretVersionId })),
          recorded: sync.recorded,
          remote,
          checkKey: provider.checkKey,
        });

        const upsert: { key: string; value: string }[] = [];
        const common = { ...actor, decision: 'allow' as const, ...scope, bundleId: runId };
        const byVersion = new Map(current.map((entry) => [entry.secretVersionId, entry]));
        const rows = ids.upsert.map((entry) => byVersion.get(entry.versionId)!);
        const opened = await openValues(vault, asking, rows.map((row) => ({
          secret: { ...scope, secretId: row.secretId, version: row.version, path: `${sourcePath}/${row.key}` },
          envelope: row.envelope,
        })));
        if (!opened.ok) throw refused(opened.refusal, scope);
        for (const [i, entry] of ids.upsert.entries()) {
          const row = rows[i];
          upsert.push({ key: entry.key, value: opened.values[i] });
          pushedVersions.set(entry.key, entry.versionId);
          log.push({
            ...common,
            action: 'sync.push',
            secretId: entry.secretId,
            metadata: { syncId, key: entry.key, version: row.version, destination, trigger },
          });
        }
        for (const key of ids.delete) {
          log.push({ ...common, action: 'sync.remove', metadata: { syncId, key, destination, trigger } });
        }
        return { upsert, delete: ids.delete, forget: ids.forget };
      });
      forget = plan.forget;

      let result: SyncApplyResult = { upserted: [], deleted: [], failed: [] };
      if (plan.upsert.length > 0 || plan.delete.length > 0) {
        result = await provider.apply(ctx, config, { upsert: plan.upsert, delete: plan.delete });
      }
      outcome = {
        status: result.failed.length === 0 ? 'ok' : 'partial',
        upserted: result.upserted,
        deleted: result.deleted,
        failed: result.failed,
        error: result.failed.length === 0 ? null : summarizeFailures(result.failed),
      };
    } catch (error) {
      outcome = { ...outcome, status: 'failed', error: describeError(error) };
    }

    try {
      await this.#record(syncId, outcome, pushedVersions, forget);
    } catch (error) {
      // The lease runs out on its own; the next run re-pushes whatever was
      // not recorded, which is safe because every push is an overwrite.
      console.error('sync result could not be recorded', error);
    }
    return outcome;
  }

  async #record(
    syncId: string,
    outcome: Exclude<RunOutcome, { status: 'busy' }>,
    pushedVersions: ReadonlyMap<string, string>,
    forget: readonly string[],
  ): Promise<void> {
    const now = new Date();
    await this.#deps.db.transaction(async (tx) => {
      const pushed = outcome.upserted.flatMap((key) => {
        const secretVersionId = pushedVersions.get(key);
        return secretVersionId === undefined ? [] : [{ syncId, key, secretVersionId, pushedAt: now, removedAt: null }];
      });
      // A key pushed again after being removed is the same row, brought back.
      await upsert(tx, syncKeys, pushed, {
        target: ['syncId', 'key'],
        columns: ['secretVersionId', 'pushedAt', 'removedAt'],
      });
      const removed = [...outcome.deleted, ...forget];
      if (removed.length > 0) {
        await update(tx, syncKeys, { syncId, key: removed, removedAt: null }, { removedAt: now });
      }
      await update(
        tx,
        syncs,
        { id: syncId },
        { lastRunAt: now, lastStatus: outcome.status, lastError: outcome.error, leaseUntil: null },
      );
    });
  }
}

// --- handlers -----------------------------------------------------------------

/** The syncs of one environment, with what each is waiting to do. The router checks `secret.read`. */
export async function listSyncs(
  ctx: ApiContext,
  place: { projectId: string; environmentId: string },
): Promise<{ syncs: SyncView[]; canManage: boolean }> {
  const rows = (await findSyncs(ctx.db, { environmentId: place.environmentId })).filter(
    (row) => row.archivedAt === null,
  );
  return {
    syncs: await ctx.syncs.views(ctx.db, rows),
    canManage: can(ctx.caller, 'environment.manage', place) && can(ctx.caller, 'secret.read', place),
  };
}

/**
 * Every live sync one person set up, for their offboarding report. Owners
 * only. A sync keeps pushing after its creator leaves, to a destination
 * they chose, so each one is worth a look.
 */
export async function syncsCreatedBy(ctx: ApiContext, principalId: string): Promise<PlacedSyncView[]> {
  if (!ctx.caller.isOwner) throw forbidden('only owners may see what someone has access to');
  const byPlace = (row: SyncRow) => `${row.project}/${row.environment}`;
  // Oldest first within each place: the sort is stable.
  const rows = (await findSyncs(ctx.db, { createdBy: principalId }))
    .filter(serves)
    .sort((a, b) => (byPlace(a) < byPlace(b) ? -1 : byPlace(a) > byPlace(b) ? 1 : 0));
  const views = await ctx.syncs.views(ctx.db, rows);
  return views.map((view, index) => ({ ...view, project: rows[index].project, environment: rows[index].environment }));
}

/** Key order must not make two configs look different. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, inner]) => `${JSON.stringify(key)}:${canonicalJson(inner)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * Start syncing an environment to a destination.
 *
 * The router checks `environment.manage` and `secret.read` on the source: a
 * sync sends every value in it somewhere else, which is a read by other
 * means. This checks `secret.read` on the credential too, so nobody can put a
 * token they could not read themselves to work.
 */
export async function createSync(
  ctx: ApiContext,
  place: { projectId: string; environmentId: string },
  input: { provider: string; config: unknown; credential: string },
): Promise<SyncView> {
  const provider = ctx.syncs.provider(input.provider);
  if (provider === null) throw badRequest(`"${input.provider}" is not a sync destination coffre knows`);
  let config: unknown;
  try {
    config = provider.parseConfig(input.config);
  } catch (error) {
    if (error instanceof SyncConfigError) throw badRequest(error.message);
    throw error;
  }
  const credentialPath = parsePath(input.credential, [3]);
  const destination = provider.describe(config);
  const metadata = { provider: provider.kind, destination, credential: formatPath(credentialPath) };

  const syncId = await audited(ctx, async (tx, log) => {
    const credential = await resolvePath(tx, credentialPath);
    const credentialPlace =
      credential?.environment == null ? null : { projectId: credential.project.id, environmentId: credential.environment.id };
    // Unknown and unreadable look the same, so the form cannot be used to
    // probe for secrets in environments the caller has no access to.
    if (
      credentialPlace === null ||
      credential!.project.archivedAt !== null ||
      credential!.environment!.archivedAt !== null ||
      credential!.secret === null ||
      credential!.secret.archivedAt !== null ||
      credential!.secret.currentVersionId === null ||
      !can(ctx.caller, 'secret.read', credentialPlace)
    ) {
      throw new Refusal(
        badRequest(`${metadata.credential} is not a secret you can read`),
        denied(ctx, 'sync.create', 'unusable_credential', { ...place, metadata }),
      );
    }

    const others = (await findSyncs(tx, { provider: provider.kind })).filter((row) => row.archivedAt === null);
    const wanted = canonicalJson(config);
    const duplicate = others.find((other) => canonicalJson(JSON.parse(other.config)) === wanted);
    if (duplicate !== undefined) {
      throw new Refusal(
        conflict(`${destination} is already synced from ${duplicate.project}/${duplicate.environment}`),
        denied(ctx, 'sync.create', 'duplicate_destination', { ...place, metadata }),
      );
    }

    const id = randomUUID();
    // The sync reads its source, and its credential where that lives elsewhere.
    const reads: GrantChange[] = [place, ...(credentialPlace!.environmentId === place.environmentId ? [] : [credentialPlace!])]
      .map((where) => ({ ...where, role: 'viewer', expiresAt: null }));
    const principal = syncPrincipal(id);
    if (!reads.every((change) => mayManageAccess(ctx.caller, principal, change))) {
      throw new Refusal(
        forbidden(`a sync reading ${metadata.credential} needs you to manage that project's environments`),
        denied(ctx, 'sync.create', 'cannot_grant_sync', { ...place, metadata }),
      );
    }
    await insert(tx, syncs, {
      id,
      ...place,
      provider: provider.kind,
      config: JSON.stringify(config),
      credentialSecretId: credential!.secret.id,
      createdBy: ctx.caller.principal.id,
    });
    // Last, so nothing the app checks can fail after the vault has granted.
    const granted = await ctx.vault.setAccess({
      actor: formatMember(ctx.caller.principal),
      principal,
      requestId: ctx.requestId,
      changes: reads,
    });
    if (!granted.ok) throw vaultRefusal(ctx, granted.refusal, 'sync.create', { ...place, metadata });
    log.push(allowed(ctx, 'sync.create', { ...place, metadata: { ...metadata, syncId: id } }));
    return id;
  });

  ctx.waitUntil(ctx.syncs.runSettled(syncId, 'create', systemActor(syncId)));
  return ctx.syncs.view(syncId);
}

/**
 * A checked, audited change to one sync. `anyOf` lists the permissions that
 * each suffice; `change: null` checks and logs only a refusal.
 */
async function manage(
  ctx: ApiContext,
  syncId: string,
  action: string,
  anyOf: readonly Permission[],
  change: ((row: SyncRow) => Partial<typeof syncs.$inferInsert>) | null,
  /** Runs in the same transaction, after the checks; a refusal rolls the change back. */
  also?: (row: SyncRow) => Promise<void>,
): Promise<void> {
  await audited(ctx, async (tx, log) => {
    const row = await lockSync(tx, syncId);
    if (row === null || !serves(row)) {
      throw new Refusal(notFound('unknown sync'), denied(ctx, action, 'unknown_sync', { metadata: { syncId } }));
    }
    const scope = { projectId: row.projectId, environmentId: row.environmentId };
    if (!anyOf.some((permission) => can(ctx.caller, permission, scope))) {
      throw new Refusal(forbidden(), denied(ctx, action, missing(anyOf[0]), { ...scope, metadata: { syncId } }));
    }
    if (change === null) return;
    await update(tx, syncs, { id: syncId }, change(row));
    await also?.(row);
    log.push(allowed(ctx, action, { ...scope, metadata: { syncId, provider: row.provider } }));
  });
}

/** Stop or restart pushing. A paused sync keeps its record of what it pushed. */
export async function setSyncPaused(ctx: ApiContext, syncId: string, paused: boolean): Promise<SyncView> {
  await manage(ctx, syncId, paused ? 'sync.pause' : 'sync.resume', ['environment.manage'], (row) => ({
    pausedAt: paused ? (row.pausedAt ?? new Date()) : null,
  }));
  // Whatever changed while it was paused goes out now.
  if (!paused) ctx.waitUntil(ctx.syncs.runSettled(syncId, 'change', systemActor(syncId)));
  return ctx.syncs.view(syncId);
}

/**
 * Stop syncing for good, and remove its principal from the vault, which
 * takes back what it could read. What was pushed stays at the destination:
 * removing a service's configuration is a decision for whoever runs that
 * service, not a side effect of tidying up coffre.
 */
export async function archiveSync(ctx: ApiContext, syncId: string): Promise<SyncView> {
  await manage(ctx, syncId, 'sync.archive', ['environment.manage'], () => ({ archivedAt: new Date() }), async (row) => {
    const removed = await ctx.vault.remove({
      actor: formatMember(ctx.caller.principal),
      principal: syncPrincipal(syncId),
      requestId: ctx.requestId,
      source: { projectId: row.projectId, environmentId: row.environmentId },
    });
    // One whose grants were all revoked already reads nothing, and may be gone.
    if (!removed.ok && removed.refusal.code !== 'removed' && removed.refusal.code !== 'not_a_member') {
      throw vaultRefusal(ctx, removed.refusal, 'sync.archive', {
        projectId: row.projectId,
        environmentId: row.environmentId,
        metadata: { syncId },
      });
    }
  });
  return ctx.syncs.view(syncId);
}

/**
 * Push now, in the caller's name, and wait for the result. Anyone who can
 * change the environment's secrets may, since a run only sends what a
 * write would have sent anyway.
 */
export async function runSync(ctx: ApiContext, syncId: string): Promise<{ sync: SyncView; outcome: RunOutcome }> {
  // Only a refusal is logged here; an allowed run logs itself as it goes.
  await manage(ctx, syncId, 'sync.run', ['secret.write', 'environment.manage'], null);
  const outcome = await ctx.syncs.runSettled(syncId, 'manual', {
    actorType: ctx.caller.principal.type,
    actorId: ctx.caller.principal.id,
    requestId: ctx.requestId,
    sourceIp: ctx.sourceIp,
  });
  return { sync: await ctx.syncs.view(syncId), outcome };
}

// --- helpers ------------------------------------------------------------------

/** A run failure whose message was written for the people reading the sync's status. */
class SyncFailure extends Error {}

function describeError(error: unknown): string {
  if (error instanceof SyncProviderError || error instanceof SyncConfigError || error instanceof SyncFailure) {
    return truncate(error.message);
  }
  console.error('sync run failed', error);
  return 'internal error; see the server log';
}

function summarizeFailures(failed: readonly { key: string; operation: string; message: string }[]): string {
  const first = failed[0];
  const rest = failed.length > 1 ? ` (and ${failed.length - 1} more)` : '';
  return truncate(`${first.key}: ${first.message}${rest}`);
}

function truncate(message: string): string {
  return message.length > MAX_ERROR_LENGTH ? `${message.slice(0, MAX_ERROR_LENGTH - 1)}…` : message;
}
