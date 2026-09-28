import { randomUUID } from 'node:crypto';

import { and, asc, eq, inArray, isNotNull, isNull } from 'drizzle-orm';

import type { Permission } from '../../../../../packages/core/src/access.ts';
import { open } from '../../../../../packages/core/src/envelope.ts';
import type { KekRegistry } from '../../../../../packages/core/src/kek/registry.ts';
import type { AuditEntry } from '../../../../../packages/db/src/audit.ts';
import type { Database, Queryable, Transaction } from '../../../../../packages/db/src/database.ts';
import { alias, forUpdate, upsertSyncKey } from '../../../../../packages/db/src/dialect.ts';
import {
  environments,
  projects,
  secrets,
  secretVersions,
  syncKeys,
  syncs,
} from '../../../../../packages/db/src/schema.ts';
import {
  getProvider,
  SyncConfigError,
  SyncProviderError,
  type SyncApplyResult,
  type SyncProvider,
} from '../../../../../packages/sync/src/index.ts';
import { can } from './caller.ts';
import { allowed, audited, denied, missing, Refusal, type ApiContext } from './context.ts';
import { badRequest, conflict, forbidden, notFound } from './errors.ts';
import { formatPath, parsePath, resolvePath } from './paths.ts';
import { currentEnvelopes, envelopeColumns, envelopeOf } from './secrets.ts';

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
  keks: KekRegistry;
  chainKey: Buffer;
  /** Injected by tests; defaults to the built-in providers. */
  resolveProvider?: (kind: string) => SyncProvider<unknown> | null;
  /** Injected by tests; defaults to the global fetch. */
  fetch?: typeof fetch;
};

const MINUTE = 60_000;
/** A run abandoned mid-way (the Worker was stopped) is picked up again after this. */
const LEASE_MS = 5 * MINUTE;
/** The whole run's budget, inside the lease. */
const RUN_TIMEOUT_MS = 4 * MINUTE;
/** How often the scheduler checks an idle, healthy destination for missing keys. */
const DRIFT_CHECK_MS = 60 * MINUTE;
/** How long the scheduler waits before retrying a sync whose last run failed. */
const RETRY_AFTER_MS = 15 * MINUTE;
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

const credentialProject = alias(projects, 'credential_project');
const credentialEnvironment = alias(environments, 'credential_environment');

/** Syncs with their place and their credential's path. Add a `where`. */
function selectSyncs(db: Queryable) {
  return db
    .select({
      id: syncs.id,
      projectId: syncs.projectId,
      environmentId: syncs.environmentId,
      provider: syncs.provider,
      config: syncs.config,
      credentialSecretId: syncs.credentialSecretId,
      createdAt: syncs.createdAt,
      createdBy: syncs.createdBy,
      pausedAt: syncs.pausedAt,
      archivedAt: syncs.archivedAt,
      leaseUntil: syncs.leaseUntil,
      lastRunAt: syncs.lastRunAt,
      lastStatus: syncs.lastStatus,
      lastError: syncs.lastError,
      project: projects.slug,
      environment: environments.slug,
      projectArchivedAt: projects.archivedAt,
      environmentArchivedAt: environments.archivedAt,
      credentialProject: credentialProject.slug,
      credentialEnvironment: credentialEnvironment.slug,
      credentialKey: secrets.key,
    })
    .from(syncs)
    .innerJoin(environments, eq(environments.id, syncs.environmentId))
    .innerJoin(projects, eq(projects.id, syncs.projectId))
    .innerJoin(secrets, eq(secrets.id, syncs.credentialSecretId))
    .innerJoin(credentialEnvironment, eq(credentialEnvironment.id, secrets.environmentId))
    .innerJoin(credentialProject, eq(credentialProject.id, secrets.projectId));
}

type SyncRow = Awaited<ReturnType<typeof selectSyncs>>[number];

/**
 * Lock one sync's row, and read it with its place. Only the sync's own row
 * is locked, not the secrets and environments it joins.
 */
async function lockSync(tx: Transaction, syncId: string): Promise<SyncRow | null> {
  await forUpdate(tx.select({ id: syncs.id }).from(syncs).where(eq(syncs.id, syncId)));
  const [row] = await selectSyncs(tx).where(eq(syncs.id, syncId));
  return row ?? null;
}

/** Syncs that serve: not archived, in a live project and environment. */
const inLivePlace = and(isNull(syncs.archivedAt), isNull(environments.archivedAt), isNull(projects.archivedAt));

function serves(row: SyncRow): boolean {
  return row.archivedAt === null && row.environmentArchivedAt === null && row.projectArchivedAt === null;
}

/** What the environment holds now: live secrets and their current version ids. */
async function loadDesired(db: Queryable, environmentId: string): Promise<DesiredKey[]> {
  return db
    .select({ key: secrets.key, secretId: secrets.id, versionId: secrets.currentVersionId })
    .from(secrets)
    .where(and(eq(secrets.environmentId, environmentId), isNull(secrets.archivedAt), isNotNull(secrets.currentVersionId)))
    .orderBy(asc(secrets.key)) as Promise<DesiredKey[]>;
}

/** What each sync last pushed and has not since removed. */
async function loadRecorded(db: Queryable, syncIds: readonly string[]): Promise<Map<string, RecordedKey[]>> {
  const bySync = new Map<string, RecordedKey[]>();
  if (syncIds.length === 0) return bySync;
  const rows = await db
    .select({ syncId: syncKeys.syncId, key: syncKeys.key, versionId: syncKeys.secretVersionId })
    .from(syncKeys)
    .where(and(inArray(syncKeys.syncId, [...syncIds]), isNull(syncKeys.removedAt)));
  for (const row of rows) {
    const list = bySync.get(row.syncId) ?? [];
    list.push({ key: row.key, versionId: row.versionId });
    bySync.set(row.syncId, list);
  }
  return bySync;
}

// --- runner -------------------------------------------------------------------

type Actor = Pick<AuditEntry, 'actorType' | 'actorId' | 'requestId' | 'sourceIp'>;

/** Runs nobody pressed a button for are the sync's own doing. */
function systemActor(syncId: string): Actor {
  return { actorType: 'system', actorId: `sync:${syncId}` };
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
      const rows = await this.#deps.db
        .select({ id: syncs.id })
        .from(syncs)
        .where(and(eq(syncs.environmentId, environmentId), isNull(syncs.archivedAt), isNull(syncs.pausedAt)));
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
    const rows = (await selectSyncs(this.#deps.db).where(and(inLivePlace, isNull(syncs.pausedAt)))).filter(
      (row) => row.leaseUntil === null || row.leaseUntil.getTime() < now,
    );
    const views = await this.views(this.#deps.db, rows);
    const toRun = rows
      .filter((row, index) => {
        const lastRun = row.lastRunAt?.getTime() ?? null;
        const due = lastRun === null || lastRun < now - DRIFT_CHECK_MS;
        const backingOff =
          (row.lastStatus === 'failed' || row.lastStatus === 'partial') &&
          lastRun !== null &&
          lastRun > now - RETRY_AFTER_MS;
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
    const rows = await selectSyncs(this.#deps.db).where(eq(syncs.id, syncId));
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
        credential: `${row.credentialProject}/${row.credentialEnvironment}/${row.credentialKey}`,
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
    rows: readonly Pick<SyncRow, 'id' | 'environmentId' | 'provider' | 'credentialSecretId'>[],
  ): Promise<Map<string, SyncPlanIds>> {
    const recorded = await loadRecorded(db, rows.map((row) => row.id));
    const desiredByEnvironment = new Map<string, DesiredKey[]>();
    const plans = new Map<string, SyncPlanIds>();
    for (const row of rows) {
      const provider = this.provider(row.provider);
      if (provider === null) continue;
      let desired = desiredByEnvironment.get(row.environmentId);
      if (desired === undefined) {
        desired = await loadDesired(db, row.environmentId);
        desiredByEnvironment.set(row.environmentId, desired);
      }
      plans.set(
        row.id,
        planSync({
          desired: desired.filter((entry) => entry.secretId !== row.credentialSecretId),
          recorded: recorded.get(row.id) ?? [],
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
    const rows = await selectSyncs(this.#deps.db).where(
      and(eq(syncs.id, syncId), isNull(syncs.archivedAt), isNull(syncs.pausedAt)),
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
      await tx.update(syncs).set({ leaseUntil: new Date(now + LEASE_MS) }).where(eq(syncs.id, syncId));
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
    const { db, chainKey, keks } = this.#deps;

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
        const [credential] = await tx
          .select({
            secretId: secrets.id,
            projectId: secrets.projectId,
            environmentId: secrets.environmentId,
            archivedAt: secrets.archivedAt,
            version: secretVersions.version,
            ...envelopeColumns,
          })
          .from(secrets)
          .innerJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
          .where(eq(secrets.id, sync.credentialSecretId));
        if (credential === undefined || credential.archivedAt !== null) {
          const path = `${sync.credentialProject}/${sync.credentialEnvironment}/${sync.credentialKey}`;
          throw new SyncFailure(`${path} is archived; restore it or point this sync at another secret`);
        }
        const value = await open(
          envelopeOf(credential),
          { projectId: credential.projectId, environmentId: credential.environmentId, secretId: credential.secretId },
          keks,
        );
        log.push({
          ...actor,
          action: 'sync.run',
          decision: 'allow',
          // Filed under the credential, which is the secret this row reads.
          projectId: credential.projectId,
          environmentId: credential.environmentId,
          secretId: credential.secretId,
          bundleId: runId,
          metadata: { syncId, source: sourcePath, provider: provider.kind, destination, trigger, version: credential.version },
        });
        return value.toString('utf8');
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
        const recorded = (await loadRecorded(tx, [syncId])).get(syncId) ?? [];
        const ids = planSync({
          desired: current.map((entry) => ({ key: entry.key, secretId: entry.secretId, versionId: entry.secretVersionId })),
          recorded,
          remote,
          checkKey: provider.checkKey,
        });

        const upsert: { key: string; value: string }[] = [];
        const common = { ...actor, decision: 'allow' as const, ...scope, bundleId: runId };
        const byVersion = new Map(current.map((entry) => [entry.secretVersionId, entry]));
        for (const entry of ids.upsert) {
          const row = byVersion.get(entry.versionId)!;
          const value = await open(row.envelope, { ...scope, secretId: entry.secretId }, keks);
          upsert.push({ key: entry.key, value: value.toString('utf8') });
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
      for (const key of outcome.upserted) {
        const secretVersionId = pushedVersions.get(key);
        if (secretVersionId === undefined) continue;
        await upsertSyncKey(tx, { syncId, key, secretVersionId, pushedAt: now });
      }
      const removed = [...outcome.deleted, ...forget];
      if (removed.length > 0) {
        await tx
          .update(syncKeys)
          .set({ removedAt: now })
          .where(and(eq(syncKeys.syncId, syncId), inArray(syncKeys.key, removed), isNull(syncKeys.removedAt)));
      }
      await tx
        .update(syncs)
        .set({ lastRunAt: now, lastStatus: outcome.status, lastError: outcome.error, leaseUntil: null })
        .where(eq(syncs.id, syncId));
    });
  }
}

// --- handlers -----------------------------------------------------------------

/** The syncs of one environment, with what each is waiting to do. The router checks `secret.read`. */
export async function listSyncs(
  ctx: ApiContext,
  place: { projectId: string; environmentId: string },
): Promise<{ syncs: SyncView[]; canManage: boolean }> {
  const rows = await selectSyncs(ctx.db)
    .where(and(eq(syncs.environmentId, place.environmentId), isNull(syncs.archivedAt)))
    .orderBy(asc(syncs.createdAt));
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
  const rows = await selectSyncs(ctx.db)
    .where(and(eq(syncs.createdBy, principalId), inLivePlace))
    .orderBy(asc(projects.slug), asc(environments.slug), asc(syncs.createdAt));
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
      credential!.project.archived ||
      credential!.environment!.archived ||
      credential!.secret === null ||
      credential!.secret.archived ||
      credential!.secret.currentVersionId === null ||
      !can(ctx.caller, 'secret.read', credentialPlace)
    ) {
      throw new Refusal(
        badRequest(`${metadata.credential} is not a secret you can read`),
        denied(ctx, 'sync.create', 'unusable_credential', { ...place, metadata }),
      );
    }

    const others = await tx
      .select({ config: syncs.config, project: projects.slug, environment: environments.slug })
      .from(syncs)
      .innerJoin(environments, eq(environments.id, syncs.environmentId))
      .innerJoin(projects, eq(projects.id, syncs.projectId))
      .where(and(eq(syncs.provider, provider.kind), isNull(syncs.archivedAt)));
    const wanted = canonicalJson(config);
    const duplicate = others.find((other) => canonicalJson(JSON.parse(other.config)) === wanted);
    if (duplicate !== undefined) {
      throw new Refusal(
        conflict(`${destination} is already synced from ${duplicate.project}/${duplicate.environment}`),
        denied(ctx, 'sync.create', 'duplicate_destination', { ...place, metadata }),
      );
    }

    const id = randomUUID();
    await tx.insert(syncs).values({
      id,
      ...place,
      provider: provider.kind,
      config: JSON.stringify(config),
      credentialSecretId: credential!.secret.id,
      createdBy: ctx.caller.principal.id,
    });
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
    await tx.update(syncs).set(change(row)).where(eq(syncs.id, syncId));
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
 * Stop syncing for good. What was pushed stays at the destination: removing
 * a service's configuration is a decision for whoever runs that service,
 * not a side effect of tidying up coffre.
 */
export async function archiveSync(ctx: ApiContext, syncId: string): Promise<SyncView> {
  await manage(ctx, syncId, 'sync.archive', ['environment.manage'], () => ({ archivedAt: new Date() }));
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
