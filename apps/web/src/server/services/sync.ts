import { randomUUID } from 'node:crypto';

import type { Database, DatabaseClient } from '../database.ts';
import { toIsoTimestamp, toNullableIsoTimestamp } from '../database.ts';
import { open } from '../../../../../packages/core/src/envelope.ts';
import type { KekRegistry } from '../../../../../packages/core/src/kek/registry.ts';
import type { AuditEntry } from '../../../../../packages/db/src/audit.ts';
import {
  getProvider,
  SyncConfigError,
  SyncProviderError,
  type SyncApplyResult,
  type SyncProvider,
} from '../../../../../packages/sync/src/index.ts';
import { runAudited } from './audited.ts';
import { has, permissionsForEnvironment, type Permission } from './permissions.ts';
import {
  AccessDenied,
  AuditedFailure,
  NotFound,
  toEnvelopeRow,
  type RequestContext,
} from './secrets.ts';

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

export type SyncView = {
  id: string;
  provider: string;
  providerLabel: string;
  /** One line naming the destination, e.g. "erwinkn/app · environment production". */
  destination: string;
  config: unknown;
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

export type RunOutcome =
  | { status: 'busy' }
  | {
      status: SyncStatus;
      upserted: string[];
      deleted: string[];
      failed: { key: string; operation: 'upsert' | 'delete'; message: string }[];
      error: string | null;
    };

export type SyncServiceDeps = {
  pool: Database;
  keks: KekRegistry;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
  /** Background work that outlives the request, such as the first run after creating a sync. */
  waitUntil?: (promise: Promise<unknown>) => void;
  /** Injected by tests; defaults to the built-in providers. */
  resolveProvider?: (kind: string) => SyncProvider<unknown> | null;
  /** Injected by tests; defaults to the global fetch. */
  fetch?: typeof fetch;
};

/** Anything that can see an environment's key names can see its syncs. */
const VIEW_PERMISSIONS: readonly Permission[] = ['secret.read', 'secret.write', 'secret.archive'];

/** A run abandoned mid-way (the Worker was stopped) is picked up again after this. */
const LEASE = '5 minutes';
/** The whole run's budget, inside the lease. */
const RUN_TIMEOUT_MS = 4 * 60_000;
/** How often the scheduler checks an idle, healthy destination for missing keys. */
const DRIFT_CHECK = '1 hour';
/** How long the scheduler waits before retrying a sync whose last run failed. */
const RETRY_AFTER = '15 minutes';
/** A run that keeps finding new changes when it finishes stops after this many passes. */
const MAX_PASSES = 3;
const MAX_ERROR_LENGTH = 1000;

type SyncRow = {
  id: string;
  project_id: string;
  environment_id: string;
  provider: string;
  config: string;
  credential_secret_id: string;
  created_at: Date | string;
  created_by: string;
  paused_at: Date | string | null;
  lease_until: Date | string | null;
  running: boolean;
  last_run_at: Date | string | null;
  last_status: SyncStatus | null;
  last_error: string | null;
  credential_path: string;
};

const SYNC_COLUMNS = `
  s.id, s.project_id, s.environment_id, s.provider, s.config, s.credential_secret_id,
  s.created_at, s.created_by, s.paused_at, s.lease_until,
  (s.lease_until IS NOT NULL AND s.lease_until > now()) AS running,
  s.last_run_at, s.last_status, s.last_error,
  cp.slug || '/' || ce.slug || '/' || cs.key AS credential_path`;

const SYNC_JOINS = `
  JOIN secrets cs ON cs.id = s.credential_secret_id
  JOIN environments ce ON ce.id = cs.environment_id
  JOIN projects cp ON cp.id = cs.project_id`;

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

// --- service ------------------------------------------------------------------

export class SyncService {
  readonly #deps: SyncServiceDeps;

  constructor(deps: SyncServiceDeps) {
    this.#deps = deps;
  }

  #provider(kind: string): SyncProvider<unknown> | null {
    return (this.#deps.resolveProvider ?? getProvider)(kind);
  }

  #baseEntry(ctx: RequestContext, action: string): Omit<AuditEntry, 'decision'> {
    return {
      actorType: ctx.principal.type,
      actorId: ctx.principal.id,
      action,
      requestId: ctx.requestId,
      sourceIp: ctx.sourceIp,
    };
  }

  #background(promise: Promise<unknown>): void {
    const waitUntil =
      this.#deps.waitUntil ??
      ((work: Promise<unknown>) => {
        work.catch((error: unknown) => console.error('sync background run failed', error));
      });
    waitUntil(promise);
  }

  /** The syncs of one environment, with what each is waiting to do. */
  async list(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
  ): Promise<{ syncs: SyncView[]; canManage: boolean }> {
    const client = await this.#deps.pool.connect();
    try {
      const env = await resolveEnvironment(client, projectSlug, environmentSlug);
      if (env === null) throw new NotFound('unknown project or environment');
      const permissions = await permissionsForEnvironment(
        client,
        ctx.principal,
        env.environmentId,
        this.#deps.rootAdmins,
      );
      if (!VIEW_PERMISSIONS.some((permission) => has(permissions, permission))) {
        throw new AccessDenied();
      }
      const rows = await client.query<SyncRow>(
        `SELECT ${SYNC_COLUMNS}
           FROM syncs s ${SYNC_JOINS}
          WHERE s.environment_id = $1 AND s.archived_at IS NULL
          ORDER BY s.created_at`,
        [env.environmentId],
      );
      return {
        syncs: await this.#views(client, rows.rows),
        canManage: has(permissions, 'environment.manage') && has(permissions, 'secret.read'),
      };
    } finally {
      await client.release();
    }
  }

  /**
   * Start syncing an environment to a destination.
   *
   * Needs `environment.manage` and `secret.read` on the source: a sync sends
   * every value in it somewhere else, which is a read by other means. Needs
   * `secret.read` on the credential too, so nobody can put a token they could
   * not read themselves to work.
   */
  async create(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    input: { provider: string; config: unknown; credential: string },
  ): Promise<SyncView> {
    const provider = this.#provider(input.provider);
    if (provider === null) throw badRequest(`"${input.provider}" is not a sync destination coffre knows`);
    let config: unknown;
    try {
      config = provider.parseConfig(input.config);
    } catch (error) {
      if (error instanceof SyncConfigError) throw badRequest(error.message);
      throw error;
    }
    const credentialPath = parseSecretPath(input.credential);
    const destination = provider.describe(config);

    const syncId = await runAudited(this.#deps.pool, this.#deps.auditChainKey, async (tx) => {
      const base = this.#baseEntry(ctx, 'sync.create');
      const env = await resolveEnvironment(tx, projectSlug, environmentSlug);
      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          metadata: { projectSlug, environmentSlug, reason: 'unknown_environment' },
        });
      }
      const scope = { projectId: env.projectId, environmentId: env.environmentId };
      const metadata = { provider: provider.kind, destination, credential: input.credential };

      const permissions = await permissionsForEnvironment(
        tx,
        ctx.principal,
        env.environmentId,
        this.#deps.rootAdmins,
      );
      const missing = (['environment.manage', 'secret.read'] as const).find(
        (permission) => !has(permissions, permission),
      );
      if (missing) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          ...scope,
          decision: 'deny',
          metadata: { ...metadata, reason: `missing_${missing.replace('.', '_')}` },
        });
      }

      const credentialEnv = await resolveEnvironment(tx, credentialPath.project, credentialPath.environment);
      const credentialPermissions = credentialEnv
        ? await permissionsForEnvironment(tx, ctx.principal, credentialEnv.environmentId, this.#deps.rootAdmins)
        : null;
      const credential = credentialEnv
        ? await tx.query<{ id: string; archived: boolean }>(
            `SELECT id, archived_at IS NOT NULL AS archived FROM secrets
              WHERE environment_id = $1 AND key = $2 AND current_version_id IS NOT NULL`,
            [credentialEnv.environmentId, credentialPath.key],
          )
        : null;
      // Unknown and unreadable look the same, so the form cannot be used to
      // probe for secrets in environments the caller has no access to.
      if (
        credential === null ||
        credential.rowCount === 0 ||
        credential.rows[0].archived ||
        !has(credentialPermissions ?? new Set(), 'secret.read')
      ) {
        throw new AuditedFailure(
          badRequest(`${input.credential} is not a secret you can read`),
          { ...base, ...scope, decision: 'deny', metadata: { ...metadata, reason: 'unusable_credential' } },
        );
      }

      const duplicate = await tx.query<{ path: string }>(
        `SELECT p.slug || '/' || e.slug AS path
           FROM syncs s
           JOIN environments e ON e.id = s.environment_id
           JOIN projects p ON p.id = s.project_id
          WHERE s.provider = $1 AND s.config::jsonb = $2::jsonb AND s.archived_at IS NULL
          LIMIT 1`,
        [provider.kind, JSON.stringify(config)],
      );
      if (duplicate.rowCount !== 0) {
        throw new AuditedFailure(
          Object.assign(new Error(`${destination} is already synced from ${duplicate.rows[0].path}`), {
            statusCode: 409,
          }),
          { ...base, ...scope, decision: 'deny', metadata: { ...metadata, reason: 'duplicate_destination' } },
        );
      }

      const inserted = await tx.query<{ id: string }>(
        `INSERT INTO syncs (project_id, environment_id, provider, config, credential_secret_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [env.projectId, env.environmentId, provider.kind, JSON.stringify(config), credential.rows[0].id, ctx.principal.id],
      );
      const id = inserted.rows[0].id;
      return {
        result: id,
        entries: [{ ...base, ...scope, decision: 'allow', metadata: { ...metadata, syncId: id } }],
      };
    });

    this.#background(this.#runSettled(syncId, 'create', systemActor(syncId)));
    return this.#view(syncId);
  }

  /** Stop or restart pushing. A paused sync keeps its record of what it pushed. */
  async setPaused(ctx: RequestContext, syncId: string, paused: boolean): Promise<SyncView> {
    await this.#manage(ctx, syncId, paused ? 'sync.pause' : 'sync.resume', ['environment.manage'], (tx) =>
      tx.query(
        'UPDATE syncs SET paused_at = CASE WHEN $2 THEN COALESCE(paused_at, now()) END WHERE id = $1',
        [syncId, paused],
      ),
    );
    // Whatever changed while it was paused goes out now.
    if (!paused) this.#background(this.#runSettled(syncId, 'change', systemActor(syncId)));
    return this.#view(syncId);
  }

  /**
   * Stop syncing for good. What was pushed stays at the destination: removing
   * a service's configuration is a decision for whoever runs that service,
   * not a side effect of tidying up coffre.
   */
  async archive(ctx: RequestContext, syncId: string): Promise<SyncView> {
    await this.#manage(ctx, syncId, 'sync.archive', ['environment.manage'], (tx) =>
      tx.query('UPDATE syncs SET archived_at = now() WHERE id = $1', [syncId]),
    );
    return this.#view(syncId);
  }

  /**
   * Push now, in the caller's name, and wait for the result. Anyone who can
   * change the environment's secrets may, since a run only sends what a
   * write would have sent anyway.
   */
  async runNow(ctx: RequestContext, syncId: string): Promise<{ sync: SyncView; outcome: RunOutcome }> {
    // Only a refusal is logged here; an allowed run logs itself as it goes.
    await this.#manage(ctx, syncId, 'sync.run', ['secret.write', 'environment.manage'], null);
    const outcome = await this.#runSettled(syncId, 'manual', {
      actorType: ctx.principal.type,
      actorId: ctx.principal.id,
      requestId: ctx.requestId,
      sourceIp: ctx.sourceIp,
    });
    return { sync: await this.#view(syncId), outcome };
  }

  /** After a secret changed: push it everywhere its environment syncs to. */
  async runForEnvironment(environmentId: string): Promise<void> {
    try {
      const rows = await this.#deps.pool.query<{ id: string }>(
        `SELECT id FROM syncs
          WHERE environment_id = $1 AND archived_at IS NULL AND paused_at IS NULL`,
        [environmentId],
      );
      const results = await Promise.allSettled(
        rows.rows.map((row) => this.#runSettled(row.id, 'change', systemActor(row.id))),
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
    const rows = await this.#deps.pool.query<SyncRow & { due: boolean; backing_off: boolean }>(
      `SELECT ${SYNC_COLUMNS},
              (s.last_run_at IS NULL OR s.last_run_at < now() - $1::interval) AS due,
              (s.last_status IN ('failed', 'partial') AND s.last_run_at > now() - $2::interval) AS backing_off
         FROM syncs s ${SYNC_JOINS}
         JOIN environments e ON e.id = s.environment_id AND e.archived_at IS NULL
         JOIN projects p ON p.id = s.project_id AND p.archived_at IS NULL
        WHERE s.archived_at IS NULL AND s.paused_at IS NULL
          AND (s.lease_until IS NULL OR s.lease_until < now())`,
      [DRIFT_CHECK, RETRY_AFTER],
    );
    const views = await this.#views(this.#deps.pool, rows.rows);
    const toRun = rows.rows
      .filter((row, index) => !row.backing_off && (row.due || views[index].pending > 0))
      .map((row) => row.id);

    const results = await Promise.allSettled(
      toRun.map((id) => this.#runSettled(id, 'scheduled', systemActor(id))),
    );
    for (const result of results) {
      if (result.status === 'rejected') console.error('scheduled sync failed', result.reason);
    }
    return { ran: toRun.length };
  }

  // --- internals --------------------------------------------------------------

  /**
   * A permission-checked, audited change to one sync. `anyOf` lists the
   * permissions that each suffice; `change: null` checks and logs only a
   * refusal.
   */
  async #manage(
    ctx: RequestContext,
    syncId: string,
    action: string,
    anyOf: readonly Permission[],
    change: ((tx: DatabaseClient) => Promise<unknown>) | null,
  ): Promise<void> {
    await runAudited(this.#deps.pool, this.#deps.auditChainKey, async (tx) => {
      const base = this.#baseEntry(ctx, action);
      const row = await tx.query<{ project_id: string; environment_id: string; provider: string }>(
        `SELECT s.project_id, s.environment_id, s.provider
           FROM syncs s
           JOIN environments e ON e.id = s.environment_id AND e.archived_at IS NULL
           JOIN projects p ON p.id = s.project_id AND p.archived_at IS NULL
          WHERE s.id = $1 AND s.archived_at IS NULL
          FOR UPDATE OF s`,
        [syncId],
      );
      if (row.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown sync'), {
          ...base,
          decision: 'deny',
          metadata: { syncId, reason: 'unknown_sync' },
        });
      }
      const scope = { projectId: row.rows[0].project_id, environmentId: row.rows[0].environment_id };
      const permissions = await permissionsForEnvironment(
        tx,
        ctx.principal,
        scope.environmentId,
        this.#deps.rootAdmins,
      );
      if (!anyOf.some((permission) => has(permissions, permission))) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          ...scope,
          decision: 'deny',
          metadata: { syncId, reason: `missing_${anyOf[0].replace('.', '_')}` },
        });
      }
      if (change === null) return { result: undefined, entries: [] };
      await change(tx);
      return {
        result: undefined,
        entries: [{ ...base, ...scope, decision: 'allow', metadata: { syncId, provider: row.rows[0].provider } }],
      };
    });
  }

  async #view(syncId: string): Promise<SyncView> {
    const rows = await this.#deps.pool.query<SyncRow>(
      `SELECT ${SYNC_COLUMNS} FROM syncs s ${SYNC_JOINS} WHERE s.id = $1`,
      [syncId],
    );
    if (rows.rowCount === 0) throw new NotFound('unknown sync');
    const [view] = await this.#views(this.#deps.pool, rows.rows);
    return view;
  }

  /** Views of syncs, with what each would do next. */
  async #views(tx: Queryable, rows: readonly SyncRow[]): Promise<SyncView[]> {
    const plans = await this.#plans(tx, rows);
    return rows.map((row) => {
      const plan = plans.get(row.id);
      return {
        ...toView(row, this.#provider(row.provider), JSON.parse(row.config) as unknown),
        synced: plan?.inSync ?? 0,
        pending: plan ? plan.upsert.length + plan.delete.length : 0,
        skipped: plan?.skipped ?? [],
      };
    });
  }

  /** What each sync would do if it ran now, going by the record alone. Decrypts nothing. */
  async #plans(
    tx: Queryable,
    rows: readonly Pick<SyncRow, 'id' | 'environment_id' | 'provider' | 'credential_secret_id'>[],
  ): Promise<Map<string, SyncPlanIds>> {
    const recorded = await loadRecorded(tx, rows.map((row) => row.id));
    const desiredByEnvironment = new Map<string, DesiredKey[]>();
    const plans = new Map<string, SyncPlanIds>();
    for (const row of rows) {
      const provider = this.#provider(row.provider);
      if (provider === null) continue;
      let desired = desiredByEnvironment.get(row.environment_id);
      if (desired === undefined) {
        desired = await loadDesired(tx, row.environment_id);
        desiredByEnvironment.set(row.environment_id, desired);
      }
      plans.set(
        row.id,
        planSync({
          desired: desired.filter((entry) => entry.secretId !== row.credential_secret_id),
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
  async #runSettled(syncId: string, trigger: SyncTrigger, actor: Actor): Promise<RunOutcome> {
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
    const rows = await this.#deps.pool.query<SyncRow>(
      `SELECT ${SYNC_COLUMNS} FROM syncs s ${SYNC_JOINS}
        WHERE s.id = $1 AND s.archived_at IS NULL AND s.paused_at IS NULL`,
      [syncId],
    );
    const plan = (await this.#plans(this.#deps.pool, rows.rows)).get(syncId);
    return plan ? [...plan.upsert.map((entry) => entry.key), ...plan.delete] : [];
  }

  /** One run: lease, open the credential, list, plan, audit, push, record. */
  async #run(syncId: string, trigger: SyncTrigger, actor: Actor): Promise<RunOutcome> {
    const pool = this.#deps.pool;
    const leased = await pool.query<
      Pick<SyncRow, 'id' | 'project_id' | 'environment_id' | 'provider' | 'config' | 'credential_secret_id'> & {
        source_path: string;
      }
    >(
      `UPDATE syncs s SET lease_until = now() + $2::interval
         FROM environments e, projects p
        WHERE s.id = $1
          AND e.id = s.environment_id AND e.archived_at IS NULL
          AND p.id = s.project_id AND p.archived_at IS NULL
          AND s.archived_at IS NULL AND s.paused_at IS NULL
          AND (s.lease_until IS NULL OR s.lease_until < now())
      RETURNING s.id, s.project_id, s.environment_id, s.provider, s.config, s.credential_secret_id,
                p.slug || '/' || e.slug AS source_path`,
      [syncId, LEASE],
    );
    if (leased.rowCount === 0) return { status: 'busy' };
    const sync = leased.rows[0];
    const scope = { projectId: sync.project_id, environmentId: sync.environment_id };
    const sourcePath = sync.source_path;
    const runId = randomUUID();

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
      const provider = this.#provider(sync.provider);
      if (provider === null) throw new SyncFailure(`coffre no longer knows the destination "${sync.provider}"`);
      const config = provider.parseConfig(JSON.parse(sync.config));
      const destination = provider.describe(config);
      const signal = AbortSignal.timeout(RUN_TIMEOUT_MS);

      // Opening the credential is a use of a secret, so it is audited as the
      // run itself, in the same transaction as the read.
      const token = await runAudited(pool, this.#deps.auditChainKey, async (tx) => {
        const credential = await tx.query(
          `SELECT s.id AS secret_id, s.project_id, s.environment_id, s.archived_at,
                  p.slug || '/' || e.slug || '/' || s.key AS path,
                  v.version, v.envelope_version, v.ciphertext, v.iv, v.auth_tag,
                  v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version
             FROM secrets s
             JOIN secret_versions v ON v.id = s.current_version_id
             JOIN environments e ON e.id = s.environment_id
             JOIN projects p ON p.id = s.project_id
            WHERE s.id = $1`,
          [sync.credential_secret_id],
        );
        if (credential.rowCount === 0 || credential.rows[0].archived_at !== null) {
          const path = credential.rows[0]?.path ?? 'its credential';
          throw new SyncFailure(`${path} is archived; restore it or point this sync at another secret`);
        }
        const row = credential.rows[0];
        const envelope = toEnvelopeRow(row);
        const value = await open(
          envelope.envelope,
          { projectId: row.project_id, environmentId: row.environment_id, secretId: row.secret_id },
          this.#deps.keks,
        );
        return {
          result: value.toString('utf8'),
          entries: [
            {
              ...actor,
              action: 'sync.run',
              decision: 'allow',
              // Filed under the credential, which is the secret this row reads.
              projectId: row.project_id,
              environmentId: row.environment_id,
              secretId: row.secret_id,
              bundleId: runId,
              metadata: {
                syncId,
                source: sourcePath,
                provider: provider.kind,
                destination,
                trigger,
                version: envelope.version,
              },
            },
          ],
        };
      });
      const ctx = { token, fetch: this.#deps.fetch, signal };

      const remote = new Set(await provider.listKeys(ctx, config));

      // Plan and decrypt in one transaction, and write a row per key before
      // any value leaves. If the push then fails, the log says more left than
      // did, never less.
      const plan = await runAudited(pool, this.#deps.auditChainKey, async (tx) => {
        const desired = (await loadDesired(tx, sync.environment_id)).filter(
          (entry) => entry.secretId !== sync.credential_secret_id,
        );
        const recorded = (await loadRecorded(tx, [syncId])).get(syncId) ?? [];
        const ids = planSync({ desired, recorded, remote, checkKey: provider.checkKey });

        const upsert: { key: string; value: string }[] = [];
        const entries: AuditEntry[] = [];
        const common = { ...actor, decision: 'allow' as const, ...scope, bundleId: runId };
        for (const entry of ids.upsert) {
          const version = await tx.query(
            `SELECT version, envelope_version, ciphertext, iv, auth_tag,
                    wrapped_dek, kek_provider, kek_id, kek_version
               FROM secret_versions WHERE id = $1`,
            [entry.versionId],
          );
          const row = toEnvelopeRow(version.rows[0]);
          const value = await open(
            row.envelope,
            { projectId: sync.project_id, environmentId: sync.environment_id, secretId: entry.secretId },
            this.#deps.keks,
          );
          upsert.push({ key: entry.key, value: value.toString('utf8') });
          pushedVersions.set(entry.key, entry.versionId);
          entries.push({
            ...common,
            action: 'sync.push',
            secretId: entry.secretId,
            metadata: { syncId, key: entry.key, version: row.version, destination, trigger },
          });
        }
        for (const key of ids.delete) {
          entries.push({ ...common, action: 'sync.remove', metadata: { syncId, key, destination, trigger } });
        }
        return { result: { upsert, delete: ids.delete, forget: ids.forget }, entries };
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
    const client = await this.#deps.pool.connect();
    try {
      await client.query('BEGIN');
      for (const key of outcome.upserted) {
        const versionId = pushedVersions.get(key);
        if (versionId === undefined) continue;
        await client.query(
          `INSERT INTO sync_keys (sync_id, key, secret_version_id, pushed_at)
           VALUES ($1, $2, $3, now())
           ON CONFLICT (sync_id, key) DO UPDATE
             SET secret_version_id = EXCLUDED.secret_version_id, pushed_at = now(), removed_at = NULL`,
          [syncId, key, versionId],
        );
      }
      const removed = [...outcome.deleted, ...forget];
      if (removed.length > 0) {
        await client.query(
          `UPDATE sync_keys SET removed_at = now()
            WHERE sync_id = $1 AND key = ANY($2::text[]) AND removed_at IS NULL`,
          [syncId, removed],
        );
      }
      await client.query(
        `UPDATE syncs
            SET last_run_at = now(), last_status = $2, last_error = $3, lease_until = NULL
          WHERE id = $1`,
        [syncId, outcome.status, outcome.error],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      await client.release();
    }
  }
}

// --- helpers ------------------------------------------------------------------

type Actor = Pick<AuditEntry, 'actorType' | 'actorId' | 'requestId' | 'sourceIp'>;

/** Runs nobody pressed a button for are the sync's own doing. */
function systemActor(syncId: string): Actor {
  return { actorType: 'system', actorId: `sync:${syncId}` };
}

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

function badRequest(message: string): Error {
  return Object.assign(new Error(message), { statusCode: 400, expose: true });
}

function parseSecretPath(path: string): { project: string; environment: string; key: string } {
  const parts = path.trim().split('/');
  if (parts.length !== 3 || parts.some((part) => part === '')) {
    throw badRequest('name the credential as project/environment/KEY');
  }
  const [project, environment, key] = parts;
  return { project, environment, key };
}

function toView(
  row: SyncRow,
  provider: SyncProvider<unknown> | null,
  config: unknown,
): Omit<SyncView, 'synced' | 'pending' | 'skipped'> {
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
    config,
    credential: row.credential_path,
    createdAt: toIsoTimestamp(row.created_at),
    createdBy: row.created_by,
    paused: row.paused_at !== null,
    running: row.running,
    lastRunAt: toNullableIsoTimestamp(row.last_run_at),
    lastStatus: row.last_status,
    lastError: row.last_error,
  };
}

type Queryable = Pick<DatabaseClient, 'query'>;

async function resolveEnvironment(
  tx: Queryable,
  projectSlug: string,
  environmentSlug: string,
): Promise<{ projectId: string; environmentId: string } | null> {
  const result = await tx.query<{ project_id: string; environment_id: string }>(
    `SELECT p.id AS project_id, e.id AS environment_id
       FROM projects p
       JOIN environments e ON e.project_id = p.id
      WHERE p.slug = $1 AND e.slug = $2
        AND p.archived_at IS NULL AND e.archived_at IS NULL`,
    [projectSlug, environmentSlug],
  );
  if (result.rowCount === 0) return null;
  return { projectId: result.rows[0].project_id, environmentId: result.rows[0].environment_id };
}

/** What the environment holds now: live secrets and their current version ids. */
async function loadDesired(tx: Queryable, environmentId: string): Promise<DesiredKey[]> {
  const result = await tx.query<{ key: string; secret_id: string; version_id: string }>(
    `SELECT key, id AS secret_id, current_version_id AS version_id
       FROM secrets
      WHERE environment_id = $1 AND archived_at IS NULL AND current_version_id IS NOT NULL
      ORDER BY key`,
    [environmentId],
  );
  return result.rows.map((row) => ({ key: row.key, secretId: row.secret_id, versionId: row.version_id }));
}

/** What each sync last pushed and has not since removed. */
async function loadRecorded(tx: Queryable, syncIds: readonly string[]): Promise<Map<string, RecordedKey[]>> {
  const bySync = new Map<string, RecordedKey[]>();
  if (syncIds.length === 0) return bySync;
  const result = await tx.query<{ sync_id: string; key: string; secret_version_id: string | null }>(
    `SELECT sync_id, key, secret_version_id
       FROM sync_keys
      WHERE sync_id = ANY($1::uuid[]) AND removed_at IS NULL`,
    [syncIds],
  );
  for (const row of result.rows) {
    const list = bySync.get(row.sync_id) ?? [];
    list.push({ key: row.key, versionId: row.secret_version_id });
    bySync.set(row.sync_id, list);
  }
  return bySync;
}
