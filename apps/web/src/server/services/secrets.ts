import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { Database, DatabaseClient } from '../database.ts';

import { seal, open, type Envelope } from '../../../../../packages/core/src/envelope.ts';
import type { SecretContext } from '../../../../../packages/core/src/context.ts';
import type { KekRegistry } from '../../../../../packages/core/src/kek/registry.ts';
import { appendAudit, type AuditEntry } from '../../../../../packages/db/src/audit.ts';
import {
  has,
  isRootAdmin as isConfiguredRootAdmin,
  permissionsForEnvironment,
  PERMISSIONS as ALL_PERMISSIONS,
  type Permission,
  type PermissionSet,
  type PrincipalRef,
} from './permissions.ts';
import { toNullableIsoTimestamp, toIsoTimestamp } from '../database.ts';

const SECRET_METADATA_PERMISSIONS: ReadonlySet<Permission> = new Set([
  'secret.read',
  'secret.write',
  'secret.archive',
]);

export type Capability = 'read' | 'write' | 'admin';

export class AccessDenied extends Error {
  readonly statusCode = 403;
  constructor(message = 'forbidden') {
    super(message);
  }
}

export class NotFound extends Error {
  readonly statusCode = 404;
  constructor(message = 'not found') {
    super(message);
  }
}

export type RequestContext = {
  principal: PrincipalRef;
  requestId: string;
  sourceIp: string | null;
};

export type SecretsServiceDeps = {
  pool: Database;
  keks: KekRegistry;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
  /** Called after a commit that changed an environment's secrets, so its syncs can push. */
  onChange?: (environmentId: string) => void;
};

/** Audit actions that change what an environment holds, and so what its syncs push. */
const CHANGE_ACTIONS: ReadonlySet<string> = new Set([
  'secret.write',
  'secret.rename',
  'secret.rollback',
  'secret.import',
  'secret.archive',
  'secret.restore',
]);

export type SecretKey = {
  key: string;
  archived: boolean;
  version: number | null;
  updatedAt: string | null;
  updatedBy: string | null;
};

type EnvironmentRow = { projectId: string; environmentId: string };

export class SecretsService {
  readonly #deps: SecretsServiceDeps;

  constructor(deps: SecretsServiceDeps) {
    this.#deps = deps;
  }

  /**
   * Run `fn` inside a transaction, and append audit entries in that SAME
   * transaction before committing.
   *
   * This is the core guarantee of the service. There is no code path that
   * returns a secret value without an audit row, because the audit row and the
   * read commit or roll back together. If the audit append throws, the caller
   * gets an error and no secret.
   */
  async #audited<T>(
    fn: (tx: DatabaseClient) => Promise<{ result: T; entries: AuditEntry[] }>,
  ): Promise<T> {
    const client = await this.#deps.pool.connect();
    try {
      await client.query('BEGIN');

      let outcome: { result: T; entries: AuditEntry[] };
      try {
        outcome = await fn(client);
      } catch (error) {
        if (error instanceof AuditedFailure) {
          // A denial. Roll back whatever the attempt touched, then write the
          // denial row in a fresh transaction and commit it.
          //
          // Rolling back and returning here -- the obvious implementation --
          // would silently discard the audit row for every refused request.
          // "Who tried to read prod and was refused" is half the value of the
          // log, so the denial path is committed just as deliberately as the
          // success path.
          await client.query('ROLLBACK');
          await client.query('BEGIN');
          await appendAudit(client, this.#deps.auditChainKey, [error.entry]);
          await client.query('COMMIT');
          throw error.cause;
        }
        throw error;
      }

      await appendAudit(client, this.#deps.auditChainKey, outcome.entries);
      await client.query('COMMIT');
      this.#notifyChanges(outcome.entries);
      return outcome.result;
    } catch (error) {
      // ROLLBACK on an already-finished transaction is a no-op warning, which
      // is why this is safe to call unconditionally here.
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      await client.release();
    }
  }

  /**
   * Tell syncs which environments just changed. The audit entries already say
   * exactly that, so no write path has to remember to call this itself.
   */
  #notifyChanges(entries: readonly AuditEntry[]): void {
    const onChange = this.#deps.onChange;
    if (onChange === undefined) return;
    const changed = new Set<string>();
    for (const entry of entries) {
      if (entry.decision === 'allow' && CHANGE_ACTIONS.has(entry.action) && entry.secretId && entry.environmentId) {
        changed.add(entry.environmentId);
      }
    }
    for (const environmentId of changed) {
      try {
        onChange(environmentId);
      } catch (error) {
        // The write has committed; a sync that cannot start now is picked up by the scheduler.
        console.error('sync notification failed', error);
      }
    }
  }

  #isRootAdmin(principal: PrincipalRef): boolean {
    return isConfiguredRootAdmin(principal, this.#deps.rootAdmins);
  }

  /**
   * Resolve slugs to ids.
   *
   * Archived projects and environments resolve to null, so every caller treats
   * them exactly as it treats one that never existed: denied, and audited.
   */
  async #resolveEnvironment(
    tx: DatabaseClient,
    projectSlug: string,
    environmentSlug: string,
  ): Promise<EnvironmentRow | null> {
    const result = await tx.query<{ project_id: string; environment_id: string }>(
      `SELECT p.id AS project_id, e.id AS environment_id
         FROM projects p
         JOIN environments e ON e.project_id = p.id
        WHERE p.slug = $1 AND e.slug = $2
          AND p.archived_at IS NULL AND e.archived_at IS NULL`,
      [projectSlug, environmentSlug],
    );
    if (result.rowCount === 0) return null;
    return {
      projectId: result.rows[0].project_id,
      environmentId: result.rows[0].environment_id,
    };
  }

  /**
   * The caller's effective capability on one environment.
   *
   * Two sources, and the strongest wins: a grant on the environment itself, or
   * a grant on the project that contains it. Project grants are what make
   * "admin on this project" mean something -- there is otherwise nothing that
   * could authorise creating an environment inside it.
   */
  #permissionsFor(
    tx: DatabaseClient,
    principal: PrincipalRef,
    environmentId: string,
  ): Promise<PermissionSet> {
    return permissionsForEnvironment(tx, principal, environmentId, this.#deps.rootAdmins);
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

  /**
   * Read one secret.
   *
   * Denials are logged too, which is half the value of the log: "who tried to
   * read prod and was refused" is exactly the anomalous activity Article
   * 12(2)(b) asks the log to make detectable.
   */
  async readSecret(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    key: string,
  ): Promise<{ key: string; value: string; version: number }> {
    return this.#audited(async (tx) => {
      const base = this.#baseEntry(ctx, 'secret.read');
      const env = await this.#resolveEnvironment(tx, projectSlug, environmentSlug);

      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          metadata: { projectSlug, environmentSlug, key, reason: 'unknown_environment' },
        });
      }

      const permissions = await this.#permissionsFor(tx, ctx.principal, env.environmentId);
      if (!has(permissions, 'secret.read')) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, reason: 'missing_secret_read' },
        });
      }

      const secret = await loadCurrentVersion(tx, env, key);
      if (secret === null || secret.archived) {
        throw new AuditedFailure(new NotFound('unknown secret'), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, reason: 'unknown_secret' },
        });
      }

      const secretContext: SecretContext = {
        projectId: env.projectId,
        environmentId: env.environmentId,
        secretId: secret.secretId,
      };
      const value = await open(secret.envelope, secretContext, this.#deps.keks);

      return {
        result: { key, value: value.toString('utf8'), version: secret.version },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: secret.secretId,
            metadata: { key, version: secret.version },
          },
        ],
      };
    });
  }

  /**
   * Read every secret in an environment. This is the DX target -- it is what
   * makes `coffre run -- <cmd>` a single round trip.
   *
   * It emits ONE AUDIT ROW PER SECRET, all sharing a bundle id. A single row
   * per bulk fetch would reduce the answer to "who read which secret" down to
   * "they read the whole environment", which is true and useless.
   */
  async readEnvironment(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
  ): Promise<{ secrets: Record<string, string>; bundleId: string }> {
    return this.#audited(async (tx) => {
      const base = this.#baseEntry(ctx, 'secret.read');
      const bundleId = randomUUID();
      const env = await this.#resolveEnvironment(tx, projectSlug, environmentSlug);

      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          bundleId,
          metadata: { projectSlug, environmentSlug, reason: 'unknown_environment' },
        });
      }

      const permissions = await this.#permissionsFor(tx, ctx.principal, env.environmentId);
      if (!has(permissions, 'secret.read')) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          bundleId,
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { reason: 'missing_secret_read' },
        });
      }

      const rows = await loadAllCurrentVersions(tx, env);

      const secrets: Record<string, string> = {};
      const entries: AuditEntry[] = [];

      for (const row of rows) {
        const value = await open(
          row.envelope,
          {
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: row.secretId,
          },
          this.#deps.keks,
        );
        Object.defineProperty(secrets, row.key, {
          value: value.toString('utf8'),
          enumerable: true,
          configurable: true,
          writable: true,
        });

        entries.push({
          ...base,
          decision: 'allow',
          bundleId,
          projectId: env.projectId,
          environmentId: env.environmentId,
          secretId: row.secretId,
          metadata: { key: row.key, version: row.version },
        });
      }

      if (entries.length === 0) {
        // An empty environment still produced a read. Log the attempt rather
        // than silently writing nothing.
        entries.push({
          ...base,
          decision: 'allow',
          bundleId,
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { reason: 'empty_environment' },
        });
      }

      return { result: { secrets, bundleId }, entries };
    });
  }

  /** Create or update a secret. Always writes a new version; never mutates one. */
  async writeSecret(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    key: string,
    value: string,
  ): Promise<{ key: string; version: number }> {
    return this.#audited(async (tx) => {
      const base = this.#baseEntry(ctx, 'secret.write');
      const env = await this.#resolveEnvironment(tx, projectSlug, environmentSlug);

      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          metadata: { projectSlug, environmentSlug, key, reason: 'unknown_environment' },
        });
      }

      const permissions = await this.#permissionsFor(tx, ctx.principal, env.environmentId);
      if (!has(permissions, 'secret.write')) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, reason: 'missing_secret_write' },
        });
      }

      if (value.includes('\u0000')) {
        throw new AuditedFailure(
          Object.assign(new Error('secret values cannot contain a NUL byte'), {
            statusCode: 409,
          }),
          {
            ...base,
            decision: 'deny',
            projectId: env.projectId,
            environmentId: env.environmentId,
            metadata: { key, reason: 'invalid_secret_value' },
          },
        );
      }

      const secret = await upsertSecret(tx, env, key);
      if (secret.archived) {
        throw new AuditedFailure(
          Object.assign(new Error('restore that secret before you write a new version'), {
            statusCode: 409,
          }),
          {
            ...base,
            decision: 'deny',
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: secret.id,
            metadata: { key, reason: 'secret_archived' },
          },
        );
      }
      const secretId = secret.id;

      const nextVersion = await tx.query<{ next: string }>(
        'SELECT COALESCE(MAX(version), 0) + 1 AS next FROM secret_versions WHERE secret_id = $1',
        [secretId],
      );
      const version = Number(nextVersion.rows[0].next);

      const envelope = await seal(
        Buffer.from(value, 'utf8'),
        { projectId: env.projectId, environmentId: env.environmentId, secretId },
        this.#deps.keks,
      );

      const inserted = await tx.query<{ id: string }>(
        `INSERT INTO secret_versions (
             secret_id, version, envelope_version, ciphertext, iv, auth_tag,
             wrapped_dek, kek_provider, kek_id, kek_version, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
        [
          secretId,
          version,
          envelope.envelopeVersion,
          envelope.ciphertext,
          envelope.iv,
          envelope.authTag,
          envelope.wrappedDek,
          envelope.kekProvider,
          envelope.kekId,
          envelope.kekVersion,
          ctx.principal.id,
        ],
      );

      await tx.query(
        'UPDATE secrets SET current_version_id = $1, updated_at = now() WHERE id = $2',
        [inserted.rows[0].id, secretId],
      );

      return {
        result: { key, version },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId,
            // The value is never logged. The log answers who and what, not what it was.
            metadata: { key, version },
          },
        ],
      };
    });
  }

  /**
   * Rename a secret without touching its versions or ciphertext.
   *
   * The envelope is bound to immutable ids, not the display key, so this is a
   * metadata update. Keeping it here (rather than copying the value to a new
   * secret) preserves the version history and its audit references.
   */
  async renameSecret(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    key: string,
    nextKey: string,
  ): Promise<{ key: string }> {
    return this.#audited(async (tx) => {
      const base = this.#baseEntry(ctx, 'secret.rename');
      const env = await this.#resolveEnvironment(tx, projectSlug, environmentSlug);

      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          metadata: { projectSlug, environmentSlug, key, nextKey, reason: 'unknown_environment' },
        });
      }

      const permissions = await this.#permissionsFor(tx, ctx.principal, env.environmentId);
      if (!has(permissions, 'secret.write')) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, nextKey, reason: 'missing_secret_write' },
        });
      }

      const secret = await tx.query<{ id: string }>(
        `SELECT id FROM secrets
          WHERE project_id = $1 AND environment_id = $2 AND key = $3
            AND archived_at IS NULL`,
        [env.projectId, env.environmentId, key],
      );
      if (secret.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown secret'), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, nextKey, reason: 'unknown_secret' },
        });
      }

      const collision = await tx.query(
        `SELECT 1 FROM secrets
          WHERE project_id = $1 AND environment_id = $2 AND key = $3 AND id <> $4`,
        [env.projectId, env.environmentId, nextKey, secret.rows[0].id],
      );
      if (collision.rowCount !== 0) {
        throw new AuditedFailure(
          Object.assign(new Error(`a secret named "${nextKey}" already exists`), {
            statusCode: 409,
          }),
          {
            ...base,
            decision: 'deny',
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: secret.rows[0].id,
            metadata: { key, nextKey, reason: 'duplicate_key' },
          },
        );
      }

      await tx.query('UPDATE secrets SET key = $1, updated_at = now() WHERE id = $2', [
        nextKey,
        secret.rows[0].id,
      ]);

      return {
        result: { key: nextKey },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: secret.rows[0].id,
            metadata: { key, nextKey },
          },
        ],
      };
    });
  }

  /**
   * Environments the caller can reach, with the permissions they hold on each.
   *
   * Returns the union of permissions across every applicable grant, rather than
   * a single "capability" -- an auditor and a viewer are no longer points on
   * one ladder, so there is no single label that describes what someone can do.
   */
  async listAccessible(
    ctx: RequestContext,
  ): Promise<{ project: string; environment: string; permissions: Permission[] }[]> {
    const client = await this.#deps.pool.connect();
    try {
      if (this.#isRootAdmin(ctx.principal)) {
        const all = await client.query<{ project: string; environment: string }>(
          `SELECT p.slug AS project, e.slug AS environment
             FROM environments e JOIN projects p ON p.id = e.project_id
            WHERE p.archived_at IS NULL AND e.archived_at IS NULL
            ORDER BY p.slug, e.slug`,
        );
        return all.rows.map((row) => ({
          ...row,
          permissions: [...ALL_PERMISSIONS],
        }));
      }

      const result = await client.query<{
        project: string;
        environment: string;
        permission: Permission;
      }>(
        `SELECT DISTINCT p.slug AS project, e.slug AS environment, rp.permission
           FROM grants g
           JOIN role_permissions rp ON rp.role_id = g.role_id
           JOIN environments e
             ON e.id = g.environment_id OR e.project_id = g.project_id
           JOIN projects p ON p.id = e.project_id
          WHERE g.principal_type = $1 AND g.principal_id = $2
            AND (g.expires_at IS NULL OR g.expires_at > now())
            AND p.archived_at IS NULL AND e.archived_at IS NULL
          ORDER BY p.slug, e.slug`,
        [ctx.principal.type, ctx.principal.id],
      );

      const byEnvironment = new Map<
        string,
        { project: string; environment: string; permissions: Permission[] }
      >();
      for (const row of result.rows) {
        const key = `${row.project}/${row.environment}`;
        const entry =
          byEnvironment.get(key) ??
          { project: row.project, environment: row.environment, permissions: [] };
        entry.permissions.push(row.permission);
        byEnvironment.set(key, entry);
      }
      return [...byEnvironment.values()];
    } finally {
      await client.release();
    }
  }

  /** Secret names and current-version metadata, never secret values. */
  async listKeys(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
  ): Promise<{ permissions: Permission[]; keys: SecretKey[] }> {
    const accessible = await this.listAccessible(ctx);
    const match = accessible.find(
      (entry) =>
        entry.project === projectSlug && entry.environment === environmentSlug,
    );
    if (
      !match
      || !match.permissions.some((permission) => SECRET_METADATA_PERMISSIONS.has(permission))
    ) {
      throw new AccessDenied();
    }

    const client = await this.#deps.pool.connect();
    try {
      const result = await client.query<{
        key: string;
        archived_at: string | null;
        version: number | null;
        created_at: string | null;
        created_by: string | null;
      }>(
        `SELECT s.key, s.archived_at, v.version, v.created_at, v.created_by
           FROM secrets s
           JOIN projects p ON p.id = s.project_id
           JOIN environments e ON e.id = s.environment_id
           LEFT JOIN secret_versions v ON v.id = s.current_version_id
          WHERE p.slug = $1 AND e.slug = $2
          ORDER BY s.key`,
        [projectSlug, environmentSlug],
      );

      return {
        permissions: match.permissions,
        keys: result.rows.map((row) => ({
          key: row.key,
          archived: row.archived_at !== null,
          version: row.version === null ? null : Number(row.version),
          updatedAt: toNullableIsoTimestamp(row.created_at),
          updatedBy: row.created_by,
        })),
      };
    } finally {
      await client.release();
    }
  }


  /**
   * A secret's version history: who wrote each version and when, never values.
   *
   * Requires secret.read even though no value is returned -- the shape of a
   * change history is itself information about the secret.
   */
  async listVersions(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    key: string,
  ): Promise<{
    key: string;
    archived: boolean;
    versions: {
      version: number;
      createdAt: string;
      createdBy: string;
      current: boolean;
      kek: string;
    }[];
  }> {
    const client = await this.#deps.pool.connect();
    try {
      const env = await this.#resolveEnvironment(client, projectSlug, environmentSlug);
      if (env === null) throw new NotFound('unknown project or environment');

      const permissions = await this.#permissionsFor(client, ctx.principal, env.environmentId);
      if (!has(permissions, 'secret.read')) throw new AccessDenied();

      const secret = await client.query<{ id: string; archived_at: string | null; current_version_id: string | null }>(
        `SELECT id, archived_at, current_version_id FROM secrets
          WHERE project_id = $1 AND environment_id = $2 AND key = $3`,
        [env.projectId, env.environmentId, key],
      );
      if (secret.rowCount === 0) throw new NotFound('unknown secret');

      const versions = await client.query(
        `SELECT id, version, created_at, created_by, kek_provider, kek_id
           FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC`,
        [secret.rows[0].id],
      );

      return {
        key,
        archived: secret.rows[0].archived_at !== null,
        versions: versions.rows.map((row) => ({
          version: Number(row.version),
          createdAt: toIsoTimestamp(row.created_at),
          createdBy: row.created_by,
          current: row.id === secret.rows[0].current_version_id,
          kek: `${row.kek_provider}:${row.kek_id}`,
        })),
      };
    } finally {
      await client.release();
    }
  }

  /**
   * Roll back to an earlier version.
   *
   * This repoints `current_version_id`; it does not copy or rewrite anything.
   * Versions are append-only, so every value that was ever current is still
   * there and rollback costs nothing -- which is exactly why the data model was
   * shaped this way.
   *
   * The old version stays where it is in the numbering. A subsequent write
   * takes MAX(version) + 1, so history reads forward even after a rollback.
   */
  async rollback(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    key: string,
    toVersion: number,
  ): Promise<{ key: string; version: number }> {
    return this.#audited(async (tx) => {
      const base = this.#baseEntry(ctx, 'secret.rollback');
      const env = await this.#resolveEnvironment(tx, projectSlug, environmentSlug);

      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          metadata: { projectSlug, environmentSlug, key, reason: 'unknown_environment' },
        });
      }

      const permissions = await this.#permissionsFor(tx, ctx.principal, env.environmentId);
      if (!has(permissions, 'secret.write')) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, toVersion, reason: 'missing_secret_write' },
        });
      }

      const secret = await tx.query<{ id: string; current_version_id: string | null }>(
        `SELECT id, current_version_id FROM secrets
          WHERE project_id = $1 AND environment_id = $2 AND key = $3 AND archived_at IS NULL
          FOR UPDATE`,
        [env.projectId, env.environmentId, key],
      );
      if (secret.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown secret'), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, toVersion, reason: 'unknown_secret' },
        });
      }

      const target = await tx.query<{ id: string; version: number }>(
        'SELECT id, version FROM secret_versions WHERE secret_id = $1 AND version = $2',
        [secret.rows[0].id, toVersion],
      );
      if (target.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown version'), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          secretId: secret.rows[0].id,
          metadata: { key, toVersion, reason: 'unknown_version' },
        });
      }

      const previous = await tx.query<{ version: number }>(
        'SELECT version FROM secret_versions WHERE id = $1',
        [secret.rows[0].current_version_id],
      );

      await tx.query(
        'UPDATE secrets SET current_version_id = $1, updated_at = now() WHERE id = $2',
        [target.rows[0].id, secret.rows[0].id],
      );

      return {
        result: { key, version: toVersion },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: secret.rows[0].id,
            metadata: {
              key,
              fromVersion: previous.rows[0] ? Number(previous.rows[0].version) : null,
              toVersion,
            },
          },
        ],
      };
    });
  }


  /**
   * Bulk import from a .env file.
   *
   * `dryRun` returns the plan without writing anything, so the UI can show a
   * diff before committing. The plan reports "unchanged" by comparing against
   * the current decrypted value, which means a dry run IS a read of every
   * existing secret -- so it is authorised as one and audited as one. Anything
   * else would make import a way to read values without a read being logged.
   */
  async importSecrets(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    entries: readonly { key: string; value: string }[],
    dryRun: boolean,
  ): Promise<{
    bundleId: string;
    plan: { key: string; action: 'create' | 'update' | 'unchanged'; version: number | null }[];
  }> {
    return this.#audited(async (tx) => {
      const action = dryRun ? 'secret.import.preview' : 'secret.import';
      const base = this.#baseEntry(ctx, action);
      const bundleId = randomUUID();
      const env = await this.#resolveEnvironment(tx, projectSlug, environmentSlug);

      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          bundleId,
          metadata: { projectSlug, environmentSlug, reason: 'unknown_environment' },
        });
      }

      const permissions = await this.#permissionsFor(tx, ctx.principal, env.environmentId);
      // Both paths need secret.write: a preview compares against existing
      // values, and secret.read alone must not unlock that.
      const required: Permission[] = ['secret.write', 'secret.read'];
      const missing = required.find((permission) => !has(permissions, permission));
      if (missing) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          bundleId,
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { reason: `missing_${missing}`, keys: entries.length },
        });
      }

      const plan: { key: string; action: 'create' | 'update' | 'unchanged'; version: number | null }[] = [];
      const auditEntries: AuditEntry[] = [];
      let changed = 0;

      for (const entry of entries) {
        const existing = await loadCurrentVersion(tx, env, entry.key);
        if (existing?.archived) {
          throw new AuditedFailure(
            Object.assign(new Error(`restore "${entry.key}" before you import a new version`), {
              statusCode: 409,
            }),
            {
              ...base,
              decision: 'deny',
              bundleId,
              projectId: env.projectId,
              environmentId: env.environmentId,
              secretId: existing.secretId,
              metadata: { key: entry.key, reason: 'secret_archived' },
            },
          );
        }

        let outcome: 'create' | 'update' | 'unchanged';
        if (existing === null) {
          outcome = 'create';
        } else {
          const current = await open(
            existing.envelope,
            { projectId: env.projectId, environmentId: env.environmentId, secretId: existing.secretId },
            this.#deps.keks,
          );
          const incoming = Buffer.from(entry.value, 'utf8');
          outcome =
            current.length === incoming.length && timingSafeEqual(current, incoming)
              ? 'unchanged'
              : 'update';
          current.fill(0);
          auditEntries.push({
            ...base,
            action: 'secret.read',
            decision: 'allow',
            bundleId,
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: existing.secretId,
            metadata: {
              key: entry.key,
              version: existing.version,
              via: action,
            },
          });
        }

        if (dryRun || outcome === 'unchanged') {
          plan.push({
            key: entry.key,
            action: outcome,
            version: existing?.version ?? null,
          });
          continue;
        }

        const secret = await upsertSecret(tx, env, entry.key);
        if (secret.archived) {
          throw new AuditedFailure(
            Object.assign(new Error(`restore "${entry.key}" before you import a new version`), {
              statusCode: 409,
            }),
            {
              ...base,
              decision: 'deny',
              bundleId,
              projectId: env.projectId,
              environmentId: env.environmentId,
              secretId: secret.id,
              metadata: { key: entry.key, reason: 'secret_archived' },
            },
          );
        }
        const secretId = secret.id;
        const next = await tx.query<{ next: string }>(
          'SELECT COALESCE(MAX(version), 0) + 1 AS next FROM secret_versions WHERE secret_id = $1',
          [secretId],
        );
        const version = Number(next.rows[0].next);

        const envelope = await seal(
          Buffer.from(entry.value, 'utf8'),
          { projectId: env.projectId, environmentId: env.environmentId, secretId },
          this.#deps.keks,
        );

        const inserted = await tx.query<{ id: string }>(
          `INSERT INTO secret_versions (
               secret_id, version, envelope_version, ciphertext, iv, auth_tag,
               wrapped_dek, kek_provider, kek_id, kek_version, created_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
          [
            secretId,
            version,
            envelope.envelopeVersion,
            envelope.ciphertext,
            envelope.iv,
            envelope.authTag,
            envelope.wrappedDek,
            envelope.kekProvider,
            envelope.kekId,
            envelope.kekVersion,
            ctx.principal.id,
          ],
        );
        await tx.query(
          'UPDATE secrets SET current_version_id = $1, updated_at = now() WHERE id = $2',
          [inserted.rows[0].id, secretId],
        );

        plan.push({ key: entry.key, action: outcome, version });
        changed += 1;
        auditEntries.push({
          ...base,
          decision: 'allow',
          bundleId,
          projectId: env.projectId,
          environmentId: env.environmentId,
          secretId,
          metadata: { key: entry.key, version, action: outcome },
        });
      }

      // A preview or no-op import still gets its own operation row in addition
      // to one secret.read row for every existing value it compared.
      if (changed === 0) {
        auditEntries.push({
          ...base,
          decision: 'allow',
          bundleId,
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: {
            keys: entries.length,
            changed: 0,
            dryRun,
          },
        });
      }

      return { result: { bundleId, plan }, entries: auditEntries };
    });
  }

  /**
   * Retire or restore a secret.
   *
   * Not a delete: audit_log references secrets with ON DELETE RESTRICT, so a
   * secret that has ever been read or written cannot be removed. Archiving
   * stops it being served and drops it from bulk fetch -- so a rotated-out
   * credential stops being injected into processes -- while its versions and
   * its history stay exactly where they are.
   */
  async setSecretArchived(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    key: string,
    archived: boolean,
  ): Promise<{ key: string; archived: boolean }> {
    return this.#audited(async (tx) => {
      const base = this.#baseEntry(ctx, archived ? 'secret.archive' : 'secret.restore');
      const env = await this.#resolveEnvironment(tx, projectSlug, environmentSlug);

      if (env === null) {
        throw new AuditedFailure(new NotFound('unknown project or environment'), {
          ...base,
          decision: 'deny',
          metadata: { projectSlug, environmentSlug, key, reason: 'unknown_environment' },
        });
      }

      const permissions = await this.#permissionsFor(tx, ctx.principal, env.environmentId);
      if (!has(permissions, 'secret.archive')) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, reason: 'missing_secret_archive' },
        });
      }

      const updated = await tx.query<{ id: string }>(
        `UPDATE secrets SET archived_at = $4
          WHERE project_id = $1 AND environment_id = $2 AND key = $3
        RETURNING id`,
        [env.projectId, env.environmentId, key, archived ? new Date().toISOString() : null],
      );
      if (updated.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown secret'), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, reason: 'unknown_secret' },
        });
      }

      return {
        result: { key, archived },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId: env.projectId,
            environmentId: env.environmentId,
            secretId: updated.rows[0].id,
            metadata: { key },
          },
        ],
      };
    });
  }
}

/**
 * An error that must still produce an audit row.
 *
 * Thrown inside the transaction, caught by the route layer after the audit
 * append has been given a chance to run. See `runAudited` below.
 */
export class AuditedFailure extends Error {
  readonly cause: Error & { statusCode?: number };
  readonly entry: AuditEntry;

  constructor(cause: Error & { statusCode?: number }, entry: AuditEntry) {
    super(cause.message);
    this.cause = cause;
    this.entry = entry;
  }
}

async function loadCurrentVersion(
  tx: DatabaseClient,
  env: EnvironmentRow,
  key: string,
): Promise<{
  secretId: string;
  version: number;
  envelope: Envelope;
  archived: boolean;
} | null> {
  const result = await tx.query(
    `SELECT s.id AS secret_id, v.version, v.envelope_version, v.ciphertext, v.iv,
            v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version,
            s.archived_at
       FROM secrets s
       JOIN secret_versions v ON v.id = s.current_version_id
      WHERE s.project_id = $1 AND s.environment_id = $2 AND s.key = $3`,
    [env.projectId, env.environmentId, key],
  );
  if (result.rowCount === 0) return null;
  return {
    ...toEnvelopeRow(result.rows[0]),
    archived: result.rows[0].archived_at !== null,
  };
}

async function loadAllCurrentVersions(
  tx: DatabaseClient,
  env: EnvironmentRow,
): Promise<{ secretId: string; key: string; version: number; envelope: Envelope }[]> {
  const result = await tx.query(
    `SELECT s.id AS secret_id, s.key, v.version, v.envelope_version, v.ciphertext, v.iv,
            v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version
       FROM secrets s
       JOIN secret_versions v ON v.id = s.current_version_id
      WHERE s.project_id = $1 AND s.environment_id = $2
        AND s.archived_at IS NULL
      ORDER BY s.key`,
    [env.projectId, env.environmentId],
  );
  return result.rows.map((row) => ({ ...toEnvelopeRow(row), key: row.key }));
}

export function toEnvelopeRow(row: Record<string, unknown>): {
  secretId: string;
  version: number;
  envelope: Envelope;
} {
  return {
    secretId: row.secret_id as string,
    version: Number(row.version),
    envelope: {
      envelopeVersion: Number(row.envelope_version),
      ciphertext: row.ciphertext as Buffer,
      iv: row.iv as Buffer,
      authTag: row.auth_tag as Buffer,
      wrappedDek: row.wrapped_dek as Buffer,
      kekProvider: row.kek_provider as string,
      kekId: row.kek_id as string,
      kekVersion: row.kek_version as string,
    },
  };
}

async function upsertSecret(
  tx: DatabaseClient,
  env: EnvironmentRow,
  key: string,
): Promise<{ id: string; archived: boolean }> {
  // A write can append a version, but it cannot also restore an archived key.
  // The no-op conflict update locks the row so an archive racing this write is
  // resolved before the caller checks the returned state.
  // The conflict update takes a row lock until commit. Concurrent writes to
  // the same key therefore allocate versions only after the prior writer has
  // committed, including when both requests create the key at the same time.
  const secret = await tx.query<{ id: string; archived: boolean }>(
    `INSERT INTO secrets (project_id, environment_id, key)
     VALUES ($1, $2, $3)
     ON CONFLICT (project_id, environment_id, key) DO UPDATE
       SET key = EXCLUDED.key
     RETURNING id, archived_at IS NOT NULL AS archived`,
    [env.projectId, env.environmentId, key],
  );
  return secret.rows[0];
}
