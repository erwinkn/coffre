import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';

import { seal, open, type Envelope } from '../../../../packages/core/src/envelope.ts';
import type { SecretContext } from '../../../../packages/core/src/context.ts';
import type { KekRegistry } from '../../../../packages/core/src/kek/registry.ts';
import type { Principal } from '../../../../packages/core/src/identity/types.ts';
import { appendAudit, type AuditEntry } from '../../../../packages/db/src/audit.ts';

export type Capability = 'read' | 'write' | 'admin';

/** Ranked so that a stronger capability satisfies a weaker requirement. */
const CAPABILITY_RANK: Record<Capability, number> = { read: 1, write: 2, admin: 3 };

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
  principal: Principal;
  requestId: string;
  sourceIp: string | null;
};

export type SecretsServiceDeps = {
  pool: Pool;
  keks: KekRegistry;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
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
    fn: (tx: PoolClient) => Promise<{ result: T; entries: AuditEntry[] }>,
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
      return outcome.result;
    } catch (error) {
      // ROLLBACK on an already-finished transaction is a no-op warning, which
      // is why this is safe to call unconditionally here.
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  #isRootAdmin(principal: Principal): boolean {
    return this.#deps.rootAdmins.includes(principal.id);
  }

  /**
   * Resolve slugs to ids.
   *
   * Archived projects and environments resolve to null, so every caller treats
   * them exactly as it treats one that never existed: denied, and audited.
   */
  async #resolveEnvironment(
    tx: PoolClient,
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
  async #capabilityFor(
    tx: PoolClient,
    principal: Principal,
    environmentId: string,
  ): Promise<Capability | null> {
    if (this.#isRootAdmin(principal)) return 'admin';

    const result = await tx.query<{ capability: Capability }>(
      `SELECT g.capability
         FROM grants g
        WHERE g.principal_type = $1
          AND g.principal_id = $2
          AND (
                g.environment_id = $3
             OR g.project_id = (SELECT project_id FROM environments WHERE id = $3)
              )`,
      [principal.type, principal.id, environmentId],
    );
    if (result.rowCount === 0) return null;

    return result.rows
      .map((row) => row.capability)
      .reduce((best, next) => (CAPABILITY_RANK[next] > CAPABILITY_RANK[best] ? next : best));
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

      const capability = await this.#capabilityFor(tx, ctx.principal, env.environmentId);
      if (capability === null) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, reason: 'no_grant' },
        });
      }

      const secret = await loadCurrentVersion(tx, env, key);
      if (secret === null) {
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

      const capability = await this.#capabilityFor(tx, ctx.principal, env.environmentId);
      if (capability === null) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          bundleId,
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { reason: 'no_grant' },
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
        secrets[row.key] = value.toString('utf8');

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

      const capability = await this.#capabilityFor(tx, ctx.principal, env.environmentId);
      if (capability === null || CAPABILITY_RANK[capability] < CAPABILITY_RANK.write) {
        throw new AuditedFailure(new AccessDenied(), {
          ...base,
          decision: 'deny',
          projectId: env.projectId,
          environmentId: env.environmentId,
          metadata: { key, reason: 'insufficient_capability' },
        });
      }

      const secretId = await upsertSecret(tx, env, key, ctx.principal.id);

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

  /** List the environments a caller may see, with their capability. */
  async listAccessible(
    ctx: RequestContext,
  ): Promise<{ project: string; environment: string; capability: Capability }[]> {
    const client = await this.#deps.pool.connect();
    try {
      if (this.#isRootAdmin(ctx.principal)) {
        const all = await client.query<{ project: string; environment: string }>(
          `SELECT p.slug AS project, e.slug AS environment
             FROM environments e JOIN projects p ON p.id = e.project_id
            WHERE p.archived_at IS NULL AND e.archived_at IS NULL
            ORDER BY p.slug, e.slug`,
        );
        return all.rows.map((row) => ({ ...row, capability: 'admin' as const }));
      }

      // An environment is visible if the caller holds a grant on it directly or
      // on its project. Where both exist, the strongest capability wins.
      const result = await client.query<{
        project: string;
        environment: string;
        capability: Capability;
      }>(
        `SELECT p.slug AS project, e.slug AS environment, g.capability
           FROM grants g
           JOIN environments e
             ON e.id = g.environment_id OR e.project_id = g.project_id
           JOIN projects p ON p.id = e.project_id
          WHERE g.principal_type = $1 AND g.principal_id = $2
            AND p.archived_at IS NULL AND e.archived_at IS NULL
          ORDER BY p.slug, e.slug`,
        [ctx.principal.type, ctx.principal.id],
      );

      const strongest = new Map<string, { project: string; environment: string; capability: Capability }>();
      for (const row of result.rows) {
        const key = `${row.project}/${row.environment}`;
        const existing = strongest.get(key);
        if (!existing || CAPABILITY_RANK[row.capability] > CAPABILITY_RANK[existing.capability]) {
          strongest.set(key, row);
        }
      }
      return [...strongest.values()];
    } finally {
      client.release();
    }
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
  tx: PoolClient,
  env: EnvironmentRow,
  key: string,
): Promise<{ secretId: string; version: number; envelope: Envelope } | null> {
  const result = await tx.query(
    `SELECT s.id AS secret_id, v.version, v.envelope_version, v.ciphertext, v.iv,
            v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version
       FROM secrets s
       JOIN secret_versions v ON v.id = s.current_version_id
      WHERE s.project_id = $1 AND s.environment_id = $2 AND s.key = $3`,
    [env.projectId, env.environmentId, key],
  );
  if (result.rowCount === 0) return null;
  return toEnvelopeRow(result.rows[0]);
}

async function loadAllCurrentVersions(
  tx: PoolClient,
  env: EnvironmentRow,
): Promise<{ secretId: string; key: string; version: number; envelope: Envelope }[]> {
  const result = await tx.query(
    `SELECT s.id AS secret_id, s.key, v.version, v.envelope_version, v.ciphertext, v.iv,
            v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version
       FROM secrets s
       JOIN secret_versions v ON v.id = s.current_version_id
      WHERE s.project_id = $1 AND s.environment_id = $2
      ORDER BY s.key`,
    [env.projectId, env.environmentId],
  );
  return result.rows.map((row) => ({ ...toEnvelopeRow(row), key: row.key }));
}

function toEnvelopeRow(row: Record<string, unknown>): {
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
  tx: PoolClient,
  env: EnvironmentRow,
  key: string,
  createdBy: string,
): Promise<string> {
  const existing = await tx.query<{ id: string }>(
    'SELECT id FROM secrets WHERE project_id = $1 AND environment_id = $2 AND key = $3',
    [env.projectId, env.environmentId, key],
  );
  if (existing.rowCount === 1) return existing.rows[0].id;

  const created = await tx.query<{ id: string }>(
    `INSERT INTO secrets (project_id, environment_id, key) VALUES ($1, $2, $3) RETURNING id`,
    [env.projectId, env.environmentId, key],
  );
  void createdBy;
  return created.rows[0].id;
}
