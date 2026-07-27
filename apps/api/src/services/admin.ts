import type { Pool, PoolClient } from 'pg';

import type { Principal } from '../../../../packages/core/src/identity/types.ts';
import { appendAudit, type AuditEntry } from '../../../../packages/db/src/audit.ts';
import {
  AccessDenied,
  AuditedFailure,
  NotFound,
  type Capability,
  type RequestContext,
} from './secrets.ts';

const CAPABILITY_RANK: Record<Capability, number> = { read: 1, write: 2, admin: 3 };

export type AdminServiceDeps = {
  pool: Pool;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
};

export type ProjectSummary = {
  slug: string;
  name: string;
  archivedAt: string | null;
  capability: Capability;
  environments: { slug: string; name: string; archivedAt: string | null; secretCount: number }[];
};

export type GrantRow = {
  id: string;
  principalType: 'user' | 'service';
  principalId: string;
  capability: Capability;
  scope: 'project' | 'environment';
  environmentSlug: string | null;
};

/**
 * Structural management: projects, environments and grants.
 *
 * Separate from SecretsService because it never touches a secret value, and so
 * never needs the KEK registry. It shares the same rule though: every mutation
 * and every denial is written to the audit log in the same transaction as the
 * change itself.
 *
 * Note there is no delete anywhere in this file. The audit log holds
 * ON DELETE RESTRICT references to projects, environments and secrets, so
 * anything that has ever been used cannot be removed without destroying the
 * trail. Archiving is the honest operation.
 */
export class AdminService {
  readonly #deps: AdminServiceDeps;

  constructor(deps: AdminServiceDeps) {
    this.#deps = deps;
  }

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
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  #isRootAdmin(principal: Principal): boolean {
    return this.#deps.rootAdmins.includes(principal.id);
  }

  #base(ctx: RequestContext, action: string): Omit<AuditEntry, 'decision'> {
    return {
      actorType: ctx.principal.type,
      actorId: ctx.principal.id,
      action,
      requestId: ctx.requestId,
      sourceIp: ctx.sourceIp,
    };
  }

  /** The caller's capability on a project: a project grant, or root admin. */
  async #projectCapability(
    tx: PoolClient,
    principal: Principal,
    projectId: string,
  ): Promise<Capability | null> {
    if (this.#isRootAdmin(principal)) return 'admin';

    const result = await tx.query<{ capability: Capability }>(
      `SELECT capability FROM grants
        WHERE principal_type = $1 AND principal_id = $2 AND project_id = $3`,
      [principal.type, principal.id, projectId],
    );
    if (result.rowCount === 0) return null;

    return result.rows
      .map((row) => row.capability)
      .reduce((best, next) => (CAPABILITY_RANK[next] > CAPABILITY_RANK[best] ? next : best));
  }

  async #requireProjectAdmin(
    tx: PoolClient,
    ctx: RequestContext,
    projectSlug: string,
    base: Omit<AuditEntry, 'decision'>,
    metadata: Record<string, unknown>,
  ): Promise<{ projectId: string }> {
    const project = await tx.query<{ id: string }>(
      'SELECT id FROM projects WHERE slug = $1',
      [projectSlug],
    );
    if (project.rowCount === 0) {
      throw new AuditedFailure(new NotFound('unknown project'), {
        ...base,
        decision: 'deny',
        metadata: { ...metadata, projectSlug, reason: 'unknown_project' },
      });
    }

    const projectId = project.rows[0].id;
    const capability = await this.#projectCapability(tx, ctx.principal, projectId);

    if (capability !== 'admin') {
      throw new AuditedFailure(new AccessDenied(), {
        ...base,
        decision: 'deny',
        projectId,
        metadata: { ...metadata, reason: 'requires_project_admin' },
      });
    }
    return { projectId };
  }

  // --- projects -------------------------------------------------------------

  /**
   * Create a project.
   *
   * Root admins only: a project does not exist yet, so there is nothing to hold
   * a grant on. This is the one operation that cannot be delegated through the
   * grants table.
   */
  async createProject(
    ctx: RequestContext,
    slug: string,
    name: string,
  ): Promise<{ slug: string; name: string }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'project.create');

      if (!this.#isRootAdmin(ctx.principal)) {
        throw new AuditedFailure(new AccessDenied('only root admins may create projects'), {
          ...base,
          decision: 'deny',
          metadata: { slug, reason: 'requires_root_admin' },
        });
      }

      const existing = await tx.query('SELECT 1 FROM projects WHERE slug = $1', [slug]);
      if (existing.rowCount !== 0) {
        throw new AuditedFailure(
          Object.assign(new Error('a project with that slug already exists'), {
            statusCode: 409,
          }),
          { ...base, decision: 'deny', metadata: { slug, reason: 'slug_taken' } },
        );
      }

      const created = await tx.query<{ id: string }>(
        'INSERT INTO projects (slug, name) VALUES ($1, $2) RETURNING id',
        [slug, name],
      );

      return {
        result: { slug, name },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId: created.rows[0].id,
            metadata: { slug, name },
          },
        ],
      };
    });
  }

  /**
   * Rename a project.
   *
   * The slug is renameable because ciphertext AAD binds to immutable UUIDs, not
   * to names. Had we bound to `project/environment/key` as originally sketched,
   * this would silently orphan every secret in the project.
   */
  async updateProject(
    ctx: RequestContext,
    projectSlug: string,
    changes: { slug?: string; name?: string },
  ): Promise<{ slug: string; name: string }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'project.update');
      const { projectId } = await this.#requireProjectAdmin(tx, ctx, projectSlug, base, changes);

      const updated = await tx.query<{ slug: string; name: string }>(
        `UPDATE projects
            SET slug = COALESCE($2, slug), name = COALESCE($3, name)
          WHERE id = $1
        RETURNING slug, name`,
        [projectId, changes.slug ?? null, changes.name ?? null],
      );

      return {
        result: updated.rows[0],
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId,
            metadata: { from: projectSlug, ...changes },
          },
        ],
      };
    });
  }

  /** Archive or restore a project. Not a delete -- see the class comment. */
  async setProjectArchived(
    ctx: RequestContext,
    projectSlug: string,
    archived: boolean,
  ): Promise<{ slug: string; archived: boolean }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, archived ? 'project.archive' : 'project.restore');
      const { projectId } = await this.#requireProjectAdmin(tx, ctx, projectSlug, base, {});

      await tx.query('UPDATE projects SET archived_at = $2 WHERE id = $1', [
        projectId,
        archived ? new Date().toISOString() : null,
      ]);

      return {
        result: { slug: projectSlug, archived },
        entries: [{ ...base, decision: 'allow', projectId, metadata: { slug: projectSlug } }],
      };
    });
  }

  // --- environments ---------------------------------------------------------

  async createEnvironment(
    ctx: RequestContext,
    projectSlug: string,
    slug: string,
    name: string,
  ): Promise<{ slug: string; name: string }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'environment.create');
      const { projectId } = await this.#requireProjectAdmin(tx, ctx, projectSlug, base, { slug });

      const existing = await tx.query(
        'SELECT 1 FROM environments WHERE project_id = $1 AND slug = $2',
        [projectId, slug],
      );
      if (existing.rowCount !== 0) {
        throw new AuditedFailure(
          Object.assign(new Error('an environment with that slug already exists'), {
            statusCode: 409,
          }),
          { ...base, decision: 'deny', projectId, metadata: { slug, reason: 'slug_taken' } },
        );
      }

      const created = await tx.query<{ id: string }>(
        'INSERT INTO environments (project_id, slug, name) VALUES ($1, $2, $3) RETURNING id',
        [projectId, slug, name],
      );

      return {
        result: { slug, name },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId,
            environmentId: created.rows[0].id,
            metadata: { slug, name },
          },
        ],
      };
    });
  }

  async updateEnvironment(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    changes: { slug?: string; name?: string },
  ): Promise<{ slug: string; name: string }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'environment.update');
      const { projectId } = await this.#requireProjectAdmin(tx, ctx, projectSlug, base, changes);

      const updated = await tx.query<{ id: string; slug: string; name: string }>(
        `UPDATE environments
            SET slug = COALESCE($3, slug), name = COALESCE($4, name)
          WHERE project_id = $1 AND slug = $2
        RETURNING id, slug, name`,
        [projectId, environmentSlug, changes.slug ?? null, changes.name ?? null],
      );
      if (updated.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown environment'), {
          ...base,
          decision: 'deny',
          projectId,
          metadata: { environmentSlug, reason: 'unknown_environment' },
        });
      }

      return {
        result: { slug: updated.rows[0].slug, name: updated.rows[0].name },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId,
            environmentId: updated.rows[0].id,
            metadata: { from: environmentSlug, ...changes },
          },
        ],
      };
    });
  }

  async setEnvironmentArchived(
    ctx: RequestContext,
    projectSlug: string,
    environmentSlug: string,
    archived: boolean,
  ): Promise<{ slug: string; archived: boolean }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, archived ? 'environment.archive' : 'environment.restore');
      const { projectId } = await this.#requireProjectAdmin(tx, ctx, projectSlug, base, {
        environmentSlug,
      });

      const updated = await tx.query<{ id: string }>(
        `UPDATE environments SET archived_at = $3
          WHERE project_id = $1 AND slug = $2 RETURNING id`,
        [projectId, environmentSlug, archived ? new Date().toISOString() : null],
      );
      if (updated.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown environment'), {
          ...base,
          decision: 'deny',
          projectId,
          metadata: { environmentSlug, reason: 'unknown_environment' },
        });
      }

      return {
        result: { slug: environmentSlug, archived },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId,
            environmentId: updated.rows[0].id,
            metadata: { environmentSlug },
          },
        ],
      };
    });
  }

  // --- grants ---------------------------------------------------------------

  async listGrants(ctx: RequestContext, projectSlug: string): Promise<GrantRow[]> {
    const client = await this.#deps.pool.connect();
    try {
      const project = await client.query<{ id: string }>(
        'SELECT id FROM projects WHERE slug = $1',
        [projectSlug],
      );
      if (project.rowCount === 0) throw new NotFound('unknown project');

      const capability = await this.#projectCapability(client, ctx.principal, project.rows[0].id);
      if (capability !== 'admin') throw new AccessDenied('requires project admin');

      const result = await client.query(
        `SELECT g.id, g.principal_type, g.principal_id, g.capability,
                e.slug AS environment_slug
           FROM grants g
           LEFT JOIN environments e ON e.id = g.environment_id
          WHERE g.project_id = $1 OR e.project_id = $1
          ORDER BY g.principal_id, e.slug NULLS FIRST`,
        [project.rows[0].id],
      );

      return result.rows.map((row) => ({
        id: row.id,
        principalType: row.principal_type,
        principalId: row.principal_id,
        capability: row.capability,
        scope: row.environment_slug === null ? ('project' as const) : ('environment' as const),
        environmentSlug: row.environment_slug,
      }));
    } finally {
      client.release();
    }
  }

  /**
   * Grant a capability, scoped to a project or to one environment within it.
   *
   * `principalType` matters: a Cloudflare Access service token has no email
   * claim, so machine callers are matched on their common_name instead. A
   * grant written against the wrong type silently never matches.
   */
  async createGrant(
    ctx: RequestContext,
    projectSlug: string,
    input: {
      principalType: 'user' | 'service';
      principalId: string;
      capability: Capability;
      environmentSlug?: string | null;
    },
  ): Promise<{ id: string }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'grant.create');
      const { projectId } = await this.#requireProjectAdmin(tx, ctx, projectSlug, base, {
        principalId: input.principalId,
      });

      let environmentId: string | null = null;
      if (input.environmentSlug) {
        const environment = await tx.query<{ id: string }>(
          'SELECT id FROM environments WHERE project_id = $1 AND slug = $2',
          [projectId, input.environmentSlug],
        );
        if (environment.rowCount === 0) {
          throw new AuditedFailure(new NotFound('unknown environment'), {
            ...base,
            decision: 'deny',
            projectId,
            metadata: { ...input, reason: 'unknown_environment' },
          });
        }
        environmentId = environment.rows[0].id;
      }

      const created = await tx.query<{ id: string }>(
        `INSERT INTO grants (principal_type, principal_id, capability,
                             project_id, environment_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT DO NOTHING
         RETURNING id`,
        [
          input.principalType,
          input.principalId,
          input.capability,
          environmentId === null ? projectId : null,
          environmentId,
          ctx.principal.id,
        ],
      );

      if (created.rowCount === 0) {
        throw new AuditedFailure(
          Object.assign(new Error('that grant already exists'), { statusCode: 409 }),
          { ...base, decision: 'deny', projectId, metadata: { ...input, reason: 'duplicate' } },
        );
      }

      return {
        result: { id: created.rows[0].id },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId,
            environmentId,
            metadata: {
              principalType: input.principalType,
              principalId: input.principalId,
              capability: input.capability,
              scope: environmentId === null ? 'project' : 'environment',
              environmentSlug: input.environmentSlug ?? null,
            },
          },
        ],
      };
    });
  }

  async revokeGrant(
    ctx: RequestContext,
    projectSlug: string,
    grantId: string,
  ): Promise<{ revoked: true }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'grant.revoke');
      const { projectId } = await this.#requireProjectAdmin(tx, ctx, projectSlug, base, { grantId });

      // Scope the delete to this project so a project admin cannot revoke a
      // grant belonging to a project they do not administer.
      const deleted = await tx.query<{
        principal_type: string;
        principal_id: string;
        capability: string;
      }>(
        `DELETE FROM grants g
          USING (SELECT $1::uuid AS pid) scope
          WHERE g.id = $2
            AND (g.project_id = scope.pid
                 OR g.environment_id IN (SELECT id FROM environments WHERE project_id = scope.pid))
        RETURNING g.principal_type, g.principal_id, g.capability`,
        [projectId, grantId],
      );

      if (deleted.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown grant'), {
          ...base,
          decision: 'deny',
          projectId,
          metadata: { grantId, reason: 'unknown_grant' },
        });
      }

      return {
        result: { revoked: true as const },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId,
            metadata: {
              grantId,
              principalId: deleted.rows[0].principal_id,
              capability: deleted.rows[0].capability,
            },
          },
        ],
      };
    });
  }

  // --- listing --------------------------------------------------------------

  /** Projects the caller can see, including archived ones for project admins. */
  async listProjects(ctx: RequestContext): Promise<ProjectSummary[]> {
    const client = await this.#deps.pool.connect();
    try {
      const isRoot = this.#isRootAdmin(ctx.principal);

      const projects = await client.query(
        `SELECT p.id, p.slug, p.name, p.archived_at,
                COALESCE(MAX(CASE
                  WHEN $3::boolean THEN 'admin'
                  ELSE g.capability
                END), NULL) AS capability
           FROM projects p
           LEFT JOIN environments e ON e.project_id = p.id
           LEFT JOIN grants g
             ON (g.project_id = p.id OR g.environment_id = e.id)
            AND g.principal_type = $1 AND g.principal_id = $2
          WHERE $3::boolean OR g.id IS NOT NULL
          GROUP BY p.id, p.slug, p.name, p.archived_at
          ORDER BY p.slug`,
        [ctx.principal.type, ctx.principal.id, isRoot],
      );

      const summaries: ProjectSummary[] = [];
      for (const project of projects.rows) {
        const environments = await client.query(
          `SELECT e.slug, e.name, e.archived_at,
                  (SELECT count(*) FROM secrets s WHERE s.environment_id = e.id)::int AS secret_count
             FROM environments e
            WHERE e.project_id = $1
            ORDER BY e.slug`,
          [project.id],
        );

        summaries.push({
          slug: project.slug,
          name: project.name,
          archivedAt: project.archived_at,
          capability: (project.capability ?? 'read') as Capability,
          environments: environments.rows.map((row) => ({
            slug: row.slug,
            name: row.name,
            archivedAt: row.archived_at,
            secretCount: row.secret_count,
          })),
        });
      }
      return summaries;
    } finally {
      client.release();
    }
  }
}
