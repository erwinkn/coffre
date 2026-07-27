import type { Pool, PoolClient } from 'pg';

import type { Principal } from '../../../../packages/core/src/identity/types.ts';
import { appendAudit, type AuditEntry } from '../../../../packages/db/src/audit.ts';
import { AccessDenied, AuditedFailure, NotFound, type RequestContext } from './secrets.ts';
import {
  has,
  PERMISSIONS,
  permissionsForProject,
  PROJECT_ONLY_PERMISSIONS,
  type Permission,
  type PermissionSet,
} from './permissions.ts';

export type AdminServiceDeps = {
  pool: Pool;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
};

export type ProjectSummary = {
  slug: string;
  name: string;
  archivedAt: string | null;
  /** What the caller may do at project scope. */
  permissions: Permission[];
  environments: { slug: string; name: string; archivedAt: string | null; secretCount: number }[];
};

export type GrantRow = {
  id: string;
  principalType: 'user' | 'service';
  principalId: string;
  role: string;
  roleName: string;
  permissions: Permission[];
  scope: 'project' | 'environment';
  environmentSlug: string | null;
  expiresAt: string | null;
};

export type RoleRow = {
  slug: string;
  name: string;
  description: string;
  permissions: Permission[];
  /** False when the role contains a project-only permission. */
  assignableToEnvironment: boolean;
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

  /** What the caller may do at project scope. Environment grants do not count. */
  #projectPermissions(
    tx: PoolClient,
    principal: Principal,
    projectId: string,
  ): Promise<PermissionSet> {
    return permissionsForProject(tx, principal, projectId, this.#deps.rootAdmins);
  }

  /** Resolve the project and assert the caller holds `permission` on it. */
  async #requireProjectPermission(
    tx: PoolClient,
    ctx: RequestContext,
    projectSlug: string,
    permission: Permission,
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
    const permissions = await this.#projectPermissions(tx, ctx.principal, projectId);

    if (!has(permissions, permission)) {
      throw new AuditedFailure(new AccessDenied(), {
        ...base,
        decision: 'deny',
        projectId,
        metadata: { ...metadata, reason: `missing_${permission}` },
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
      const { projectId } = await this.#requireProjectPermission(tx, ctx, projectSlug, 'project.manage', base, changes);

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
      const { projectId } = await this.#requireProjectPermission(tx, ctx, projectSlug, 'project.manage', base, {});

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
      const { projectId } = await this.#requireProjectPermission(tx, ctx, projectSlug, 'environment.manage', base, { slug });

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
      const { projectId } = await this.#requireProjectPermission(tx, ctx, projectSlug, 'environment.manage', base, changes);

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
      const { projectId } = await this.#requireProjectPermission(tx, ctx, projectSlug, 'environment.manage', base, {
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

      const permissions = await this.#projectPermissions(client, ctx.principal, project.rows[0].id);
      if (!has(permissions, 'grant.manage')) {
        throw new AccessDenied('requires grant.manage on this project');
      }

      const result = await client.query(
        `SELECT g.id, g.principal_type, g.principal_id, g.expires_at,
                r.slug AS role, r.name AS role_name,
                e.slug AS environment_slug,
                (SELECT array_agg(rp.permission ORDER BY rp.permission)
                   FROM role_permissions rp WHERE rp.role_id = r.id) AS permissions
           FROM grants g
           JOIN roles r ON r.id = g.role_id
           LEFT JOIN environments e ON e.id = g.environment_id
          WHERE g.project_id = $1 OR e.project_id = $1
          ORDER BY g.principal_id, e.slug NULLS FIRST`,
        [project.rows[0].id],
      );

      const granted: GrantRow[] = result.rows.map((row) => ({
        id: row.id,
        principalType: row.principal_type,
        principalId: row.principal_id,
        role: row.role,
        roleName: row.role_name,
        permissions: row.permissions ?? [],
        scope: row.environment_slug === null ? ('project' as const) : ('environment' as const),
        environmentSlug: row.environment_slug,
        expiresAt: row.expires_at,
      }));

      // Root admins hold everything from configuration, not from this table.
      // An access list that omitted the most privileged principals in the
      // system would be quietly misleading, so they are shown -- flagged as
      // coming from config, and not revocable here.
      const roots: GrantRow[] = this.#deps.rootAdmins.map((id) => ({
        id: `root:${id}`,
        principalType: 'user' as const,
        principalId: id,
        role: 'root-admin',
        roleName: 'Root admin (from configuration)',
        permissions: [...PERMISSIONS],
        scope: 'project' as const,
        environmentSlug: null,
        expiresAt: null,
      }));

      return [...roots, ...granted];
    } finally {
      client.release();
    }
  }

  /** Every role, with its permissions and where it may be assigned. */
  async listRoles(): Promise<RoleRow[]> {
    const client = await this.#deps.pool.connect();
    try {
      const result = await client.query(
        `SELECT r.slug, r.name, r.description,
                COALESCE(
                  (SELECT array_agg(rp.permission ORDER BY rp.permission)
                     FROM role_permissions rp WHERE rp.role_id = r.id),
                  ARRAY[]::text[]
                ) AS permissions
           FROM roles r
          ORDER BY r.slug`,
      );

      return result.rows.map((row) => ({
        slug: row.slug,
        name: row.name,
        description: row.description,
        permissions: row.permissions,
        assignableToEnvironment: !row.permissions.some((permission: Permission) =>
          PROJECT_ONLY_PERMISSIONS.includes(permission),
        ),
      }));
    } finally {
      client.release();
    }
  }

  /**
   * Grant a role, scoped to a project or to one environment within it.
   *
   * An environment-scoped grant is inherently project-specific: the environment
   * is resolved by (project_id, slug), and `environments.project_id` is NOT
   * NULL, so an environment belongs to exactly one project.
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
      role: string;
      environmentSlug?: string | null;
      expiresAt?: string | null;
    },
  ): Promise<{ id: string }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'grant.create');
      const { projectId } = await this.#requireProjectPermission(tx, ctx, projectSlug, 'grant.manage', base, {
        principalId: input.principalId,
      });

      const role = await tx.query<{ id: string; permissions: Permission[] }>(
        `SELECT r.id,
                COALESCE(
                  (SELECT array_agg(rp.permission) FROM role_permissions rp WHERE rp.role_id = r.id),
                  ARRAY[]::text[]
                ) AS permissions
           FROM roles r WHERE r.slug = $1`,
        [input.role],
      );
      if (role.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown role'), {
          ...base,
          decision: 'deny',
          projectId,
          metadata: { ...input, reason: 'unknown_role' },
        });
      }

      let environmentId: string | null = null;
      if (input.environmentSlug) {
        // Some permissions are meaningless on a single environment --
        // environment.manage on one environment would authorise creating its
        // own siblings. Reject rather than silently granting less than asked.
        const projectOnly = role.rows[0].permissions.filter((permission) =>
          PROJECT_ONLY_PERMISSIONS.includes(permission),
        );
        if (projectOnly.length > 0) {
          throw new AuditedFailure(
            Object.assign(
              new Error(
                `role "${input.role}" cannot be scoped to one environment: it includes ${projectOnly.join(', ')}`,
              ),
              { statusCode: 409 },
            ),
            {
              ...base,
              decision: 'deny',
              projectId,
              metadata: { ...input, reason: 'role_is_project_scoped' },
            },
          );
        }

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
        `INSERT INTO grants (principal_type, principal_id, role_id,
                             project_id, environment_id, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT DO NOTHING
         RETURNING id`,
        [
          input.principalType,
          input.principalId,
          role.rows[0].id,
          environmentId === null ? projectId : null,
          environmentId,
          input.expiresAt ?? null,
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
              role: input.role,
              scope: environmentId === null ? 'project' : 'environment',
              environmentSlug: input.environmentSlug ?? null,
              expiresAt: input.expiresAt ?? null,
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
      const { projectId } = await this.#requireProjectPermission(tx, ctx, projectSlug, 'grant.manage', base, { grantId });

      // Scope the delete to this project so a project admin cannot revoke a
      // grant belonging to a project they do not administer.
      const deleted = await tx.query<{
        principal_type: string;
        principal_id: string;
        role_id: string;
      }>(
        `DELETE FROM grants g
          USING (SELECT $1::uuid AS pid) scope
          WHERE g.id = $2
            AND (g.project_id = scope.pid
                 OR g.environment_id IN (SELECT id FROM environments WHERE project_id = scope.pid))
        RETURNING g.principal_type, g.principal_id, g.role_id`,
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
            },
          },
        ],
      };
    });
  }

  /**
   * Every principal and what they can reach, across the projects the caller
   * administers.
   *
   * The inverse of the per-project access table, and the query you actually
   * want when offboarding someone: "what does this person still hold?"
   */
  async listPrincipals(ctx: RequestContext): Promise<
    {
      principalType: 'user' | 'service';
      principalId: string;
      isRootAdmin: boolean;
      grants: { project: string; scope: string; role: string; expiresAt: string | null }[];
    }[]
  > {
    const client = await this.#deps.pool.connect();
    try {
      const isRoot = this.#isRootAdmin(ctx.principal);

      const result = await client.query(
        `SELECT g.principal_type, g.principal_id, g.expires_at,
                r.slug AS role,
                p.slug AS project,
                e.slug AS environment_slug
           FROM grants g
           JOIN roles r ON r.id = g.role_id
           LEFT JOIN environments e ON e.id = g.environment_id
           JOIN projects p ON p.id = COALESCE(g.project_id, e.project_id)
          WHERE $1::boolean OR p.id IN (
                  SELECT COALESCE(mg.project_id, me.project_id)
                    FROM grants mg
                    JOIN role_permissions mrp ON mrp.role_id = mg.role_id
                    LEFT JOIN environments me ON me.id = mg.environment_id
                   WHERE mg.principal_type = $2 AND mg.principal_id = $3
                     AND mrp.permission = 'grant.manage'
                     AND (mg.expires_at IS NULL OR mg.expires_at > now())
                )
          ORDER BY g.principal_id, p.slug`,
        [isRoot, ctx.principal.type, ctx.principal.id],
      );

      const byPrincipal = new Map<string, {
        principalType: 'user' | 'service';
        principalId: string;
        isRootAdmin: boolean;
        grants: { project: string; scope: string; role: string; expiresAt: string | null }[];
      }>();

      // Root admins first, so offboarding cannot miss them.
      if (isRoot) {
        for (const id of this.#deps.rootAdmins) {
          byPrincipal.set(`user:${id}`, {
            principalType: 'user',
            principalId: id,
            isRootAdmin: true,
            grants: [],
          });
        }
      }

      for (const row of result.rows) {
        const key = `${row.principal_type}:${row.principal_id}`;
        const entry =
          byPrincipal.get(key) ??
          {
            principalType: row.principal_type,
            principalId: row.principal_id,
            isRootAdmin: this.#deps.rootAdmins.includes(row.principal_id),
            grants: [],
          };
        entry.grants.push({
          project: row.project,
          scope: row.environment_slug === null ? 'whole project' : row.environment_slug,
          role: row.role,
          expiresAt: row.expires_at,
        });
        byPrincipal.set(key, entry);
      }

      return [...byPrincipal.values()];
    } finally {
      client.release();
    }
  }

  // --- listing --------------------------------------------------------------

  /** Projects the caller can see, including archived ones for project admins. */
  async listProjects(ctx: RequestContext): Promise<ProjectSummary[]> {
    const client = await this.#deps.pool.connect();
    try {
      const isRoot = this.#isRootAdmin(ctx.principal);

      // Visibility: any grant anywhere inside the project, including one on a
      // single environment. The permissions reported are the PROJECT-scope ones
      // though -- an environment grant makes a project visible without
      // conferring authority over its structure.
      const projects = await client.query(
        `SELECT DISTINCT p.id, p.slug, p.name, p.archived_at
           FROM projects p
           LEFT JOIN environments e ON e.project_id = p.id
           LEFT JOIN grants g
             ON (g.project_id = p.id OR g.environment_id = e.id)
            AND g.principal_type = $1 AND g.principal_id = $2
            AND (g.expires_at IS NULL OR g.expires_at > now())
          WHERE $3::boolean OR g.id IS NOT NULL
          ORDER BY p.slug`,
        [ctx.principal.type, ctx.principal.id, isRoot],
      );

      const summaries: ProjectSummary[] = [];
      for (const project of projects.rows) {
        const permissions = await this.#projectPermissions(client, ctx.principal, project.id);
        const environments = await client.query(
          `SELECT e.slug, e.name, e.archived_at,
                  (SELECT count(*) FROM secrets s
                    WHERE s.environment_id = e.id AND s.archived_at IS NULL)::int AS secret_count
             FROM environments e
            WHERE e.project_id = $1
            ORDER BY e.slug`,
          [project.id],
        );

        summaries.push({
          slug: project.slug,
          name: project.name,
          archivedAt: project.archived_at,
          permissions: [...permissions],
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
