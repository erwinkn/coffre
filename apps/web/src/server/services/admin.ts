import type { Database, DatabaseClient } from '../database.ts';

import { appendAudit, type AuditEntry } from '../../../../../packages/db/src/audit.ts';
import { AccessDenied, AuditedFailure, NotFound, type RequestContext } from './secrets.ts';
import {
  has,
  isRootAdmin as isConfiguredRootAdmin,
  permissionsForProject,
  PROJECT_ONLY_PERMISSIONS,
  type Permission,
  type PermissionSet,
  type PrincipalRef,
} from './permissions.ts';

export type AdminServiceDeps = {
  pool: Database;
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

export type InstancePrincipalRow = {
  principalType: 'user' | 'service';
  principalId: string;
  instanceRole: 'user' | 'owner' | 'root-admin';
  isRootAdmin: boolean;
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

  #isRootAdmin(principal: PrincipalRef): boolean {
    return isConfiguredRootAdmin(principal, this.#deps.rootAdmins);
  }

  async #lockPrincipals(
    tx: DatabaseClient,
    principals: readonly PrincipalRef[],
  ): Promise<void> {
    const keys = [
      ...new Set(
        principals.map(
          (principal) =>
            `coffre:principal:${principal.type}:${principal.id}`,
        ),
      ),
    ].sort();
    for (const key of keys) {
      await tx.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        key,
      ]);
    }
  }

  async #lockPrincipal(
    tx: DatabaseClient,
    principalType: 'user' | 'service',
    principalId: string,
  ): Promise<void> {
    await this.#lockPrincipals(tx, [{ type: principalType, id: principalId }]);
  }

  async #isInstanceOwner(tx: DatabaseClient, principal: PrincipalRef): Promise<boolean> {
    if (this.#isRootAdmin(principal)) return true;
    if (principal.type !== 'user') return false;

    const result = await tx.query(
      `SELECT 1 FROM principals
        WHERE principal_type = 'user'
          AND principal_id = $1
          AND active
          AND instance_role = 'owner'`,
      [principal.id],
    );
    return result.rowCount !== 0;
  }

  async #requireInstanceOwner(
    tx: DatabaseClient,
    ctx: RequestContext,
    base: Omit<AuditEntry, 'decision'>,
    metadata: Record<string, unknown> = {},
  ): Promise<void> {
    if (await this.#isInstanceOwner(tx, ctx.principal)) return;
    throw new AuditedFailure(new AccessDenied('only owners may manage users'), {
      ...base,
      decision: 'deny',
      metadata: { ...metadata, reason: 'requires_instance_owner' },
    });
  }

  async instanceRole(
    principal: PrincipalRef,
  ): Promise<'user' | 'owner' | 'root-admin'> {
    if (this.#isRootAdmin(principal)) return 'root-admin';
    if (principal.type !== 'user') return 'user';

    const result = await this.#deps.pool.query<{ instance_role: 'user' | 'owner' }>(
      `SELECT instance_role
         FROM principals
        WHERE principal_type = 'user'
          AND principal_id = $1
          AND active`,
      [principal.id],
    );
    return result.rows[0]?.instance_role ?? 'user';
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
    tx: DatabaseClient,
    principal: PrincipalRef,
    projectId: string,
  ): Promise<PermissionSet> {
    return permissionsForProject(tx, principal, projectId, this.#deps.rootAdmins);
  }

  /** Resolve the project and assert the caller holds `permission` on it. */
  async #requireProjectPermission(
    tx: DatabaseClient,
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

      // Creating a project also establishes its first real project-level
      // owner. Root admin is deployment-wide bootstrap authority; it must not
      // masquerade as a project grant in the access table.
      await this.#lockPrincipal(tx, ctx.principal.type, ctx.principal.id);
      await tx.query(
        `INSERT INTO principals (
           principal_type, principal_id, instance_role, created_by, active
         )
         VALUES ($1, $2, 'user', $2, true)
         ON CONFLICT (principal_type, principal_id) DO UPDATE
           SET active = true`,
        [ctx.principal.type, ctx.principal.id],
      );
      await tx.query(
        `INSERT INTO grants (
           principal_type, principal_id, role_id, project_id, created_by
         )
         SELECT $1, $2, r.id, $3, $2
           FROM roles r
          WHERE r.slug = 'owner'`,
        [ctx.principal.type, ctx.principal.id, created.rows[0].id],
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

      return result.rows.map((row) => ({
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

      await this.#lockPrincipal(tx, input.principalType, input.principalId);
      await tx.query(
        `INSERT INTO principals (
           principal_type, principal_id, instance_role, created_by, active
         )
         VALUES ($1, $2, 'user', $3, true)
         ON CONFLICT DO NOTHING`,
        [input.principalType, input.principalId, ctx.principal.id],
      );
      const registered = await tx.query<{ active: boolean }>(
        `SELECT active
           FROM principals
          WHERE principal_type = $1 AND principal_id = $2`,
        [input.principalType, input.principalId],
      );
      if (!registered.rows[0]?.active) {
        throw new AuditedFailure(
          Object.assign(
            new Error(
              'that principal was removed; add it to the directory before granting access',
            ),
            { statusCode: 409 },
          ),
          {
            ...base,
            decision: 'deny',
            projectId,
            metadata: { ...input, reason: 'principal_inactive' },
          },
        );
      }

      const grantValues = [
        input.principalType,
        input.principalId,
        role.rows[0].id,
        environmentId === null ? projectId : null,
        environmentId,
        input.expiresAt ?? null,
        ctx.principal.id,
      ];
      const restored = await tx.query<{ id: string }>(
        `UPDATE grants
            SET expires_at = $6,
                created_by = $7
          WHERE principal_type = $1
            AND principal_id = $2
            AND role_id = $3
            AND project_id IS NOT DISTINCT FROM $4
            AND environment_id IS NOT DISTINCT FROM $5
            AND expires_at <= now()
        RETURNING id`,
        grantValues,
      );
      const created =
        restored.rowCount !== 0
          ? restored
          : await tx.query<{ id: string }>(
              `INSERT INTO grants (
                 principal_type, principal_id, role_id,
                 project_id, environment_id, expires_at, created_by
               )
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT DO NOTHING
               RETURNING id`,
              grantValues,
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

      // Scope the revocation to this project so a project admin cannot revoke a
      // grant belonging to a project they do not administer.
      const revoked = await tx.query<{
        principal_type: string;
        principal_id: string;
        role_id: string;
      }>(
        `UPDATE grants g
            SET expires_at = now()
           FROM (SELECT $1::uuid AS pid) scope
          WHERE g.id = $2
            AND (g.expires_at IS NULL OR g.expires_at > now())
            AND (g.project_id = scope.pid
                 OR g.environment_id IN (
                      SELECT id FROM environments WHERE project_id = scope.pid
                    ))
        RETURNING g.principal_type, g.principal_id, g.role_id`,
        [projectId, grantId],
      );

      if (revoked.rowCount === 0) {
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
              principalId: revoked.rows[0].principal_id,
            },
          },
        ],
      };
    });
  }

  async updateGrant(
    ctx: RequestContext,
    projectSlug: string,
    grantId: string,
    roleSlug: string,
  ): Promise<{ updated: true }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'grant.update');
      const { projectId } = await this.#requireProjectPermission(
        tx,
        ctx,
        projectSlug,
        'grant.manage',
        base,
        { grantId, role: roleSlug },
      );

      const grant = await tx.query<{
        id: string;
        principal_type: string;
        principal_id: string;
        role_id: string;
        environment_id: string | null;
      }>(
        `SELECT g.id, g.principal_type, g.principal_id, g.role_id, g.environment_id
           FROM grants g
           LEFT JOIN environments e ON e.id = g.environment_id
          WHERE g.id = $1 AND (g.project_id = $2 OR e.project_id = $2)`,
        [grantId, projectId],
      );
      if (grant.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown grant'), {
          ...base,
          decision: 'deny',
          projectId,
          metadata: { grantId, role: roleSlug, reason: 'unknown_grant' },
        });
      }

      const role = await tx.query<{ id: string; permissions: Permission[] }>(
        `SELECT r.id,
                COALESCE(
                  (SELECT array_agg(rp.permission)
                     FROM role_permissions rp WHERE rp.role_id = r.id),
                  ARRAY[]::text[]
                ) AS permissions
           FROM roles r WHERE r.slug = $1`,
        [roleSlug],
      );
      if (role.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown role'), {
          ...base,
          decision: 'deny',
          projectId,
          metadata: { grantId, role: roleSlug, reason: 'unknown_role' },
        });
      }

      if (
        grant.rows[0].environment_id !== null &&
        role.rows[0].permissions.some((permission) =>
          PROJECT_ONLY_PERMISSIONS.includes(permission),
        )
      ) {
        throw new AuditedFailure(
          Object.assign(
            new Error(`role "${roleSlug}" cannot be scoped to one environment`),
            { statusCode: 409 },
          ),
          {
            ...base,
            decision: 'deny',
            projectId,
            environmentId: grant.rows[0].environment_id,
            metadata: { grantId, role: roleSlug, reason: 'role_is_project_scoped' },
          },
        );
      }

      const duplicate = await tx.query(
        `SELECT 1 FROM grants
          WHERE id <> $1
            AND principal_type = $2 AND principal_id = $3
            AND role_id = $4
            AND project_id IS NOT DISTINCT FROM $5
            AND environment_id IS NOT DISTINCT FROM $6`,
        [
          grantId,
          grant.rows[0].principal_type,
          grant.rows[0].principal_id,
          role.rows[0].id,
          grant.rows[0].environment_id === null ? projectId : null,
          grant.rows[0].environment_id,
        ],
      );
      if (duplicate.rowCount !== 0) {
        throw new AuditedFailure(
          Object.assign(new Error('that grant already exists'), { statusCode: 409 }),
          {
            ...base,
            decision: 'deny',
            projectId,
            metadata: { grantId, role: roleSlug, reason: 'duplicate' },
          },
        );
      }

      await tx.query('UPDATE grants SET role_id = $1 WHERE id = $2', [
        role.rows[0].id,
        grantId,
      ]);

      return {
        result: { updated: true as const },
        entries: [
          {
            ...base,
            decision: 'allow',
            projectId,
            environmentId: grant.rows[0].environment_id,
            metadata: {
              grantId,
              principalType: grant.rows[0].principal_type,
              principalId: grant.rows[0].principal_id,
              role: roleSlug,
            },
          },
        ],
      };
    });
  }

  /**
   * Revoke every grant for one principal that the caller is allowed to manage.
   * Root admins remove the principal everywhere; delegated access managers
   * remove it from the projects visible in their access overview.
   *
   * This is intentionally separate from deleting an identity from the
   * instance directory. Project access managers may revoke grants, but only
   * instance owners may remove identities from Coffre.
   */
  async removePrincipal(
    ctx: RequestContext,
    principalType: 'user' | 'service',
    principalId: string,
  ): Promise<{ revoked: number }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'principal.remove');
      const isRoot = this.#isRootAdmin(ctx.principal);

      if (principalType === 'user' && this.#deps.rootAdmins.includes(principalId)) {
        throw new AuditedFailure(
          Object.assign(
            new Error('root admins are managed by COFFRE_ROOT_ADMINS'),
            { statusCode: 409 },
          ),
          {
            ...base,
            decision: 'deny',
            metadata: { principalType, principalId, reason: 'configured_root_admin' },
          },
        );
      }

      const revoked = await tx.query<{ id: string }>(
        `UPDATE grants g
            SET expires_at = now()
          WHERE g.principal_type = $1 AND g.principal_id = $2
            AND (g.expires_at IS NULL OR g.expires_at > now())
            AND (
              $3::boolean
              OR COALESCE(
                   g.project_id,
                   (SELECT e.project_id FROM environments e WHERE e.id = g.environment_id)
                 ) IN (
                   SELECT COALESCE(mg.project_id, me.project_id)
                     FROM grants mg
                     JOIN role_permissions mrp ON mrp.role_id = mg.role_id
                     LEFT JOIN environments me ON me.id = mg.environment_id
                    WHERE mg.principal_type = $4 AND mg.principal_id = $5
                      AND mrp.permission = 'grant.manage'
                      AND (mg.expires_at IS NULL OR mg.expires_at > now())
                 )
            )
        RETURNING g.id`,
        [
          principalType,
          principalId,
          isRoot,
          ctx.principal.type,
          ctx.principal.id,
        ],
      );
      if (revoked.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown principal'), {
          ...base,
          decision: 'deny',
          metadata: { principalType, principalId, reason: 'no_manageable_grants' },
        });
      }

      return {
        result: { revoked: revoked.rowCount ?? 0 },
        entries: [
          {
            ...base,
            decision: 'allow',
            metadata: { principalType, principalId, revoked: revoked.rowCount ?? 0 },
          },
        ],
      };
    });
  }

  /**
   * Every principal and what they can reach, across the projects the caller
   * administers.
   *
   * This remains the grant-aware operational/offboarding view. The instance
   * directory is exposed separately because a user may exist without grants.
   */
  async listPrincipals(ctx: RequestContext): Promise<
    {
      principalType: 'user' | 'service';
      principalId: string;
      isRootAdmin: boolean;
      grants: {
        id: string;
        project: string;
        scope: string;
        environmentSlug: string | null;
        role: string;
        expiresAt: string | null;
      }[];
    }[]
  > {
    const client = await this.#deps.pool.connect();
    try {
      const isRoot = this.#isRootAdmin(ctx.principal);

      const result = await client.query(
        `SELECT g.id, g.principal_type, g.principal_id, g.expires_at,
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

      const byPrincipal = new Map<
        string,
        {
          principalType: 'user' | 'service';
          principalId: string;
          isRootAdmin: boolean;
          grants: {
            id: string;
            project: string;
            scope: string;
            environmentSlug: string | null;
            role: string;
            expiresAt: string | null;
          }[];
        }
      >();

      // Root admins first, so offboarding cannot miss them.
      if (isRoot) {
        for (const id of this.#deps.rootAdmins) {
          byPrincipal.set(`user:${id}`, {
            principalType: 'user',
            principalId: id,
            isRootAdmin: true,
            grants: [] as {
              id: string;
              project: string;
              scope: string;
              environmentSlug: string | null;
              role: string;
              expiresAt: string | null;
            }[],
          });
        }
      }

      for (const row of result.rows) {
        const key = `${row.principal_type}:${row.principal_id}`;
        const entry: NonNullable<ReturnType<typeof byPrincipal.get>> =
          byPrincipal.get(key) ??
          {
            principalType: row.principal_type,
            principalId: row.principal_id,
            isRootAdmin:
              row.principal_type === 'user' &&
              this.#deps.rootAdmins.includes(row.principal_id),
            grants: [],
          };
        entry.grants.push({
          id: row.id,
          project: row.project,
          scope: row.environment_slug === null ? 'whole project' : row.environment_slug,
          environmentSlug: row.environment_slug,
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

  async addDirectoryPrincipal(
    ctx: RequestContext,
    input: {
      principalType: 'user' | 'service';
      principalId: string;
      instanceRole: 'user' | 'owner';
    },
  ): Promise<{ created: true }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'directory.create');
      await this.#lockPrincipals(tx, [
        ctx.principal,
        { type: input.principalType, id: input.principalId },
      ]);
      await this.#requireInstanceOwner(tx, ctx, base, input);

      if (input.principalType === 'service' && input.instanceRole !== 'user') {
        throw new AuditedFailure(
          Object.assign(new Error('service accounts cannot be instance owners'), {
            statusCode: 409,
          }),
          {
            ...base,
            decision: 'deny',
            metadata: { ...input, reason: 'service_cannot_be_owner' },
          },
        );
      }
      if (
        input.principalType === 'user' &&
        this.#deps.rootAdmins.includes(input.principalId)
      ) {
        throw new AuditedFailure(
          Object.assign(new Error('that root admin is already configured'), {
            statusCode: 409,
          }),
          {
            ...base,
            decision: 'deny',
            metadata: { ...input, reason: 'configured_root_admin' },
          },
        );
      }

      const created = await tx.query(
        `INSERT INTO principals (
           principal_type, principal_id, instance_role, created_by, active
         )
         VALUES ($1, $2, $3, $4, true)
         ON CONFLICT (principal_type, principal_id) DO UPDATE
           SET instance_role = EXCLUDED.instance_role,
               active = true,
               created_at = now(),
               created_by = EXCLUDED.created_by
         WHERE NOT principals.active
         RETURNING 1`,
        [
          input.principalType,
          input.principalId,
          input.instanceRole,
          ctx.principal.id,
        ],
      );
      if (created.rowCount === 0) {
        throw new AuditedFailure(
          Object.assign(new Error('that principal already exists'), { statusCode: 409 }),
          {
            ...base,
            decision: 'deny',
            metadata: { ...input, reason: 'duplicate' },
          },
        );
      }

      return {
        result: { created: true as const },
        entries: [{ ...base, decision: 'allow', metadata: input }],
      };
    });
  }

  async updateDirectoryPrincipalRole(
    ctx: RequestContext,
    principalId: string,
    instanceRole: 'user' | 'owner',
  ): Promise<{ updated: true }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'directory.update');
      await this.#lockPrincipals(tx, [
        ctx.principal,
        { type: 'user', id: principalId },
      ]);
      await this.#requireInstanceOwner(tx, ctx, base, { principalId, instanceRole });

      if (this.#deps.rootAdmins.includes(principalId)) {
        throw new AuditedFailure(
          Object.assign(new Error('root admins are managed by COFFRE_ROOT_ADMINS'), {
            statusCode: 409,
          }),
          {
            ...base,
            decision: 'deny',
            metadata: { principalId, instanceRole, reason: 'configured_root_admin' },
          },
        );
      }

      const updated = await tx.query(
        `UPDATE principals
            SET instance_role = $2
          WHERE principal_type = 'user'
            AND principal_id = $1
            AND active`,
        [principalId, instanceRole],
      );
      if (updated.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown user'), {
          ...base,
          decision: 'deny',
          metadata: { principalId, instanceRole, reason: 'unknown_principal' },
        });
      }

      return {
        result: { updated: true as const },
        entries: [
          {
            ...base,
            decision: 'allow',
            metadata: { principalType: 'user', principalId, instanceRole },
          },
        ],
      };
    });
  }

  async removeDirectoryPrincipal(
    ctx: RequestContext,
    principalType: 'user' | 'service',
    principalId: string,
  ): Promise<{ revoked: number }> {
    return this.#audited(async (tx) => {
      const base = this.#base(ctx, 'directory.remove');
      await this.#lockPrincipals(tx, [
        ctx.principal,
        { type: principalType, id: principalId },
      ]);
      await this.#requireInstanceOwner(tx, ctx, base, {
        principalType,
        principalId,
      });

      if (principalType === 'user' && this.#deps.rootAdmins.includes(principalId)) {
        throw new AuditedFailure(
          Object.assign(
            new Error('root admins are managed by COFFRE_ROOT_ADMINS'),
            { statusCode: 409 },
          ),
          {
            ...base,
            decision: 'deny',
            metadata: { principalType, principalId, reason: 'configured_root_admin' },
          },
        );
      }

      const principal = await tx.query(
        `SELECT 1 FROM principals
          WHERE principal_type = $1
            AND principal_id = $2
            AND active`,
        [principalType, principalId],
      );
      if (principal.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown principal'), {
          ...base,
          decision: 'deny',
          metadata: { principalType, principalId, reason: 'unknown_principal' },
        });
      }

      const affectedProjects = await tx.query<{
        project_id: string;
        revoked: number;
      }>(
        `WITH revoked_grants AS (
           UPDATE grants
              SET expires_at = now()
            WHERE principal_type = $1
              AND principal_id = $2
              AND (expires_at IS NULL OR expires_at > now())
           RETURNING project_id, environment_id
         )
         SELECT COALESCE(d.project_id, e.project_id) AS project_id,
                count(*)::int AS revoked
           FROM revoked_grants d
           LEFT JOIN environments e ON e.id = d.environment_id
          GROUP BY COALESCE(d.project_id, e.project_id)
          ORDER BY COALESCE(d.project_id, e.project_id)`,
        [principalType, principalId],
      );
      await tx.query(
        `UPDATE principals
            SET active = false
          WHERE principal_type = $1 AND principal_id = $2`,
        [principalType, principalId],
      );

      const revoked = affectedProjects.rows.reduce(
        (total, project) => total + project.revoked,
        0,
      );

      return {
        result: { revoked },
        entries: [
          {
            ...base,
            decision: 'allow',
            metadata: { principalType, principalId, revoked },
          },
          ...affectedProjects.rows.map((project) => ({
            ...base,
            decision: 'allow' as const,
            projectId: project.project_id,
            metadata: {
              principalType,
              principalId,
              revoked: project.revoked,
            },
          })),
        ],
      };
    });
  }

  /** Every identity registered with this Coffre instance. */
  async listDirectory(ctx: RequestContext): Promise<InstancePrincipalRow[]> {
    const client = await this.#deps.pool.connect();
    try {
      if (!(await this.#isInstanceOwner(client, ctx.principal))) {
        throw new AccessDenied('only owners may manage users');
      }

      const result = await client.query<{
        principal_type: 'user' | 'service';
        principal_id: string;
        instance_role: 'user' | 'owner';
      }>(
        `SELECT principal_type, principal_id, instance_role
           FROM principals
          WHERE active
          ORDER BY principal_type DESC, principal_id`,
      );

      const byPrincipal = new Map<string, InstancePrincipalRow>();
      for (const row of result.rows) {
        byPrincipal.set(`${row.principal_type}:${row.principal_id}`, {
          principalType: row.principal_type,
          principalId: row.principal_id,
          instanceRole: row.instance_role,
          isRootAdmin: false,
        });
      }

      for (const id of this.#deps.rootAdmins) {
        byPrincipal.set(`user:${id}`, {
          principalType: 'user',
          principalId: id,
          instanceRole: 'root-admin',
          isRootAdmin: true,
        });
      }

      return [...byPrincipal.values()].sort(
        (a, b) =>
          a.principalType.localeCompare(b.principalType) ||
          a.principalId.localeCompare(b.principalId),
      );
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
