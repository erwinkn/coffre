import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import pg from 'pg';
import { z } from 'zod';

import { AccessIdentityVerifier } from '../../../packages/core/src/identity/verifier.ts';
import type { IdentityVerifier } from '../../../packages/core/src/identity/types.ts';
import type { AuthMode } from '../../../packages/core/src/identity/auth-mode.ts';
import type { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import { verifyChain, GENESIS_HASH } from '../../../packages/core/src/audit/chain.ts';
import { readAuditRows, OCCURRED_AT_SQL } from '../../../packages/db/src/audit.ts';
import { registerAuth } from './auth.ts';
import { parseDotenv } from './services/dotenv.ts';
import { heartbeatAgeSeconds } from './heartbeat.ts';
import {
  SecretsService,
  AccessDenied,
  NotFound,
  type RequestContext,
} from './services/secrets.ts';
import { AdminService } from './services/admin.ts';
import { isRootAdmin } from './services/permissions.ts';

/**
 * Rows per batch when verifying the chain.
 *
 * Bounded so that verifying a long log does not materialise it in one array.
 * The whole log is still covered: batches continue until the reader runs dry.
 */
const VERIFY_BATCH = 5_000;

const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
const secretKey = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);

export type BuildOptions = {
  pool: pg.Pool;
  verifier: IdentityVerifier;
  authMode: AuthMode;
  keks: KekRegistry;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
  logger?: boolean;
};

export function buildApp(options: BuildOptions): FastifyInstance {
  const app = Fastify({
    logger: options.logger ?? false,
    genReqId: () => randomUUID(),
  });

  const secrets = new SecretsService({
    pool: options.pool,
    keks: options.keks,
    auditChainKey: options.auditChainKey,
    rootAdmins: options.rootAdmins,
  });

  const admin = new AdminService({
    pool: options.pool,
    auditChainKey: options.auditChainKey,
    rootAdmins: options.rootAdmins,
  });

  registerAuth(app, {
    verifier: options.verifier,
    authMode: options.authMode,
    publicPaths: ['/healthz'],
  });

  function contextOf(request: { id: string; ip: string; principal: unknown }): RequestContext {
    return {
      principal: request.principal as RequestContext['principal'],
      requestId: request.id,
      sourceIp: request.ip ?? null,
    };
  }

  app.setErrorHandler((error, request, reply) => {
    const status = (error as { statusCode?: number }).statusCode;
    if (status === 403) return reply.code(403).send({ error: 'forbidden' });
    if (status === 404) return reply.code(404).send({ error: 'not_found' });
    if (status === 409) return reply.code(409).send({ error: 'conflict', message: error.message });
    if ((error as { validation?: unknown }).validation || status === 400) {
      return reply.code(400).send({ error: 'bad_request' });
    }
    request.log.error({ err: error }, 'unhandled error');
    return reply.code(500).send({ error: 'internal_error' });
  });

  // --- health ---------------------------------------------------------------

  /**
   * Health, including audit-logging liveness.
   *
   * A secrets service whose audit log has silently stopped accepting writes is
   * NOT healthy, even if it is happily serving secrets. Reporting it here is
   * the cheapest form of Art 12(2)(e) detection.
   */
  app.get('/healthz', async (_request, reply) => {
    const age = await heartbeatAgeSeconds(options.pool);
    const auditStale = age === null || age > 300;
    if (auditStale) reply.code(503);
    return { ok: !auditStale, auditHeartbeatAgeSeconds: age };
  });

  // --- identity -------------------------------------------------------------

  app.get('/v1/me', async (request) => {
    const ctx = contextOf(request);
    const [environments, instanceRole] = await Promise.all([
      secrets.listAccessible(ctx),
      admin.instanceRole(ctx.principal),
    ]);
    return { principal: request.principal, instanceRole, environments };
  });

  // --- secrets --------------------------------------------------------------

  /**
   * Bulk fetch. The DX target: one round trip for `coffre run`.
   * Emits one audit row per secret returned, sharing a bundle id.
   */
  app.get('/v1/projects/:project/environments/:environment/secrets', async (request) => {
    const params = z
      .object({ project: slug, environment: slug })
      .parse(request.params);

    return secrets.readEnvironment(contextOf(request), params.project, params.environment);
  });

  app.get('/v1/projects/:project/environments/:environment/secrets/:key', async (request) => {
    const params = z
      .object({ project: slug, environment: slug, key: secretKey })
      .parse(request.params);

    return secrets.readSecret(
      contextOf(request),
      params.project,
      params.environment,
      params.key,
    );
  });

  app.put('/v1/projects/:project/environments/:environment/secrets/:key', async (request) => {
    const params = z
      .object({ project: slug, environment: slug, key: secretKey })
      .parse(request.params);
    const body = z.object({ value: z.string().max(64 * 1024) }).parse(request.body);

    return secrets.writeSecret(
      contextOf(request),
      params.project,
      params.environment,
      params.key,
      body.value,
    );
  });

  app.patch('/v1/projects/:project/environments/:environment/secrets/:key', async (request) => {
    const params = z
      .object({ project: slug, environment: slug, key: secretKey })
      .parse(request.params);
    const body = z.object({ key: secretKey }).parse(request.body);

    return secrets.renameSecret(
      contextOf(request),
      params.project,
      params.environment,
      params.key,
      body.key,
    );
  });

  /**
   * Retire or restore a secret. Not a delete -- audit_log references secrets
   * with ON DELETE RESTRICT, so nothing ever read or written can be removed.
   */
  app.post(
    '/v1/projects/:project/environments/:environment/secrets/:key/archive',
    async (request) => {
      const params = z
        .object({ project: slug, environment: slug, key: secretKey })
        .parse(request.params);
      const body = z.object({ archived: z.boolean().default(true) }).parse(request.body ?? {});

      return secrets.setSecretArchived(
        contextOf(request),
        params.project,
        params.environment,
        params.key,
        body.archived,
      );
    },
  );

  /** Version history: who wrote each version and when. Never values. */
  app.get(
    '/v1/projects/:project/environments/:environment/secrets/:key/versions',
    async (request) => {
      const params = z
        .object({ project: slug, environment: slug, key: secretKey })
        .parse(request.params);

      return secrets.listVersions(
        contextOf(request),
        params.project,
        params.environment,
        params.key,
      );
    },
  );

  /** Repoint a secret at an earlier version. Versions are append-only, so this costs nothing. */
  app.post(
    '/v1/projects/:project/environments/:environment/secrets/:key/rollback',
    async (request) => {
      const params = z
        .object({ project: slug, environment: slug, key: secretKey })
        .parse(request.params);
      const body = z.object({ version: z.number().int().positive() }).parse(request.body);

      return secrets.rollback(
        contextOf(request),
        params.project,
        params.environment,
        params.key,
        body.version,
      );
    },
  );

  /**
   * Bulk import from a .env file. `dryRun` returns the plan without writing.
   *
   * Parsing happens here rather than in the client so the CLI and the UI cannot
   * disagree about what a .env file means.
   */
  app.post('/v1/projects/:project/environments/:environment/import', async (request) => {
    const params = z.object({ project: slug, environment: slug }).parse(request.params);
    const body = z
      .object({
        content: z.string().max(1024 * 1024),
        dryRun: z.boolean().default(false),
      })
      .parse(request.body);

    const parsed = parseDotenv(body.content);
    if (parsed.entries.length === 0 && parsed.problems.length > 0) {
      return { bundleId: null, plan: [], problems: parsed.problems };
    }

    const result = await secrets.importSecrets(
      contextOf(request),
      params.project,
      params.environment,
      parsed.entries,
      body.dryRun,
    );

    return { ...result, problems: parsed.problems };
  });

  // --- metadata (no secret values) -----------------------------------------

  app.get('/v1/projects', async (request) => {
    const accessible = await secrets.listAccessible(contextOf(request));
    const byProject = new Map<string, { slug: string; environments: unknown[] }>();
    for (const entry of accessible) {
      const project = byProject.get(entry.project) ?? { slug: entry.project, environments: [] };
      project.environments.push({ slug: entry.environment, permissions: entry.permissions });
      byProject.set(entry.project, project);
    }
    return { projects: [...byProject.values()] };
  });

  /**
   * Secret keys and metadata for an environment, WITHOUT values.
   *
   * The admin UI lists secrets constantly; if listing required fetching values
   * it would bury the audit log in reads that never revealed anything. Reading
   * a value is a separate, individually logged action.
   */
  app.get('/v1/projects/:project/environments/:environment/keys', async (request) => {
    const params = z.object({ project: slug, environment: slug }).parse(request.params);
    const ctx = contextOf(request);

    const accessible = await secrets.listAccessible(ctx);
    const match = accessible.find(
      (entry) => entry.project === params.project && entry.environment === params.environment,
    );
    if (!match) throw new AccessDenied();

    const result = await options.pool.query(
      `SELECT s.key, s.archived_at, v.version, v.created_at, v.created_by
         FROM secrets s
         JOIN projects p ON p.id = s.project_id
         JOIN environments e ON e.id = s.environment_id
         LEFT JOIN secret_versions v ON v.id = s.current_version_id
        WHERE p.slug = $1 AND e.slug = $2
        ORDER BY s.key`,
      [params.project, params.environment],
    );

    return {
      permissions: match.permissions,
      keys: result.rows.map((row) => ({
        key: row.key,
        archived: row.archived_at !== null,
        version: row.version === null ? null : Number(row.version),
        updatedAt: row.created_at,
        updatedBy: row.created_by,
      })),
    };
  });

  // --- project and environment management -----------------------------------
  //
  // Note the absence of DELETE. The audit log holds ON DELETE RESTRICT
  // references to projects, environments and secrets, so anything that has ever
  // been used cannot be removed without destroying the trail. Archiving is the
  // operation that actually exists.

  app.get('/v1/admin/projects', async (request) => ({
    projects: await admin.listProjects(contextOf(request)),
  }));

  app.post('/v1/admin/projects', async (request, reply) => {
    const body = z.object({ slug, name: z.string().min(1).max(120) }).parse(request.body);
    reply.code(201);
    return admin.createProject(contextOf(request), body.slug, body.name);
  });

  app.patch('/v1/admin/projects/:project', async (request) => {
    const params = z.object({ project: slug }).parse(request.params);
    const body = z
      .object({ slug: slug.optional(), name: z.string().min(1).max(120).optional() })
      .parse(request.body);

    return admin.updateProject(contextOf(request), params.project, body);
  });

  app.post('/v1/admin/projects/:project/archive', async (request) => {
    const params = z.object({ project: slug }).parse(request.params);
    const body = z.object({ archived: z.boolean().default(true) }).parse(request.body ?? {});

    return admin.setProjectArchived(contextOf(request), params.project, body.archived);
  });

  app.post('/v1/admin/projects/:project/environments', async (request, reply) => {
    const params = z.object({ project: slug }).parse(request.params);
    const body = z.object({ slug, name: z.string().min(1).max(120) }).parse(request.body);

    reply.code(201);
    return admin.createEnvironment(contextOf(request), params.project, body.slug, body.name);
  });

  app.patch('/v1/admin/projects/:project/environments/:environment', async (request) => {
    const params = z.object({ project: slug, environment: slug }).parse(request.params);
    const body = z
      .object({ slug: slug.optional(), name: z.string().min(1).max(120).optional() })
      .parse(request.body);

    return admin.updateEnvironment(contextOf(request), params.project, params.environment, body);
  });

  app.post('/v1/admin/projects/:project/environments/:environment/archive', async (request) => {
    const params = z.object({ project: slug, environment: slug }).parse(request.params);
    const body = z.object({ archived: z.boolean().default(true) }).parse(request.body ?? {});

    return admin.setEnvironmentArchived(
      contextOf(request),
      params.project,
      params.environment,
      body.archived,
    );
  });

  // --- roles and grants -----------------------------------------------------

  app.get('/v1/admin/roles', async () => ({ roles: await admin.listRoles() }));

  /** Grant-aware access overview, retained for the CLI and access managers. */
  app.get('/v1/admin/principals', async (request) => ({
    principals: await admin.listPrincipals(contextOf(request)),
  }));

  /** Identities registered with this Coffre instance, including grantless users. */
  app.get('/v1/admin/directory', async (request) => ({
    principals: await admin.listDirectory(contextOf(request)),
  }));

  app.post('/v1/admin/directory', async (request, reply) => {
    const body = z
      .object({
        principalType: z.enum(['user', 'service']),
        principalId: z.string().min(1).max(320),
        instanceRole: z.enum(['user', 'owner']).default('user'),
      })
      .parse(request.body);

    reply.code(201);
    return admin.addDirectoryPrincipal(contextOf(request), body);
  });

  app.patch('/v1/admin/directory/user/:principalId', async (request) => {
    const params = z
      .object({ principalId: z.string().min(1).max(320) })
      .parse(request.params);
    const body = z.object({ instanceRole: z.enum(['user', 'owner']) }).parse(request.body);

    return admin.updateDirectoryPrincipalRole(
      contextOf(request),
      params.principalId,
      body.instanceRole,
    );
  });

  app.get('/v1/admin/projects/:project/grants', async (request) => {
    const params = z.object({ project: slug }).parse(request.params);
    return { grants: await admin.listGrants(contextOf(request), params.project) };
  });

  app.post('/v1/admin/projects/:project/grants', async (request, reply) => {
    const params = z.object({ project: slug }).parse(request.params);
    const body = z
      .object({
        principalType: z.enum(['user', 'service']),
        principalId: z.string().min(1).max(320),
        role: slug,
        // Omit or null to scope the grant to the whole project.
        environmentSlug: slug.nullish(),
        // Omit or null for a grant that does not expire.
        expiresAt: z.string().datetime().nullish(),
      })
      .parse(request.body);

    reply.code(201);
    return admin.createGrant(contextOf(request), params.project, body);
  });

  app.delete('/v1/admin/projects/:project/grants/:grantId', async (request) => {
    const params = z
      .object({ project: slug, grantId: z.string().uuid() })
      .parse(request.params);

    return admin.revokeGrant(contextOf(request), params.project, params.grantId);
  });

  app.patch('/v1/admin/projects/:project/grants/:grantId', async (request) => {
    const params = z
      .object({ project: slug, grantId: z.string().uuid() })
      .parse(request.params);
    const body = z.object({ role: slug }).parse(request.body);

    return admin.updateGrant(contextOf(request), params.project, params.grantId, body.role);
  });

  app.delete('/v1/admin/principals/:principalType/:principalId', async (request) => {
    const params = z
      .object({
        principalType: z.enum(['user', 'service']),
        principalId: z.string().min(1).max(320),
      })
      .parse(request.params);

    return admin.removePrincipal(
      contextOf(request),
      params.principalType,
      params.principalId,
    );
  });

  app.delete('/v1/admin/directory/:principalType/:principalId', async (request) => {
    const params = z
      .object({
        principalType: z.enum(['user', 'service']),
        principalId: z.string().min(1).max(320),
      })
      .parse(request.params);

    return admin.removeDirectoryPrincipal(
      contextOf(request),
      params.principalType,
      params.principalId,
    );
  });

  // --- audit ----------------------------------------------------------------

  app.get('/v1/audit', async (request) => {
    const query = z
      .object({
        limit: z.coerce.number().int().min(1).max(500).default(100),
        actorId: z.string().optional(),
        decision: z.enum(['allow', 'deny']).optional(),
      })
      .parse(request.query);

    // Audit visibility no longer requires root admin.
    //
    // Under the old capability ladder, seeing the audit log meant holding
    // 'admin', which also meant being able to read every secret. For a service
    // whose purpose is audit, that was backwards: you could not appoint someone
    // to answer "who read which secret" without handing them the whole vault.
    //
    // The 'auditor' role carries audit.read and nothing else. A caller sees the
    // entries for the projects they hold it on; root admins see everything.
    const auditableProjects = await projectsWithAuditRead(
      options.pool,
      contextOf(request),
      options.rootAdmins,
    );
    if (auditableProjects !== 'all' && auditableProjects.length === 0) {
      throw new AccessDenied('you do not hold audit.read on any project');
    }

    const filters: string[] = [];
    const values: unknown[] = [];
    if (auditableProjects !== 'all') {
      values.push(auditableProjects);
      // Rows with no project (for example a denied read of an unknown project)
      // are only visible to root admins, since they cannot be attributed.
      filters.push(`project_id = ANY($${values.length}::uuid[])`);
    }
    if (query.actorId) {
      values.push(query.actorId);
      filters.push(`actor_id = $${values.length}`);
    }
    if (query.decision) {
      values.push(query.decision);
      filters.push(`decision = $${values.length}`);
    }
    values.push(query.limit);

    const result = await options.pool.query(
      `SELECT seq, ${OCCURRED_AT_SQL} AS occurred_at, actor_type, actor_id, action,
              decision, project_id, environment_id, secret_id, bundle_id, metadata
         FROM audit_log
        ${filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : ''}
        ORDER BY seq DESC
        LIMIT $${values.length}`,
      values,
    );

    return {
      entries: result.rows.map((row) => ({
        seq: Number(row.seq),
        occurredAt: row.occurred_at,
        actorType: row.actor_type,
        actorId: row.actor_id,
        action: row.action,
        decision: row.decision,
        bundleId: row.bundle_id,
        metadata: JSON.parse(row.metadata),
      })),
    };
  });

  /**
   * Verify the whole chain, from genesis to the head row.
   *
   * Two things are checked, and the second is not optional. Recomputing the
   * links catches mutation, reordering and holes punched in the middle. It
   * cannot catch the tail being cut off, because what remains is a perfectly
   * consistent shorter chain -- so the recomputed head and length are compared
   * against `audit_chain_head`, which is the only thing in the database that
   * remembers how long the log is supposed to be.
   *
   * An attacker holding the chain key defeats both. That is the point of
   * publishing checkpoints somewhere coffre cannot write; see
   * `audit_checkpoints`.
   */
  app.get('/v1/audit/verify', async (request) => {
    const auditable = await projectsWithAuditRead(
      options.pool,
      contextOf(request),
      options.rootAdmins,
    );
    if (auditable !== 'all' && auditable.length === 0) {
      throw new AccessDenied('you do not hold audit.read on any project');
    }

    const client = await options.pool.connect();
    try {
      // One snapshot for the head row and every batch under it. Without it a
      // concurrent append lands between two batches and the recomputed head
      // fails to match a head row read a moment earlier -- a false alarm on
      // the one check that must never cry wolf.
      await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');

      const head = await client.query<{ next_seq: string; head_hash: Buffer }>(
        'SELECT next_seq, head_hash FROM audit_chain_head WHERE only_row LIMIT 1',
      );
      if (head.rowCount !== 1) {
        return {
          ok: false,
          failedAtSeq: 0,
          reason: 'audit_chain_head is missing, so the length of the log cannot be established',
        };
      }

      // Batched rather than one 100k-row read: the previous cap silently
      // verified a prefix and reported success over it once the log outgrew
      // the limit, which is the failure mode this endpoint exists to catch.
      let prevHash = GENESIS_HASH;
      let nextSeq = 0n;
      let rows = 0;

      for (;;) {
        const batch = await readAuditRows(client, nextSeq, VERIFY_BATCH);
        if (batch.length === 0) break;

        const result = verifyChain(options.auditChainKey, batch, prevHash);
        if (!result.ok) {
          return {
            ok: false,
            failedAtSeq: Number(result.failedAtSeq),
            reason: result.reason,
          };
        }

        rows += result.rows;
        prevHash = result.head;
        nextSeq = batch[batch.length - 1].seq + 1n;
        if (batch.length < VERIFY_BATCH) break;
      }

      const expectedSeq = BigInt(head.rows[0].next_seq);
      if (nextSeq !== expectedSeq) {
        const missing = expectedSeq - nextSeq;
        return {
          ok: false,
          failedAtSeq: Number(nextSeq),
          reason:
            missing > 0n
              ? `the log ends at seq ${nextSeq} but the chain head expects ${expectedSeq}: ${missing} ${missing === 1n ? 'entry has' : 'entries have'} been removed from the end`
              : `the log runs to seq ${nextSeq} but the chain head only expects ${expectedSeq}`,
        };
      }
      if (!prevHash.equals(head.rows[0].head_hash)) {
        return {
          ok: false,
          failedAtSeq: Number(nextSeq),
          reason: 'the recomputed head does not match the stored chain head',
        };
      }

      return { ok: true, rows, head: prevHash.toString('hex') };
    } finally {
      // Read-only throughout; ending the snapshot is all this has to do.
      await client.query('ROLLBACK').catch(() => {});
      client.release();
    }
  });

  void NotFound;
  return app;
}

/**
 * Which projects the caller may read audit entries for.
 *
 * Returns 'all' for root admins. Otherwise the ids of every project where the
 * caller holds audit.read, whether granted on the project or on one of its
 * environments.
 */
async function projectsWithAuditRead(
  pool: pg.Pool,
  ctx: RequestContext,
  rootAdmins: readonly string[],
): Promise<'all' | string[]> {
  if (isRootAdmin(ctx.principal, rootAdmins)) return 'all';
  if (ctx.principal.type === 'user') {
    const owner = await pool.query(
      `SELECT 1 FROM principals
        WHERE principal_type = 'user'
          AND principal_id = $1
          AND active
          AND instance_role = 'owner'`,
      [ctx.principal.id],
    );
    if (owner.rowCount !== 0) return 'all';
  }

  const result = await pool.query<{ project_id: string }>(
    `SELECT DISTINCT COALESCE(g.project_id, e.project_id) AS project_id
       FROM grants g
       JOIN role_permissions rp ON rp.role_id = g.role_id
       LEFT JOIN environments e ON e.id = g.environment_id
      WHERE g.principal_type = $1
        AND g.principal_id = $2
        AND rp.permission = 'audit.read'
        AND (g.expires_at IS NULL OR g.expires_at > now())`,
    [ctx.principal.type, ctx.principal.id],
  );

  return result.rows.map((row) => row.project_id);
}
