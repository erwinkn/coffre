import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import pg from 'pg';
import { z } from 'zod';

import { AccessIdentityVerifier } from '../../../packages/core/src/identity/verifier.ts';
import type { IdentityVerifier } from '../../../packages/core/src/identity/types.ts';
import type { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import { verifyChain, GENESIS_HASH } from '../../../packages/core/src/audit/chain.ts';
import { readAuditRows, OCCURRED_AT_SQL } from '../../../packages/db/src/audit.ts';
import { registerAuth } from './auth.ts';
import { heartbeatAgeSeconds } from './heartbeat.ts';
import {
  SecretsService,
  AccessDenied,
  NotFound,
  type RequestContext,
} from './services/secrets.ts';

const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
const secretKey = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);

export type BuildOptions = {
  pool: pg.Pool;
  verifier: IdentityVerifier;
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

  registerAuth(app, { verifier: options.verifier, publicPaths: ['/healthz'] });

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

  app.get('/v1/me', async (request) => ({
    principal: request.principal,
    environments: await secrets.listAccessible(contextOf(request)),
  }));

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

  // --- metadata (no secret values) -----------------------------------------

  app.get('/v1/projects', async (request) => {
    const accessible = await secrets.listAccessible(contextOf(request));
    const byProject = new Map<string, { slug: string; environments: unknown[] }>();
    for (const entry of accessible) {
      const project = byProject.get(entry.project) ?? { slug: entry.project, environments: [] };
      project.environments.push({ slug: entry.environment, capability: entry.capability });
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
      `SELECT s.key, v.version, v.created_at, v.created_by
         FROM secrets s
         JOIN projects p ON p.id = s.project_id
         JOIN environments e ON e.id = s.environment_id
         LEFT JOIN secret_versions v ON v.id = s.current_version_id
        WHERE p.slug = $1 AND e.slug = $2
        ORDER BY s.key`,
      [params.project, params.environment],
    );

    return {
      capability: match.capability,
      keys: result.rows.map((row) => ({
        key: row.key,
        version: row.version === null ? null : Number(row.version),
        updatedAt: row.created_at,
        updatedBy: row.created_by,
      })),
    };
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

    if (!options.rootAdmins.includes((request.principal as { id: string }).id)) {
      throw new AccessDenied('only root admins may read the audit log');
    }

    const filters: string[] = [];
    const values: unknown[] = [];
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

  /** Verify the whole chain. This is the "prove the log was not edited" button. */
  app.get('/v1/audit/verify', async (request) => {
    if (!options.rootAdmins.includes((request.principal as { id: string }).id)) {
      throw new AccessDenied('only root admins may verify the audit log');
    }

    const client = await options.pool.connect();
    try {
      const rows = await readAuditRows(client, 0n, 100_000);
      const result = verifyChain(options.auditChainKey, rows, GENESIS_HASH);
      return result.ok
        ? { ok: true, rows: result.rows, head: result.head.toString('hex') }
        : { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: result.reason };
    } finally {
      client.release();
    }
  });

  void NotFound;
  return app;
}
