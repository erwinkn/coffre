import type { Database } from '../database.ts';

import { GENESIS_HASH, verifyChain } from '../../../../../packages/core/src/audit/chain.ts';
import {
  OCCURRED_AT_SQL,
  readAuditRows,
} from '../../../../../packages/db/src/audit.ts';
import { AccessDenied, type RequestContext } from './secrets.ts';
import { isRootAdmin } from './permissions.ts';
import {
  writeAuditHeartbeat,
  type HeartbeatLogger,
} from '../heartbeat.ts';

const VERIFY_BATCH = 5_000;

export type AuditEntry = {
  seq: number;
  occurredAt: string;
  actorType: string;
  actorId: string;
  action: string;
  decision: 'allow' | 'deny';
  project: string | null;
  environment: string | null;
  bundleId: string | null;
  metadata: Record<string, unknown>;
};

export type AuditVerification =
  | { ok: true; rows: number; head: string }
  | { ok: false; failedAtSeq: number; reason: string };

type AuditScope =
  | 'all'
  | { projectIds: string[]; environmentIds: string[] };

export class AuditService {
  readonly #pool: Database;
  readonly #chainKey: Buffer;
  readonly #rootAdmins: readonly string[];

  constructor(options: {
    pool: Database;
    chainKey: Buffer;
    rootAdmins: readonly string[];
  }) {
    this.#pool = options.pool;
    this.#chainKey = options.chainKey;
    this.#rootAdmins = options.rootAdmins;
  }

  writeHeartbeat(log: HeartbeatLogger): Promise<boolean> {
    return writeAuditHeartbeat(this.#pool, this.#chainKey, log);
  }

  async canRead(ctx: RequestContext): Promise<boolean> {
    const scope = await this.#auditScope(ctx);
    return (
      scope === 'all' || scope.projectIds.length > 0 || scope.environmentIds.length > 0
    );
  }

  async list(
    ctx: RequestContext,
    options: {
      limit: number;
      actorId?: string;
      decision?: 'allow' | 'deny';
    },
  ): Promise<AuditEntry[]> {
    const scope = await this.#auditScope(ctx);
    if (scope !== 'all' && scope.projectIds.length === 0 && scope.environmentIds.length === 0) {
      throw new AccessDenied('you do not hold audit.read on any project');
    }

    const filters: string[] = [];
    const values: unknown[] = [];
    if (scope !== 'all') {
      const scopeFilters: string[] = [];
      if (scope.projectIds.length > 0) {
        values.push(scope.projectIds);
        scopeFilters.push(`audit_log.project_id = ANY($${values.length}::uuid[])`);
      }
      if (scope.environmentIds.length > 0) {
        values.push(scope.environmentIds);
        scopeFilters.push(`audit_log.environment_id = ANY($${values.length}::uuid[])`);
      }
      filters.push(`(${scopeFilters.join(' OR ')})`);
    }
    if (options.actorId) {
      values.push(options.actorId);
      filters.push(`audit_log.actor_id = $${values.length}`);
    }
    if (options.decision) {
      values.push(options.decision);
      filters.push(`audit_log.decision = $${values.length}`);
    }
    values.push(options.limit);

    const result = await this.#pool.query(
      `SELECT audit_log.seq, ${OCCURRED_AT_SQL} AS occurred_at,
              audit_log.actor_type, audit_log.actor_id, audit_log.action,
              audit_log.decision, audit_log.bundle_id, audit_log.metadata,
              projects.slug AS project_slug,
              environments.slug AS environment_slug
         FROM audit_log
         LEFT JOIN projects ON projects.id = audit_log.project_id
         LEFT JOIN environments ON environments.id = audit_log.environment_id
        ${filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : ''}
        ORDER BY audit_log.seq DESC
        LIMIT $${values.length}`,
      values,
    );

    return result.rows.map((row) => ({
      seq: Number(row.seq),
      occurredAt: row.occurred_at,
      actorType: row.actor_type,
      actorId: row.actor_id,
      action: row.action,
      decision: row.decision,
      project: row.project_slug,
      environment: row.environment_slug,
      bundleId: row.bundle_id,
      metadata: JSON.parse(row.metadata),
    }));
  }

  /** Verify every audit row and compare the recomputed result with the stored head. */
  async verify(ctx: RequestContext): Promise<AuditVerification> {
    const scope = await this.#auditScope(ctx);
    if (scope !== 'all') {
      throw new AccessDenied(
        'only a root admin or instance owner may verify the complete audit chain',
      );
    }

    const client = await this.#pool.connect();
    try {
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

      let previousHash = GENESIS_HASH;
      let nextSequence = 0n;
      let rows = 0;

      for (;;) {
        const batch = await readAuditRows(client, nextSequence, VERIFY_BATCH);
        if (batch.length === 0) break;

        const result = verifyChain(this.#chainKey, batch, previousHash);
        if (!result.ok) {
          return {
            ok: false,
            failedAtSeq: Number(result.failedAtSeq),
            reason: result.reason,
          };
        }

        rows += result.rows;
        previousHash = result.head;
        nextSequence = batch[batch.length - 1].seq + 1n;
        if (batch.length < VERIFY_BATCH) break;
      }

      const expectedSequence = BigInt(head.rows[0].next_seq);
      if (nextSequence !== expectedSequence) {
        const missing = expectedSequence - nextSequence;
        return {
          ok: false,
          failedAtSeq: Number(nextSequence),
          reason:
            missing > 0n
              ? `the log ends at seq ${nextSequence} but the chain head expects ${expectedSequence}: ${missing} ${missing === 1n ? 'entry has' : 'entries have'} been removed from the end`
              : `the log runs to seq ${nextSequence} but the chain head only expects ${expectedSequence}`,
        };
      }
      if (!previousHash.equals(head.rows[0].head_hash)) {
        return {
          ok: false,
          failedAtSeq: Number(nextSequence),
          reason: 'the recomputed head does not match the stored chain head',
        };
      }

      return { ok: true, rows, head: previousHash.toString('hex') };
    } finally {
      await client.query('ROLLBACK').catch(() => {});
      await client.release();
    }
  }

  async #auditScope(ctx: RequestContext): Promise<AuditScope> {
    if (isRootAdmin(ctx.principal, this.#rootAdmins)) return 'all';
    if (ctx.principal.type === 'user') {
      const owner = await this.#pool.query(
        `SELECT 1 FROM principals
          WHERE principal_type = 'user'
            AND principal_id = $1
            AND active
            AND instance_role = 'owner'`,
        [ctx.principal.id],
      );
      if (owner.rowCount !== 0) return 'all';
    }

    const result = await this.#pool.query<{
      project_id: string | null;
      environment_id: string | null;
    }>(
      `SELECT DISTINCT g.project_id, g.environment_id
         FROM grants g
         JOIN role_permissions rp ON rp.role_id = g.role_id
        WHERE g.principal_type = $1
          AND g.principal_id = $2
          AND rp.permission = 'audit.read'
          AND (g.expires_at IS NULL OR g.expires_at > now())`,
      [ctx.principal.type, ctx.principal.id],
    );

    return {
      projectIds: result.rows.flatMap((row) => row.project_id === null ? [] : [row.project_id]),
      environmentIds: result.rows.flatMap((row) =>
        row.environment_id === null ? [] : [row.environment_id],
      ),
    };
  }
}
