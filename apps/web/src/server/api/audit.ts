import { and, desc, eq, inArray, lt, or, type SQL } from 'drizzle-orm';

import { roleGrants } from '../../../../../packages/core/src/access.ts';
import { GENESIS_HASH, verifyChain } from '../../../../../packages/core/src/audit/chain.ts';
import { canonicalTimestamp, readAuditRows } from '../../../../../packages/db/src/audit.ts';
import { auditChainHead, auditLog, environments, projects } from '../../../../../packages/db/src/schema.ts';
import type { ApiContext } from './context.ts';
import { forbidden, notFound } from './errors.ts';
import { parseMember, resolvePath, type Path } from './paths.ts';

const VERIFY_BATCH = 5_000;

export type AuditEntryView = {
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

export type AuditQuery = {
  path?: Path;
  /** `user:ada@acme.example`, `token:ci-deploy`, or a raw actor id such as `sync:…`. */
  actor?: string;
  decision?: 'allow' | 'deny';
  /** Entries older than this seq, for paging backwards. */
  before?: number;
  limit: number;
};

/**
 * Newest first. Owners read everything; anyone else reads the projects and
 * environments where they hold `audit.read`, and nothing else.
 */
export async function listAudit(
  ctx: ApiContext,
  query: AuditQuery,
): Promise<{ entries: AuditEntryView[] }> {
  const filters: SQL[] = [];
  const { caller } = ctx;
  if (!caller.isOwner) {
    const readable = caller.grants.filter((grant) => roleGrants(grant.role, 'audit.read'));
    const projectIds = readable.filter((grant) => grant.environmentId === null).map((grant) => grant.projectId);
    const environmentIds = readable.flatMap((grant) => grant.environmentId ?? []);
    if (projectIds.length === 0 && environmentIds.length === 0) {
      throw forbidden('you do not hold audit.read on any project');
    }
    const scope = [
      ...(projectIds.length > 0 ? [inArray(auditLog.projectId, projectIds)] : []),
      ...(environmentIds.length > 0 ? [inArray(auditLog.environmentId, environmentIds)] : []),
    ];
    filters.push(or(...scope)!);
  }
  if (query.path !== undefined) {
    const place = await resolvePath(ctx.db, query.path);
    if (place === null) throw notFound('no such project');
    filters.push(eq(auditLog.projectId, place.project.id));
    if (query.path.environment !== undefined) {
      if (place.environment === null) throw notFound('no such environment');
      filters.push(eq(auditLog.environmentId, place.environment.id));
    }
    if (query.path.key !== undefined) {
      if (place.secret === null) throw notFound('no such secret');
      filters.push(eq(auditLog.secretId, place.secret.id));
    }
  }
  if (query.actor !== undefined) {
    if (/^(user|token):/.test(query.actor)) {
      const member = parseMember(query.actor);
      filters.push(eq(auditLog.actorType, member.type), eq(auditLog.actorId, member.id));
    } else {
      filters.push(eq(auditLog.actorId, query.actor));
    }
  }
  if (query.decision !== undefined) filters.push(eq(auditLog.decision, query.decision));
  if (query.before !== undefined) filters.push(lt(auditLog.seq, BigInt(query.before)));

  const rows = await ctx.db
    .select({
      seq: auditLog.seq,
      occurredAt: auditLog.occurredAt,
      actorType: auditLog.actorType,
      actorId: auditLog.actorId,
      action: auditLog.action,
      decision: auditLog.decision,
      bundleId: auditLog.bundleId,
      metadata: auditLog.metadata,
      project: projects.slug,
      environment: environments.slug,
    })
    .from(auditLog)
    .leftJoin(projects, eq(projects.id, auditLog.projectId))
    .leftJoin(environments, eq(environments.id, auditLog.environmentId))
    .where(and(...filters))
    .orderBy(desc(auditLog.seq))
    .limit(query.limit);

  return {
    entries: rows.map((row) => ({
      ...row,
      seq: Number(row.seq),
      occurredAt: canonicalTimestamp(row.occurredAt),
      decision: row.decision as 'allow' | 'deny',
      metadata: JSON.parse(row.metadata) as Record<string, unknown>,
    })),
  };
}

/**
 * Recompute the whole chain and compare it with the stored head, in one
 * read-only snapshot so appends made meanwhile cannot look like tampering.
 * Owners only: a partial view of the chain cannot be verified.
 */
export async function verifyAudit(ctx: ApiContext): Promise<AuditVerification> {
  if (!ctx.caller.isOwner) {
    throw forbidden('only a root admin or instance owner may verify the complete audit chain');
  }
  return ctx.db.transaction(
    async (tx): Promise<AuditVerification> => {
      const [head] = await tx
        .select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash })
        .from(auditChainHead)
        .limit(1);
      if (head === undefined) {
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
        const batch = await readAuditRows(tx, nextSequence, VERIFY_BATCH);
        if (batch.length === 0) break;
        const result = verifyChain(ctx.chainKey, batch, previousHash);
        if (!result.ok) {
          return { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: result.reason };
        }
        rows += result.rows;
        previousHash = result.head;
        nextSequence = batch[batch.length - 1].seq + 1n;
        if (batch.length < VERIFY_BATCH) break;
      }

      if (nextSequence !== head.nextSeq) {
        const missing = head.nextSeq - nextSequence;
        return {
          ok: false,
          failedAtSeq: Number(nextSequence),
          reason:
            missing > 0n
              ? `the log ends at seq ${nextSequence} but the chain head expects ${head.nextSeq}: ${missing} ${missing === 1n ? 'entry has' : 'entries have'} been removed from the end`
              : `the log runs to seq ${nextSequence} but the chain head only expects ${head.nextSeq}`,
        };
      }
      if (!previousHash.equals(head.headHash)) {
        return {
          ok: false,
          failedAtSeq: Number(nextSequence),
          reason: 'the recomputed head does not match the stored chain head',
        };
      }
      return { ok: true, rows, head: previousHash.toString('hex') };
    },
    { isolationLevel: 'repeatable read', accessMode: 'read only' },
  );
}
