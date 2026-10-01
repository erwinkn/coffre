import { roleGrants } from '../../../core/src/access.ts';
import { GENESIS_HASH, verifyChain } from '../../../core/src/audit/chain.ts';
import { SNAPSHOT } from '../db/dialect.ts';
import {
  auditHead,
  auditPage,
  auditRange,
  resolvePath,
  type AuditFilter,
} from '../db/queries.ts';
import { verifyCheckpoint } from '../../../vault/src/checkpoint.ts';
import type { LogPage } from '../../../vault/src/types.ts';
import type { ApiContext } from './context.ts';
import { forbidden, notFound, vaultRefused } from './errors.ts';
import { formatMember, parseMember, type Path } from './paths.ts';

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
  | {
      ok: true;
      rows: number;
      head: string;
      /** The last head the vault signed, which the log still matches; null before the first. */
      checkpoint: { seq: number; signedAt: string } | null;
    }
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
  const filter: AuditFilter = { decision: query.decision, limit: query.limit };
  const { caller } = ctx;
  if (!caller.isOwner) {
    const readable = caller.grants.filter((grant) => roleGrants(grant.role, 'audit.read'));
    const projectIds = readable.filter((grant) => grant.environmentId === null).map((grant) => grant.projectId);
    const environmentIds = readable.flatMap((grant) => grant.environmentId ?? []);
    if (projectIds.length === 0 && environmentIds.length === 0) {
      throw forbidden('you do not hold audit.read on any project');
    }
    filter.within = { projectIds, environmentIds };
  }
  if (query.path !== undefined) {
    const place = await resolvePath(ctx.db, query.path);
    if (place === null) throw notFound('no such project');
    filter.projectId = place.project.id;
    if (query.path.environment !== undefined) {
      if (place.environment === null) throw notFound('no such environment');
      filter.environmentId = place.environment.id;
    }
    if (query.path.key !== undefined) {
      if (place.secret === null) throw notFound('no such secret');
      filter.secretId = place.secret.id;
    }
  }
  if (query.actor !== undefined) {
    if (/^(user|token):/.test(query.actor)) {
      const member = parseMember(query.actor);
      filter.actorType = member.type;
      filter.actorId = member.id;
    } else {
      filter.actorId = query.actor;
    }
  }
  if (query.before !== undefined) filter.beforeSeq = BigInt(query.before);

  const rows = await auditPage(ctx.db, filter);
  return {
    entries: rows.map((row) => ({
      seq: Number(row.seq),
      occurredAt: row.occurredAt,
      actorType: row.actorType,
      actorId: row.actorId,
      action: row.action,
      decision: row.decision as 'allow' | 'deny',
      project: row.project,
      environment: row.environment,
      bundleId: row.bundleId,
      metadata: JSON.parse(row.metadata) as Record<string, unknown>,
    })),
  };
}

/**
 * Recompute the whole chain and compare it with the stored head, in one
 * read-only snapshot so appends made meanwhile cannot look like tampering.
 * Then check the log against the vault's latest signed checkpoint: the chain
 * key catches a row changed by someone who holds only the database, and the
 * checkpoint one changed and chained again by someone who holds the app too.
 * Owners only: a partial view of the chain cannot be verified.
 */
export async function verifyAudit(ctx: ApiContext): Promise<AuditVerification> {
  if (!ctx.caller.isOwner) {
    throw forbidden('only a root admin or instance owner may verify the complete audit chain');
  }
  const { checkpoint, publicKey } = await ctx.vault.latestCheckpoint();
  if (checkpoint !== null && !(await verifyCheckpoint(checkpoint, publicKey))) {
    return { ok: false, failedAtSeq: checkpoint.seq, reason: 'the latest checkpoint does not carry the vault\'s signature' };
  }
  const signedSeq = checkpoint === null ? null : BigInt(checkpoint.seq);
  let signedHash: string | null = null;
  return ctx.db.transaction(
    async (tx): Promise<AuditVerification> => {
      const head = await auditHead(tx);
      if (head === null) {
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
        const batch = await auditRange(tx, nextSequence, VERIFY_BATCH);
        if (batch.length === 0) break;
        const result = verifyChain(ctx.chainKey, batch, previousHash);
        if (!result.ok) {
          return { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: result.reason };
        }
        rows += result.rows;
        previousHash = result.head;
        const signed = batch.find((row) => row.seq === signedSeq);
        if (signed !== undefined) signedHash = signed.hash.toString('hex');
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
      if (checkpoint !== null) {
        if (signedHash === null) {
          return {
            ok: false,
            failedAtSeq: Number(nextSequence),
            reason: `the log ends before seq ${checkpoint.seq}, which the vault signed at ${checkpoint.signedAt}`,
          };
        }
        if (signedHash !== checkpoint.headHash) {
          return {
            ok: false,
            failedAtSeq: checkpoint.seq,
            reason: `the log up to seq ${checkpoint.seq} is not the one the vault signed at ${checkpoint.signedAt}: it was rewritten`,
          };
        }
      }
      return {
        ok: true,
        rows,
        head: previousHash.toString('hex'),
        checkpoint: checkpoint === null ? null : { seq: checkpoint.seq, signedAt: checkpoint.signedAt },
      };
    },
    SNAPSHOT,
  );
}

/**
 * A page of the vault's own log, which the app can read but never write.
 * Root admins only, which the vault decides; the app only refuses early.
 */
export async function vaultLog(ctx: ApiContext, query: { before?: number; limit: number }): Promise<LogPage> {
  if (!ctx.caller.isRootAdmin) throw forbidden('only a root admin may read the vault log');
  const page = await ctx.vault.log({ actor: formatMember(ctx.caller.principal), ...query });
  if (!page.ok) throw vaultRefused(page.refusal);
  return { entries: page.entries, verification: page.verification };
}
