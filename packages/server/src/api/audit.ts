import { roleGrants } from '@coffre/core/access';
import { GENESIS_HASH, verifyChain } from '@coffre/core/audit';
import { verifyCheckpoint, type Checkpoint, type LogPage } from '@coffre/core/vault';

import { SNAPSHOT } from '../db/dialect.ts';
import {
  auditHead,
  auditPage,
  auditRange,
  resolvePath,
  type AuditFilter,
} from '../db/queries.ts';
import { CHECKPOINT_ACTION, readCheckpoint, vaultBehind } from '../heartbeat.ts';
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
  /** The request that wrote it, which the vault logs too for each key it unwraps or wraps. */
  requestId: string | null;
  metadata: Record<string, unknown>;
};

export type AuditVerification =
  | {
      ok: true;
      rows: number;
      head: string;
      /** The last head the vault signed, which the log still matches; null before the first. */
      checkpoint: { seq: number; signedAt: string } | null;
      /**
       * The vault's own log, checked whole: its chain from the first entry,
       * the head the app last recorded from a checkpoint, and every member
       * and grant replayed from it.
       */
      vault: { entries: number };
    }
  | {
      ok: false;
      /** Which failed: the app's audit log, or the vault's log and store. */
      log: 'audit' | 'vault';
      /** The entry of that log where it breaks, or null when the fault is not at one. */
      failedAtSeq: number | null;
      reason: string;
    };

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
      requestId: row.requestId,
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
 * Then the other way: the vault's log against the last checkpoint the app
 * recorded, which catches a vault store rewritten or put back to an older
 * copy. Owners only: a partial view of the chain cannot be verified.
 */
export async function verifyAudit(ctx: ApiContext): Promise<AuditVerification> {
  if (!ctx.caller.isOwner) {
    throw forbidden('only a root admin or instance owner may verify the complete audit chain');
  }
  const audit = (failedAtSeq: number | bigint, reason: string) =>
    ({ ok: false, log: 'audit', failedAtSeq: Number(failedAtSeq), reason }) as const;
  const vault = (failedAtSeq: number | null, reason: string) => ({ ok: false, log: 'vault', failedAtSeq, reason }) as const;

  const { checkpoint, publicKey } = await ctx.vault.latestCheckpoint();
  if (checkpoint !== null && !(await verifyCheckpoint(checkpoint, publicKey))) {
    return vault(null, `the latest checkpoint, at seq ${checkpoint.seq}, does not carry the vault's signature`);
  }
  const signedSeq = checkpoint === null ? null : BigInt(checkpoint.seq);
  const chain = await ctx.db.transaction(
    async (tx) => {
      const head = await auditHead(tx);
      if (head === null) {
        return audit(0, 'audit_chain_head is missing, so the length of the log cannot be established');
      }

      let previousHash = GENESIS_HASH;
      let nextSequence = 0n;
      let rows = 0;
      let signedHash: string | null = null;
      let recorded: ReturnType<typeof readCheckpoint> | null = null;
      for (;;) {
        const batch = await auditRange(tx, nextSequence, VERIFY_BATCH);
        if (batch.length === 0) break;
        const result = verifyChain(ctx.chainKey, batch, previousHash);
        if (!result.ok) return audit(result.failedAtSeq, result.reason);
        rows += result.rows;
        previousHash = result.head;
        for (const row of batch) {
          if (row.seq === signedSeq) signedHash = row.hash.toString('hex');
          if (row.action === CHECKPOINT_ACTION) recorded = readCheckpoint(row.seq, row.metadata);
        }
        nextSequence = batch[batch.length - 1].seq + 1n;
        if (batch.length < VERIFY_BATCH) break;
      }

      if (nextSequence !== head.nextSeq) {
        const missing = head.nextSeq - nextSequence;
        return audit(
          nextSequence,
          missing > 0n
            ? `the log ends at seq ${nextSequence} but the chain head expects ${head.nextSeq}: ${missing} ${missing === 1n ? 'entry has' : 'entries have'} been removed from the end`
            : `the log runs to seq ${nextSequence} but the chain head only expects ${head.nextSeq}`,
        );
      }
      if (!previousHash.equals(head.headHash)) {
        return audit(nextSequence, 'the recomputed head does not match the stored chain head');
      }
      if (checkpoint !== null) {
        if (signedHash === null) {
          return audit(
            nextSequence,
            `the log ends before seq ${checkpoint.seq}, which the vault signed at ${checkpoint.signedAt}`,
          );
        }
        if (signedHash !== checkpoint.headHash) {
          return audit(
            checkpoint.seq,
            `the log up to seq ${checkpoint.seq} is not the one the vault signed at ${checkpoint.signedAt}: it was rewritten`,
          );
        }
      }
      return { ok: true as const, rows, head: previousHash.toString('hex'), recorded };
    },
    SNAPSHOT,
  );
  if (!chain.ok) return chain;
  const { rows, head, recorded } = chain;

  // The vault's side. Its latest checkpoint is read again: one signed and
  // recorded since the first read is in the snapshot, and is not behind.
  let through: Checkpoint['vault'] | null = null;
  if (recorded !== null) {
    if (!recorded.ok || !(await verifyCheckpoint(recorded.checkpoint, publicKey))) {
      return audit(recorded.seq, 'this entry records a checkpoint the vault did not sign');
    }
    const behind = vaultBehind((await ctx.vault.latestCheckpoint()).checkpoint, recorded.checkpoint);
    if (behind !== null) return vault(null, behind);
    through = recorded.checkpoint.vault;
  }
  const verified = await ctx.vault.verifyLog({ through });
  if (!verified.ok) return vault(verified.failedAtSeq, verified.reason);
  return {
    ok: true,
    rows,
    head,
    checkpoint: checkpoint === null ? null : { seq: checkpoint.seq, signedAt: checkpoint.signedAt },
    vault: { entries: verified.entries },
  };
}

/**
 * A page of the vault's own log, which the app can read but never write.
 * Root admins only, which the vault decides; the app only refuses early.
 */
export async function vaultLog(
  ctx: ApiContext,
  query: { before?: number; limit: number; full?: boolean },
): Promise<LogPage> {
  if (!ctx.caller.isRootAdmin) throw forbidden('only a root admin may read the vault log');
  const page = await ctx.vault.log({ actor: formatMember(ctx.caller.principal), ...query });
  if (!page.ok) throw vaultRefused(page.refusal);
  return { entries: page.entries, verification: page.verification };
}
