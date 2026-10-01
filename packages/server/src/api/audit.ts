import { roleGrants } from '@coffre/core/access';
import { GENESIS_HASH, verifyEntries } from '@coffre/core/audit';
import { describeAccessFault, verifyCheckpoint, type Checkpoint, type LogEntry, type LogVerification } from '@coffre/core/vault';
import { SNAPSHOT } from '@coffre/db/dialect';

import { actorParts, appLogKey } from '../db/audit.ts';
import {
  auditHead,
  auditPage,
  auditRange,
  places,
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

/** The vault's verdict as the API gives it, its fault already in words. */
export type VaultVerification =
  | { ok: true; entries: number }
  | { ok: false; failedAtSeq: number | null; reason: string };

export type AuditQuery = {
  path?: Path;
  /** `user:ada@acme.example`, `token:ci-deploy`, or a raw actor id such as `sync:…`. */
  actor?: string;
  decision?: 'allow' | 'deny';
  /**
   * `sign-ins` leaves out `auth.signin` and `auth.signout`, for a view about
   * what was done with secrets and access. They stay in the log and its
   * chain, and are returned unless asked otherwise.
   */
  exclude?: 'sign-ins';
  /** Entries older than this seq, for paging backwards. */
  before?: number;
  limit: number;
};

/** What `exclude=sign-ins` leaves out. Binding an account and issuing a credential stay. */
export const SIGN_IN_ACTIONS = ['auth.signin', 'auth.signout'] as const;

/**
 * Newest first. Owners read everything; anyone else reads the projects and
 * environments where they hold `audit.read`, and nothing else.
 */
export async function listAudit(
  ctx: ApiContext,
  query: AuditQuery,
): Promise<{ entries: AuditEntryView[] }> {
  const filter: AuditFilter = {
    decision: query.decision,
    excludeActions: query.exclude === 'sign-ins' ? SIGN_IN_ACTIONS : undefined,
    limit: query.limit,
  };
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
    filter.actors = /^(user|token):/.test(query.actor)
      ? [formatMember(parseMember(query.actor))]
      : ['user', 'token', 'sync', 'system'].map((prefix) => `${prefix}:${query.actor}`).concat(query.actor);
  }
  if (query.before !== undefined) filter.beforeSeq = BigInt(query.before);

  const rows = await auditPage(ctx.db, filter);
  return {
    entries: rows.map((row) => ({
      seq: Number(row.seq),
      occurredAt: row.occurredAt,
      ...actorParts(row.actor),
      action: row.action,
      decision: row.decision as 'allow' | 'deny',
      project: row.project,
      environment: row.environment,
      bundleId: row.operationId,
      requestId: row.requestId,
      metadata: JSON.parse(row.metadata) as Record<string, unknown>,
    })),
  };
}

/**
 * Recompute the whole chain and compare it with the stored head, in one
 * read-only snapshot so appends made meanwhile cannot look like tampering.
 * Each author authenticates its own entries: the app here, by its chain
 * key, and the vault by its own, over the same entries, up to the last one
 * the app verified. Anyone who can insert a row can link it to the chain,
 * so an entry whose author did not write it fails one check or the other.
 * Then check the log against the vault's latest signed checkpoint: the chain
 * key catches a row changed by someone who holds only the database, and the
 * checkpoint one changed and chained again by someone who holds the app too.
 * Then the other way: the vault's entries against the last checkpoint the
 * app recorded, which catches them rewritten or cut back. Owners only: a
 * partial view of the chain cannot be verified.
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
        // From the first entry, each batch carrying on from the one before:
        // the numbers, the links, the hashes, and the app's MACs. The
        // vault's entries only by their place: the vault checks their MACs
        // over the same entries, below, and its key never leaves it.
        const result = verifyEntries(batch, {
          startSeq: nextSequence,
          startPrevHash: previousHash,
          keys: [appLogKey(ctx.chainKey)],
          chainOnly: ['vault'],
        });
        if (!result.ok) return audit(result.failedAtSeq, result.reason);
        rows += result.entries;
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
      const last = nextSequence === 0n ? null : { seq: Number(nextSequence - 1n), hash: previousHash.toString('hex') };
      return { ok: true as const, rows, head: previousHash.toString('hex'), last, recorded };
    },
    SNAPSHOT,
  );
  if (!chain.ok) return chain;
  const { rows, head, last, recorded } = chain;

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
  // The vault's entries by its key, up to the entry the app verified to:
  // only then is every entry of the prefix authenticated, by its author.
  const verified = await named(ctx, await ctx.vault.verifyLog({ through, upTo: last }));
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
): Promise<{ entries: LogEntry[]; verification: VaultVerification }> {
  if (!ctx.caller.isRootAdmin) throw forbidden('only a root admin may read the vault log');
  const page = await ctx.vault.log({ actor: formatMember(ctx.caller.principal), ...query });
  if (!page.ok) throw vaultRefused(page.refusal);
  return { entries: page.entries, verification: await named(ctx, page.verification) };
}

/**
 * The vault's verdict with its fault worded by name: the vault knows people
 * and places only by id, and `market/prod` is what an owner can act on.
 */
async function named(ctx: ApiContext, verification: LogVerification): Promise<VaultVerification> {
  if (verification.ok) return verification;
  const { fault, ...verdict } = verification;
  if (fault === undefined) return verdict;
  const known = await places(ctx.db);
  const reason = describeAccessFault(fault, {
    principal: principalName,
    place: (projectId, environmentId) => {
      const project = known.find((place) => place.id === projectId);
      if (project === undefined) return environmentId === null ? projectId : `${projectId}/${environmentId}`;
      if (environmentId === null) return project.slug;
      const environment = project.environments.find((place) => place.id === environmentId);
      return `${project.slug}/${environment?.slug ?? environmentId}`;
    },
  });
  return { ...verdict, reason };
}

/** `user:ada@acme.example` as `ada@acme.example`, `token:ci-deploy` as `ci-deploy (token)`. */
function principalName(principal: string): string {
  if (principal.startsWith('user:')) return principal.slice('user:'.length);
  if (principal.startsWith('token:')) return `${principal.slice('token:'.length)} (token)`;
  return principal;
}
