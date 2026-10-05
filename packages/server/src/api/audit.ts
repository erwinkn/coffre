import { grantKind, roleGrants } from '@coffre/core/access';
import { GENESIS_HASH, verifyEntries } from '@coffre/core/audit';
import { describeAccessFault, type LogVerification } from '@coffre/core/vault';
import { SNAPSHOT } from '@coffre/db/dialect';

import { actorParts, appLogKey } from '../db/audit.ts';
import {
  auditActionCounts,
  auditHead,
  auditPage,
  auditRange,
  exchangesOf,
  latestCheckpoint,
  places,
  resolvePath,
  type AuditFilter,
} from '../db/queries.ts';
import type { ApiContext } from './context.ts';
import { forbidden, notFound } from './errors.ts';
import { formatMember, parseMember, type Path } from './paths.ts';

/** Entries the full check reads at once: some ten megabytes, within a Worker's memory, and few round trips. */
const VERIFY_BATCH = 10_000;

export type AuditEntryView = {
  seq: number;
  /** Which component wrote it: the app, or the vault, which decides on keys and access. */
  author: 'app' | 'vault';
  occurredAt: string;
  actorType: 'user' | 'service' | 'system';
  /** A sync acts as the system, with `sync:<id>` as its id. */
  actorId: string;
  /** What was done; `ACTIONS` below, and `DETAIL_ACTIONS` for the hidden ones. */
  action: string;
  decision: 'allow' | 'deny';
  /** Why a refusal: the vault's code (`no_grant`, `bulk_limit`, `tampered`, …), or the app's reason. */
  reason: string | null;
  /** A technical step or a sign-in: left out unless asked for. */
  detail: boolean;
  /** The member an access or membership entry is about: `user:ada@acme.example`, `token:ci`, `sync:…`. */
  subject: string | null;
  project: string | null;
  environment: string | null;
  /** The secret's key, for an entry about one. */
  key: string | null;
  /** The version a read released, or a write or restore stored. */
  version: number | null;
  /** One id for everything one action did: a reveal's reads, a write's versions, an access change. */
  operationId: string | null;
  /** An earlier entry this one follows from, such as the `key.wrap` behind a `secret.write`. */
  relatedSeq: number | null;
  /** The request that wrote it. */
  requestId: string | null;
  /**
   * For an entry written on a credential a trust binding issued, and for
   * the exchange itself: the CI run the issuer said it was for, from the
   * `token.exchange` entry at `exchangeSeq`. What the issuer asserted, not
   * proof of which run sent the request.
   */
  run: { exchangeSeq: number; claims: Record<string, string | number> } | null;
  metadata: Record<string, unknown>;
};

/**
 * Technical steps and sign-ins: in the log and its chain like everything
 * else, but not what someone did with secrets or access, so a page leaves
 * them out unless asked.
 */
export const DETAIL_ACTIONS = [
  'sign_in',
  'sign_out',
  'token.create',
  'token.revoke',
  'device.approve',
  'device.deny',
  // An MCP client's code redeemed, or its tokens refreshed: every hour of its use.
  'mcp.token',
  // A read-only tool's call through MCP that went through. Its refusals, and every change, are `mcp.call`, shown.
  'mcp.read',
  'account.link',
  'account.unlink',
  'key.wrap',
  'key.rewrap',
  // The vault's seal of a reference: the app's `secret.reference` says it in words.
  'reference.create',
  'key.intent',
  'key.check',
  'sync.run',
  'audit.heartbeat',
  'audit.checkpoint',
] as const;

/** Detail entries a page left out, by action. */
export type HiddenCount = { action: string; count: number };

export type AuditVerification =
  | {
      ok: true;
      /** The last entry both authors verified, each its own by its key: "verified through 5170". */
      through: number | null;
      entries: number;
      /** The newest prefix the vault signed, which the log still holds; null before the first. */
      checkpoint: { seq: number; signedAt: string } | null;
      /** Key batches at a key service still under way: accounted for once they finish. */
      pending?: number;
    }
  | {
      ok: false;
      /** The last entry verified: the one before the fault, or the newest when the fault is in no entry. */
      through: number | null;
      /** The entry where it breaks, or null when the fault is not at one, such as a member's row. */
      failedAtSeq: number | null;
      /** Whose check found it: the app's, of its entries and the chain, or the vault's, of its own and its rows. */
      author: 'app' | 'vault';
      reason: string;
    };

/**
 * What an escrowed key is checked against, and nothing more: the id the
 * log records for the app key, a fingerprint of it; the vault key the vault
 * wraps under now; and each vault key's check, a known value wrapped under
 * it, as the vault wrote it. `coffre verify keys` holds a key to them on the
 * operator's machine, so the key is never sent, and nothing here answers a
 * guess: it is public material, as hard to use against a 32-byte key as the
 * log itself.
 */
export type AuditKeys = {
  app: { keyId: string };
  vault: {
    current: { vaultId: string; provider: string };
    /** Newest first: the vault ID each names, and the check value wrapped under it, base64. */
    checks: { seq: number; vaultId: string; provider: string; version: string; wrapped: string }[];
  };
};

/** The vault's verdict as the API gives it, its fault already in words. */
export type VaultVerification =
  | { ok: true; entries: number; pending?: number }
  | { ok: false; failedAtSeq: number | null; reason: string };

export type AuditQuery = {
  path?: Path;
  /** `user:ada@acme.example`, `token:ci-deploy`, or a raw actor id such as `sync:…`. */
  actor?: string;
  decision?: 'allow' | 'deny';
  /** Include the detail entries, `DETAIL_ACTIONS`. */
  detail?: boolean;
  /** Entries older than this seq, for paging backwards. */
  before?: number;
  limit: number;
};

/**
 * Newest first, both authors. Owners read everything; anyone else reads the
 * projects and environments where they hold `audit.read`, and nothing else:
 * an entry about no place, such as a member's removal, is owners' alone.
 *
 * Without `detail`, the page says what it left out: the detail entries the
 * same filters match in the page's stretch of the log, by action. A page's
 * stretch runs from its oldest entry, or the log's first on the last page,
 * up to where it started, the head or `before`: pages tile the log, and
 * each hidden entry is counted on exactly one.
 */
export async function listAudit(
  ctx: ApiContext,
  query: AuditQuery,
): Promise<{ entries: AuditEntryView[]; hidden?: HiddenCount[] }> {
  const filter: AuditFilter = {
    decision: query.decision,
    excludeActions: query.detail === true ? undefined : DETAIL_ACTIONS,
    limit: query.limit,
  };
  const { caller } = ctx;
  if (!caller.isOwner) {
    const readable = caller.grants.filter((grant) => roleGrants(grant.role, 'audit.read'));
    const projectIds = readable.flatMap((grant) => (grantKind(grant) === 'project' ? [grant.projectId!] : []));
    const environmentIds = readable.flatMap((grant) => (grantKind(grant) === 'environment' ? [grant.environmentId!] : []));
    // A grant on every project reads each project's log, or each environment's of its slug, as they are now.
    const everywhere = readable.filter((grant) => grantKind(grant) === 'every-project');
    if (everywhere.length > 0) {
      for (const project of await places(ctx.db)) {
        if (everywhere.some((grant) => grant.environmentSlug === null)) projectIds.push(project.id);
        for (const environment of project.environments) {
          if (everywhere.some((grant) => grant.environmentSlug === environment.slug)) environmentIds.push(environment.id);
        }
      }
    }
    if (projectIds.length === 0 && environmentIds.length === 0) {
      throw forbidden('you do not hold audit.read on any project');
    }
    filter.within = { projectIds, environmentIds };
  }
  if (query.path !== undefined) {
    // A deleted place's entries stay readable by its tombstone's slug.
    const place = await resolvePath(ctx.db, query.path, { tombstones: true });
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
  const entries = await withRuns(ctx, rows.map(entryView));
  if (query.detail === true) return { entries };
  const last = rows.length < query.limit ? undefined : rows[rows.length - 1].seq;
  const hidden = await auditActionCounts(ctx.db, filter, DETAIL_ACTIONS, last);
  // Most of what is hidden first.
  hidden.sort((a, b) => b.count - a.count || (a.action < b.action ? -1 : a.action > b.action ? 1 : 0));
  return { entries, hidden };
}

/** Each entry's run, when it was written on a credential a trust binding issued: one read for the page. */
async function withRuns(ctx: ApiContext, entries: AuditEntryView[]): Promise<AuditEntryView[]> {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const ids = [...new Set(entries.flatMap((entry) => {
    const id = entry.metadata.credentialId;
    return entry.action !== 'token.exchange' && typeof id === 'string' && UUID.test(id) ? [id] : [];
  }))];
  const exchanges = await exchangesOf(ctx.db, ids);
  return entries.map((entry) => {
    if (entry.action === 'token.exchange') return { ...entry, run: { exchangeSeq: entry.seq, claims: runClaims(entry.metadata.run) } };
    const exchange = typeof entry.metadata.credentialId === 'string' ? exchanges.get(entry.metadata.credentialId) : undefined;
    return exchange === undefined ? entry : { ...entry, run: { exchangeSeq: Number(exchange.seq), claims: runClaims(exchange.run) } };
  });
}

function runClaims(run: unknown): Record<string, string | number> {
  if (typeof run !== 'object' || run === null) return {};
  return Object.fromEntries(Object.entries(run).filter((pair): pair is [string, string | number] => typeof pair[1] === 'string' || typeof pair[1] === 'number'));
}

const DETAIL = new Set<string>(DETAIL_ACTIONS);

function entryView(row: Awaited<ReturnType<typeof auditPage>>[number]): AuditEntryView {
  const metadata = JSON.parse(row.metadata) as Record<string, unknown>;
  // The vault names a secret by its path, the app by its key.
  const path = typeof metadata.subject === 'string' ? metadata.subject : null;
  const key = row.key ?? (typeof metadata.key === 'string' ? metadata.key : path?.split('/').at(-1) ?? null);
  return {
    seq: Number(row.seq),
    author: row.author as 'app' | 'vault',
    occurredAt: row.occurredAt,
    ...actorParts(row.actor),
    action: row.action,
    decision: row.decision as 'allow' | 'deny',
    reason: row.code ?? (typeof metadata.reason === 'string' ? metadata.reason : null),
    detail: DETAIL.has(row.action),
    subject: row.subjectPrincipal,
    project: row.project,
    environment: row.environment,
    key,
    version: typeof metadata.version === 'number' ? metadata.version : null,
    operationId: row.operationId,
    relatedSeq: row.relatedSeq === null ? null : Number(row.relatedSeq),
    requestId: row.requestId,
    run: null,
    metadata,
  };
}

/** What the keys are checked against (`AuditKeys`): owners and root admins only, as verification is. */
export async function auditKeys(ctx: ApiContext): Promise<AuditKeys> {
  if (!ctx.caller.isOwner) {
    throw forbidden('only a root admin or instance owner may read what the keys are checked against');
  }
  const { current, checks } = await ctx.vault.keyChecks();
  return {
    app: { keyId: appLogKey(ctx.chainKey).keyId },
    vault: {
      current: { vaultId: current.kekId, provider: current.kekProvider },
      checks: checks.map(({ seq, kekProvider, kekId, kekVersion, bytes }) => ({ seq, vaultId: kekId, provider: kekProvider, version: kekVersion, wrapped: bytes })),
    },
  };
}

/**
 * Check the whole log: the app here, every link and hash and its own
 * entries' MACs, from the first entry to the head, in one read-only
 * snapshot so appends made meanwhile cannot look like tampering; then the
 * vault, its own entries by its key over the same entries, every checkpoint
 * against the prefix it signed, its key batches accounted for, and the
 * members and grants replayed. Anyone who can insert a row can link it to
 * the chain, so an entry whose author did not write it fails one check or
 * the other. Owners only: a partial view of the chain cannot be verified.
 */
export async function verifyAudit(ctx: ApiContext): Promise<AuditVerification> {
  if (!ctx.caller.isOwner) {
    throw forbidden('only a root admin or instance owner may verify the complete audit chain');
  }
  const failed = (author: 'app' | 'vault', failedAtSeq: number | bigint | null, reason: string, through: bigint | null) => ({
    ok: false as const,
    through: through === null || through < 0n ? null : Number(through),
    failedAtSeq: failedAtSeq === null ? null : Number(failedAtSeq),
    author,
    reason,
  });

  const chain = await ctx.db.transaction(
    async (tx) => {
      const head = await auditHead(tx);
      if (head === null) return failed('app', 0, 'audit_chain_head is missing, so the length of the log cannot be established', null);
      let previousHash = GENESIS_HASH;
      let nextSequence = 0n;
      let entries = 0;
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
        if (!result.ok) {
          // Verified through the entry read before the faulty one: with a gap, not the seq before it.
          const at = batch.findIndex((row) => row.seq === result.failedAtSeq);
          return failed('app', result.failedAtSeq, result.reason, at > 0 ? batch[at - 1].seq : nextSequence - 1n);
        }
        entries += result.entries;
        previousHash = result.head;
        nextSequence = result.nextSeq;
        if (batch.length < VERIFY_BATCH) break;
      }
      if (nextSequence !== head.nextSeq) {
        const missing = head.nextSeq - nextSequence;
        return failed(
          'app',
          nextSequence,
          missing > 0n
            ? `the log ends at seq ${nextSequence} but the chain head expects ${head.nextSeq}: ${missing} ${missing === 1n ? 'entry has' : 'entries have'} been removed from the end`
            : `the log runs to seq ${nextSequence} but the chain head only expects ${head.nextSeq}`,
          nextSequence - 1n,
        );
      }
      if (!previousHash.equals(head.headHash)) {
        return failed('app', nextSequence, 'the recomputed head does not match the stored chain head', nextSequence - 1n);
      }
      const last = nextSequence === 0n ? null : { seq: Number(nextSequence - 1n), hash: previousHash.toString('hex') };
      // In the same snapshot: the newest checkpoint of the prefix just verified, which the vault checks below.
      return { ok: true as const, entries, last, checkpoint: await latestCheckpoint(tx) };
    },
    SNAPSHOT,
  );
  if (!chain.ok) return chain;

  // The vault's entries by its key, up to the entry the app verified to:
  // only then is every entry of the prefix authenticated, by its author.
  const verified = await named(ctx, await ctx.vault.verifyLog({ upTo: chain.last }));
  const { checkpoint } = chain;
  if (!verified.ok) {
    // The app verified the chain whole, so the vault's fault is at the entry it names, or in no entry at all.
    const last = chain.last === null ? null : BigInt(chain.last.seq);
    return failed('vault', verified.failedAtSeq, verified.reason, verified.failedAtSeq === null ? last : BigInt(verified.failedAtSeq) - 1n);
  }
  return {
    ok: true,
    through: chain.last?.seq ?? null,
    entries: chain.entries,
    checkpoint: checkpoint === null ? null : { seq: checkpoint.seq, signedAt: checkpoint.signedAt },
    ...(verified.pending === undefined ? {} : { pending: verified.pending }),
  };
}

/**
 * The vault's verdict with its fault worded by name: the vault knows people
 * and places only by id, and `market/prod` is what an owner can act on.
 */
async function named(ctx: ApiContext, verification: LogVerification): Promise<VaultVerification> {
  if (verification.ok) return verification;
  const { fault, ...verdict } = verification;
  if (fault === undefined) return verdict;
  const known = await places(ctx.db, { tombstones: true });
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
