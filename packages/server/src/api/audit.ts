import { readsWholeLog, runsInstance } from '@coffre/core/access';
import { describeAccessFault, type LogVerification } from '@coffre/core/vault';
import { SNAPSHOT } from '@coffre/db/dialect';
import { missingEntry } from '@coffre/db/log';

import { actorParts, appLogKey, CHAIN_START, CHAIN_WALK, resumePoint, walkChain, type ChainPoint } from '../db/audit.ts';
import {
  auditActionCounts,
  auditHashAt,
  auditHead,
  auditPage,
  exchangesOf,
  personalTokensOf,
  latestCheckpoint,
  latestTallied,
  places,
  resolvePath,
  talliedAfter,
  talliedAt,
  type AuditFilter,
  type Signed,
} from '../db/queries.ts';
import { can, canAnywhere, placeOf } from './caller.ts';
import type { ApiContext } from './context.ts';
import { badRequest, forbidden, notFound } from './errors.ts';
import { formatMember, parseMember, type Path } from './paths.ts';
import { ownerOf } from './personal.ts';

export type AuditEntryView = {
  seq: number;
  /** Which component wrote it: the app, or the vault, which decides on keys and access. */
  author: 'app' | 'vault';
  occurredAt: string;
  actorType: 'user' | 'service' | 'system';
  actorId: string;
  /** What was done; `ACTIONS` below, and `DETAIL_ACTIONS` for the hidden ones. */
  action: string;
  decision: 'allow' | 'deny';
  /** Why a refusal: the vault's code (`no_grant`, `bulk_limit`, `tampered`, …), or the app's reason. */
  reason: string | null;
  /** A technical step or a sign-in: left out unless asked for. */
  detail: boolean;
  /** The member an access or membership entry is about: `user:ada@acme.example`, `token:ci`. */
  subject: string | null;
  project: string | null;
  environment: string | null;
  /** The secret's key, for an entry about one. */
  key: string | null;
  /** The version a read released, or a write or restore stored. */
  version: number | null;
  /**
   * For a read of several secrets at one place, logged as one entry: each
   * key, with the version released, in the order read. `key` and `version`
   * are then null. Null for an entry about one secret, or none.
   */
  secrets: { key: string | null; version: number | null }[] | null;
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
  /**
   * For an entry written on a personal token: the token, by its row's id
   * and the label its `token.create` entry logged, for "ada via token
   * 'cursor-agent'". The entry's actor is its person.
   */
  token: { id: string; label: string } | null;
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
      /**
       * The first entry this check read: what came before it was verified by
       * the checks the checkpoints and heartbeats record, and is pinned by the
       * hash the newest checkpoint signed. 0 for a check from the first entry.
       */
      from: number;
      /**
       * Entries after `through` this check did not reach, no more than one
       * walk a request: 0 once the checkpoints keep up with the log, as they
       * do but after an upgrade from 0.10.0, for a beat or a few.
       */
      remaining: number;
      /**
       * For a stretch of the walk from the first entry (`from` asked for):
       * the checkpoint the next stretch goes on from, as `from`, its entry
       * and that entry's hash (`9412:3f9a…`), or null for the last, from the
       * newest checkpoint. The whole log is verified only
       * when the last says `remaining` 0: past the newest checkpoint, a
       * stretch goes no further than one walk, and none goes on from there.
       */
      next?: string | null;
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
  | { ok: true; entries: number; pending?: number; through?: number }
  | { ok: false; failedAtSeq: number | null; reason: string };

export type AuditQuery = {
  path?: Path;
  /** `user:ada@acme.example`, `token:ci-deploy`, or a system actor's name. */
  actor?: string;
  decision?: 'allow' | 'deny';
  /** Include the detail entries, `DETAIL_ACTIONS`. */
  detail?: boolean;
  /** Entries older than this seq, for paging backwards. */
  before?: number;
  limit: number;
};

/**
 * Newest first, both authors. Whoever reads the whole log reads everything:
 * an Auditor, Admin or Owner whose scope narrows nothing (`readsWholeLog`). Anyone else reads the projects and environments where
 * they hold `audit.read`, by a grant or their instance role, and nothing
 * else: an entry about no place, such as a sign-in or a member's removal,
 * is the instance's, and theirs alone.
 *
 * Without `detail`, the page says what it left out: the detail entries the
 * same filters match in the page's stretch of the log, by action. A page's
 * stretch runs from its oldest entry, or the log's first on the last page,
 * up to where it started, the head or `before`: pages tile the log, and
 * each hidden entry is counted on exactly one.
 *
 * A page holds `limit` entries, or fewer where they list more secrets than
 * a page holds (`auditPage`): `more` says whether to page back, `before`
 * the oldest seq on it.
 */
export async function listAudit(
  ctx: ApiContext,
  query: AuditQuery,
): Promise<{ entries: AuditEntryView[]; more: boolean; hidden?: HiddenCount[] }> {
  const filter: AuditFilter = {
    decision: query.decision,
    excludeActions: query.detail === true ? undefined : DETAIL_ACTIONS,
    limit: query.limit,
  };
  const { caller } = ctx;
  if (!readsWholeLog(caller)) {
    const projectIds: string[] = [];
    const environmentIds: string[] = [];
    const except: string[] = [];
    // A project's whole log where they read all of it, else each environment's they read, as places are now; in a
    // project they read, but for an environment whose log their role leaves out there, a protected one.
    if (canAnywhere(caller, 'audit.read')) {
      for (const project of await places(ctx.db)) {
        const unread = project.environments.filter((environment) => !can(caller, 'audit.read', placeOf(project, environment))).map((environment) => environment.id);
        if (can(caller, 'audit.read', placeOf(project, null))) {
          projectIds.push(project.id);
          except.push(...unread);
        } else environmentIds.push(...project.environments.filter((environment) => !unread.includes(environment.id)).map((environment) => environment.id));
      }
    }
    if (projectIds.length === 0 && environmentIds.length === 0) {
      throw forbidden('you do not hold audit.read on any project');
    }
    filter.within = { projectIds, environmentIds, except };
  }
  if (query.path !== undefined) {
    // A deleted place's entries stay readable by its tombstone's slug.
    // `market/dev@me`: the caller's own personal config of dev.
    const place = await resolvePath(ctx.db, query.path, { tombstones: true, owner: ownerOf(ctx) });
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
      : ['user', 'token', 'system'].map((prefix) => `${prefix}:${query.actor}`).concat(query.actor);
  }
  if (query.before !== undefined) filter.beforeSeq = BigInt(query.before);

  const { rows, more } = await auditPage(ctx.db, filter);
  const entries = await withCredentials(ctx, rows.map(entryView));
  if (query.detail === true) return { entries, more };
  const last = more ? rows[rows.length - 1]!.seq : undefined;
  const hidden = await auditActionCounts(ctx.db, filter, DETAIL_ACTIONS, last);
  // Most of what is hidden first.
  hidden.sort((a, b) => b.count - a.count || (a.action < b.action ? -1 : a.action > b.action ? 1 : 0));
  return { entries, more, hidden };
}

/**
 * What each entry was written on, when its request came in on a credential
 * it names: the run, for one a trust binding issued; the token, for a
 * personal token. One read of each for the page.
 */
async function withCredentials(ctx: ApiContext, entries: AuditEntryView[]): Promise<AuditEntryView[]> {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const ids = [...new Set(entries.flatMap((entry) => {
    const id = entry.metadata.credentialId;
    return entry.action !== 'token.exchange' && typeof id === 'string' && UUID.test(id) ? [id] : [];
  }))];
  const [exchanges, tokens] = await Promise.all([exchangesOf(ctx.db, ids), personalTokensOf(ctx.db, ids)]);
  return entries.map((entry) => {
    if (entry.action === 'token.exchange') return { ...entry, run: { exchangeSeq: entry.seq, claims: runClaims(entry.metadata.run) } };
    const id = typeof entry.metadata.credentialId === 'string' ? entry.metadata.credentialId : undefined;
    const exchange = id === undefined ? undefined : exchanges.get(id);
    const token = id === undefined ? undefined : tokens.get(id);
    return {
      ...entry,
      ...(exchange === undefined ? {} : { run: { exchangeSeq: Number(exchange.seq), claims: runClaims(exchange.run) } }),
      ...(token === undefined ? {} : { token: { id: id!, label: token.label } }),
    };
  });
}

function runClaims(run: unknown): Record<string, string | number> {
  if (typeof run !== 'object' || run === null) return {};
  return Object.fromEntries(Object.entries(run).filter((pair): pair is [string, string | number] => typeof pair[1] === 'string' || typeof pair[1] === 'number'));
}

const DETAIL = new Set<string>(DETAIL_ACTIONS);

function entryView(row: Awaited<ReturnType<typeof auditPage>>['rows'][number]): AuditEntryView {
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
    secrets: readSecrets(row.action, metadata),
    operationId: row.operationId,
    relatedSeq: row.relatedSeq === null ? null : Number(row.relatedSeq),
    requestId: row.requestId,
    run: null,
    token: null,
    metadata,
  };
}

/**
 * The secrets a read of several lists (`readsByPlace` in the vault), in its
 * order, by the key each path ends in: null for a version that named no
 * secret, refused as `bad_claim`.
 */
function readSecrets(action: string, metadata: Record<string, unknown>): AuditEntryView['secrets'] {
  if (action !== 'secret.read' || !Array.isArray(metadata.secrets)) return null;
  return metadata.secrets.map((secret: unknown) => {
    const { subject, version } = (secret ?? {}) as { subject?: unknown; version?: unknown };
    return { key: typeof subject === 'string' ? subject.split('/').at(-1)! : null, version: typeof version === 'number' ? version : null };
  });
}

/** What the keys are checked against (`AuditKeys`): for those who run the instance, whose keys they are. */
export async function auditKeys(ctx: ApiContext): Promise<AuditKeys> {
  if (!runsInstance(ctx.caller)) {
    throw forbidden('only an admin or owner of the whole instance may read what the keys are checked against');
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
 * Check the log from where the last checks left off: the app here, every
 * link and hash and its own entries' MACs, from the newest point both its
 * heartbeats and the vault's checkpoints vouch for, to the head, in one
 * read-only snapshot so appends made meanwhile cannot look like tampering;
 * then the vault, its own entries by its key over the same entries, every
 * checkpoint among them against the prefix it signed, its key batches
 * accounted for, and the members and grants replayed on from its newest
 * checkpoint's tally. Anyone who can insert a row can link it to the chain,
 * so an entry whose author did not write it fails one check or the other.
 * What came before is pinned by the hash the newest checkpoint signed, and
 * every entry of it is there, by one count of the log's index.
 *
 * So a check reads what was written since the last beat, five minutes'
 * worth, however long the log, and never more than one walk
 * (`CHAIN_WALK`): `remaining` says what it left for the checkpoints to
 * catch up with.
 *
 * With `from`, a stretch of the walk from the first entry instead, which
 * checks again what the checkpoints vouch for: from the first entry, or
 * the checkpoint the stretch before ended at, through the furthest
 * checkpoint one walk reaches, the newest once within reach, whose tally the
 * vault's walk must come to; then from the newest to the head, as above.
 * `next` says where the next stretch goes on. For whoever reads the whole
 * log (`readsWholeLog`): a part of the chain cannot be verified.
 */
export async function verifyAudit(ctx: ApiContext, query: { from?: string } = {}): Promise<AuditVerification> {
  if (!readsWholeLog(ctx.caller)) {
    throw forbidden('only those who read the whole log may verify it: an auditor, admin or owner of the whole instance');
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
      // Where the app's walk starts, where the vault's does, and, for a stretch, the checkpoint it ends at.
      let start: ChainPoint;
      let vaultFrom: number | 'start';
      let to: { entry: bigint; at: ChainPoint; hash: string } | null = null;
      if (query.from === undefined) {
        // From the older of where the app's MACs and the vault's tally were last verified to.
        const [own, tallied] = await Promise.all([resumePoint(tx, ctx.chainKey), latestTallied(tx)]);
        if (tallied !== null && tallied.checkpoint === null) return failed('vault', tallied.entry, UNREADABLE, tallied.entry - 1n);
        const signed = tallied === null ? CHAIN_START : pointOf(tallied.checkpoint!);
        // The prefix it says it signed still there, or the checkpoint is what is wrong, not the entry it names.
        if (tallied !== null && (await auditHashAt(tx, signed.seq)) !== tallied.checkpoint!.hash) {
          return failed('vault', tallied.entry, `the log up to entry ${signed.seq} is not the prefix this checkpoint signed`, signed.seq - 1n);
        }
        start = own.seq <= signed.seq ? own : signed;
        vaultFrom = tallied === null ? 'start' : Number(tallied.entry);
      } else {
        // The checkpoint the stretch before ended at, as it was then, by its entry's hash: what it held to the log
        // is what this one starts from, not anything put in its place since.
        const [entry, hash] = query.from === 'start' ? [null, null] : [BigInt(query.from.split(':')[0]!), query.from.split(':')[1]!];
        const anchor = entry === null ? null : await talliedAt(tx, entry);
        // Named with its hash, it was there for the stretch before: gone now, it was cut. One there by that hash
        // that keeps no tally was never a stretch's end: the request named it, not a walk.
        if (entry !== null && anchor === null) {
          const stored = await auditHashAt(tx, entry);
          if (stored === hash) throw badRequest(`entry ${entry} is not a checkpoint that keeps a tally`);
          return failed('app', entry, `${stored === null ? 'cut' : 'changed'} since the stretch before held its tally to the log`, entry - 1n);
        }
        if (anchor !== null && anchor.hash !== hash) return failed('app', entry, 'changed since the stretch before held its tally to the log', entry! - 1n);
        if (anchor !== null && anchor.checkpoint === null) return failed('vault', entry, UNREADABLE, entry! - 1n);
        start = anchor === null ? CHAIN_START : pointOf(anchor.checkpoint!);
        vaultFrom = entry === null ? 'start' : Number(entry);
        // The furthest checkpoint one walk reaches, or the next however far it is; none, and this is the last stretch.
        const later = await talliedAfter(tx, entry ?? -1n, CHAIN_WALK / 2 + 1);
        const target = later.filter(({ signs }) => signs - start.seq <= CHAIN_WALK).at(-1) ?? later[0];
        const ends = target === undefined ? null : await talliedAt(tx, target.entry);
        if (target !== undefined && ends?.checkpoint === null) return failed('vault', target.entry, UNREADABLE, target.signs);
        if (target !== undefined && ends !== null) to = { entry: target.entry, at: pointOf(ends.checkpoint!), hash: ends.hash };
      }
      // Every entry before where it starts still there: one count, and only a log with a gap pays to find where.
      const gap = await missingEntry(tx, start.seq);
      if (gap !== null) return failed('app', gap.found, `sequence gap: expected seq ${gap.expected}, found ${gap.found}`, gap.expected - 1n);
      // A stretch runs to its checkpoint however far that is: one more than a walk apart only when the
      // checkpoints stopped for a while, and the vault cannot end a stretch anywhere else.
      const walked = await walkChain(tx, ctx.chainKey, start, to === null ? {} : { to: to.at.seq, limit: Infinity });
      if (!walked.ok) return failed('app', walked.failedAtSeq, walked.reason, walked.through);
      // Whether it ends at the hash the checkpoint signed is the vault's to say, once it has checked its own entries.
      const { at } = walked;
      // A stretch that ran out of entries before its checkpoint's prefix found them missing.
      if (to !== null && !walked.done) {
        return failed('app', at.seq + 1n, `sequence gap: expected seq ${at.seq + 1n}, found none before entry ${to.at.seq}`, at.seq);
      }
      // A log that runs past its head is broken wherever the walk stopped.
      if (at.seq >= head.nextSeq) {
        return failed('app', head.nextSeq, `the log runs to seq ${at.seq + 1n} but the chain head only expects ${head.nextSeq}`, head.nextSeq - 1n);
      }
      if (to === null && walked.done) {
        if (at.seq + 1n !== head.nextSeq) {
          const missing = head.nextSeq - at.seq - 1n;
          return failed(
            'app',
            at.seq + 1n,
            missing > 0n
              ? `the log ends at seq ${at.seq + 1n} but the chain head expects ${head.nextSeq}: ${missing} ${missing === 1n ? 'entry has' : 'entries have'} been removed from the end`
              : `the log runs to seq ${at.seq + 1n} but the chain head only expects ${head.nextSeq}`,
            at.seq,
          );
        }
        if (!at.hash.equals(head.headHash)) return failed('app', at.seq + 1n, 'the recomputed head does not match the stored chain head', at.seq);
      }
      return {
        ok: true as const,
        start,
        last: at.seq < 0n ? null : { seq: Number(at.seq), hash: at.hash.toString('hex') },
        remaining: Number(head.nextSeq - 1n - at.seq),
        vaultFrom,
        to,
        // In the same snapshot: the newest checkpoint, which the vault checks below.
        checkpoint: await latestCheckpoint(tx),
      };
    },
    SNAPSHOT,
  );
  if (!chain.ok) return chain;

  // The vault's entries by its key, over the same stretch, up to the entry the app verified to: only then is
  // every entry of it authenticated, by its author.
  const verified = await named(ctx, await ctx.vault.verifyLog({
    upTo: chain.last,
    from: chain.vaultFrom,
    ...(chain.to === null ? {} : { to: Number(chain.to.entry) }),
  }));
  const { checkpoint } = chain;
  if (!verified.ok) {
    // The app verified the chain over the stretch, so the vault's fault is at the entry it names, or in no entry at all.
    const last = chain.last === null ? null : BigInt(chain.last.seq);
    return failed('vault', verified.failedAtSeq, verified.reason, verified.failedAtSeq === null ? last : BigInt(verified.failedAtSeq) - 1n);
  }
  // Verified as far as both got: the vault's own walk stops short of the app's head only when it had more than a
  // walk of its own entries to read since its tally.
  const through = chain.last === null ? null : Math.min(chain.last.seq, verified.through ?? chain.last.seq);
  return {
    ok: true,
    through,
    entries: (through ?? -1) + 1,
    from: Number(chain.start.seq + 1n),
    remaining: chain.remaining + (chain.last?.seq ?? -1) - (through ?? -1),
    ...(query.from === undefined ? {} : { next: chain.to === null ? null : `${chain.to.entry}:${chain.to.hash}` }),
    checkpoint: checkpoint === null ? null : { seq: checkpoint.seq, signedAt: checkpoint.signedAt },
    ...(verified.pending === undefined ? {} : { pending: verified.pending }),
  };
}

/** Why a check stops at a checkpoint whose entry names no prefix: the vault never wrote it so. */
const UNREADABLE = "not a checkpoint of the vault's that keeps a tally: it names no prefix it signed";

/** Where a checkpoint's prefix ends, as a walk of the chain names it. */
function pointOf(checkpoint: Signed): ChainPoint {
  return { seq: BigInt(checkpoint.seq), hash: Buffer.from(checkpoint.hash, 'hex') };
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
