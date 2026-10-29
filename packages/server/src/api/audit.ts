import { ownsInstance, readsWholeLog, runsInstance } from '@coffre/core/access';
import { describeAccessFault, type LogVerification, type TreeVerification } from '@coffre/core/vault';
import { SNAPSHOT } from '@coffre/db/dialect';
import { missingEntry } from '@coffre/db/log';

import { actorParts, appLogKey, CHAIN_START, CHAIN_WALK, walkChain, type ChainPoint } from '../db/audit.ts';
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
  signInPage,
  talliedAfter,
  talliedAt,
  type AuditFilter,
  type Signed,
  type SignInChange,
} from '../db/queries.ts';
import { Refusal } from '../watch.ts';
import { can, canAnywhere, placeOf } from './caller.ts';
import type { ApiContext } from './context.ts';
import { badRequest, forbidden, notFound } from './errors.ts';
import { formatMember, parseMember, type Path } from './paths.ts';
import { ownerOf } from './personal.ts';

export type AuditEntryView = {
  /** Its number in the log `log` names. */
  seq: number;
  /**
   * Which log holds it: 0.14's chain, or 0.15's sealed log, where a
   * sign-in through a trust binding is a change, recorded there alone
   * (D147), and numbered among its changes and uses.
   */
  log: '0.14' | '0.15';
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
   * the sign-in itself: the CI run the issuer said it was for, from the
   * sign-in at `exchangeSeq` of the log `log` names, 0.14's `token.exchange`
   * entry or 0.15's change. What the issuer asserted, not proof of which run
   * sent the request.
   */
  run: { exchangeSeq: number; log: '0.14' | '0.15'; claims: Record<string, string | number> } | null;
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
  // A step of the app key's rotation, a hundred rows signed again; its `key.rotate` is shown.
  'key.reseal',
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
 * log records for the app key, a fingerprint of it, and those of the app
 * keys it replaced, `previousAuditChainKeys`; the vault key the vault
 * wraps under now; and each vault key's check, a known value wrapped under
 * it, as the vault wrote it. `coffre verify keys` holds a key to them on the
 * operator's machine, so the key is never sent, and nothing here answers a
 * guess: it is public material, as hard to use against a 32-byte key as the
 * log itself.
 */
export type AuditKeys = {
  /** `previous`, in the configuration's order; absent from 0.13.0's answer and earlier releases'. */
  app: { keyId: string; previous?: string[] };
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
  /**
   * Include what 0.15's sealed log alone records, merged by time: the
   * sign-ins through trust bindings (D147). A client pages such a list by
   * its `next`. Without it, 0.14's log alone, as before 0.15, which a
   * client that pages by the last entry's seq still pages whole.
   */
  sealed?: boolean;
  /**
   * Entries older than this, for paging backwards: a page's `next`, which
   * names where it stopped in both logs and lists both (`sealed`); or a
   * seq, which pages 0.14's log alone, as before 0.15.
   */
  before?: number | string;
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
 * With 0.15's log, a sign-in through a trust binding is its change alone
 * (D147): asked to (`sealed`), the page lists those too, where 0.14's
 * `token.exchange` would stand, for whoever reads the instance's entries,
 * merged by time. Each log is paged by its own order, so the page says
 * where it stopped in each: `next`, `<seq>:<at>.<change>`, `-` for a log
 * with nothing older, which the next page takes as `before`. A client
 * that does not ask pages 0.14's log by its seqs, as before 0.15: a page
 * that mixed both would leave it nothing consistent to page by.
 *
 * A page holds `limit` entries, or fewer where they list more secrets than
 * a page holds (`auditPage`): `more` says whether to page back.
 */
export async function listAudit(
  ctx: ApiContext,
  query: AuditQuery,
): Promise<{ entries: AuditEntryView[]; more: boolean; next: string | null; hidden?: HiddenCount[] }> {
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
  const before = startOf(query.before);
  if (before.seq !== undefined && before.seq !== 'done') filter.beforeSeq = before.seq;
  // Sign-ins are the instance's, of no place, and never refused; a service's alone.
  const actor = filter.actors?.find((name) => name.startsWith('token:'));
  const signIns = (query.sealed === true || typeof query.before === 'string') && filter.within === undefined && query.path === undefined
    && query.decision !== 'deny' && (filter.actors === undefined || actor !== undefined);

  const [old, sealed] = await Promise.all([
    before.seq === 'done' ? { rows: [], more: false } : auditPage(ctx.db, filter),
    signIns && before.change !== 'done' ? signInPage(ctx.db, { actor, before: before.change, limit: query.limit }) : { rows: [], more: false },
  ]);
  const page = merged(
    { read: old.rows.map((row) => ({ at: Date.parse(row.occurredAt), entry: entryView(row), below: `${row.seq}`, above: `${row.seq + 1n}` })), more: old.more },
    { read: sealed.rows.map((row) => ({ at: row.at, entry: signInView(row), below: `${row.at}.${row.number}`, above: `${row.at}.${row.number + 1n}` })), more: sealed.more },
    query.limit,
  );
  const entries = await withCredentials(ctx, page.entries);
  const result = { entries, more: page.next !== null, next: page.next };
  if (query.detail === true) return result;
  // The page's stretch of 0.14's log: from its oldest entry, or where the page before stopped when it shows none, to
  // where it started; to the first entry when nothing older is left; nothing when the page before was the last of it.
  const hidden = before.seq === 'done' ? [] : await auditActionCounts(ctx.db, filter, DETAIL_ACTIONS, page.oldStop === null ? undefined : BigInt(page.oldStop));
  // Most of what is hidden first.
  hidden.sort((a, b) => b.count - a.count || (a.action < b.action ? -1 : a.action > b.action ? 1 : 0));
  return { ...result, hidden };
}

/** A page's `next`: `<seq>:<at>.<change>`, each `-` for a log with nothing older. */
export const AUDIT_NEXT = /^(?:-?[0-9]{1,19}|-):(?:[0-9]{1,16}\.-?[0-9]{1,19}|-)$/;

/**
 * Where a page starts in each log, from the newest (undefined), or past the
 * oldest (`done`): below a seq of 0.14's; below a change of 0.15's, by its
 * `at`, then its number, as sign-ins are listed.
 */
type Point = { seq?: bigint | 'done'; change?: { at: number; number: bigint } | 'done' };

/** `before` as a point: a page's `next`, or a seq of 0.14's log alone, as clients before 0.15 page. */
function startOf(before: number | string | undefined): Point {
  if (before === undefined) return {};
  if (typeof before === 'number') return { seq: BigInt(before), change: 'done' };
  const [seq, change] = before.split(':') as [string, string];
  const [at, number] = change.split('.') as [string, string];
  return { seq: seq === '-' ? 'done' : BigInt(seq), change: change === '-' ? 'done' : { at: Number(at), number: BigInt(number) } };
}

/**
 * An entry as a log's page read it: when, by the clock its log orders by;
 * its view, or null for one no page shows; and where a page goes on from,
 * below it, or from it.
 */
type Read = { at: number; entry: AuditEntryView | null; below: string; above: string };

/**
 * The newest `limit` of two logs' entries, each read newest first, up to
 * `limit`, merged by time: none past what either has unread (`more`), which
 * could be newer. A row read that shows nothing is passed over, and the
 * page goes on past it. `next` names where it stopped in each, or null
 * when both are done; `oldStop` is where it stopped in 0.14's log, the seq
 * as text, or null when nothing older is left there.
 */
function merged(old: { read: Read[]; more: boolean }, sealed: { read: Read[]; more: boolean }, limit: number) {
  const entries: AuditEntryView[] = [];
  let [i, j] = [0, 0];
  while (entries.length < limit) {
    const [a, b] = [old.read[i], sealed.read[j]];
    if ((a === undefined && old.more) || (b === undefined && sealed.more) || (a === undefined && b === undefined)) break;
    const next = b === undefined || (a !== undefined && a.at >= b.at) ? old.read[i++]! : sealed.read[j++]!;
    if (next.entry !== null) entries.push(next.entry);
  }
  // Below the last taken of a log; or, where it took none, from the first read, as the page before stopped.
  const stop = ({ read, more }: { read: Read[]; more: boolean }, taken: number) =>
    taken < read.length || more ? (taken > 0 ? read[taken - 1]!.below : read[0]!.above) : null;
  const [oldStop, change] = [stop(old, i), stop(sealed, j)];
  return { entries, next: oldStop === null && change === null ? null : `${oldStop ?? '-'}:${change ?? '-'}`, oldStop };
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
    if (entry.action === 'token.exchange') return { ...entry, run: { exchangeSeq: entry.seq, log: entry.log, claims: runClaims(entry.metadata.run) } };
    const id = typeof entry.metadata.credentialId === 'string' ? entry.metadata.credentialId : undefined;
    const exchange = id === undefined ? undefined : exchanges.get(id);
    const token = id === undefined ? undefined : tokens.get(id);
    return {
      ...entry,
      ...(exchange === undefined ? {} : { run: { exchangeSeq: Number(exchange.seq), log: exchange.log, claims: runClaims(exchange.run) } }),
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
    log: '0.14',
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
 * A sign-in 0.15's log records, as 0.14's `token.exchange` entry showed it
 * (D147): by the service, of the vault, which made it; the credential, the
 * binding, the account's generation, the issuer and the proof, the
 * credential's end, a workload's key and hard end, and the run (`run`).
 * None for a change whose payload is not a sign-in's, which only a database
 * writer could leave under the index's condition. No request: the change's
 * id is the vault's own, which names none.
 */
function signInView(row: SignInChange): AuditEntryView | null {
  const payload = JSON.parse(row.payload) as { ref?: { kind?: unknown; id?: unknown }; generation?: unknown; expiresAt?: unknown; signIn?: Record<string, unknown> };
  const { ref, signIn } = payload;
  if (ref?.kind !== 'credential' || typeof ref.id !== 'string' || typeof signIn !== 'object' || signIn === null || !row.actor.startsWith('token:')) return null;
  const time = (value: unknown) => (typeof value === 'number' && Number.isSafeInteger(value) ? new Date(value).toISOString() : null);
  const workload = typeof signIn.jkt === 'string';
  return {
    seq: Number(row.number),
    log: '0.15',
    author: 'vault',
    occurredAt: new Date(row.at).toISOString(),
    ...actorParts(row.actor),
    action: 'token.exchange',
    decision: 'allow',
    reason: null,
    detail: false,
    subject: null,
    project: null,
    environment: null,
    key: null,
    version: null,
    secrets: null,
    operationId: null,
    relatedSeq: null,
    requestId: null,
    run: null,
    token: null,
    metadata: {
      ...(workload ? { kind: 'workload' } : {}),
      credentialId: ref.id,
      bindingId: signIn.binding,
      generation: payload.generation,
      issuer: signIn.issuer,
      proof: signIn.proof,
      expiresAt: time(payload.expiresAt),
      ...(workload ? { jkt: signIn.jkt, notAfter: time(signIn.notAfter) } : {}),
      run: signIn.run,
    },
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
    app: { keyId: appLogKey(ctx.chainKey).keyId, previous: ctx.previousChainKeys.map((key) => appLogKey(key).keyId) },
    vault: {
      current: { vaultId: current.kekId, provider: current.kekProvider },
      checks: checks.map(({ seq, kekProvider, kekId, kekVersion, bytes }) => ({ seq, vaultId: kekId, provider: kekProvider, version: kekVersion, wrapped: bytes })),
    },
  };
}

/**
 * Check the log from where the last checks left off: the app here, every
 * link and hash and its own entries' MACs, from the newest point both its
 * anchor and the vault's checkpoints vouch for, to the head, in one
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

  // Where the app last verified to, the audit watch's anchor's, outside the database and read before its
  // transaction. Without a watch nobody walked the app's MACs since the checkpoints: the check goes on from the
  // newest, and only the walk from the first entry reads what came before; so too with a store that cannot be read.
  const watched =
    query.from === undefined && ctx.watch
      ? await ctx.watch.hooks.verified(ctx.watch.context()).catch((error: Error) => {
          console.warn('the audit check goes on from the newest checkpoint: the audit anchor could not be read', error.message);
          return undefined;
        })
      : undefined;
  const own: ChainPoint | null =
    watched === undefined ? null : watched === null ? CHAIN_START : { seq: BigInt(watched.seq), hash: Buffer.from(watched.hash, 'hex') };
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
        const tallied = await latestTallied(tx);
        if (tallied !== null && tallied.checkpoint === null) return failed('vault', tallied.entry, UNREADABLE, tallied.entry - 1n);
        const signed = tallied === null ? CHAIN_START : pointOf(tallied.checkpoint!);
        // The prefix it says it signed still there, or the checkpoint is what is wrong, not the entry it names.
        if (tallied !== null && (await auditHashAt(tx, signed.seq)) !== tallied.checkpoint!.hash) {
          return failed('vault', tallied.entry, `the log up to entry ${signed.seq} is not the prefix this checkpoint signed`, signed.seq - 1n);
        }
        start = own !== null && own.seq <= signed.seq ? own : signed;
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
      const walked = await walkChain(tx, ctx, start, to === null ? {} : { to: to.at.seq, limit: Infinity });
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

/**
 * 0.15's log checked by the vault (`verifyTrees`, docs/design/0.15-plan.md
 * PR 8): the newest signed checkpoint and every entry since, by its MAC and
 * request, as the audit page checks it on every visit. With 0.14's log
 * alone, `kept` false. For whoever reads the whole log (`readsWholeLog`),
 * as `verifyAudit`.
 */
export async function verifyAuditTrees(ctx: ApiContext): Promise<TreeVerification> {
  if (!readsWholeLog(ctx.caller)) {
    throw forbidden('only those who read the whole log may verify it: an auditor, admin or owner of the whole instance');
  }
  if (ctx.vault.verifyTrees === undefined) return { kept: false };
  return ctx.vault.verifyTrees();
}

/**
 * An Owner of the whole instance accepts that entries `from` to `to` are
 * lost for good (plugins/audit-watch.ts, `acceptLoss`): the finding the
 * watch's anchor holds, of a tail cut with no backup, say, is inside the
 * range, and stays in the log; the anchor goes on past it. A person's,
 * never a token's or a service's.
 */
export async function acceptAuditLoss(ctx: ApiContext, range: { from: number; to: number }): Promise<{ resumes: number | null }> {
  if (ctx.caller.principal.type !== 'user' || !runsInstance(ctx.caller) || !ownsInstance(ctx.caller)) {
    throw forbidden('only an owner of the whole instance, as a person, may accept the loss of audit entries');
  }
  if (!ctx.watch) throw badRequest('this deployment watches no audit log: there is no anchor to move (docs/deploy.md, "The audit watch")');
  try {
    return await ctx.watch.hooks.acceptLoss(ctx.watch.context(true), range);
  } catch (error) {
    if (error instanceof Refusal) throw badRequest(error.message);
    throw error;
  }
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
