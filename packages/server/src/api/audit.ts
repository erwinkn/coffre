import { ownsInstance, readsWholeLog, runsInstance } from '@coffre/core/access';
import { describeAccessFault, useOfCode, type LogVerification, type ReadsVerification, type TreeVerification } from '@coffre/core/vault';
import { SNAPSHOT } from '@coffre/db/dialect';
import { missingEntry } from '@coffre/db/log';

import { actorParts, appLogKey, CHAIN_START, CHAIN_WALK, walkChain, type ChainPoint } from '../db/audit.ts';
import {
  auditActionCounts,
  auditHashAt,
  auditHead,
  auditPage,
  isMember,
  latestCheckpoint,
  latestTallied,
  originsOf,
  places,
  resolvePath,
  sealedHidden,
  sealedPage,
  sealedReach,
  talliedAfter,
  talliedAt,
  type AuditFilter,
  type ChangePoint,
  type CredentialOrigin,
  type RecordedChange,
  type Signed,
} from '../db/queries.ts';
import { readsPage, readsStanding, type ListedRead } from '../db/reads.ts';
import { Refusal } from '../watch.ts';
import { can, canAnywhere, placeOf } from './caller.ts';
import { traceFields, type ApiContext } from './context.ts';
import { keeps015 } from './changes.ts';
import { ApiError, badRequest, forbidden, notFound } from './errors.ts';
import { formatMember, parseMember, type Path } from './paths.ts';
import { ownerOf } from './personal.ts';

export type AuditEntryView = {
  /** Its number in the log `log` names. */
  seq: number;
  /**
   * Which log holds it: 0.14's chain, or 0.15's sealed log, where a
   * sign-in through a trust binding, and a token's issue, revoke or
   * sign-out, is a change, recorded there alone (D147), and a read is a use
   * (R53, T166), each numbered among its changes and uses.
   */
  log: '0.14' | '0.15';
  /**
   * For an entry of 0.15's log: the vault does not vouch for it, its MAC not
   * holding over what it says. It was written, or edited, around coffre.
   * Absent for every other, and for 0.14's, which its chain's check covers.
   */
  forged?: true;
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
   * reads, each a use (T166); the sign-ins through trust bindings, and the
   * tokens' issues, revokes and sign-outs, which are detail (D147). A
   * client pages such a list by its `next`. Without it, 0.14's log alone,
   * as before 0.15, which a client that pages by the last entry's seq
   * still pages whole.
   */
  sealed?: boolean;
  /**
   * With `sealed`, count what the page leaves out (`hidden`), which costs a
   * read of each log's stretch: a page counts no more than `HIDDEN_COUNTED`
   * of 0.15's records, and stops showing entries where it reaches the last
   * it counts, so a caller that asks follows `next` though a page show
   * nothing. Without `sealed`, a page counts, as before 0.15.
   */
  hidden?: boolean;
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
 * Without `detail`, the page says what it left out, `hidden` (asked for,
 * with `sealed`): the detail entries the same filters match in the page's
 * stretch of the log, by action. A page's
 * stretch runs from its oldest entry, or the log's first on the last page,
 * up to where it started, the head or `before`: pages tile the log, and
 * each hidden entry is counted on exactly one.
 *
 * With 0.15's log, a sign-in through a trust binding, and a token's issue,
 * revoke or sign-out, is its change alone (D147): asked to (`sealed`), the
 * page lists those too, where 0.14's `token.exchange`, `token.create`,
 * `token.revoke` and `sign_out` would stand, for whoever reads the
 * instance's entries, merged by time; the last three are detail, and
 * counted where hidden, over the page's stretch of that log too. A read is
 * its use alone (R53): asked to, the page lists each where 0.14's
 * `secret.read` would stand, at the places the caller reads and the path
 * names, by the members asked for (T166). Every entry of 0.15's log a page
 * lists, the vault vouches for, or the page marks it `forged`. Each log
 * is paged by its own order, so the page says where it stopped in each:
 * `next`, `<seq>:<at>.<change>`, or `<seq>:<at>` where it stopped at a
 * time, `-` for a log with nothing older, which the next page takes as
 * `before`. A client that does not ask pages 0.14's log by its seqs, as
 * before 0.15: a page that mixed both would leave it nothing consistent to
 * page by.
 *
 * A page holds `limit` entries, or fewer where they list more secrets than
 * a page holds (`auditPage`): `more` says whether to page back.
 */
export async function listAudit(
  ctx: ApiContext,
  query: AuditQuery,
): Promise<{ entries: AuditEntryView[]; more: boolean; next: string | null; hidden?: HiddenCount[]; reads?: ReadsListed; readsOmitted?: ReadsOmitted }> {
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
  // What 0.15's log alone records is the instance's, of no place, never refused, and some member's.
  const recorded = (query.sealed === true || typeof query.before === 'string') && filter.within === undefined && query.path === undefined
    && query.decision !== 'deny' && (filter.actors === undefined || filter.actors.some(isMember))
    && before.change !== 'done';
  const start = before.change === 'done' ? undefined : before.change;
  const detail = query.detail === true;
  // What it leaves out, counted: as before 0.15 without `sealed`; with it, when asked. No first-party page shows the
  // counts, and one that does not ask reads nothing for them, and always fills with what it shows.
  const counted = !detail && (query.sealed !== true && typeof query.before !== 'string' ? true : query.hidden === true);

  // The reads 0.15's log records, each a use, as the vault's projector lists them (T166), and how far they are listed:
  // on the whole log and by member, as its other records, to whoever reads the whole log; and to anyone, their own.
  // Not at a place: in 0.15 no page of a project, environment or key lists them (D160), and a reader of some places
  // sees no one's but their own. Never a refusal (one the vault refuses before it writes a use is the app's entry), nor
  // below its log's end.
  const own = filter.actors !== undefined && filter.actors.length === 1 && filter.actors[0] === formatMember(caller.principal);
  const asked = (query.sealed === true || typeof query.before === 'string') && query.decision !== 'deny' && before.change !== 'done';
  const used = asked && query.path === undefined && (filter.within === undefined || own);

  // A page that counts 0.15's records reads how far it may (`sealedReach`) beside the page.
  const counting = recorded && counted;
  const [old, sealed, reads, standing, reach] = await Promise.all([
    before.seq === 'done' ? { rows: [], more: false } : auditPage(ctx.db, filter),
    recorded ? sealedPage(ctx.db, { actors: filter.actors, detail, before: start, limit: query.limit }) : { rows: [], more: false },
    used ? readsPage(ctx.db, { actors: filter.actors, before: start, limit: query.limit }) : { rows: [], more: false },
    used ? readsStanding(ctx.db) : null,
    counting ? sealedReach(ctx.db, { actors: filter.actors, before: start }) : null,
  ]);
  const oldRead = old.rows.map((row) => ({ at: Date.parse(row.occurredAt), entry: entryView(row), below: `${row.seq}`, above: `${row.seq + 1n}` }));
  const changesRead = sealed.rows.map((row) => ({ at: row.at, entry: sealedView(row), below: { at: row.at, number: row.number } }));
  const readsRead = reads.rows.map((row) => ({ at: row.at, entry: readView(row), below: { at: row.at, number: row.number } }));
  // Beside each other: whether the vault vouches for each entry of 0.15's log the page read, and for how far the reads
  // are listed; and how the entries' credentials came to be.
  const [vouches, origins] = await Promise.all([
    vouched(ctx, sealed.rows, reads.rows, standing),
    originsOf(ctx.db, credentialsNamed([...oldRead, ...changesRead, ...readsRead].map((read) => read.entry))),
  ]);
  for (const read of [...changesRead, ...readsRead]) {
    if (read.entry !== null && vouches.forged.has(read.below.number)) read.entry.forged = true;
  }
  const page = merged(
    { read: oldRead, more: old.more },
    sealedStream({ read: changesRead, more: sealed.more }, { read: readsRead, more: reads.more }),
    query.limit,
    // Those of its own time, so it goes on in that log while 0.14's does; and no more than `HIDDEN_COUNTED` of them, so
    // it shows nothing older than the last of those, and stops there (reviews r2, r3).
    counting,
    reach,
  );
  // Where it stopped at that last one, or took everything older than it, the pages after count the rest.
  const change = reach !== null && (page.reached || page.change === null) ? reach : page.change;
  const next = page.oldStop === null && change === null ? null : `${page.oldStop ?? '-'}:${change === null ? '-' : pointText(change)}`;
  const entries = withOrigins(page.entries, origins);
  const shown = standing === null ? null : readsListed(standing, vouches.cursorForged);
  // A page that would have listed reads under 0.14's log says where they are under 0.15's: `readsOmitted`.
  const omitted = asked && !used && (await keeps015(ctx.vault)) ? { readsOmitted: query.path !== undefined ? 'path' as const : 'scope' as const } : {};
  const listed = { ...(shown === null ? {} : { reads: shown }), ...omitted };
  if (!counted) return { entries, more: next !== null, next, ...listed };
  // The page's stretch of each log, from where it stopped there to where it started; to the first entry when nothing
  // older is left; nothing when the page before was the last of it. 0.14's stops at its oldest entry shown, or where
  // the page before stopped when it shows none; 0.15's at the time the page ended, or at its oldest sign-in when it
  // ended on one, or past them at the last of its records it counts.
  const counts = await Promise.all([
    before.seq === 'done' ? [] : auditActionCounts(ctx.db, filter, DETAIL_ACTIONS, page.oldStop === null ? undefined : BigInt(page.oldStop)),
    recorded ? sealedHidden(ctx.db, { actors: filter.actors, from: change ?? undefined, before: start }) : [],
  ]);
  const hidden = new Map<string, number>();
  for (const { action, count } of counts.flat()) hidden.set(action, (hidden.get(action) ?? 0) + count);
  // Most of what is hidden first.
  return {
    entries,
    more: next !== null,
    next,
    ...listed,
    hidden: [...hidden].map(([action, count]) => ({ action, count })).sort((a, b) => b.count - a.count || (a.action < b.action ? -1 : a.action > b.action ? 1 : 0)),
  };
}

/** A page's `next`: `<seq>:<at>.<change>`, or `<seq>:<at>` below a time, each `-` for a log with nothing older. */
export const AUDIT_NEXT = /^(?:-?[0-9]{1,19}|-):(?:[0-9]{1,16}(?:\.-?[0-9]{1,19})?|-)$/;

/**
 * Where a page starts in each log, from the newest (undefined), or past the
 * oldest (`done`): below a seq of 0.14's; below a point of 0.15's
 * (`ChangePoint`), as its records are listed.
 */
type Point = { seq?: bigint | 'done'; change?: ChangePoint | 'done' };

/** `before` as a point: a page's `next`, or a seq of 0.14's log alone, as clients before 0.15 page. */
function startOf(before: number | string | undefined): Point {
  if (before === undefined) return {};
  if (typeof before === 'number') return { seq: BigInt(before), change: 'done' };
  const [seq, change] = before.split(':') as [string, string];
  const [at, number] = change.split('.') as [string, string | undefined];
  return {
    seq: seq === '-' ? 'done' : BigInt(seq),
    change: change === '-' ? 'done' : { at: Number(at), ...(number === undefined ? {} : { number: BigInt(number) }) },
  };
}

/** Which of two points of 0.15's log is newer, as its records are listed: a time alone is above every change asked at it. */
function compare(a: ChangePoint, b: ChangePoint): number {
  if (a.at !== b.at) return a.at < b.at ? -1 : 1;
  if (a.number === b.number) return 0;
  if (a.number === undefined || b.number === undefined) return a.number === undefined ? 1 : -1;
  return a.number < b.number ? -1 : 1;
}

/** A point of 0.15's log as `next` names it: `<at>.<number>`, or `<at>` for a time. */
function pointText(point: ChangePoint): string {
  return point.number === undefined ? `${point.at}` : `${point.at}.${point.number}`;
}

/**
 * An entry as a log's page read it: when, by the clock its log orders by;
 * its view, or null for one no page shows; and where a page goes on from,
 * below it.
 */
type Read<P> = { at: number; entry: AuditEntryView | null; below: P };

/**
 * The newest `limit` of two logs' entries, each read newest first, up to
 * `limit`, merged by time: none past what either has unread (`more`), which
 * could be newer, and none older than `floor`, a point of 0.15's log
 * (`reached` says it stopped there). A row read that shows nothing is
 * passed over, and the page goes on past it. Where it stopped in each,
 * null when nothing older is left there: `oldStop`, in 0.14's log, the seq
 * as text, below the last taken, or, where it took none, from the first
 * read, as the page before stopped; `change`, in 0.15's, below the last
 * taken when the page ended on one of its, else below the time it ended
 * at, which every one taken is newer than and every one left no newer.
 * That rests on 0.14's entries being in time order as they are in seq
 * order: each takes its time, the database's clock, under the log's head,
 * as it takes its seq (`readUnderHead` in @coffre/db's log.ts). Were their
 * times to come from elsewhere, a time could stand above a 0.15 record a
 * page already took, and `next` would list it again (Fable).
 * With `counting`, 0.15's goes on while 0.14's does, though it shows
 * nothing more: the page after counts the records it hides of its own time.
 */
function merged(
  old: { read: (Read<string> & { above: string })[]; more: boolean },
  sealed: { read: Read<ChangePoint>[]; more: boolean },
  limit: number,
  counting: boolean,
  floor: ChangePoint | null,
) {
  const entries: AuditEntryView[] = [];
  let [i, j] = [0, 0];
  let last: Read<unknown> | undefined;
  let reached = false;
  while (entries.length < limit) {
    const [a, b] = [old.read[i], sealed.read[j]];
    if ((a === undefined && old.more) || (b === undefined && sealed.more) || (a === undefined && b === undefined)) break;
    const fromOld = b === undefined || (a !== undefined && a.at >= b.at);
    // Where the page would stop, taking it: at its time, for 0.14's; below it, for 0.15's.
    if (floor !== null && compare(fromOld ? { at: a!.at } : b!.below, floor) < 0) {
      reached = true;
      break;
    }
    last = fromOld ? old.read[i++]! : sealed.read[j++]!;
    if (last.entry !== null) entries.push(last.entry);
  }
  const oldStop = i < old.read.length || old.more ? (i > 0 ? old.read[i - 1]!.below : old.read[0]!.above) : null;
  const goesOn = j < sealed.read.length || sealed.more || (counting && oldStop !== null);
  const change = !goesOn || last === undefined ? null : last === sealed.read[j - 1] ? sealed.read[j - 1]!.below : { at: last.at };
  return { entries, oldStop, change, reached };
}

/**
 * 0.15's two streams as one, newest first by `(at, number)`, each read up
 * to its page: its changes (`sealedPage`) and its reads (`readsPage`), which
 * share the log's numbers. None past what either has unread, which could be
 * newer; `more` while either has any left.
 */
function sealedStream(changes: { read: Read<ChangePoint>[]; more: boolean }, uses: { read: Read<ChangePoint>[]; more: boolean }): { read: Read<ChangePoint>[]; more: boolean } {
  const read: Read<ChangePoint>[] = [];
  let [i, j] = [0, 0];
  for (;;) {
    const [a, b] = [changes.read[i], uses.read[j]];
    if ((a === undefined && changes.more) || (b === undefined && uses.more) || (a === undefined && b === undefined)) break;
    read.push(b === undefined || (a !== undefined && compare(a.below, b.below) > 0) ? changes.read[i++]! : uses.read[j++]!);
  }
  return { read, more: changes.more || uses.more || i < changes.read.length || j < uses.read.length };
}


/**
 * The entries of 0.15's log a page read that the vault does not vouch for
 * (`Vault.vouch`), by number: every change and read, as read, each with the
 * columns its MAC covers (a read's, its number too); and whether it vouches
 * for the reads' cursor, which says how far they are listed. One call for
 * the page, none for a page without them. A vault that cannot vouch (older
 * than this app) fails the page: nothing of 0.15's is listed unchecked.
 */
async function vouched(
  ctx: ApiContext, changes: readonly RecordedChange[], reads: readonly ListedRead[], standing: Awaited<ReturnType<typeof readsStanding>> | null,
): Promise<{ forged: Set<bigint>; cursorForged: boolean }> {
  if (changes.length === 0 && reads.length === 0 && standing === null) return { forged: new Set(), cursorForged: false };
  if (ctx.vault.vouch === undefined) throw new ApiError('unavailable', "the vault cannot vouch for 0.15's log: it is older than this app, so deploy it first", 'vault_outdated');
  const hex = (bytes: Buffer | null) => (bytes === null ? null : bytes.toString('hex'));
  const { forged } = await ctx.vault.vouch({
    entries: [
      ...changes.map((row) => ({
        tree: 'changes' as const, number: String(row.number), at: row.at, requestId: row.requestId, object: row.object, actor: row.actor, payload: row.payload, seal: hex(row.seal), mac: hex(row.mac)!,
      })),
      ...reads.map((row) => ({
        tree: 'reads' as const, number: String(row.number), at: row.at, credential: row.credential, purpose: row.purpose, principal: row.principal, secret: row.secret,
        environment: row.environment, project: row.project, place: row.place, source: row.source, sourceEnvironment: row.sourceEnvironment, sourceProject: row.sourceProject,
        version: row.version, mac: hex(row.mac)!,
      })),
      ...(standing === null ? [] : [{ tree: 'cursor' as const, number: 'cursor' as const, through: String(standing.through), pair: String(standing.pair), at: standing.at, mac: hex(standing.mac) }]),
    ],
  });
  const cursorForged = forged.includes('cursor');
  return { forged: new Set(forged.flatMap((number) => (/^[0-9]{1,19}$/.test(number) ? [BigInt(number)] : []))), cursorForged };
}

/**
 * How far a page's reads are listed (`reads`): the reads 0.15's log seals are
 * listed once the vault's projector has written them, which runs apart from
 * sealing (T166). A page says how far, so that a projector behind, or
 * stopped, shows rather than leaves reads missing unsaid.
 */
export type ReadsListed = {
  /** Every read the log sealed up to this time is listed; null before any. */
  through: string | null;
  /**
   * Whether sealed reads newer than that wait to be listed: the newest pair's
   * not all listed, it signed more than `READS_BEHIND_MS` after the listing's
   * or that long ago. Strict (a report's): any of its reads not listed.
   */
  behind: boolean;
  /** The vault does not vouch for where the reads' listing stands: its cursor was moved around the projector. */
  forged?: true;
};

/**
 * Why a page lists no reads of 0.15's log (T166, D160), where 0.14's would
 * have listed its reads' entries: `path`, it is a project's, environment's
 * or key's, whose reads the whole log and each member's page list in 0.15;
 * `scope`, its reader reads some places only, and sees their own reads
 * alone, on their own page.
 */
export type ReadsOmitted = 'path' | 'scope';

/** How far behind the newest pair the reads' listing is said to be behind: a few ticks, so that the one a seal takes says nothing. */
export const READS_BEHIND_MS = 5_000;

/**
 * How far the reads are listed, as a page or a report says it: null where
 * the log has no signed pair, which 0.14's alone has not. A projector
 * stopped after the newest pair shows too, by the clock (review r4): no
 * later pair need come to show it.
 */
export function readsListed(standing: Awaited<ReturnType<typeof readsStanding>>, forged: boolean, options: { strict?: boolean } = {}): ReadsListed | null {
  if (standing.sealed === null || standing.sealedAt === null) return null;
  const waiting = standing.through < standing.sealed;
  const late = options.strict === true || standing.sealedAt - standing.at > READS_BEHIND_MS || Date.now() - standing.sealedAt > READS_BEHIND_MS;
  return { through: standing.at === 0 ? null : new Date(standing.at).toISOString(), behind: (waiting && late) || forged, ...(forged ? { forged: true as const } : {}) };
}

/**
 * A read of 0.15's log (R53, T166), as the vault's projector wrote it,
 * shown as 0.14's `secret.read` showed a read of one key: by the vault,
 * which logged it, numbered by its use, by the account its way in acts as,
 * for its purpose, of the version it read. Filed as 0.14 filed a read:
 * through a reference, at its source, the reference's holder beside it
 * (`via`, `also`); otherwise at its key, the fork it was read in beside it
 * (`through`, `also`). Each from the sealed objects at the use's number.
 * What the slim row leaves out stays out: the app's request and operation,
 * and the proxy's upstream. A use is the request (R53): one the vault
 * refused after it was written, the bulk cap's say, shows as this read too,
 * the log's record of what was asked, never less than happened.
 *
 *   Ada's `coffre run` of market/dev        a `secret.read` for each key, `run`
 *   the proxy's use of STRIPE_KEY          a `secret.read` of it, `use`, via its credential
 */
function readView(row: ListedRead): AuditEntryView {
  const code = useOfCode(row.purpose);
  const way = code?.way ?? 'credential';
  const through = row.source !== null;
  const holder = row.key === null || row.projectSlug === null || row.environmentSlug === null ? null : `${row.projectSlug}/${row.environmentSlug}/${row.key}`;
  const via = {
    ...(through ? { path: holder } : {}),
    ...(way === 'connection' ? { connectionId: row.credential, ...(row.client === null ? {} : { clientId: row.client.id, clientName: row.client.name }) } : {}),
  };
  const also = through
    ? { projectId: row.project, environmentId: row.environment, secretId: row.secret }
    : row.place !== null ? { projectId: row.project, environmentId: row.place } : null;
  return {
    seq: Number(row.number),
    log: '0.15',
    author: 'vault',
    occurredAt: new Date(row.at).toISOString(),
    ...actorParts(row.principal),
    action: 'secret.read',
    decision: 'allow',
    reason: null,
    detail: false,
    subject: null,
    project: through ? row.sourceProjectSlug : row.projectSlug,
    environment: through ? row.sourceEnvironmentSlug : row.environmentSlug,
    key: through ? row.sourceKey : row.key,
    version: row.versionNumber,
    secrets: null,
    operationId: null,
    relatedSeq: null,
    requestId: null,
    run: null,
    token: null,
    metadata: {
      purpose: code?.purpose ?? `unknown (${row.purpose})`,
      ...(code?.keepsSensitive ? { keepsSensitive: true } : {}),
      secretId: through ? row.source : row.secret,
      ...(row.versionNumber === null ? {} : { version: row.versionNumber }),
      ...(Object.keys(via).length === 0 ? {} : { via }),
      ...(row.place === null ? {} : { through: { environmentId: row.place, ...(row.forkSlug === null ? {} : { slug: row.forkSlug }) } }),
      ...(also === null ? {} : { also }),
      ...(way === 'credential' ? { credentialId: row.credential } : way === 'binding' ? { bindingId: row.credential } : way === 'access' ? { access: true } : {}),
    },
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The credentials entries were written on, which a page asks how they came
 * to be (`originsOf`, one read for the page): each entry's that names one, a
 * read's through a credential included.
 */
function credentialsNamed(entries: readonly (AuditEntryView | null)[]): string[] {
  return [...new Set(entries.flatMap((entry) => {
    const id = entry?.metadata.credentialId;
    return entry !== null && entry.action !== 'token.exchange' && typeof id === 'string' && UUID.test(id) ? [id] : [];
  }))];
}

/**
 * What each entry was written on, when its request came in on a credential
 * it names: the run, for one a trust binding issued; the token, for a
 * personal token, as `originsOf` found them.
 */
function withOrigins(entries: AuditEntryView[], origins: Map<string, CredentialOrigin>): AuditEntryView[] {
  return entries.map((entry) => {
    if (entry.action === 'token.exchange') return { ...entry, run: { exchangeSeq: entry.seq, log: entry.log, claims: runClaims(entry.metadata.run) } };
    const id = typeof entry.metadata.credentialId === 'string' ? entry.metadata.credentialId : undefined;
    const origin = id === undefined ? undefined : origins.get(id);
    if (origin?.kind === 'signIn') return { ...entry, run: { exchangeSeq: Number(origin.seq), log: origin.log, claims: runClaims(origin.run) } };
    if (origin?.kind === 'personal') return { ...entry, token: { id: id!, label: origin.label } };
    return entry;
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
 * A change 0.15's log records in place of 0.14's entry (D147), shown as that
 * entry showed it, of the vault, which made it, and numbered by its change:
 *
 * - a sign-in, `token.exchange`, by the service: the credential, the
 *   binding, the account's generation, the issuer and the proof, the
 *   credential's end, a workload's key and hard end, and the run (`run`);
 * - a token's issue, `token.create`, by its issuer: its kind, the account
 *   it acts as, its label, the credential, its end and its scope;
 * - a revoke by request, `token.revoke`, by whoever asked: the credential,
 *   its kind and its account;
 * - a sign-out, `sign_out`, by the credential's own account: the
 *   credential and its kind.
 *
 * The last three name whose act it was, as 0.14's entries did, from the
 * record's trace (`traceOf`): `credentialId`, a run's credential, a
 * personal token or an MCP connection, and through MCP its `via`. None for a change whose payload is none of these, which only a database
 * writer could leave under the indexes' conditions. No request: the
 * change's id is the vault's own, which names none.
 */
function sealedView(row: RecordedChange): AuditEntryView | null {
  type Fields = Record<string, unknown>;
  const payload = JSON.parse(row.payload) as Fields & { ref?: { kind?: unknown; id?: unknown }; signIn?: unknown; issue?: unknown; revoke?: unknown };
  const { ref } = payload;
  if (ref?.kind !== 'credential' || typeof ref.id !== 'string' || !isMember(row.actor)) return null;
  const record = (value: unknown): Fields | null => (typeof value === 'object' && value !== null ? (value as Fields) : null);
  const time = (value: unknown) => (typeof value === 'number' && Number.isSafeInteger(value) ? new Date(value).toISOString() : null);
  const view = (action: string, metadata: Fields): AuditEntryView => ({
    seq: Number(row.number),
    log: '0.15',
    author: 'vault',
    occurredAt: new Date(row.at).toISOString(),
    ...actorParts(row.actor),
    action,
    decision: 'allow',
    reason: null,
    detail: DETAIL.has(action),
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
    metadata,
  });
  // Whose credential, as 0.14's entries named the account; and the credential the request came in on.
  const account = (member: unknown): Fields => {
    if (typeof member !== 'string' || !isMember(member)) return {};
    const { actorType, actorId } = actorParts(member);
    return { principalType: actorType, principalId: actorId };
  };
  // As 0.14's entry would, from the trace the record keeps (`traceFields`): one of another shape says nothing.
  const traced = (trace: unknown): Fields => {
    const { credentialId, mcp } = (record(trace) ?? {}) as { credentialId?: unknown; mcp?: unknown };
    if (typeof credentialId !== 'string') return {};
    const app = record(mcp);
    const text = (value: unknown) => (typeof value === 'string' ? value : null);
    const [connectionId, clientId, clientName] = [text(app?.connectionId), text(app?.clientId), text(app?.clientName)];
    if (app === null || connectionId === null || clientId === null || clientName === null) return traceFields({ credentialId, mcp: null });
    return traceFields({ credentialId, mcp: { connectionId, clientId, clientName, approvalId: text(app.approvalId) } });
  };

  const [signIn, issue, revoke] = [record(payload.signIn), record(payload.issue), record(payload.revoke)];
  if (signIn !== null) {
    if (!row.actor.startsWith('token:')) return null;
    const workload = typeof signIn.jkt === 'string';
    return view('token.exchange', {
      ...(workload ? { kind: 'workload' } : {}),
      credentialId: ref.id,
      bindingId: signIn.binding,
      generation: payload.generation,
      issuer: signIn.issuer,
      proof: signIn.proof,
      expiresAt: time(payload.expiresAt),
      ...(workload ? { jkt: signIn.jkt, notAfter: time(signIn.notAfter) } : {}),
      run: signIn.run,
    });
  }
  if (issue !== null) {
    return view('token.create', {
      kind: issue.kind,
      ...account(payload.principal),
      label: issue.label ?? null,
      targetCredentialId: ref.id,
      expiresAt: time(payload.expiresAt),
      scope: payload.scope,
      ...traced(issue.trace),
    });
  }
  if (revoke?.reason === 'revoke') return view('token.revoke', { targetCredentialId: ref.id, kind: revoke.kind, ...account(revoke.principal), ...traced(revoke.trace) });
  if (revoke?.reason === 'sign_out') return view('sign_out', { targetCredentialId: ref.id, kind: revoke.kind, ...traced(revoke.trace) });
  return null;
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
 * A stretch of the reads' check (the vault's `verifyReads`, T166): the
 * reads the audit pages list held to the uses 0.15's log sealed, each
 * stretch a checkpoint's range at most, for whoever reads the whole log, as
 * `verifyAudit`. With 0.14's log alone, `kept` false.
 */
export async function verifyAuditReads(ctx: ApiContext, input: { from: string }): Promise<ReadsVerification> {
  if (!readsWholeLog(ctx.caller)) {
    throw forbidden('only those who read the whole log may verify it: an auditor, admin or owner of the whole instance');
  }
  if (ctx.vault.verifyReads === undefined) return { kept: false };
  return ctx.vault.verifyReads({ from: input.from });
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
