import { ownsInstance, readsWholeLog, runsInstance } from '@coffre/core/access';
import { DETAIL_ACTIONS } from '@coffre/core/audit';
import { describeAccessFault, type LogVerification, type ReadsVerification, type TreeVerification } from '@coffre/core/vault';
import { SNAPSHOT } from '@coffre/db/dialect';
import { missingEntry, newestWindow } from '@coffre/db/log';

import { actorParts, appLogKey, CHAIN_START, CHAIN_WALK, walkChain, type ChainPoint } from '../db/audit.ts';
import { eventsPage, namesOf, type CursorStanding, type EventRow, type PageNames, type Position, type Stream } from '../db/events.ts';
import {
  auditHashAt,
  auditHead,
  auditTimeAt,
  latestCheckpoint,
  latestTallied,
  originsOf,
  places,
  resolvePath,
  talliedAfter,
  talliedAt,
  type CredentialOrigin,
  type Signed,
} from '../db/queries.ts';
import { Refusal } from '../watch.ts';
import { can, canAnywhere, placeOf } from './caller.ts';
import { type ApiContext } from './context.ts';
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
   * The vault does not vouch for it, its MAC not holding over what it says:
   * it was written, or edited, around coffre. Absent for every other.
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

/** Technical steps and sign-ins, which a page leaves out unless asked: @coffre/core's, the projection's `shown` too. */
export { DETAIL_ACTIONS };

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
  /** Count what the page leaves out (`hidden`), over its stretch. */
  hidden?: boolean;
  /** Entries older than this, for paging backwards: a page's `next`; or a seq of 0.14's log, as clients before 0.15 page. */
  before?: number | string;
  limit: number;
};

/**
 * Newest first, every log as one, from the projection
 * (db/events.ts): each entry of 0.14's chain, each change of 0.15's log and
 * each read, a use, once the vault's projector has listed it. Whoever reads
 * the whole log reads everything: an Auditor, Admin or Owner whose scope
 * narrows nothing (`readsWholeLog`). Anyone else reads the entries at the
 * projects and environments where they hold `audit.read`, by a grant or
 * their instance role, and none at an environment their role leaves out
 * there: an entry about no place, such as a sign-in or a member's removal,
 * is the instance's, and theirs alone.
 *
 * A page reads one stream of the projection, newest first: the place its
 * path names, the members asked for, the places a reader of some places
 * reads, or everyone's. Its other filters pass over rows of that stream,
 * `WINDOW` of them at most past a page: a page may then hold fewer than
 * `limit` entries, and `next`, where it stopped, is where the next one
 * starts (`<log>:<at>.<number>`). Each page reads as much however long the
 * log is.
 *
 * Without `detail`, a page asked to count (`hidden`) says what it left out: the detail entries the same
 * filters match in the page's stretch, by action. A page's stretch runs
 * from where it started down to the last row it read: pages tile the log,
 * and each hidden entry is counted on exactly one.
 *
 * Every entry a page shows, the vault vouches for, or the page marks it
 * `forged`; so for how far the projection is listed (`reads`), which the
 * page says.
 */
export async function listAudit(
  ctx: ApiContext,
  query: AuditQuery,
): Promise<{ entries: AuditEntryView[]; more: boolean; next: string | null; hidden?: HiddenCount[]; reads?: ReadsListed; listingOlder?: true }> {
  const { caller } = ctx;
  // What a reader of some places reads: a project's whole log where they read all of it, but for an environment whose
  // log their role leaves out there, a protected one; else each environment's they read.
  // `partly`: the projects of which they read some environments only.
  let within: { places: string[]; except: string[]; partly: Set<string> } | undefined;
  if (!readsWholeLog(caller)) {
    const read: string[] = [];
    const except: string[] = [];
    const partly = new Set<string>();
    if (canAnywhere(caller, 'audit.read')) {
      for (const project of await places(ctx.db)) {
        const unread = project.environments.filter((environment) => !can(caller, 'audit.read', placeOf(project, environment))).map((environment) => environment.id);
        if (can(caller, 'audit.read', placeOf(project, null))) {
          read.push(project.id);
          except.push(...unread);
        } else {
          const some = project.environments.filter((environment) => !unread.includes(environment.id)).map((environment) => environment.id);
          read.push(...some);
          if (some.length > 0) partly.add(project.id);
        }
      }
    }
    if (read.length === 0) throw forbidden('you do not hold audit.read on any project');
    within = { places: read, except, partly };
  }
  let place: string | undefined;
  if (query.path !== undefined) {
    // A deleted place's entries stay readable by its tombstone's slug.
    // `market/dev@me`: the caller's own personal config of dev.
    const resolved = await resolvePath(ctx.db, query.path, { tombstones: true, owner: ownerOf(ctx) });
    if (resolved === null) throw notFound('no such project');
    if (query.path.environment !== undefined && resolved.environment === null) throw notFound('no such environment');
    if (query.path.key !== undefined && resolved.secret === null) throw notFound('no such secret');
    place = resolved.secret?.id ?? resolved.environment?.id ?? resolved.project.id;
    // A place its reader reads nothing of lists nothing, not even where a page stopped: no `next` walks its entries,
    // their times and numbers.
    const environment = resolved.environment?.id;
    const readable = within === undefined || (environment === undefined
      ? within.places.includes(resolved.project.id) || within.partly.has(resolved.project.id)
      : within.places.includes(environment) || (within.places.includes(resolved.project.id) && !within.except.includes(environment)));
    if (!readable) return { entries: [], more: false, next: null, ...(query.detail !== true && query.hidden === true ? { hidden: [] } : {}) };
  }
  const actors = query.actor === undefined
    ? undefined
    : /^(user|token):/.test(query.actor)
      ? [formatMember(parseMember(query.actor))]
      : ['user', 'token', 'system'].map((prefix) => `${prefix}:${query.actor}`).concat(query.actor);
  const detail = query.detail === true;
  const counted = !detail && query.hidden === true;
  // The page's stream: the place its path names, the members asked for, the places its reader reads, or everyone's. Each
  // filter it does not hold, the page holds the stream's rows to, a place's included: each row of a place's stream must
  // name the place among its event's own (`places`, under its MAC), or it is no entry of that place.
  const stream: Stream = place !== undefined
    ? { places: [place] }
    : actors !== undefined
      ? { actors }
      : within !== undefined
        ? { places: within.places }
        : { all: true, shownOnly: !detail && !counted };
  const page = await eventsPage(ctx.db, {
    stream,
    match: {
      allowed: query.decision === undefined ? undefined : query.decision === 'allow',
      actors: actors !== undefined && 'places' in stream ? actors : undefined,
      within: place !== undefined ? (within === undefined ? [place] : within.places.includes(place) ? [place] : within.places) : within?.places,
      except: within?.except,
    },
    detail,
    counted,
    before: await startOf(ctx, query.before),
    limit: query.limit,
  });
  const details = page.rows.map((row) => JSON.parse(row.detail) as Record<string, unknown>);
  // Beside each other: whether the vault vouches for each entry the page shows and for how far they are listed; how the
  // entries' credentials came to be; and the names its reads show that their rows hold by id.
  const [vouches, origins, names] = await Promise.all([
    vouched(ctx, page.rows, page.standing),
    originsOf(ctx.db, credentialsNamed(page.rows, details)),
    namesOf(ctx.db, namedBy(page.rows, details)),
  ]);
  const listed = page.rows.map((row, i) => ({ row, entry: eventView(row, details[i]!, names) }));
  for (const { row, entry } of listed) if (vouches.forged.has(eventName(row))) entry.forged = true;
  const entries = withOrigins(listed.map(({ entry }) => entry), origins);
  const next = page.next === null ? null : `${page.next.log}:${page.next.at}.${page.next.number}`;
  const shown = readsListed(page.standing, vouches.cursorForged);
  // Entries of the log before 0.16 still being listed, newest first (after the upgrade, or a rebuild): the history
  // stops early, and the page says so rather than end as if it were all.
  const reads = { ...(shown === null ? {} : { reads: shown }), ...(vouches.listingOlder ? { listingOlder: true as const } : {}) };
  if (!counted) return { entries, more: next !== null, next, ...reads };
  // Most of what is hidden first.
  const hidden = [...page.hidden].map(([action, count]) => ({ action, count })).sort((a, b) => b.count - a.count || (a.action < b.action ? -1 : a.action > b.action ? 1 : 0));
  return { entries, more: next !== null, next, ...reads, hidden };
}

/** A page's `next`: `<log>:<at>.<number>`; and, from before 0.16, `<seq>:<at>.<change>` or `<seq>:<at>`, each `-` for nothing older. */
export const AUDIT_NEXT = /^(?:-?[0-9]{1,19}|-):(?:[0-9]{1,16}(?:\.-?[0-9]{1,19})?|-)$/;

/** The logs a `next` names: 0.14's, 0.15's changes, its uses. */
const LOGS = new Set([14, 15, 16]);

/**
 * Where a page starts: below the entry its `next` names; below a time, for
 * a `next` of an earlier release, which named where it stopped in each log
 * apart; nowhere, past the oldest, for one that said nothing older was left
 * in 0.15's; or below a seq of 0.14's log, as clients before 0.15 page,
 * where that entry is listed (one read of `audit_log`'s primary key).
 */
async function startOf(ctx: ApiContext, before: number | string | undefined): Promise<Position | undefined> {
  if (before === undefined) return undefined;
  if (typeof before === 'number') {
    const at = await auditTimeAt(ctx.db, BigInt(before));
    return at === null ? { at: 0, number: 0n, log: 0 } : { at, number: BigInt(before), log: 14 };
  }
  const [first, point] = before.split(':') as [string, string];
  // An earlier release's `<seq>:-`: nothing older in 0.15's, 0.14's going on below that seq.
  if (point === '-') return first === '-' ? { at: 0, number: 0n, log: 0 } : startOf(ctx, Number(first));
  const [at, number] = point.split('.') as [string, string | undefined];
  const log = Number(first);
  if (LOGS.has(log) && number !== undefined) return { at: Number(at), number: BigInt(number), log };
  return { at: Number(at), number: 9_223_372_036_854_775_807n, log: 32_767 };
}

/** How a page names an entry to the vault, which answers which it does not vouch for. */
const eventName = (row: EventRow) => `${row.log}:${row.number}`;

/**
 * The entries a page shows that the vault does not vouch for (`Vault.vouch`),
 * by `eventName`, each with every column its MAC covers; and whether it
 * vouches for the cursor, which says how far they are listed. One call for
 * the page. A vault that cannot vouch for the projection's rows (older than
 * this app: 0.14's has no `vouch`, 0.15.0's answers no `listingOlder`) fails
 * the page: nothing is listed unchecked.
 */
async function vouched(ctx: ApiContext, rows: readonly EventRow[], standing: CursorStanding): Promise<{ forged: Set<string>; cursorForged: boolean; listingOlder: boolean }> {
  if (ctx.vault.vouch === undefined) throw new ApiError('unavailable', 'the vault cannot vouch for the audit log: it is older than this app, so deploy it first', 'vault_outdated');
  const hex = (bytes: Buffer | null) => (bytes === null ? null : bytes.toString('hex'));
  const { forged, listingOlder } = await ctx.vault.vouch({
    entries: [
      ...rows.map((row) => ({
        tree: 'event' as const, name: eventName(row), at: row.at, number: String(row.number), log: row.log, author: row.author, action: row.action, shown: row.shown,
        allowed: row.allowed, code: row.code, actor: row.actor, subject: row.subject, credential: row.credential, project: row.project,
        environment: row.environment, secret: row.secret, version: row.version, places: row.places, requestId: row.requestId, operationId: row.operationId,
        related: row.related === null ? null : String(row.related), sourceIp: row.sourceIp, detail: row.detail, mac: hex(row.mac)!,
      })),
      ...(standing.missing ? [] : [{
        tree: 'cursor' as const, name: 'cursor' as const, through: String(standing.through), pair: String(standing.pair), at: standing.at,
        oldFloor: String(standing.oldFloor), oldFrom: String(standing.oldFrom), oldTop: String(standing.oldTop), oldHash: hex(standing.oldHash)!, mac: hex(standing.mac),
      }]),
    ],
  });
  if (typeof listingOlder !== 'boolean') throw new ApiError('unavailable', 'the vault cannot vouch for the audit log: it is older than this app, so deploy it first', 'vault_outdated');
  return { forged: new Set(forged), cursorForged: forged.includes('cursor'), listingOlder };
}

/**
 * How far a report's reads are listed (an offboarding report, the removed
 * members' counts), strictly: through `upTo` when given, the change that
 * removed its member, else through the newest pair; and behind while the
 * walk down the log before 0.16 is open, whose reads it weighs too. The
 * report is whole once listed that far, which only the cursor says: the
 * vault vouches for it, one call, as for a page. A cursor gone says
 * `forged` without one.
 */
export async function readsReported(ctx: ApiContext, standing: CursorStanding, upTo?: bigint): Promise<ReadsListed | null> {
  if (standing.sealed === null || standing.sealedAt === null) return null;
  const { cursorForged, listingOlder } = standing.missing ? { cursorForged: true, listingOlder: false } : await vouched(ctx, [], standing);
  const reads = readsListed(standing, cursorForged, { strict: true, ...(upTo === undefined ? {} : { upTo }) });
  return reads === null || !listingOlder ? reads : { ...reads, behind: true };
}

/**
 * How far a page's entries are listed (`reads`): the vault's projector lists
 * what the checkpointer has signed, apart from sealing. A page says how far,
 * so that a projector behind, or stopped, shows rather than leaves entries
 * missing unsaid.
 */
export type ReadsListed = {
  /** Every entry the log sealed up to this time is listed; null before any. */
  through: string | null;
  /**
   * Whether sealed entries newer than that wait to be listed: the newest
   * pair's not all listed, it signed more than `READS_BEHIND_MS` after the
   * listing's or that long ago. Strict (a report's): any it weighs not listed.
   */
  behind: boolean;
  /** The vault does not vouch for where the listing stands: its cursor was moved around the projector. */
  forged?: true;
};

/** How far behind the newest pair the listing is said to be behind: a few ticks, so that the one a seal takes says nothing. */
export const READS_BEHIND_MS = 5_000;

/**
 * How far the entries are listed, as a page or a report says it: null where
 * the log has no signed pair. A projector stopped after the newest pair
 * shows too, by the clock: no later pair need come to show it. A report's
 * (`strict`) is behind until the cursor has passed `upTo`, the change that
 * removed its member, every read of theirs numbered below it; or, for a
 * member not removed, the newest pair.
 */
export function readsListed(standing: CursorStanding, unvouched: boolean, options: { strict?: boolean; upTo?: bigint } = {}): ReadsListed | null {
  if (standing.sealed === null || standing.sealedAt === null) return null;
  // A cursor gone is one the vault vouches for no more than one moved: only a database writer deletes it.
  const forged = unvouched || standing.missing;
  const waiting = standing.through < (options.upTo ?? standing.sealed);
  const late = options.strict === true || standing.sealedAt - standing.at > READS_BEHIND_MS || Date.now() - standing.sealedAt > READS_BEHIND_MS;
  return { through: standing.at === 0 ? null : new Date(standing.at).toISOString(), behind: (waiting && late) || forged, ...(forged ? { forged: true as const } : {}) };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The credentials entries were written on, which a page asks how they came
 * to be (`originsOf`, one read for the page): each entry's that names one, a
 * read's through a credential included.
 */
function credentialsNamed(rows: readonly EventRow[], details: readonly Record<string, unknown>[]): string[] {
  return [...new Set(details.flatMap((metadata, i) => {
    const id = metadata.credentialId;
    return rows[i]!.action !== 'token.exchange' && typeof id === 'string' && UUID.test(id) ? [id] : [];
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
    // A two-trip change names its request's credential whatever it is; 0.14's entry named only a run's or a personal
    // token's (the request's provenance), so a session's or a CLI login's stays unsaid (Fable's review of #490).
    if (id !== undefined && entry.log === '0.15' && TWO_TRIP.has(entry.action)) {
      const { credentialId: _, ...metadata } = entry.metadata;
      return { ...entry, metadata };
    }
    return entry;
  });
}

/** The actions 0.15's two-trip changes record: a key write, a member's first add. */
const TWO_TRIP = new Set(['secret.write', 'member.add']);

function runClaims(run: unknown): Record<string, string | number> {
  if (typeof run !== 'object' || run === null) return {};
  return Object.fromEntries(Object.entries(run).filter((pair): pair is [string, string | number] => typeof pair[1] === 'string' || typeof pair[1] === 'number'));
}

/** The ids a page's reads and key writes name whose names the page shows (`namesOf`): holders, forks, MCP connections. */
function namedBy(rows: readonly EventRow[], details: readonly Record<string, unknown>[]): { secrets: string[]; environments: string[]; connections: string[] } {
  const [secrets, environments, connections] = [new Set<string>(), new Set<string>(), new Set<string>()];
  const id = (value: unknown) => (typeof value === 'string' && UUID.test(value) ? value : null);
  rows.forEach((row, i) => {
    if (row.log !== 16) return;
    const { also, through, via } = details[i] as { also?: { secretId?: unknown }; through?: { environmentId?: unknown }; via?: { connectionId?: unknown } };
    for (const [set, value] of [[secrets, also?.secretId], [environments, through?.environmentId], [connections, via?.connectionId]] as const) {
      const found = id(value);
      if (found !== null) set.add(found);
    }
  });
  return { secrets: [...secrets], environments: [...environments], connections: [...connections] };
}

/**
 * An entry as the projector listed it, as the API shows it: its place's and
 * key's names as their rows say now (a deleted place's, its tombstone's),
 * else as it named them; its version's number, as it named it, else as its
 * row says; its `metadata` the projector's `detail`, with the names the page
 * adds to a read and to a key write (`withNames`).
 */
function eventView(row: EventRow, logged: Record<string, unknown>, names: PageNames): AuditEntryView {
  const metadata = row.log === 16 ? readMetadata(row, logged, names) : row.log === 15 && row.action === 'secret.write' && row.allowed ? writeMetadata(row, logged) : logged;
  // The vault named a secret by its path in 0.14's log, the app by its key; a refused write, the place it was asked at.
  const path = typeof metadata.subject === 'string' ? metadata.subject : null;
  const asked = row.log === 15 && !row.allowed && typeof metadata.path === 'string' ? metadata.path.split('/') : null;
  return {
    seq: Number(row.number),
    log: row.log === 14 ? '0.14' : '0.15',
    author: row.author,
    occurredAt: new Date(row.at).toISOString(),
    ...actorParts(row.actor),
    action: row.action,
    decision: row.allowed ? 'allow' : 'deny',
    reason: row.code ?? (typeof metadata.reason === 'string' ? metadata.reason : null),
    detail: !row.shown,
    subject: row.subject,
    project: asked === null ? row.projectSlug : asked[0] ?? null,
    environment: asked === null ? row.environmentSlug : asked[1] ?? null,
    key: row.key ?? (typeof metadata.key === 'string' ? metadata.key : path?.split('/').at(-1) ?? null),
    version: typeof metadata.version === 'number' ? metadata.version : null,
    secrets: readSecrets(row.action, metadata),
    operationId: row.operationId,
    relatedSeq: row.related === null ? null : Number(row.related),
    requestId: row.requestId,
    run: null,
    token: null,
    metadata,
  };
}

/**
 * A use's metadata as the page shows it (0.15's `readView`): the projector's, with the version's number after the key's
 * id, and the names it holds by id: through a reference its holder's path, an MCP app's id and name, the fork's slug.
 */
function readMetadata(row: EventRow, logged: Record<string, unknown>, names: PageNames): Record<string, unknown> {
  const { purpose, keepsSensitive, secretId, via, through, also, ...rest } = logged as Record<string, unknown> & {
    via?: { connectionId?: string }; through?: { environmentId?: string }; also?: { secretId?: string };
  };
  const holder = typeof also?.secretId === 'string' ? also.secretId : null;
  const connection = typeof via?.connectionId === 'string' ? via.connectionId : null;
  const client = connection === null ? undefined : names.clients.get(connection);
  const named = {
    ...(holder === null ? {} : { path: names.paths.get(holder) ?? null }),
    ...(connection === null ? {} : { connectionId: connection, ...(client === undefined ? {} : { clientId: client.id, clientName: client.name }) }),
  };
  const fork = typeof through?.environmentId === 'string' ? through.environmentId : null;
  const slug = fork === null ? undefined : names.slugs.get(fork);
  return {
    purpose,
    ...(keepsSensitive === undefined ? {} : { keepsSensitive }),
    secretId,
    ...(row.versionNumber === null ? {} : { version: row.versionNumber }),
    ...(Object.keys(named).length === 0 ? {} : { via: named }),
    ...(fork === null ? {} : { through: { environmentId: fork, ...(slug === undefined ? {} : { slug }) } }),
    ...(also === undefined ? {} : { also }),
    ...rest,
  };
}

/** A key write's metadata as the page shows it (0.15's `withNames`): its key's name, its version's number and recipe first, as their rows say now. */
function writeMetadata(row: EventRow, logged: Record<string, unknown>): Record<string, unknown> {
  return {
    ...(row.key === null ? {} : { key: row.key }),
    ...(row.versionNumber === null ? {} : { version: row.versionNumber, ...(row.recipe === null ? {} : { recipe: row.recipe }) }),
    ...logged,
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
      // Every entry before where it starts still there: one count, and only a log with a gap pays to find where. A count
      // holds a million entries at most (T245): on a longer log the newest million, and the vault's checkpoints count
      // round the rest, whose refusal the vault's verification below says.
      const gap = await missingEntry(tx, start.seq, newestWindow(start.seq));
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
    // In the Owner's name, naming the touch that confirmed the request (`FRESH_ROUTES`, passkeys.md, section 11).
    return await ctx.watch.hooks.acceptLoss(ctx.watch.context(true, ctx.confirmed), range);
  } catch (error) {
    if (error instanceof Refusal) throw badRequest(error.message);
    throw error;
  }
}

/**
 * `coffre audit rebuild`: the audit projection emptied and started over, as an Owner of the whole instance, as a
 * person, as `accept-loss`. The vault writes the record naming who asked and resets in one transaction; its projector
 * lists every log again, the frozen `audit_log` included, and the pages say how far it has gone meanwhile.
 */
export async function rebuildAudit(ctx: ApiContext): Promise<{ number: string }> {
  if (ctx.caller.principal.type !== 'user' || !runsInstance(ctx.caller) || !ownsInstance(ctx.caller)) {
    throw forbidden('only an owner of the whole instance, as a person, may rebuild the audit projection');
  }
  if (ctx.vault.rebuildAudit === undefined) throw new ApiError('unavailable', 'the vault cannot rebuild the audit projection: it is older than this app, so deploy it first', 'vault_outdated');
  return await ctx.vault.rebuildAudit({ actor: formatMember(ctx.caller.principal), requestId: ctx.requestId });
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
