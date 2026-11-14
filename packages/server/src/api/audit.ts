import { readsWholeLog } from '@coffre/core/access';
import { inclusionProof, leafHash, nodesFrom, tileKey, tilesFor, verifyInclusion, type Hash, type Nodes } from '@coffre/core/log';
import { personalOf } from '@coffre/core/schemas';
import type { Called, SignedHead } from '@coffre/core/vault';

import { logPlaces, logProofs, logStretch, type LogPlaces, type LogRow, type TileAt } from '../db/queries/audit.ts';
import { can, canAnywhere, placeOf, projectsReached } from './caller.ts';
import type { ApiContext } from './context.ts';
import { badRequest, forbidden, notFound } from './errors.ts';
import type { Path } from './paths.ts';
import { memberOf } from './routes/members.ts';

/**
 * The audit page on the 0.16 log (docs/design/0.16.md, "The log's head,
 * when asked", and "Pages"). One call to the vault, `caller` with the head
 * it signed; then a stretch of `log`, or of `log_index` for a filter, and
 * the tiles that prove what the page shows, against that head:
 *
 *   proven     its body is the leaf the head's tree holds at its place
 *   unproven   past the head in both trees: signed since the vault's
 *              read, there with an older head put back, or planted; a
 *              reload settles the first. Every entry, when no head stands
 *   failed     within the head, and not what it signed: edited, or its
 *              tiles are; or at a place no entry the head numbered can
 *              stand, past its own tree and within the other (its tree
 *              and leaf are columns a writer edits, not under the tree)
 *
 * A page of the whole log, unfiltered, also says what its stretch lacks
 * (`holes`). A filtered one cannot: it reads `log_index`, which nothing
 * holds to the log, so a deleted index row hides an entry there with no
 * trace. It holds what it shows to the head, and looks for nothing absent.
 */

export type AuditEntryView = {
  seq: number;
  /** 0.14.7's: which component wrote it. Every 0.16 entry is the vault's. */
  author: 'app' | 'vault';
  occurredAt: string;
  actorType: 'user' | 'service' | 'system';
  actorId: string;
  /** What was done; `DETAIL_ACTIONS` for the ones a page leaves out unless asked. */
  action: string;
  decision: 'allow' | 'deny';
  /** Why a refusal: the vault's code (`no_access`, `bulk_limit`, …). */
  reason: string | null;
  /** A technical step or a sign-in: left out unless asked for. */
  detail: boolean;
  /** The member an access or membership entry is about, when not its actor: `user:ada@acme.example`, `token:ci`. */
  subject: string | null;
  project: string | null;
  environment: string | null;
  /** The secret's key, for an entry about one. */
  key: string | null;
  /** The version a read released, or a write stored. */
  version: number | null;
  /** For a read of several secrets at one place, logged as one entry: each key, with the version released. `key` and `version` are then null. */
  secrets: { key: string | null; version: number | null }[] | null;
  /** 0.14.7's: no 0.16 entry has one. */
  operationId: string | null;
  /** 0.14.7's: no 0.16 entry has one. */
  relatedSeq: number | null;
  /** The request that wrote it. */
  requestId: string | null;
  /** For a CI run's exchange: the run the issuer said it was for. What the issuer asserted, not proof of which run sent the request. */
  run: { exchangeSeq: number; claims: Record<string, string | number> } | null;
  /** For an entry written on a personal token: the token, by its id and its label. The entry's actor is its person. */
  token: { id: string; label: string } | null;
  /** What else the entry says (its body's `detail`). Never a value. */
  metadata: Record<string, unknown>;
  /** Whether the head the vault vouched for holds this entry as it is: see above. */
  proof: 'proven' | 'unproven' | 'failed';
};

/**
 * Technical steps and sign-ins: in the log and under its trees like
 * everything else, but not what someone did with secrets or access, so a
 * page leaves them out unless asked.
 */
export const DETAIL_ACTIONS = [
  'sign_in',
  'sign_out',
  'credential.end',
  'token.create',
  'token.revoke',
  'device.start',
  'device.approve',
  'device.deny',
  'device.decide',
  'device.redeem',
  // An MCP client's code redeemed, or its tokens refreshed: every hour of its use.
  'mcp.token',
  'account.link',
  'account.unlink',
  // A workload's session: each CI run's, and each sidecar's renewal.
  'workload.signin',
  'workload.renew',
  // What lapsed, removed by the vault itself.
  'upkeep.expire',
] as const;

/** Detail entries a page left out, by action. */
export type HiddenCount = { action: string; count: number };

/**
 * Entries the head says were signed, and not pruned, that a page of the
 * whole log does not find, between the two it found around them (`above`
 * the newer, null for the head; `below` the older, null for the log's
 * start): how many of each tree. A prune between the vault's read of the
 * head and the page's read of the log shows as uses missing here; a reload
 * settles it.
 */
export type AuditHole = { above: number | null; below: number | null; kept: number; aging: number };

export type AuditPage = {
  /** Newest first. */
  entries: AuditEntryView[];
  /** Whether the log goes on below this page: `next` is where. */
  more: boolean;
  /** The `before` of the page below, or null on the last. */
  next: number | null;
  /** Without `detail`: what the page's stretch left out, most first. */
  hidden?: HiddenCount[];
  /** The head the page is proven against, as the vault signed it; null when none stands under its keys. */
  head: { size: number; signedAt: string } | null;
  /** On a page of the whole log with no path or actor, under a head: what its stretch lacks. Null otherwise. */
  holes: AuditHole[] | null;
};

export type AuditQuery = {
  path?: Path;
  /** `user:ada@acme.example`, `token:ci-deploy`, or a bare name for either. */
  actor?: string;
  decision?: 'allow' | 'deny';
  /** Include the detail entries, `DETAIL_ACTIONS`. */
  detail?: boolean;
  /** Entries older than this seq, for paging backwards: the page above's `next`. */
  before?: number;
  limit: number;
};

/** A log entry's body, as the vault writes it (`Entry` in @coffre/vault): what of it a page reads. */
type Body = { at?: unknown; action?: unknown; actor?: unknown; credential?: unknown; request?: unknown; objects?: unknown; detail?: unknown };

const DETAIL = new Set<string>(DETAIL_ACTIONS);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** How many entries a page reads for every one it may show: room for those it leaves out. */
const READ_PER_SHOWN = 2;
/** The most a page reads, whatever it shows. */
const MOST_READ = 1000;

/**
 * Newest first. Whoever reads the whole log reads everything: an Auditor,
 * Admin or Owner whose scope narrows nothing (`readsWholeLog`). Anyone else
 * reads the entries whose every place they hold `audit.read` at, by a
 * grant or their instance role, and nothing else: an entry about no place,
 * such as a sign-in or a member's removal, is the instance's, and theirs
 * alone.
 *
 * A page reads a stretch of at most twice `limit` entries, a thousand at
 * most, and shows up to `limit` of them: those its filters and the caller
 * may see, without the detail ones unless asked, which it counts. So it
 * may show fewer than `limit` and go on (`more`): its stretch ends where
 * it stopped reading, `next`, and pages tile the log, each entry read by
 * one. Its statements: the places it is about (none for whoever reads the
 * whole log, with no path), the stretch, and the tiles and names.
 */
export async function listAudit(ctx: ApiContext, query: AuditQuery): Promise<AuditPage> {
  const who = await ctx.caller({ head: true });
  const head = who.head ?? null;
  const whole = readsWholeLog(who.holds);
  if (!whole && !canAnywhere(who, 'audit.read')) throw forbidden('you do not hold audit.read on any project');

  const actors = query.actor === undefined ? null : actorsNamed(query.actor);
  // The places the page is about, and the objects of `log_index` it reads by: the path's place; else the actor; else
  // the places the caller reads the log of; else none, the log itself.
  let places: LogPlaces | null = null;
  let objects: string[] | null = null;
  let about: string[] | null = null;
  if (query.path !== undefined) {
    const at = await placeAt(ctx, who, whole, query.path);
    places = at.places;
    objects = about = at.objects;
  } else if (!whole) {
    places = await logPlaces(ctx.db, { within: projectsReached(who) });
    objects = readable(who, places);
    if (objects.length === 0) throw forbidden('you do not hold audit.read on any project');
  }
  if (actors !== null && query.path === undefined) objects = actors.map((actor) => `principal:${actor}`);
  // Only a stretch of the whole log can say what it lacks: it reads the entry at `before` too, the page above's last.
  const unfiltered = objects === null;
  const reading = Math.min(query.limit * READ_PER_SHOWN, MOST_READ);
  const read = await logStretch(ctx.db, { objects, before: query.before ?? null, rows: reading + (unfiltered && query.before !== undefined ? 1 : 0) });
  const anchor = unfiltered && query.before !== undefined && read[0]?.seq === query.before ? read.shift()! : null;
  if (anchor === null && unfiltered && read.length > reading) read.pop();

  const shown: { row: LogRow; body: Body }[] = [];
  const hidden = new Map<string, number>();
  let taken = 0;
  for (const row of read) {
    if (shown.length === query.limit) break;
    taken += 1;
    const body = parsed(row.body);
    const mentions = mentionsOf(body);
    if (!whole && !visibleTo(who, mentions, places!)) continue;
    // What the index says an entry mentions is a writer's to edit: the body, under the tree, decides.
    if (about !== null && !about.some((object) => mentions.includes(object))) continue;
    if (actors !== null && !actors.includes(String(body.actor))) continue;
    if (query.decision !== undefined && decisionOf(body) !== query.decision) continue;
    const action = String(body.action);
    if (query.detail !== true && DETAIL.has(action)) hidden.set(action, (hidden.get(action) ?? 0) + 1);
    else shown.push({ row, body });
  }
  const stretch = read.slice(0, taken);
  // Nothing is numbered below 0: a stretch that reached it is the log's end.
  const more = (taken < read.length || read.length >= reading) && stretch.at(-1)?.seq !== 0;
  const next = more && stretch.length > 0 ? stretch.at(-1)!.seq : null;

  const ids = { projects: new Set<string>(), environments: new Set<string>(), secrets: new Set<string>(), credentials: new Set<string>() };
  for (const { body } of shown) {
    for (const object of mentionsOf(body)) {
      const [kind, id] = [object.slice(0, object.indexOf(':')), object.slice(object.indexOf(':') + 1)];
      if (!UUID.test(id)) continue;
      if (kind === 'project') ids.projects.add(id);
      else if (kind === 'environment') ids.environments.add(id);
      else if (kind === 'secret') ids.secrets.add(id);
    }
    if (typeof body.credential === 'string' && UUID.test(body.credential)) ids.credentials.add(body.credential);
  }
  const proving = head === null ? [] : shown.flatMap(({ row }) => (placed(head, row) === 'within' ? [row] : []));
  const found = await logProofs(ctx.db, tilesOf(head, proving), {
    projects: [...ids.projects],
    environments: [...ids.environments],
    secrets: [...ids.secrets],
    credentials: [...ids.credentials],
  });
  const proofOf = prover(head, found.tiles);
  const entries = shown.map(({ row, body }) => ({ ...viewOf(row, body, found), proof: proofOf(row) }));
  const holes = head !== null && unfiltered ? holesOf(head, query.before === undefined ? 'head' : anchor, stretch, more) : null;
  const page: AuditPage = { entries, more, next, head: head === null ? null : { size: head.size, signedAt: head.signedAt }, holes };
  if (query.detail === true) return page;
  // Most of what is hidden first.
  return { ...page, hidden: [...hidden].map(([action, count]) => ({ action, count })).sort((a, b) => b.count - a.count || (a.action < b.action ? -1 : a.action > b.action ? 1 : 0)) };
}

/** A member as `actor` names one: in full, or a bare name for a person's or a service account's. */
function actorsNamed(actor: string): string[] {
  if (/^(user|token):/.test(actor)) return [memberOf(actor)];
  const named = [`user:${actor}`, `token:${actor}`].flatMap((member) => {
    try {
      return [memberOf(member)];
    } catch {
      return [];
    }
  });
  if (named.length === 0) throw badRequest('name a member as user:<email>, token:<name>, or either bare');
  return named;
}

/**
 * The path's place, and the objects its entries mention: a project's, an
 * environment's, or each secret's of that key there. To whoever does not
 * read the whole log, a place they may not read the log of is refused as
 * one that is not there: neither says whether it is.
 */
async function placeAt(ctx: ApiContext, who: Called, whole: boolean, path: Path): Promise<{ places: LogPlaces; objects: string[] }> {
  const places = await logPlaces(ctx.db, { slug: path.project, ...(path.key === undefined ? {} : { key: path.key }) });
  const hidden = (what: string) => (whole ? notFound(`no such ${what}`) : forbidden(`you do not hold audit.read at ${[path.project, path.environment].filter(Boolean).join('/')}`));
  const projectId = [...places.projects].find(([, slug]) => slug === path.project)?.[0];
  if (projectId === undefined) throw hidden('project');
  if (path.environment === undefined) {
    if (!whole && !can(who, 'audit.read', placeOf({ id: projectId }, null))) throw hidden('project');
    return { places, objects: [`project:${projectId}`] };
  }
  const mine = personalOf(path.environment);
  const environment = [...places.environments.values()].find((row) =>
    row.projectId === projectId && (mine === null ? row.slug === path.environment : row.owner === who.principal && row.parent?.slug === mine),
  );
  if (environment === undefined || (!whole && !can(who, 'audit.read', placeOf({ id: projectId }, environment)))) throw hidden('environment');
  if (path.key === undefined) return { places, objects: [`environment:${environment.id}`] };
  const secrets = places.secrets.filter((secret) => secret.environmentId === environment.id);
  if (secrets.length === 0) throw notFound('no such secret');
  return { places, objects: secrets.map((secret) => `secret:${secret.id}`) };
}

/** The objects of the places the caller reads the log of: each project's they read it all of, and each environment's. */
function readable(who: Called, places: LogPlaces): string[] {
  const objects: string[] = [];
  for (const [id] of places.projects) if (can(who, 'audit.read', placeOf({ id }, null))) objects.push(`project:${id}`);
  for (const environment of places.environments.values()) {
    if (can(who, 'audit.read', placeOf({ id: environment.projectId }, environment))) objects.push(`environment:${environment.id}`);
  }
  return objects;
}

/**
 * Whether the caller may see an entry: it is about a place, and they read
 * the log of every place it mentions, an environment at the environment,
 * a project mentioned alone at the project. One the page does not know is
 * not theirs.
 */
function visibleTo(who: Called, mentions: readonly string[], places: LogPlaces): boolean {
  const environments = mentions.filter((object) => object.startsWith('environment:')).map((object) => object.slice('environment:'.length));
  const projects = mentions.filter((object) => object.startsWith('project:')).map((object) => object.slice('project:'.length));
  if (environments.length + projects.length === 0) return false;
  const within = new Set<string>();
  for (const id of environments) {
    const environment = places.environments.get(id);
    if (environment === undefined || !can(who, 'audit.read', placeOf({ id: environment.projectId }, environment))) return false;
    within.add(environment.projectId);
  }
  return projects.every((id) => within.has(id) || (places.projects.has(id) && can(who, 'audit.read', placeOf({ id }, null))));
}

function parsed(text: string): Body {
  try {
    const body = JSON.parse(text) as unknown;
    return typeof body === 'object' && body !== null && !Array.isArray(body) ? (body as Body) : {};
  } catch {
    return {};
  }
}

const mentionsOf = (body: Body): string[] => (Array.isArray(body.objects) ? body.objects.filter((object): object is string => typeof object === 'string') : []);
const detailOf = (body: Body): Record<string, unknown> => (typeof body.detail === 'object' && body.detail !== null && !Array.isArray(body.detail) ? (body.detail as Record<string, unknown>) : {});
/** A refused change's entry says why (D236): what tells it from one that went through. */
const decisionOf = (body: Body): 'allow' | 'deny' => (typeof detailOf(body).refused === 'string' ? 'deny' : 'allow');
const sizeOf = (head: SignedHead, kept: boolean) => (kept ? head.keptSize : head.agingSize);

/**
 * Where the head puts an entry, by the counts it says come before it (its
 * own tree's, its leaf; the other's, its seq less its leaf): within its
 * tree, past both, or neither, a place no entry the signer numbered holds.
 * The head numbered `size` entries: one past its own tree and within the
 * other, or the reverse, was moved there.
 */
function placed(head: SignedHead, row: LogRow): 'within' | 'past' | 'nowhere' {
  if (row.leaf < sizeOf(head, row.kept)) return 'within';
  return row.seq - row.leaf >= sizeOf(head, !row.kept) ? 'past' : 'nowhere';
}

/** The tiles that prove each entry, by tree: one read for the page. */
function tilesOf(head: SignedHead | null, rows: readonly LogRow[]): TileAt[] {
  if (head === null) return [];
  const tiles = new Map<string, TileAt>();
  for (const { kept, leaf } of rows) {
    for (const { level, index } of tilesFor((nodes) => inclusionProof(nodes, leaf, sizeOf(head, kept)))) tiles.set(`${kept} ${level}/${index}`, { kept, level, index });
  }
  return [...tiles.values()];
}

/**
 * Each entry against the head: its leaf hash, up the tree the tiles hold,
 * to the head's root. The nodes are remembered for the page, which proves
 * its entries up the same few paths.
 */
function prover(head: SignedHead | null, tiles: { kept: Map<string, Buffer>; aging: Map<string, Buffer> }): (row: LogRow) => AuditEntryView['proof'] {
  if (head === null) return () => 'unproven';
  const remembered = (from: Nodes): Nodes => {
    const known = new Map<string, Hash>();
    return (level, index) => {
      const key = tileKey(level, index);
      let hash = known.get(key);
      if (hash === undefined) known.set(key, (hash = from(level, index)));
      return hash;
    };
  };
  const trees = {
    kept: { nodes: remembered(nodesFrom(tiles.kept)), size: head.keptSize, root: Buffer.from(head.keptRoot, 'hex') },
    aging: { nodes: remembered(nodesFrom(tiles.aging)), size: head.agingSize, root: Buffer.from(head.agingRoot, 'hex') },
  };
  return (row) => {
    const { kept, leaf, body } = row;
    const where = placed(head, row);
    if (where !== 'within') return where === 'past' ? 'unproven' : 'failed';
    const { nodes, size, root } = trees[kept ? 'kept' : 'aging'];
    try {
      return verifyInclusion(leafHash(Buffer.from(body)), leaf, size, inclusionProof(nodes, leaf, size), root) ? 'proven' : 'failed';
    } catch {
      // A tile on the way up is missing or short: not as signed.
      return 'failed';
    }
  };
}

/**
 * What a stretch of the whole log lacks, by the trees' counts. An entry
 * says how many of each tree come before it: its own tree's, its leaf; the
 * other's, its seq less its leaf. Going down the stretch from `top`, the
 * head on the first page or the entry the page above ended at on the next
 * (null when that entry is not there: the page starts at its own first),
 * each entry should follow the last with nothing of either tree between,
 * and the last page should reach each tree's start: the kept one's first
 * entry, the aging one's first not pruned (`agingFrom`). An entry past the
 * head stands outside it, and is passed over; an entry above past it
 * starts the page at the head.
 *
 * A seq is not under the trees, only a leaf: a writer who deletes an
 * entry and numbers the ones after it again moves the hole, and may move
 * it off the page. The signer's re-check finds the deletion by leaf.
 */
export function holesOf(head: SignedHead, top: 'head' | LogRow | null, stretch: readonly LogRow[], more: boolean): AuditHole[] {
  const within = (row: LogRow) => placed(head, row) === 'within';
  const before = (row: LogRow) => ({ kept: row.kept ? row.leaf : row.seq - row.leaf, aging: row.kept ? row.seq - row.leaf : row.leaf });
  const holes: AuditHole[] = [];
  /** The counts of each tree below `above`: what the next entry down must make up. */
  let at: { above: number | null; kept: number; aging: number } | null =
    top === null ? null : top === 'head' || !within(top) ? { above: null, kept: head.keptSize, aging: head.agingSize } : { above: top.seq, ...before(top) };
  const hole = (above: number | null, below: number | null, kept: number, agingAbove: number, agingBelow: number) => {
    // Uses below the first not pruned are gone as the head says.
    const aging = Math.max(0, agingAbove - Math.max(agingBelow, head.agingFrom));
    if (kept > 0 || aging > 0) holes.push({ above, below, kept: Math.max(0, kept), aging });
  };
  for (const row of stretch) {
    if (!within(row)) continue;
    const counts = before(row);
    const own = { kept: row.kept ? 1 : 0, aging: row.kept ? 0 : 1 };
    if (at !== null) hole(at.above, row.seq, at.kept - counts.kept - own.kept, at.aging, counts.aging + own.aging);
    at = { above: row.seq, ...counts };
  }
  if (!more && at !== null) hole(at.above, null, at.kept, at.aging, 0);
  return holes;
}

/** An entry as the page shows it, its places and keys by name. */
function viewOf(row: LogRow, body: Body, names: Awaited<ReturnType<typeof logProofs>>): Omit<AuditEntryView, 'proof'> {
  const detail = detailOf(body);
  const mentions = mentionsOf(body);
  const ids = (kind: string) => mentions.filter((object) => object.startsWith(`${kind}:`)).map((object) => object.slice(kind.length + 1));
  const environment = ids('environment').map((id) => names.environments.get(id)).find((found) => found !== undefined);
  const projectId = environment?.projectId ?? ids('project').find((id) => names.projects.has(id));
  const actor = typeof body.actor === 'string' ? body.actor : null;
  const subject = ids('principal').find((principal) => principal !== actor) ?? null;
  // A use names each key it released; a change of one secret, the secret.
  const released = Array.isArray(detail.keys) && body.action === 'secret.read'
    ? (detail.keys as unknown[]).map((item) => {
        const { key, version } = (item ?? {}) as { key?: unknown; version?: unknown };
        return { key: typeof key === 'string' ? key : null, version: typeof version === 'number' ? version : null };
      })
    : null;
  const secretIds = ids('secret');
  const key = released?.length === 1 ? released[0]!.key : released === null ? ((secretIds.length === 1 ? names.secrets.get(secretIds[0]!) : undefined) ?? (typeof detail.key === 'string' ? detail.key : null)) : null;
  const version = released?.length === 1 ? released[0]!.version : released === null && typeof detail.version === 'number' ? detail.version : null;
  const credential = typeof body.credential === 'string' ? names.credentials.get(body.credential) : undefined;
  return {
    seq: row.seq,
    author: 'vault',
    occurredAt: typeof body.at === 'number' && Number.isFinite(body.at) ? new Date(body.at).toISOString() : '',
    ...actorParts(actor),
    action: typeof body.action === 'string' ? body.action : '',
    decision: decisionOf(body),
    reason: typeof detail.refused === 'string' ? detail.refused : null,
    detail: DETAIL.has(String(body.action)),
    subject,
    project: projectId === undefined ? null : (names.projects.get(projectId) ?? null),
    environment: environment?.slug ?? null,
    key,
    version,
    secrets: released !== null && released.length !== 1 ? released : null,
    operationId: null,
    relatedSeq: null,
    requestId: typeof body.request === 'string' ? body.request : null,
    run: body.action === 'token.exchange' ? { exchangeSeq: row.seq, claims: runClaims(detail.run) } : null,
    token: credential?.kind === 'personal' ? { id: body.credential as string, label: credential.label ?? '' } : null,
    metadata: detail,
  };
}

/** `user:ada@acme.example` as a person, `token:ci` as a service account, and no actor as the vault itself. */
function actorParts(actor: string | null): Pick<AuditEntryView, 'actorType' | 'actorId'> {
  if (actor === null) return { actorType: 'system', actorId: 'vault' };
  if (actor.startsWith('user:')) return { actorType: 'user', actorId: actor.slice('user:'.length) };
  if (actor.startsWith('token:')) return { actorType: 'service', actorId: actor.slice('token:'.length) };
  return { actorType: 'system', actorId: actor };
}

function runClaims(run: unknown): Record<string, string | number> {
  if (typeof run !== 'object' || run === null) return {};
  return Object.fromEntries(Object.entries(run).filter((pair): pair is [string, string | number] => typeof pair[1] === 'string' || typeof pair[1] === 'number'));
}
