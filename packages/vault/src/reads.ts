import { createHmac, timingSafeEqual } from 'node:crypto';

import { entryLeaf, inclusionProof, nodesFrom, openPair, tileMap, tilesFor, verifyInclusion, verifyLog, type Cut, type LogEntry, type LogReader, type Pair, type PairVerifiers, type StoredPair } from '@coffre/core/merkle';
import { USE_WAYS } from '@coffre/core/vault';

import { logObject } from './inputs.ts';
import { authentic, retentionCut } from './log-entry.ts';

// The audit pages' reads (T166; docs/design/0.15-plan.md, "As built: T166";
// formal/Reads.tla). A use is the slim row of R53: its way in, its key, the
// fork it was read in, its purpose and when, under a MAC that cannot cover
// the number Postgres gives it. It names neither whose read it was nor where.
// The projector says so, for every use a signed pair seals: its account, its
// key's place, through a reference the source and its place, the version
// read, each from the sealed objects at the use's number (the number orders
// every use against every change, R50), under a MAC over all of it, the
// number included. It runs apart from the checkpointer, from a cursor of its
// own: a projection behind, or failing, lags the pages, which say so, and
// delays no seal, no change, no use.

/** A use as the pages list it (`log_reads`), every id lower-case. */
export type ReadRow = {
  number: bigint;
  at: number;
  credential: string;
  /** The use's code: its purpose, keepsSensitive and way in (`USE_PURPOSES`). */
  purpose: number;
  principal: string;
  /** The key the use named, where it is held: a reference's holder. */
  secret: string;
  environment: string;
  project: string;
  /** The fork it was read in. */
  place: string | null;
  /** Through a reference: its source then, and where that is. */
  source: string | null;
  sourceEnvironment: string | null;
  sourceProject: string | null;
  /** The version read: its key's, or its source's; null where its object names none. */
  version: string | null;
  mac: Buffer;
};

/**
 * A read at one of its places (`log_read_places`), under a key filed there,
 * with every place it is at besides (`partners`, sorted; none at one place).
 */
export type ReadPlace = { environment: string; partners: string[]; at: number; number: bigint; principal: string; secret: string };

/**
 * How far the projector has gone: every use at or below `through` is
 * projected; `pair`, the signed pair at or below it; `at`, the signed time
 * of the newest pair whose uses are all projected, which the pages say they
 * list reads through when it is behind.
 */
export type ReadsCursor = { through: bigint; pair: bigint; at: number; mac: Buffer | null };

/** A way in's or key's object as the log holds it, for a projection: a change of it, whole, for its MAC; null for none. */
export type Sealed = LogEntry | null;

/** What the projector needs of the database (log-store.ts, on both engines). */
export type ReadsStore = Pick<LogReader, 'tiles'> & {
  readsCursor(): Promise<ReadsCursor>;
  /** The newest retention change and its leaf index in the changes tree (plan PR 7), for `sealedCut`. */
  retention(): Promise<{ entry: LogEntry; index: number } | null>;
  pair(upto: bigint): Promise<{ upto: bigint; notes: { changes: string; uses: string } } | null>;
  pairs(after: bigint, limit: number): Promise<{ upto: bigint; notes: { changes: string; uses: string } }[]>;
  newest(): Promise<{ upto: bigint; notes: { changes: string; uses: string } } | null>;
  entries(after: bigint, upto: bigint, options?: { floor?: number; limit?: number }): Promise<LogEntry[]>;
  /**
   * Each object asked, in order: its first change (`first`), or its newest
   * numbered below `below`; null for none.
   */
  objects(asked: readonly { object: string; below: bigint; first: boolean }[]): Promise<Sealed[]>;
  /** The reads' days these are (`make_reads_day` on Postgres), once a store: a log older than the days made ahead holds uses of others. */
  makeReadsDays(days: readonly string[]): Promise<void>;
  /** The reads and their places, each read once by its number, and the cursor on to `cursor`, never back: one write. */
  writeReads(reads: readonly ReadRow[], places: readonly ReadPlace[], cursor: ReadsCursor): Promise<void>;
  /**
   * What the listing holds of a stretch (`checkReads`): its reads numbered
   * in `(after, upto]` at times in `[from, to]`; for each of `places`, the
   * principal its row names, or null for none; and whether its set of
   * places is listed (`log_read_partners`).
   */
  listing(stretch: { after: bigint; upto: bigint; from: number; to: number }, places: readonly ReadPlace[]): Promise<{ reads: ReadRow[]; places: (string | null)[]; pairs: boolean[] }>;
};

/** How many entries one step of the projector reads: a tick's worth at R44's 1,000 uses a second, and more. */
export const PROJECTED_AT_ONCE = 1_000;

const MAC_BYTES = 16;

/** A read's MAC: HMAC-SHA256 under the log's MAC key, over every column but itself, the number included, cut to 16 bytes. */
export function readMac(key: Buffer, row: Omit<ReadRow, 'mac'>): Buffer {
  const columns = [
    String(row.number), String(row.at), row.credential, String(row.purpose), row.principal, row.secret, row.environment, row.project,
    row.place, row.source, row.sourceEnvironment, row.sourceProject, row.version,
  ];
  return createHmac('sha256', key).update('coffre.reads.v1\0').update(JSON.stringify(columns)).digest().subarray(0, MAC_BYTES);
}

/** The cursor's MAC (formal/Reads.tla, CursorMac): over where it stands, so that one moved ahead never has the pages list reads as whole. */
export function cursorMac(key: Buffer, cursor: Pick<ReadsCursor, 'through' | 'pair' | 'at'>): Buffer {
  return createHmac('sha256', key).update('coffre.reads.cursor.v1\0').update(`${cursor.through}:${cursor.pair}:${cursor.at}`).digest().subarray(0, MAC_BYTES);
}

/** Whether a cursor's MAC holds under `key`: the start, before any read is projected, has none. */
export function cursorHolds(key: Buffer, cursor: ReadsCursor): boolean {
  if (cursor.mac === null) return cursor.through === 0n && cursor.pair === 0n && cursor.at === 0;
  return cursor.mac.length === MAC_BYTES && timingSafeEqual(cursorMac(key, cursor), cursor.mac);
}

/** Whether a read's MAC holds under `key`. */
export function readHolds(key: Buffer, row: ReadRow): boolean {
  return row.mac.length === MAC_BYTES && timingSafeEqual(readMac(key, row), row.mac);
}

/** What one run of the projector did: where it stands, the newest signed pair's number, and how many reads it wrote. */
export type Projected = { through: bigint; sealed: bigint; projected: number };

/**
 * A range of the log, from the pair at `start` (null: the genesis) to
 * `next`, read whole and held to the trees (WindowChecked): its entries,
 * from the floor `start` signed, must give `next`'s signed heads from
 * `start`'s, both trees, so that a use or change deleted, edited,
 * renumbered or slipped in since its seal fails the range, never a read
 * derived from it. A tick seals its whole window, so a range is what one
 * tick sealed: a few hundred entries, more after an outage, which the
 * checkpointer read whole too. Only a range at or above retention's cut
 * (`sealedCut`) is asked for, whose uses are all kept. Throws on a range
 * that does not hold.
 */
async function sealedRange(store: ReadsStore, verifiers: PairVerifiers, start: StoredPair | null, next: StoredPair): Promise<LogEntry[]> {
  const walked: LogEntry[] = [];
  // The log as far as `next`, and no further: the walk takes `next` for the newest pair.
  const reader: LogReader = {
    pairs: async (after, limit) => (after >= next.upto ? [] : (await store.pairs(after, limit)).filter((row) => row.upto <= next.upto)),
    pair: async (upto) => (upto > next.upto ? null : store.pair(upto)),
    entries: async (after, upto, options) => (after >= next.upto ? [] : store.entries(after, upto < next.upto ? upto : next.upto, options)),
    tiles: (tree, keys) => store.tiles(tree, keys),
  };
  const verdict = await verifyLog(reader, { verifiers, ...(start === null ? {} : { from: start.notes }), check: (entry) => (walked.push(entry), null) });
  if (!verdict.ok || verdict.headPair?.upto !== next.upto) {
    throw new Error(`the log up to ${next.upto} does not hold to the pair that sealed it: ${verdict.problems[0] ?? 'the walk stopped short'}`);
  }
  return walked;
}

/**
 * Where retention cut the log, when it has (plan PR 7): the newest
 * retention change, proven in the changes tree of the newest pair (`head`)
 * from its tiles, as the whole log's walk holds it (Seal.tla's CutSealed),
 * and the cut it names. Below it, uses are gone with their days, and their
 * reads with them: the projector and the check start at the cut. Null
 * before any retention change is sealed; throws on one a writer put there.
 */
async function sealedCut(store: ReadsStore, head: Pair): Promise<Cut | null> {
  const retained = await store.retention();
  if (retained === null || retained.entry.number > head.upto) return null;
  const { entry, index } = retained;
  const cut = retentionCut(entry);
  const size = head.changes.size;
  const proof = cut !== null && Number.isSafeInteger(index) && index >= 0 && index < size
    ? inclusionProof(nodesFrom(tileMap(await store.tiles('changes', tilesFor((nodes) => inclusionProof(nodes, index, size))))), index, size)
    : null;
  if (cut === null || proof === null || !verifyInclusion(entryLeaf('changes', entry.number, entry.columns), index, size, proof, head.changes.root)) {
    throw new Error(`the retention change ${entry.number} is not one the log sealed`);
  }
  return cut;
}

/** The range the pair at `at` starts: its row (none for the genesis at 0), the next pair's, and that one opened. */
async function rangeAt(store: ReadsStore, verifiers: PairVerifiers, at: bigint): Promise<{ start: StoredPair | null; next: StoredPair; pair: Pair }> {
  const start = await store.pair(at);
  if (start === null && at !== 0n) throw new Error(`no pair at ${at}, where the reads' projection stands: checkpoints were deleted`);
  const [next] = await store.pairs(at, 1);
  const pair = next === undefined ? null : await openPair(next.notes, verifiers);
  if (next === undefined || pair === null) throw new Error(`the pair after ${at} is not one the vault signed`);
  return { start, next, pair };
}

/**
 * Project the sealed uses above the cursor, `atOnce` at a time (a step),
 * up to `steps` steps, a checkpoint's range after another: never past the
 * newest pair whose signatures hold (ProjectSealedOnly), each range read
 * whole and held to the trees (`sealedRange`, WindowChecked), once a run,
 * then derived (`derive`) and written, the rows before the cursor
 * (CursorAfterRows), each once (IdempotentByNumber). A range that does not
 * hold stops the projection, an alarm, and the pages say how far they
 * list: nothing it would derive is listed (fail closed).
 */
export async function projectReads(store: ReadsStore, keys: { verifiers: PairVerifiers; mac: Buffer }, options: { steps?: number; atOnce?: number } = {}): Promise<Projected> {
  const atOnce = options.atOnce ?? PROJECTED_AT_ONCE;
  let cursor = await store.readsCursor();
  if (!cursorHolds(keys.mac, cursor)) throw new Error(`the reads' cursor, at ${cursor.through}, is not the vault's: it was moved around the projector`);
  const newest = await store.newest();
  const head = newest === null ? null : await openPair(newest.notes, keys.verifiers);
  if (head === null) return { through: cursor.through, sealed: cursor.through, projected: 0 };
  // Retention drops no day, nor tile, the projector has yet to read (retention.ts): below its cut it goes on as anywhere,
  // and a range gone all the same stops it, never skipped (review r4).
  let projected = 0;
  // The range the cursor stands in, read once a run however many chunks it takes.
  let range: { at: bigint; pair: Pair; uses: LogEntry[] } | null = null;
  for (let step = 0; step < (options.steps ?? 4) && cursor.through < head.upto; step += 1) {
    if (range === null || range.at !== cursor.pair) {
      const { start, next, pair } = await rangeAt(store, keys.verifiers, cursor.pair);
      if (pair.upto > head.upto) throw new Error(`the pair after ${cursor.pair} is past the newest`);
      range = { at: cursor.pair, pair, uses: (await sealedRange(store, keys.verifiers, start, next)).filter((entry) => entry.tree === 'uses') };
    }
    const { pair } = range;
    // Where a step before this one stopped inside the range, on from there.
    const left = range.uses.filter((entry) => entry.number > cursor.through);
    const chunk = left.slice(0, atOnce);
    const { reads, places } = await derive(store, keys.mac, chunk);
    // Its time, once a range is whole: the pair's, as signed, which every read of it is at or below.
    const moved = chunk.length === left.length ? { through: pair.upto, pair: pair.upto, at: pair.at } : { through: chunk.at(-1)!.number, pair: cursor.pair, at: cursor.at };
    cursor = { ...moved, mac: cursorMac(keys.mac, moved) };
    // Each read's day there to hold it: uses of a log older than the days made ahead (review r4).
    await store.makeReadsDays([...new Set(reads.map((read) => new Date(read.at).toISOString().slice(0, 10)))]);
    await store.writeReads(reads, places, cursor);
    projected += reads.length;
  }
  return { through: cursor.through, sealed: head.upto, projected };
}

/** The most problems a stretch names; more are counted. */
const PROBLEMS_NAMED = 20;

/**
 * The reads' listing held to the sealed log, a checkpoint's range at a
 * time, from the pair at `from` (T166, steer 3): the explicit check of
 * the whole log, `coffre verify log`, never a page's. Each range is read
 * whole and held to the trees (`sealedRange`), its uses derived again as
 * the projector derives them, and each read and each of its places held to
 * the listing, as far as the projector has gone: the range it stands in
 * too, to the cursor. A read deleted from it, edited, renumbered or listed
 * twice, a place row deleted or changed, a set of places dropped, each is
 * named; and a range that does not hold, which stops the projector there.
 * A read planted under a number, or at a time, no use of the range may
 * have, it reads no further for: every page shows that one forged, by its
 * MAC. Below retention's cut no use is left to hold a read to: the check
 * starts at the cut. Flat: a stretch reads one range however long the log.
 */
export async function checkReads(store: ReadsStore, keys: { verifiers: PairVerifiers; mac: Buffer }, from: bigint): Promise<{ problems: string[]; through: bigint; listed: bigint; next: bigint | null }> {
  const cursor = await store.readsCursor();
  const stop = (problem: string) => ({ problems: [problem], through: from, listed: cursor.through, next: null });
  if (!cursorHolds(keys.mac, cursor)) return stop(`the reads' cursor, at ${cursor.through}, is not the vault's: it was moved around the projector`);
  // From the retention cut, when it is past `from`.
  const newest = await store.newest();
  const head = newest === null ? null : await openPair(newest.notes, keys.verifiers);
  if (head === null) return { problems: [], through: from, listed: cursor.through, next: null };
  let cut;
  try {
    cut = await sealedCut(store, head);
  } catch (error) {
    return stop((error as Error).message);
  }
  const at = cut !== null && cut.upto > from ? cut.upto : from;
  // The range the projector stands in is held as far as it has gone; past it, none.
  const last = at >= cursor.pair;
  if (last && (await store.pairs(cursor.pair, 1)).length === 0) return { problems: [], through: cursor.through, listed: cursor.through, next: null };
  let range;
  try {
    range = await rangeAt(store, keys.verifiers, last ? cursor.pair : at);
    range = { ...range, entries: await sealedRange(store, keys.verifiers, range.start, range.next) };
  } catch (error) {
    return stop(last ? `the projection is stopped at ${cursor.through}: ${(error as Error).message}` : (error as Error).message);
  }
  const { pair, entries, start } = range;
  const upto = last ? cursor.through : pair.upto;
  const floor = start === null ? 0 : ((await openPair(start.notes, keys.verifiers))?.floor ?? 0);
  const uses = entries.filter((entry) => entry.tree === 'uses' && entry.number <= upto);
  let problems: string[];
  try {
    problems = await listedAsSealed(store, keys.mac, uses, { after: start?.upto ?? 0n, upto, floor, signedAt: pair.at });
  } catch (error) {
    // A change a use is read from that does not hold: what stops the projector stops the check too, said.
    return stop((error as Error).message);
  }
  const named = problems.length <= PROBLEMS_NAMED ? problems : [...problems.slice(0, PROBLEMS_NAMED), `and ${problems.length - PROBLEMS_NAMED} more`];
  return { problems: named, through: upto, listed: cursor.through, next: last ? null : pair.upto };
}

/** What a range's uses, derived again, find wrong in the listing between `after` and `upto` (`checkReads`). */
async function listedAsSealed(store: ReadsStore, mac: Buffer, uses: readonly LogEntry[], range: { after: bigint; upto: bigint; floor: number; signedAt: number }): Promise<string[]> {
  const { reads, places } = await derive(store, mac, uses);
  if (reads.length === 0) return [];
  const problems: string[] = [];
  // Every time a use of the range may be at: none is below the floor the pair under it signed, nor, but for a clock
  // apart, past the time the pair over it was signed at.
  const ats = reads.map((read) => read.at);
  const listing = await store.listing({ after: range.after, upto: range.upto, from: Math.min(range.floor, ...ats), to: Math.max(range.signedAt, ...ats) }, places);
  const listed = new Map<bigint, ReadRow>();
  for (const read of listing.reads) {
    if (listed.has(read.number)) problems.push(`read ${read.number} is listed twice`);
    listed.set(read.number, read);
  }
  for (const read of reads) {
    const row = listed.get(read.number);
    listed.delete(read.number);
    if (row === undefined) problems.push(`read ${read.number} is sealed but not listed`);
    else if (!readHolds(mac, row) || !row.mac.equals(read.mac)) problems.push(`read ${read.number} is listed otherwise than the log sealed it`);
  }
  for (const number of listed.keys()) problems.push(`read ${number} is listed, but the log seals no such use`);
  places.forEach((place, i) => {
    const principal = listing.places[i];
    if (principal == null) problems.push(`read ${place.number} is not listed at a place it was read`);
    else if (principal !== place.principal) problems.push(`read ${place.number} is listed otherwise at a place it was read`);
    if (!listing.pairs[i]) problems.push(`read ${place.number}'s places are not listed together, so no page there lists it`);
  });
  return problems;
}

/** A use's columns as the uses tree holds them: [at, request, credential, secret, purpose, place, mac]. */
function useOf(entry: LogEntry) {
  const [at, , credential, secret, purpose, place] = entry.columns as [bigint, bigint, string, string, number, string | null];
  return { number: entry.number, at: Number(at), credential, secret, purpose, place };
}

/** A change's payload as JSON, or nothing for one that is not an object. */
function parsed(sealed: Sealed): Record<string, unknown> | null {
  const payload = sealed?.columns[4];
  if (typeof payload !== 'string') return null;
  try {
    const value = JSON.parse(payload) as unknown;
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const text = (value: unknown) => (typeof value === 'string' && value !== '' ? value : null);
const record = (value: unknown) => (typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null);

/**
 * The account a way in's first change names: a credential's issue, a
 * connection's or binding's making, the cutover's object, a principal's
 * admission. An account never changes: its first change says it for good.
 */
function accountOf(sealed: Sealed): string | null {
  const op = parsed(sealed);
  if (op === null) return null;
  const value = record(op.value);
  if (op.op === 'genesis') return text(value?.principal) ?? (value?.kind === 'principal' ? text(value.id) : null);
  if (op.op === 'member.add') return text(record(op.ref)?.id);
  return text(op.principal) ?? text(value?.principal);
}

/** A key's object as a change holds it whole: a write's, or the cutover's; nothing for a deletion, or a payload of another shape. */
function keyOf(sealed: Sealed): { projectId: string; environmentId: string; version: string | null; source: string | null } | null {
  const op = parsed(sealed);
  const object = op?.op === 'secret.write' ? op : op?.op === 'genesis' && record(op.value)?.kind === 'secret' ? record(op.value) : null;
  const [projectId, environmentId] = [text(object?.projectId), text(object?.environmentId)];
  if (object === null || projectId === null || environmentId === null) return null;
  return { projectId, environmentId, version: text(object.version), source: text(object.source) };
}

/** A way in's object, by its code (`USE_WAYS`): a credential's, a connection's or a binding's, or behind Access the person's own, which the use names. */
function wayObject(use: { credential: string; purpose: number }): string {
  const way = USE_WAYS[Math.floor(use.purpose / 512)];
  if (way === undefined) throw new Error(`a use's code, ${use.purpose}, names no way in`);
  return way === 'access' ? use.credential : logObject(way, use.credential);
}

/**
 * What each use read, from the sealed objects at its number: its way in's
 * account (its first change), its key's object below it, and through a
 * reference its source's below it. A use whose objects say nothing of it
 * (only a database writer leaves one so: a use of a key never sealed is
 * refused) is projected as the log says it, its account and place unknown:
 * shown, never dropped. Each change read is held to its MAC: one a writer
 * edited since its seal stops the projection (fail closed), never derives
 * a read from it. Its places: its key's environment, the fork, the
 * source's, each a row for each key filed there (a reference's holder and
 * its source in one environment, two), with all its places besides.
 */
async function derive(store: ReadsStore, mac: Buffer, entries: readonly LogEntry[]): Promise<{ reads: ReadRow[]; places: ReadPlace[] }> {
  const holds = authentic(mac);
  const read = async (asked: { object: string; below: bigint; first: boolean; use: bigint }[]) => (await store.objects(asked)).map((change, i) => {
    if (change !== null && !holds(change)) throw new Error(`change ${change.number}, which use ${asked[i]!.use} is read from, does not hold to its MAC: edited since its seal`);
    return change;
  });
  const uses = entries.map(useOf);
  const sealed = await read(uses.flatMap((use) => [
    { object: wayObject(use), below: use.number, first: true, use: use.number },
    { object: logObject('secret', use.secret), below: use.number, first: false, use: use.number },
  ]));
  const keys = uses.map((_, i) => keyOf(sealed[2 * i + 1]!));
  const through = uses.flatMap((use, i) => (keys[i]?.source == null ? [] : [{ i, object: logObject('secret', keys[i]!.source!), below: use.number, first: false, use: use.number }]));
  const sources = new Map((await read(through)).map((object, j) => [through[j]!.i, keyOf(object)]));
  const reads: ReadRow[] = [];
  const places: ReadPlace[] = [];
  uses.forEach((use, i) => {
    const key = keys[i];
    const source = key?.source == null ? null : sources.get(i) ?? null;
    const row: Omit<ReadRow, 'mac'> = {
      number: use.number,
      at: use.at,
      credential: use.credential,
      purpose: use.purpose,
      principal: accountOf(sealed[2 * i]!) ?? 'system:unknown',
      secret: use.secret,
      environment: key?.environmentId ?? NOWHERE,
      project: key?.projectId ?? NOWHERE,
      place: use.place,
      source: key?.source ?? null,
      sourceEnvironment: source?.environmentId ?? null,
      sourceProject: source?.projectId ?? null,
      version: key?.source == null ? (key?.version ?? null) : (source?.version ?? null),
    };
    reads.push({ ...row, mac: readMac(mac, row) });
    // Each place the read is at, and each key filed there: its holder at its own and the fork's, the source at the source's.
    const filed: [string, string][] = [[row.environment, row.secret]];
    if (row.place !== null) filed.push([row.place, row.secret]);
    if (row.source !== null && row.sourceEnvironment !== null) filed.push([row.sourceEnvironment, row.source]);
    const at = [...new Set(filed.map(([environment]) => environment))];
    for (const [environment, secret] of new Map(filed.map((pair) => [pair.join(':'), pair])).values()) {
      places.push({ environment, partners: at.filter((other) => other !== environment).sort(), at: row.at, number: row.number, principal: row.principal, secret });
    }
  });
  return { reads, places };
}

/** The place of a read whose key's object names none: no environment's, so no place's page lists it, but the whole log's and its member's. */
export const NOWHERE = '00000000-0000-0000-0000-000000000000';

/**
 * The projector as a host runs it, apart from its checkpointer: on Node,
 * `kick` after each tick starts a run unless one is going, and returns at
 * once (checkpointer-node.ts); on Workers, an object of its own runs it on
 * its own alarm (checkpointer-workers.ts). Either way no tick, seal, change
 * or use ever waits on it (formal/Reads.tla, SealNeverWaitsOnProjection).
 * Each run opens the store it reads and writes, goes some steps, and lets
 * go. A failure is an alarm, said once while it stands; the pages show the
 * lag meanwhile.
 */
export class Projector {
  readonly #open: () => Promise<{ store: ReadsStore; close(): Promise<void> }>;
  readonly #keys: { verifiers: PairVerifiers; mac: Buffer };
  readonly #alert: (message: string) => void;
  #running: Promise<boolean> | null = null;
  #failed: string | null = null;
  #stopped = false;

  constructor(open: () => Promise<{ store: ReadsStore; close(): Promise<void> }>, keys: { verifiers: PairVerifiers; mac: Buffer }, alert: (message: string) => void) {
    this.#open = open;
    this.#keys = keys;
    this.#alert = alert;
  }

  /** Start a run unless one is going or the projector is stopped; never waits on it. */
  kick(): void {
    void this.run();
  }

  /** A run, or the one going: whether it left sealed uses to project. Never throws. */
  run(): Promise<boolean> {
    if (this.#stopped) return Promise.resolve(false);
    return (this.#running ??= this.#run().finally(() => {
      this.#running = null;
    }));
  }

  /** The run going, if any, ended: for a host that stops, and for tests. */
  async settled(): Promise<void> {
    await this.#running;
  }

  /** No run after this one: a host's stop. */
  async stop(): Promise<void> {
    this.#stopped = true;
    await this.#running;
  }

  async #run(): Promise<boolean> {
    let opened: { store: ReadsStore; close(): Promise<void> } | null = null;
    try {
      opened = await this.#open();
      const { through, sealed } = await projectReads(opened.store, this.#keys);
      this.#failed = null;
      return through < sealed;
    } catch (error) {
      const message = `the reads' projection failed: ${error instanceof Error ? error.message : String(error)}`;
      if (message !== this.#failed) this.#alert(message);
      this.#failed = message;
      return false;
    } finally {
      await opened?.close().catch(() => {});
    }
  }
}
