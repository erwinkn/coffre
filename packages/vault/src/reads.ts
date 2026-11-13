import { Edge, edgeOf, entryLeaf, inclusionProof, nodesFrom, tileMap, tilesFor, verifyInclusion, verifyLog, type Cut, type LogEntry, type LogReader, type Pair, type StoredPair } from '@coffre/core/merkle';
import { USE_WAYS } from '@coffre/core/vault';

import { logObject } from './inputs.ts';
import { entryVouched, keysAt, openUnder, type Keyring } from './keyring.ts';
import { retentionCut } from './log-entry.ts';

// A use as the audit pages list it (formal/Reads.tla). A use is a slim row: its way in, its key,
// the fork it was read in, its purpose and when. It names neither whose read it was nor where. The audit projector
// (projection.ts) says so, for every use a signed pair seals, from what this derives: its account, its key's place,
// through a reference the source and its place, the version read, each from the sealed objects at the use's number
// (the number orders every use against every change). And the walk both the projector and the listing's check
// (audit-check.ts) read a checkpoint's range by, held to the pair that signed it.

/** A use as derived for the pages, every id lower-case. */
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
};

/** A way in's or key's object as the log holds it, for a projection: a change of it, whole, for its MAC; null for none. */
export type Sealed = LogEntry | null;

/** What the projector needs of the database (log-store.ts). */
export type ReadsStore = Pick<LogReader, 'tiles'> & {
  /** The log's rotations of the vault's signing key (T168) and its newest pair, in one statement: each key it replaced bounded by them (keyring.ts). */
  keyringRows(): Promise<{ rotations: LogEntry[]; newest: StoredPair | null }>;
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
};

/**
 * A range of the log, from the pair at `start` (null: the genesis) to
 * `next`, read whole and held to the trees (WindowChecked): its entries,
 * from the floor `start` signed, must give `next`'s signed heads from
 * `start`'s, both trees, so that a use or change deleted, edited,
 * renumbered or slipped in since its seal fails the range, never a read
 * derived from it. A tick seals its whole window, so a range is what one
 * tick sealed: a few hundred entries, more after an outage, which the
 * checkpointer read whole too. Only a range at or above retention's cut
 * (`sealedCut`) is asked for its uses, which are all kept there; a range at
 * or below `cut` is its changes alone (`changesBelow`), for the audit
 * projection, which lists changes from the start. Throws on a range that
 * does not hold.
 */
export async function sealedRange(
  store: Pick<ReadsStore, 'tiles' | 'pair' | 'pairs' | 'entries'>, ring: Keyring, start: StoredPair | null, next: StoredPair, cut: Cut | null = null,
): Promise<LogEntry[]> {
  if (cut !== null && next.upto <= cut.upto) return changesBelow(store, ring, start, next);
  const walked: LogEntry[] = [];
  // The log as far as `next`, and no further: the walk takes `next` for the newest pair.
  const reader: LogReader = {
    pairs: async (after, limit) => (after >= next.upto ? [] : (await store.pairs(after, limit)).filter((row) => row.upto <= next.upto)),
    pair: async (upto) => (upto > next.upto ? null : store.pair(upto)),
    entries: async (after, upto, options) => (after >= next.upto ? [] : store.entries(after, upto < next.upto ? upto : next.upto, options)),
    tiles: (tree, keys) => store.tiles(tree, keys),
  };
  // Under the keys that vouch where the range starts (T168): the pair at its end is held to its own by `rangeAt`.
  const verifiers = keysAt(ring, start?.upto ?? 0n).map((key) => key.verifiers);
  const verdict = await verifyLog(reader, { verifiers, ...(start === null ? {} : { from: start.notes }), check: (entry) => (walked.push(entry), null) });
  if (!verdict.ok || verdict.headPair?.upto !== next.upto) {
    throw new Error(`the log up to ${next.upto} does not hold to the pair that sealed it: ${verdict.problems[0] ?? 'the walk stopped short'}`);
  }
  return walked;
}

/**
 * A range below retention's cut, whose uses went with their days, and the
 * uses tree's tiles with them: its changes alone, which are kept for good,
 * held to the changes tree as `verifyLog` holds a walk below a cut, from the
 * edge the start's tiles give to `next`'s signed head, numbers rising and
 * the pair's time and floor never back. A use still there (a straggler of
 * the next day) is neither expected nor listed: the uses tree there is gone,
 * so nothing would vouch for it (as `checkListed`).
 */
async function changesBelow(store: Pick<ReadsStore, 'tiles' | 'pairs' | 'entries'>, ring: Keyring, start: StoredPair | null, next: StoredPair): Promise<LogEntry[]> {
  const row = start ?? (await store.pairs(-1n, 1))[0] ?? null;
  const from = row === null ? null : ((await openUnder(ring, row.notes))?.pair ?? null);
  const to = (await openUnder(ring, next.notes))?.pair ?? null;
  if (from === null || to === null || from.upto !== (start?.upto ?? 0n) || to.upto !== next.upto) {
    throw new Error(`the pairs at ${start?.upto ?? 0n} and ${next.upto} are not ones the vault signed`);
  }
  const edge = Edge.load(from.changes.size, tileMap(await store.tiles('changes', edgeOf(from.changes.size).filter((e) => e.width > 0))));
  if (!edge.root().equals(from.changes.root)) throw new Error(`checkpoint ${from.upto}: the changes tiles at its edge do not give its signed head`);
  const changes = (await store.entries(from.upto, to.upto, { floor: from.floor })).filter((entry) => entry.tree === 'changes');
  let previous = from.upto;
  for (const entry of changes) {
    if (entry.number <= previous || entry.number > to.upto) throw new Error(`${entry.number}: out of order, or outside the range from ${from.upto} to ${to.upto}`);
    previous = entry.number;
  }
  edge.append(changes.map((entry) => entryLeaf('changes', entry.number, entry.columns)));
  if (edge.size !== to.changes.size || !edge.root().equals(to.changes.root) || to.at < from.at || to.floor < from.floor) {
    throw new Error(`the log up to ${to.upto} does not hold to the pair that sealed it: the changes head differs from the entries, or its time or floor runs back`);
  }
  return changes;
}

/**
 * Where retention cut the log, when it has (plan PR 7): the newest
 * retention change, proven in the changes tree of the newest pair (`head`)
 * from its tiles, as the whole log's walk holds it (Seal.tla's CutSealed),
 * and the cut it names. Below it, uses are gone with their days, and their
 * reads with them: the projector and the check start at the cut. Null
 * before any retention change is sealed; throws on one a writer put there.
 */
export async function sealedCut(store: Pick<ReadsStore, 'retention' | 'tiles'>, head: Pair): Promise<Cut | null> {
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
  // Retention cuts a sealed prefix, then logs the cut: a cut at or above its own change (so above the head too) is
  // none the vault made.
  if (cut.upto >= entry.number) throw new Error(`the retention change ${entry.number} names a cut at ${cut.upto}, not below it`);
  return cut;
}

/** The range the pair at `at` starts: its row (none for the genesis at 0), the next pair's, and that one opened. */
export async function rangeAt(store: Pick<ReadsStore, 'pair' | 'pairs'>, ring: Keyring, at: bigint): Promise<{ start: StoredPair | null; next: StoredPair; pair: Pair }> {
  const start = await store.pair(at);
  if (start === null && at !== 0n) throw new Error(`no pair at ${at}, where the reads' projection stands: checkpoints were deleted`);
  const [next] = await store.pairs(at, 1);
  const pair = next === undefined ? null : ((await openUnder(ring, next.notes))?.pair ?? null);
  if (next === undefined || pair === null) throw new Error(`the pair after ${at} is not one the vault signed`);
  return { start, next, pair };
}

/**
 * The newest signed pair, opened under the vault's keys; null for a log that
 * has none yet, while the cursor is still at the start; otherwise why it
 * cannot be read: no pair under a cursor moved on, a pair whose signatures
 * fail, or a cursor past it (pairs deleted under it). Never taken for a log
 * with nothing to project or check (review r12: a newest pair edited had
 * the check answer ok, and the projector caught up, unsaid).
 */
export async function newestHeld(store: Pick<ReadsStore, 'newest'>, ring: Keyring, cursor: { through: bigint }): Promise<Pair | null | string> {
  const newest = await store.newest();
  if (newest === null) return cursor.through === 0n ? null : `the reads are listed through ${cursor.through}, but the log holds no signed pair`;
  const head = (await openUnder(ring, newest.notes))?.pair ?? null;
  if (head === null) return `the newest pair, through ${newest.upto}, does not hold to the vault's signatures`;
  if (cursor.through > head.upto) return `the reads are listed through ${cursor.through}, past the newest pair, through ${head.upto}`;
  return head;
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
 * a read from it.
 */
export async function derive(store: Pick<ReadsStore, 'objects'>, ring: Keyring, entries: readonly LogEntry[]): Promise<ReadRow[]> {
  const holds = (change: LogEntry) => entryVouched(ring, change) === 'held';
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
  return uses.map((use, i) => {
    const key = keys[i];
    const source = key?.source == null ? null : sources.get(i) ?? null;
    return {
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
  });
}

/** The place of a read whose key's object names none: no environment's; the whole log and its member's page list it. */
export const NOWHERE = '00000000-0000-0000-0000-000000000000';
