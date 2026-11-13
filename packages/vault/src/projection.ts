import { timingSafeEqual } from 'node:crypto';

import { DETAIL_ACTIONS, entryHash, entryMac as chainMac, GENESIS_HASH, type LogKey, type StoredEntry } from '@coffre/core/audit';
import type { LogEntry, Pair } from '@coffre/core/merkle';
import { useOfCode, type RebuildAuditInput } from '@coffre/core/vault';
import type { ChangeRecord } from '@coffre/db/log';

import { cursorMac, cursorVouched, eventMac, oldWalkOpen, type AuditCursor, type AuditEvent } from './audit-rows.ts';
import { logObject } from './inputs.ts';
import { keyringOf, type Keyring, type VerifierKeys } from './keyring.ts';
import { entryMac, type LogMacKey } from './log-entry.ts';
import { EVENT_KIND, eventObject } from './note.ts';
import { derive, newestHeld, NOWHERE, rangeAt, sealedCut, sealedRange, type ReadRow, type ReadsStore } from './reads.ts';

// The audit projector (0.16; docs/design/state-rows.md, sections 2 and 6; formal/Reads.tla): the one job that
// writes `audit_events`, `audit_event_places` and `audit_member_keys`, and moves `audit_cursor`, one transaction a batch
// (`project_audit`). Its sources:
//
// - the chains, `log_changes` and `log_uses`, a checkpoint's range at a time, each range read whole and held to the
//   pair that signed it, as the reads' projector holds it (reads.ts): nothing past the newest signed pair;
// - `audit_log`, walked backward by its hashes from an anchor, 5,000 entries a batch: an entry's hash covers its
//   content and the hash before it, so each batch is authenticated by the one above it, with no key and no walk from
//   the first entry. Heartbeats and checkpoints are left out.
//
// While `audit_log` is still appended to, its anchor is the newest signed 0.14 checkpoint, the `audit.checkpoint`
// entry whose MAC holds under the vault's 0.14 log key: the prefix it names, by its last entry's seq and hash. A newer
// one starts a walk down to the newest entry listed, once the walk under way has closed its gap: an entry of
// `audit_log` alone (a sign-in, a refusal the app decides) is listed at the next beat, as a use is at the next tick.
// That goes once the log is frozen (`oldFloor`, `oldTop`, `nextWalk`): the anchor is then the change naming its last
// entry, and one walk goes down from it to the first. `lossesAbove` and the accepted-loss message of `broken` go with
// them: the upgrade refuses a log holding an `audit.loss_accepted` entry, and a frozen log has no path that writes one,
// so no released 0.16 reaches that branch. Temporary, all of it: keep none by accident.
//
// What the projector lists of each log: every entry of `audit_log` but its heartbeats and checkpoints; every use, as
// a read; and of the changes, those that `audit_log` does not record too, which today's pages list from `log_changes`
// (`RECORDS`; here, from the payload's top-level keys: `SHAPES`): a sign-in through a trust binding, the vault's token
// issues, revokes and sign-outs, the two-trip key writes and first adds and their refusals, and the rebuilds
// (`rebuildAudit`); a change that carries its entry (`reported`), from that entry alone, ahead of all of these; and
// every event (note.ts), from its payload. A site that hands its entry to its change, or writes it as an event, stops
// appending it to `audit_log` in the same commit, so no act is listed twice; every other change lists nothing.

/** A member's newest read or write of a version of a key (`audit_member_keys`). */
export type MemberKey = { principal: string; secret: string; version: string; wrote: boolean; at: number; number: bigint };

/** What the projector needs of the database (log-store.ts). */
export type ProjectionStore = Pick<ReadsStore, 'tiles' | 'keyringRows' | 'retention' | 'pair' | 'pairs' | 'newest' | 'entries' | 'objects'> & {
  /** The cursor's row; throws `CursorGone`-like when a database writer deleted it. */
  auditCursor(): Promise<AuditCursor>;
  /** The vault's newest signed 0.14 checkpoint entry, or null for none. */
  oldAnchor(): Promise<StoredEntry | null>;
  /** The entries of `audit_log` with a seq in [`from`, `below`), in any order. */
  oldEntries(from: bigint, below: bigint): Promise<StoredEntry[]>;
  /** The `audit.loss_accepted` entries of `audit_log` above `seq`, oldest first: read only where a walk breaks. Temporary, as `oldFloor`. */
  lossesAbove(seq: bigint): Promise<StoredEntry[]>;
  /** The id of each version asked by its key and number (`secret:number`), that the database still holds. */
  versionIds(asked: readonly { secret: string; version: number }[]): Promise<Map<string, string>>;
  /** One batch, in one transaction (`project_audit`): only while the cursor still stands at `from`. Whether it wrote. */
  writeAudit(events: readonly AuditEvent[], keys: readonly MemberKey[], from: AuditCursor, to: AuditCursor): Promise<boolean>;
};

/**
 * How many entries one batch reads and writes, and one transaction holds: a
 * 0.14 entry is about 350 bytes, so a batch is about 1.7 MB, far inside a
 * Worker's 128 MB, and a few milliseconds of hashing, inside its CPU limit
 * (state-rows.md, section 6). Equisafe's 440,000 entries are 88 batches.
 */
export const PROJECTED_AT_ONCE = 5_000;

/** What one run did: where it stands in each log, and whether a batch is left that the next run should start at once. */
export type AuditProjected = { through: bigint; sealed: bigint; oldFrom: bigint; oldFloor: bigint; events: number; more: boolean };

const DETAIL = new Set<string>(DETAIL_ACTIONS);
const HEARTBEATS = new Set(['audit.heartbeat', 'audit.checkpoint']);

/**
 * Some batches, up to `steps`: the chains first, a range of theirs at a
 * time, then `audit_log`. A range or an entry that does not hold stops the
 * projection there, an alarm, and nothing it would derive is listed (fail
 * closed).
 */
export async function projectAudit(
  store: ProjectionStore, keys: VerifierKeys, oldKeys: readonly LogKey[], options: { steps?: number; atOnce?: number } = {},
): Promise<AuditProjected> {
  const atOnce = options.atOnce ?? PROJECTED_AT_ONCE;
  let cursor = await store.auditCursor();
  const ring = await keyringOf(keys, store);
  if (!cursorVouched(ring, cursor)) throw new Error(`the audit cursor, at ${cursor.through}, is not the vault's: it was moved around the projector`);
  const newest = await newestHeld(store, ring, cursor);
  if (typeof newest === 'string') throw new Error(newest);
  const head: Pair | null = newest;
  // Retention's cut, sealed in the newest pair: below it the uses went with their days, and a range there is its changes
  // alone, which are kept for good. A cursor starts below it on any database a day was dropped from before this
  // projector ran (an upgrade from 0.15) and after any rebuild. Read once a run: a day dropped under a newer cut while
  // the run reads its uses fails the range, and the next run starts from that cut.
  const cut = head === null ? null : await sealedCut(store, head);
  let events = 0;
  let range: { at: bigint; pair: Pair; entries: LogEntry[] } | null = null;
  const done = (more: boolean): AuditProjected => ({ through: cursor.through, sealed: head?.upto ?? 0n, oldFrom: cursor.oldFrom, oldFloor: cursor.oldFloor, events, more });
  for (let step = 0; step < (options.steps ?? 4); step += 1) {
    let batch: { events: Omit<AuditEvent, 'mac'>[]; keys: MemberKey[]; to: Omit<AuditCursor, 'mac'> } | null;
    if (head !== null && cursor.through < head.upto) {
      if (range === null || range.at !== cursor.pair) {
        const { start, next, pair } = await rangeAt(store, ring, cursor.pair);
        if (pair.upto > head.upto) throw new Error(`the pair after ${cursor.pair} is past the newest`);
        range = { at: cursor.pair, pair, entries: await sealedRange(store, ring, start, next, cut) };
      }
      batch = await chainBatch(store, ring, cursor, range.pair, range.entries, atOnce);
    } else {
      batch = await oldBatch(store, oldKeys, cursor, atOnce);
      if (batch === null) return done(false);
    }
    const to: AuditCursor = { ...batch.to, mac: cursorMac(ring.current.mac, batch.to) };
    const signed = batch.events.map((row) => ({ ...row, mac: eventMac(ring.current.mac, row) }));
    // Overtaken, or reset by a rebuild: the run ends, and the next starts from where the cursor stands then.
    if (!(await store.writeAudit(signed, newestKeys(batch.keys), cursor, to))) return done(false);
    cursor = to;
    events += signed.length;
  }
  // Its steps spent before it found nothing left: there may be more (a newer anchor is only looked for once the chains
  // are listed), and the next run starts at once.
  return done(true);
}

/** The next batch of a checkpoint's range: its entries above the cursor, as rows, and the cursor past them. */
async function chainBatch(store: ProjectionStore, ring: Keyring, cursor: AuditCursor, pair: Pair, entries: readonly LogEntry[], atOnce: number) {
  const left = entries.filter((entry) => entry.number > cursor.through);
  const chunk = left.slice(0, atOnce);
  const reads = await derive(store, ring, chunk.filter((entry) => entry.tree === 'uses'));
  const events: Omit<AuditEvent, 'mac'>[] = [];
  const keys: MemberKey[] = [];
  for (const read of reads) {
    events.push(readEvent(read));
    // The value read: through a reference, its source's, as 0.14's entries named it.
    if (read.version !== null && isMember(read.principal)) keys.push({ principal: read.principal, secret: read.source ?? read.secret, version: read.version, wrote: false, at: read.at, number: read.number });
  }
  for (const entry of chunk) {
    if (entry.tree !== 'changes') continue;
    const listed = changeRow(entry);
    if (listed === null) continue;
    events.push(listed.event);
    // A member's alone, as every other summary row (a read's, `oldKeysOf`, `recordRow`'s).
    if (listed.wrote !== null && isMember(listed.event.actor)) keys.push({ principal: listed.event.actor, ...listed.wrote, wrote: true, at: listed.event.at, number: listed.event.number });
  }
  // A range whole: the pair's place and signed time, which every entry of it is at or below.
  const to = chunk.length === left.length
    ? { ...cursor, through: pair.upto, pair: pair.upto, at: pair.at }
    : { ...cursor, through: chunk.at(-1)!.number };
  return { events, keys, to };
}

/**
 * The next batch of `audit_log`, newest first: below `oldFrom`, down to
 * `oldFloor` at most. Each entry must hash to what the one above it chains
 * to, the first to `oldHash`; where the walk reaches `oldFloor`, the hash
 * it ends on must be that of the entry below it, listed by an earlier walk
 * (or the genesis), and the gap is closed. With no gap, the next walk, from
 * a newer anchor (temporary, as `oldFloor`). Null when nothing is left to list.
 */
async function oldBatch(store: ProjectionStore, oldKeys: readonly LogKey[], cursor: AuditCursor, atOnce: number) {
  let walk = cursor;
  if (!oldWalkOpen(walk)) {
    const next = await nextWalk(store, oldKeys, walk);
    if (next === null) return null;
    walk = next;
  }
  const lo = walk.oldFrom - BigInt(atOnce) > walk.oldFloor ? walk.oldFrom - BigInt(atOnce) : walk.oldFloor;
  const joins = lo === walk.oldFloor && lo > 0n;
  const bySeq = new Map((await store.oldEntries(joins ? lo - 1n : lo, walk.oldFrom)).map((entry) => [entry.seq, entry]));
  const hashOf = (entry: StoredEntry) => {
    try {
      return entryHash(entry.prevHash, entry, entry.mac);
    } catch {
      return null;
    }
  };
  let expected = walk.oldHash;
  const listed: StoredEntry[] = [];
  for (let seq = walk.oldFrom - 1n; seq >= lo; seq -= 1n) {
    const entry = bySeq.get(seq);
    if (entry === undefined) throw await broken(store, seq, `entry ${seq} of audit_log is gone: the walk from its anchor stops there`);
    if (!(hashOf(entry)?.equals(expected) ?? false)) {
      throw await broken(store, seq, `entry ${seq} of audit_log does not hash to what the entry above it chains to: edited since it was written`);
    }
    expected = entry.prevHash;
    if (!HEARTBEATS.has(entry.action)) listed.push(entry);
  }
  let to: Omit<AuditCursor, 'mac'>;
  if (lo === walk.oldFloor) {
    const below = joins ? bySeq.get(lo - 1n) : undefined;
    const joined = joins ? below !== undefined && (hashOf(below)?.equals(expected) ?? false) : expected.equals(GENESIS_HASH);
    if (!joined) throw new Error(`the walk down from ${walk.oldTop - 1n} does not join the entries of audit_log listed below ${lo}`);
    to = { ...walk, oldFloor: walk.oldTop, oldFrom: walk.oldTop, oldHash: expected };
  } else {
    to = { ...walk, oldFrom: lo, oldHash: expected };
  }
  const versions = await store.versionIds(listed.flatMap(numberedVersions));
  const events: Omit<AuditEvent, 'mac'>[] = [];
  const keys: MemberKey[] = [];
  for (const entry of listed) {
    events.push(oldEvent(entry));
    keys.push(...oldKeysOf(entry, versions));
  }
  return { events, keys, to };
}

/**
 * Why the walk stops at `seq`: an Owner's acceptance of a loss whose range
 * holds it (`audit.loss_accepted`, its `from` and `to`), named, or `why`.
 * Either way the walk does not go below it: the hashes break at a range
 * accepted as lost (the entry after it was checked alone), and nothing at
 * or below that break is listed. Temporary: the acceptance's branch and
 * `lossesAbove` go with `oldFloor` and `oldTop` (the upgrade refuses
 * a log holding one, and no released 0.16 can write one), leaving `why`.
 */
async function broken(store: ProjectionStore, seq: bigint, why: string): Promise<Error> {
  for (const entry of await store.lossesAbove(seq)) {
    const { from, to } = parse(entry.metadata) as { from?: unknown; to?: unknown };
    if (Number.isSafeInteger(from) && Number.isSafeInteger(to) && BigInt(from as number) <= seq && seq <= BigInt(to as number)) {
      return new Error(
        `entry ${seq} of audit_log is in entries ${from as number} to ${to as number}, whose loss an Owner accepted (entry ${entry.seq}, audit.loss_accepted): the walk does not go below an accepted loss, and nothing at or below ${seq} is listed`,
      );
    }
  }
  return new Error(why);
}

/**
 * The walk from the newest signed 0.14 checkpoint, when it names a prefix
 * past what is listed: its last entry's seq and hash, which its MAC, the
 * vault's, covers. Null for none, or none newer. Throws on a checkpoint
 * whose MAC does not hold: a database writer's.
 */
async function nextWalk(store: ProjectionStore, oldKeys: readonly LogKey[], cursor: AuditCursor): Promise<AuditCursor | null> {
  const entry = await store.oldAnchor();
  if (entry === null) return null;
  const key = oldKeys.find((held) => held.keyId === entry.keyId);
  const mac = key === undefined || entry.prevHash.length !== 32 ? null : chainMac(key.key, entry.prevHash, entry);
  if (mac === null || mac.length !== entry.mac.length || !timingSafeEqual(mac, entry.mac)) {
    throw new Error(`the newest checkpoint of audit_log, ${entry.seq}, does not hold to the vault's MAC: no walk starts from it`);
  }
  const { seq, hash } = parse(entry.metadata) as { seq?: unknown; hash?: unknown };
  if (!Number.isSafeInteger(seq) || (seq as number) < 0 || BigInt(seq as number) >= entry.seq || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) {
    throw new Error(`the newest checkpoint of audit_log, ${entry.seq}, names no prefix`);
  }
  const top = BigInt(seq as number) + 1n;
  if (top <= cursor.oldTop) return null;
  return { ...cursor, oldFrom: top, oldTop: top, oldHash: Buffer.from(hash, 'hex') };
}

/** The summary's rows, one per key: the newest of each (`project_audit` takes none twice). */
function newestKeys(keys: readonly MemberKey[]): MemberKey[] {
  const newest = new Map<string, MemberKey>();
  for (const key of keys) {
    const id = `${key.principal}\0${key.secret}\0${key.version}\0${key.wrote}`;
    const had = newest.get(id);
    if (had === undefined || had.at < key.at || (had.at === key.at && had.number < key.number)) newest.set(id, key);
  }
  return [...newest.values()];
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const uuid = (value: unknown) => (typeof value === 'string' && UUID.test(value) ? value : null);
const text = (value: unknown) => (typeof value === 'string' ? value : null);
type Fields = Record<string, unknown>;
const record = (value: unknown): Fields | null => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Fields) : null);
const isMember = (actor: string) => actor.startsWith('user:') || actor.startsWith('token:');
const placesOf = (...ids: (string | null)[]) => [...new Set(ids.filter((id): id is string => id !== null && id !== NOWHERE))].sort();

function parse(json: string): Fields {
  try {
    return record(JSON.parse(json)) ?? {};
  } catch {
    return {};
  }
}

/**
 * The places an entry is about, as today's page matches an entry of
 * `audit_log` (`auditWhere` in the server's queries): its three columns, the
 * place on the other side of a reference (`also`), and for a read of
 * several, each key it lists and that key's source. A carried entry is one
 * of `audit_log`'s, moved: the same, from its own places and detail.
 */
function listedAt(action: string, project: string | null, environment: string | null, secret: string | null, metadata: Fields): string[] {
  const also = record(metadata.also) ?? {};
  const listed =
    action === 'secret.read' && secret === null && Array.isArray(metadata.secrets)
      ? metadata.secrets.flatMap((each: unknown) => {
          const secret = record(each) ?? {};
          return [uuid(secret.secretId), uuid(record(secret.also)?.secretId)];
        })
      : [];
  return placesOf(project, environment, secret, uuid(also.projectId), uuid(also.environmentId), uuid(also.secretId), ...listed);
}

/** An entry of `audit_log` as a row: its columns as they are, its metadata as stored. */
function oldEvent(entry: StoredEntry): Omit<AuditEvent, 'mac'> {
  const metadata = parse(entry.metadata);
  return {
    at: entry.occurredAt,
    number: entry.seq,
    log: 14,
    author: entry.author,
    action: entry.action,
    shown: !DETAIL.has(entry.action),
    allowed: entry.decision === 'allow',
    code: entry.code ?? text(metadata.reason),
    actor: entry.actor,
    subject: entry.subjectPrincipal,
    credential: uuid(metadata.credentialId),
    project: entry.projectId,
    environment: entry.environmentId,
    secret: entry.secretId,
    version: entry.secretVersionId,
    places: listedAt(entry.action, entry.projectId, entry.environmentId, entry.secretId, metadata),
    requestId: entry.requestId,
    operationId: entry.operationId,
    related: entry.relatedSeq,
    sourceIp: entry.sourceIp,
    detail: entry.metadata,
  };
}

/** The values an entry of `audit_log` says its member read or wrote, by key and number: a read of several, each. */
function numberedValues(entry: StoredEntry): { secret: string; version: number; id: string | null; wrote: boolean }[] {
  if (entry.decision !== 'allow' || !isMember(entry.actor) || (entry.action !== 'secret.read' && entry.action !== 'secret.write')) return [];
  const metadata = parse(entry.metadata);
  const wrote = entry.action === 'secret.write';
  if (entry.secretId !== null) {
    const version = metadata.version;
    if (entry.secretVersionId !== null) return [{ secret: entry.secretId, version: 0, id: entry.secretVersionId, wrote }];
    return Number.isSafeInteger(version) && (version as number) > 0 ? [{ secret: entry.secretId, version: version as number, id: null, wrote }] : [];
  }
  if (wrote || !Array.isArray(metadata.secrets)) return [];
  return metadata.secrets.flatMap((each: unknown) => {
    const { secretId, version } = record(each) ?? {};
    const secret = uuid(secretId);
    return secret !== null && Number.isSafeInteger(version) && (version as number) > 0 ? [{ secret, version: version as number, id: null, wrote }] : [];
  });
}

const numberedVersions = (entry: StoredEntry) => numberedValues(entry).filter((value) => value.id === null);

function oldKeysOf(entry: StoredEntry, versions: ReadonlyMap<string, string>): MemberKey[] {
  return numberedValues(entry).flatMap(({ secret, version, id, wrote }) => {
    const found = id ?? versions.get(`${secret}:${version}`);
    return found === undefined ? [] : [{ principal: entry.actor, secret, version: found, wrote, at: entry.occurredAt, number: entry.seq }];
  });
}

/**
 * A use as a row, as the pages show it in 0.14's `secret.read`'s place: by
 * the account its way in acts as, at the key it read, or through a
 * reference at its source, the holder beside it (`also`), every id the
 * projector derived; names are the page's to add.
 */
export function readEvent(read: ReadRow): Omit<AuditEvent, 'mac'> {
  const code = useOfCode(read.purpose);
  const way = code?.way ?? 'credential';
  const through = read.source !== null;
  const also = through
    ? { projectId: read.project, environmentId: read.environment, secretId: read.secret }
    : read.place !== null ? { projectId: read.project, environmentId: read.place } : null;
  const metadata = {
    purpose: code?.purpose ?? `unknown (${read.purpose})`,
    ...(code?.keepsSensitive ? { keepsSensitive: true } : {}),
    secretId: through ? read.source : read.secret,
    ...(way === 'connection' ? { via: { connectionId: read.credential } } : {}),
    ...(read.place === null ? {} : { through: { environmentId: read.place } }),
    ...(also === null ? {} : { also }),
    ...(way === 'credential' ? { credentialId: read.credential } : way === 'binding' ? { bindingId: read.credential } : way === 'access' ? { access: true } : {}),
  };
  return {
    at: read.at,
    number: read.number,
    log: 16,
    author: 'vault',
    action: 'secret.read',
    shown: true,
    allowed: true,
    code: null,
    actor: read.principal,
    subject: null,
    credential: read.credential,
    project: through ? read.sourceProject : read.project === NOWHERE ? null : read.project,
    environment: through ? read.sourceEnvironment : read.environment === NOWHERE ? null : read.environment,
    secret: through ? read.source : read.secret,
    version: read.version,
    places: placesOf(read.secret, read.environment, read.project, read.place, read.source, read.sourceEnvironment, read.sourceProject),
    requestId: null,
    operationId: null,
    related: null,
    sourceIp: null,
    detail: JSON.stringify(metadata),
  };
}

/** An object's first key, as JSON.parse keeps them in the text's order. */
const first = (value: unknown) => {
  const fields = record(value);
  return fields === null ? null : Object.keys(fields)[0] ?? null;
};

/**
 * Whether a change is one of `records`, as the pages' partial indexes match it by text (`RECORDS`, change-records.ts),
 * but decided from the parsed payload's own top-level keys: never from text it holds, so nothing nested in it (a
 * carried entry's `reported.detail`, which its caller chose) can classify a change. On the canonical payloads the
 * vault writes (keys in order, so `starts` is the first key), each shape implies its index's match: the projector
 * lists no change the page would not.
 */
const SHAPES: Record<ChangeRecord, (payload: Fields) => boolean> = {
  signIn: (p) => record(p.signIn) !== null,
  issue: (p) => first(p) === 'caller' && typeof p.caller === 'string' && first(p.issue) === 'by' && typeof record(p.issue)!.by === 'string',
  revoke: (p) => first(p) === 'op' && p.op === 'credential.revoke' && record(p.revoke)?.reason === 'revoke',
  signOut: (p) => first(p) === 'op' && p.op === 'credential.revoke' && record(p.revoke)?.reason === 'sign_out',
  written: (p) => first(p) === 'digest' && typeof p.inputs === 'string',
  admitted: (p) => first(p) === 'inputs' && typeof p.inputs === 'string' && p.op === 'member.add',
  refusedWrite: (p) => first(p) === 'code' && typeof p.code === 'string' && p.op === 'write.refused',
  refusedAdd: (p) => first(p) === 'code' && typeof p.code === 'string' && p.op === 'add.refused',
};
const recorded = (payload: Fields, ...records: ChangeRecord[]) => records.some((name) => SHAPES[name](payload));

/** A rebuild's change (`rebuildAudit`): of its request's object, as a refusal's, its payload naming the op first. */
export const REBUILD_STARTS = '{"op":"audit.rebuild",';

/**
 * A rebuild's record (`rebuildAudit`), as `rebuild_audit` takes it: a change
 * of the request's own object, as a refusal's, by whoever asked, its payload
 * the op and that object, under the vault's MAC.
 */
export function rebuildRow(key: LogMacKey, input: RebuildAuditInput, at: number) {
  if (typeof input?.actor !== 'string' || !/^(user|token):.+$/.test(input.actor) || typeof input.requestId !== 'string' || input.requestId === '') {
    throw new Error('a rebuild names the member who asked and the request');
  }
  const payload = JSON.stringify({ op: 'audit.rebuild', ref: { id: input.requestId, kind: 'request' } });
  const row = { at, requestId: input.requestId, object: logObject('request', input.requestId), actor: input.actor, payload, seal: null };
  return { ...row, mac: entryMac(key, { tree: 'changes', row }) };
}

/** A change as a row (`changeRow`), null for one the pages do not list. */
export const changeEvent = (entry: LogEntry): Omit<AuditEvent, 'mac'> | null => changeRow(entry)?.event ?? null;

/**
 * A change as a row, for those the pages list from `log_changes` (see the
 * top): an event, from its payload; a change that carries its entry, from it; the vault's own records,
 * as the server's audit page shows them today (`sealedView`, `twoTripView`,
 * `refusalView` in packages/server/src/api/audit.ts); null for every other.
 * `at` is the vault's time when it asked. With the value its member wrote
 * (`audit_member_keys`), for a key write that supplied one.
 */
function changeRow(entry: LogEntry): { event: Omit<AuditEvent, 'mac'>; wrote: { secret: string; version: string } | null } | null {
  const [, requestId, object, actor, payloadText] = entry.columns as [bigint, string, string, string, string];
  if (typeof payloadText !== 'string' || typeof actor !== 'string') return null;
  const payload = parse(payloadText);
  const ref = record(payload.ref);
  // The key and version a key write's change names, under the vault's MAC: the object the vault changed and the
  // version it sealed, never what the app's entry says of them.
  const written = () => {
    const [secret, version] = [ref?.kind === 'secret' && payload.op === 'secret.write' ? uuid(ref.id) : null, uuid(payload.version)];
    return secret === null || version === null ? null : { secret, version };
  };
  // An event (note.ts: its object its own, from its id, and its op `event`): the same fields as a carried entry, at
  // its payload's top level, `author` among them, and the row's actor and time. It records no write.
  if (payload.op === EVENT_KIND && ref?.kind === EVENT_KIND && ref.id === requestId && object === eventObject(requestId)) {
    const event = carriedEvent(entry, actor, payload, null);
    return event === null ? null : { event, wrote: null };
  }
  // A change carrying its entry is listed from that entry alone, before the records below: one row whatever else its
  // payload holds (a two-trip write's record beside it), as `reported` is a key at the top level, never by text. A
  // `reported` of no entry's shape lists nothing, and no record is read in its place. The entry is whole (its detail
  // holds all its row shows: a token's kind and label, a sign-in's run), so it is never merged with a record beside
  // it; a payload with both an entry and `issue` or `signIn` would be listed from the entry, but the vault's
  // `issueToken` and `signIn` take no entry, so none is written.
  if (Object.hasOwn(payload, 'reported')) {
    const reported = record(payload.reported);
    const event = reported === null ? null : carriedEvent(entry, actor, reported, written()?.version ?? null);
    if (event === null) return null;
    // A value supplied, as an allowed write without `kept` supplies it: a mark (`kept`, the value as it was at another
    // level), a loosening and a restore supply none, and the report ties those to their value by its ciphertext.
    const supplied = event.action === 'secret.write' && event.allowed && !Object.hasOwn(record(reported!.detail)!, 'kept');
    return { event, wrote: supplied ? written() : null };
  }
  const listed = recordRow(entry, actor, requestId, payloadText, payload, ref);
  return listed === null ? null : { event: listed, wrote: listed.action === 'secret.write' && listed.allowed ? written() : null };
}

/**
 * A carried entry or an event as a row (state-rows.md, "A change carries its entry"): an event's fields, as `note`
 * takes them, with the change's own actor and time; the places it carries, as they were when it was written, but the version a
 * key write sealed (`sealed`, the change's own `version`: the app's entry, `reportedPayload`, names it null).
 * Null for an entry of another shape, which the vault never signs.
 */
function carriedEvent(entry: LogEntry, actor: string, reported: Fields, sealed: string | null): Omit<AuditEvent, 'mac'> | null {
  const { action, allowed, author, code, credential, operationId, requestId, sourceIp, subject } = reported;
  const [places, detail] = [record(reported.places), record(reported.detail)];
  if (typeof action !== 'string' || typeof allowed !== 'boolean' || (author !== 'app' && author !== 'vault') || places === null || detail === null) return null;
  const [project, environment, secret, version] = [uuid(places.projectId), uuid(places.environmentId), uuid(places.secretId), sealed ?? uuid(places.versionId)];
  return {
    at: entry.at,
    number: entry.number,
    log: 15,
    author,
    action,
    shown: !DETAIL.has(action),
    allowed,
    // As an entry of `audit_log`'s (`oldEvent`), which this one was.
    code: text(code) ?? text(detail.reason),
    actor,
    subject: text(subject),
    // The entry's credential, else its detail's, as `oldEvent` reads an entry of `audit_log`: how the caller got in
    // (a caller behind a connection is named in `detail` alone, by `traceFields`), but a token exchange's is the run
    // credential it issued.
    credential: uuid(credential) ?? uuid(detail.credentialId),
    project,
    environment,
    secret,
    version,
    places: listedAt(action, project, environment, secret, detail),
    requestId: text(requestId),
    operationId: uuid(operationId),
    related: null,
    sourceIp: text(sourceIp),
    detail: JSON.stringify(detail),
  };
}

/** One of the vault's own records as a row (`changeRow`). */
function recordRow(entry: LogEntry, actor: string, requestId: string, payloadText: string, payload: Fields, ref: Fields | null): Omit<AuditEvent, 'mac'> | null {
  const row = (action: string, fields: Partial<Omit<AuditEvent, 'mac'>>, metadata: Fields): Omit<AuditEvent, 'mac'> => ({
    at: entry.at,
    number: entry.number,
    log: 15,
    author: 'vault',
    action,
    shown: !DETAIL.has(action),
    allowed: true,
    code: null,
    actor,
    subject: null,
    credential: uuid(metadata.credentialId),
    project: null,
    environment: null,
    secret: null,
    version: null,
    places: [],
    requestId: null,
    operationId: null,
    related: null,
    sourceIp: null,
    ...fields,
    detail: JSON.stringify(metadata),
  });
  if (payloadText.startsWith(REBUILD_STARTS) && payload.op === 'audit.rebuild' && ref?.kind === 'request' && ref.id === requestId) {
    return row('audit.rebuild', { requestId }, {});
  }
  if (!isMember(actor)) return null;
  const request = record(payload.request);
  const confirmed = confirmedBy(request?.confirmed);
  if (recorded(payload, 'written', 'admitted')) {
    const credentialId = text(request?.credential);
    if (request === null || typeof ref?.id !== 'string' || typeof payload.inputs !== 'string') return null;
    const asked = { requestId: text(request.requestId), operationId: uuid(request.operationId) };
    const by = { ...confirmed, ...(credentialId === null ? {} : { credentialId }) };
    if (ref.kind === 'secret' && payload.op === 'secret.write' && typeof payload.version === 'string') {
      const [project, environment, secret, version] = [uuid(payload.projectId), uuid(payload.environmentId), uuid(ref.id), uuid(payload.version)];
      return row('secret.write', { ...asked, project, environment, secret, version, places: placesOf(project, environment, secret) },
        { ...(payload.nature === 'sensitive' ? { sensitive: true } : {}), ...by });
    }
    if (ref.kind === 'principal' && payload.op === 'member.add') return row('member.add', { ...asked, subject: ref.id }, { role: payload.role ?? null, scope: payload.scope ?? null, ...by });
    return null;
  }
  if (recorded(payload, 'refusedWrite', 'refusedAdd')) {
    const code = text(payload.code);
    if (request === null || code === null || ref?.kind !== 'request') return null;
    const credentialId = text(payload.credential);
    const refused = { allowed: false, code, requestId: text(request.requestId), operationId: uuid(request.operationId) };
    const why = { reason: code, ...(credentialId === null ? {} : { credentialId }) };
    if (payload.op === 'write.refused') {
      const [project, environment] = [uuid(payload.projectId), uuid(payload.environmentId)];
      const keys = Array.isArray(payload.keys) ? payload.keys.filter((key): key is string => typeof key === 'string') : [];
      return row('secret.write', { ...refused, project, environment, places: placesOf(project, environment) }, { path: text(payload.path), keys, ...why });
    }
    if (payload.op === 'add.refused' && typeof payload.principal === 'string') {
      return row('member.add', { ...refused, subject: payload.principal }, { role: payload.role ?? null, scope: payload.scope ?? null, ...why });
    }
    return null;
  }
  if (ref?.kind !== 'credential' || typeof ref.id !== 'string') return null;
  const [signIn, issue, revoke] = [record(payload.signIn), record(payload.issue), record(payload.revoke)];
  const time = (value: unknown) => (typeof value === 'number' && Number.isSafeInteger(value) ? new Date(value).toISOString() : null);
  if (recorded(payload, 'signIn') && signIn !== null) {
    if (!actor.startsWith('token:')) return null;
    const workload = typeof signIn.jkt === 'string';
    return row('token.exchange', {}, {
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
  if (recorded(payload, 'issue') && issue !== null) {
    return row('token.create', {}, {
      kind: issue.kind, ...account(payload.principal), label: issue.label ?? null, targetCredentialId: ref.id, expiresAt: time(payload.expiresAt), scope: payload.scope,
      ...confirmedBy(issue.confirmed), ...traced(issue.trace),
    });
  }
  if (recorded(payload, 'revoke') && revoke?.reason === 'revoke') {
    return row('token.revoke', {}, { targetCredentialId: ref.id, kind: revoke.kind, ...account(revoke.principal), ...traced(revoke.trace) });
  }
  if (recorded(payload, 'signOut') && revoke?.reason === 'sign_out') return row('sign_out', {}, { targetCredentialId: ref.id, kind: revoke.kind, ...traced(revoke.trace) });
  return null;
}

/** Whose credential, as 0.14's entries named the account. */
function account(member: unknown): Fields {
  if (typeof member !== 'string' || !isMember(member)) return {};
  const colon = member.indexOf(':');
  return { principalType: member.startsWith('user:') ? 'user' : 'service', principalId: member.slice(colon + 1) };
}

/** What confirmed an act a fresh check guards, as the server's `confirmedFields` names it; one of another shape, nothing. */
function confirmedBy(confirmed: unknown): Fields {
  const { by, at } = record(confirmed) ?? {};
  return typeof by === 'string' && typeof at === 'string' ? { confirmedBy: by, confirmedAt: at } : {};
}

/** Whose act it was, from the record's trace, as the server's `traceFields` names it; one of another shape, nothing. */
function traced(trace: unknown): Fields {
  const { credentialId, mcp } = record(trace) ?? {};
  if (typeof credentialId !== 'string') return {};
  const app = record(mcp);
  const [connectionId, clientId, clientName] = [text(app?.connectionId), text(app?.clientId), text(app?.clientName)];
  if (app === null || connectionId === null || clientId === null || clientName === null) return { credentialId };
  const approvalId = text(app.approvalId);
  return { via: { connectionId, clientId, clientName, ...(approvalId === null ? {} : { approvalId }) }, credentialId };
}

/**
 * The projector as a host runs it, beside the checkpointer and the reads'
 * projector: on Node, `kick` after each tick (checkpointer-node.ts); on
 * Workers, in the checkpointer's object, on its alarm, after the reads'
 * projector and on the same connection (checkpointer-workers.ts).
 * No tick, seal, change or use waits on it. A failure is an alarm, said
 * once while it stands; the pages show the lag meanwhile.
 */
export class AuditProjector {
  readonly #run: () => Promise<AuditProjected>;
  readonly #alert: (message: string) => void;
  #running: Promise<boolean> | null = null;
  #failed: string | null = null;
  #stopped = false;

  constructor(store: ProjectionStore, keys: VerifierKeys, oldKeys: readonly LogKey[], alert: (message: string) => void) {
    this.#run = () => projectAudit(store, keys, oldKeys);
    this.#alert = alert;
  }

  /** Start a run unless one is going or the projector is stopped; never waits on it. */
  kick(): void {
    void this.run();
  }

  /** A run, or the one going: whether it left a batch to do at once. Never throws. */
  run(): Promise<boolean> {
    if (this.#stopped) return Promise.resolve(false);
    return (this.#running ??= this.#once().finally(() => {
      this.#running = null;
    }));
  }

  /** The run going, if any, ended. */
  async settled(): Promise<void> {
    await this.#running;
  }

  /** No run after this one: a host's stop. */
  async stop(): Promise<void> {
    this.#stopped = true;
    await this.#running;
  }

  async #once(): Promise<boolean> {
    try {
      const { more } = await this.#run();
      this.#failed = null;
      return more;
    } catch (error) {
      const message = `the audit projection failed: ${error instanceof Error ? error.message : String(error)}`;
      if (message !== this.#failed) this.#alert(message);
      this.#failed = message;
      return false;
    }
  }
}
