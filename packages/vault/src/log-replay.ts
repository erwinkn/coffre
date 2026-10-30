import type { Queryable } from '@coffre/db';

import { bulkStep, type BulkRows } from './bulk.ts';
import { loggedChange } from './changes.ts';
import type { BulkLimit } from './config.ts';
import { decideUse, useEnvironments, type Read, type UseCode, type UseRequest, type UseView, type Way, type WayInput } from './decide.ts';
import { applyOp, objectKey, POLICY_REF, ROLES_REF, sealed, sealKey, type Input, type Kind, type Op, type Ref, type SealKeys } from './inputs.ts';
import { CUTOVER_OBJECT, RETENTION_OBJECT } from './log-entry.ts';
import { loggedRows } from './store.ts';

/**
 * The 0.15 log replayed (plan, PR 3; the verifier of PR 8 walks it): its
 * changes applied in number order with the same `applyOp` the change path
 * applies, and each use decided again on the state of the entries numbered
 * before it, at its own time. The log stores no outcome: this is the only
 * record of one, and it must be the live answer (R53).
 *
 * Live, a use reads rows; replayed, it reads the objects the log built,
 * each with the seal its newest change left. `readUse` is both reads: the
 * use's statement (PR 5) over a map of rows, so that a replay and the rows
 * it should match are read the same way.
 */

/** A change as logged: its number, its time, its object, what it did, and the seal it left (null: none, the object gone). */
export type LoggedChange = { kind: 'change'; number: bigint; at: number; ref: Ref; op: Op; seal: Buffer | null };
/** A use as logged: the request (UseRequest), numbered. */
export type LoggedUse = { kind: 'use'; number: bigint; request: UseRequest };
export type Logged = LoggedChange | LoggedUse;

/** Rows by object key: each input's row as stored, with the seal on it. */
export type Rows = ReadonlyMap<string, { row: Input; seal: Buffer | null }>;

/**
 * What a use's one statement reads, from `rows`, with each object's newest
 * seal from the changes (`newest`), in one snapshot: the credential, its
 * principal, the roles and the policy, the key and a reference's source,
 * and the environments the decision weighs. It moves the cap as the
 * statement does, on `bulk`'s rows of the principal, with `limit`, the
 * count and window the policy's newest change logged (HotPathOne's
 * `CapSealed`, `CapFromPolicy`): never the policy's row, which the
 * statement reads before anyone checks its seal, so a row put back would
 * move the cap otherwise than the replay (`BulkReplayAgrees`). Every request
 * the cap admits moves it, however it is decided after, `stale` included
 * (`HotPathOneStaleBulk`).
 */
export function readUse(rows: Rows, newest: ReadonlyMap<string, Buffer | null>, limit: BulkLimit | null, bulk: Map<string, BulkRows>, request: UseRequest): UseView {
  const read = <K extends Kind>(kind: K, id: string): Read<Extract<Input, { kind: K }>> => {
    const key = objectKey({ kind, id });
    // Each kind is a table of its own: a key's row is one of its kind or none.
    const stored = rows.get(key)?.row.kind === kind ? rows.get(key)! : undefined;
    return { row: (stored?.row ?? null) as Extract<Input, { kind: K }> | null, seal: stored?.seal ?? null, newest: newest.get(key) ?? null };
  };
  // The way in's object, of its own kind; behind Access none, the person being the one the request's key names (T147).
  const way = request.way ?? 'credential';
  const credential: Read<WayInput> = way === 'access' ? { row: null, seal: null, newest: null } : read(way, request.credential);
  const person = way === 'access' && rows.get(request.credential)?.row.kind === 'principal' ? (rows.get(request.credential)!.row as Extract<Input, { kind: 'principal' }>).principal : null;
  const secret = read('secret', request.secretId);
  const policy = read('policy', POLICY_REF.id);
  const holder = way === 'access' ? person : credential.row?.principal ?? null;
  const principal = holder === null ? null : read('principal', holder);
  const source = secret.row?.source == null ? null : read('secret', secret.row.source);
  const environments = new Map<string, Read<Extract<Input, { kind: 'environment' }>>>();
  // Each environment the rows read so far name, until no new one: the statement's joins, in order.
  for (let named = useEnvironments({ secret, source, environments }, request); named.some((id) => !environments.has(id)); named = useEnvironments({ secret, source, environments }, request)) {
    for (const id of named) if (!environments.has(id)) environments.set(id, read('environment', id));
  }
  let cap = null;
  if (holder !== null) {
    const held = bulk.get(holder) ?? new Map<string, number>();
    bulk.set(holder, held);
    // No policy in the log, no cap to move: the decision refuses the use (`no_policy`).
    cap = limit === null ? { inSet: false, others: 0 } : bulkStep(held, request.secretId, request.at, limit);
  }
  return { credential, principal, roles: read('roles', ROLES_REF.id), policy, secret, source, environments, bulk: cap };
}

/**
 * A use's purpose, keepsSensitive and way in as its row stores them, in
 * one smallint (schema 0022, 0046): the purpose's code, plus 256 when a
 * copy keeps values sensitive, plus 512 times its way in's (`WAYS`; T147).
 */
export const PURPOSES = ['reveal', 'run', 'compare', 'copy', 'use', 'expose'] as const satisfies readonly UseRequest['purpose'][];

// Every purpose has a code: one missing here fails to compile.
const everyPurpose: [Exclude<UseRequest['purpose'], (typeof PURPOSES)[number]>] extends [never] ? true : never = true;
void everyPurpose;

/** Each way in (decide.ts, `Way`), by its code: a credential's, 0, as every use before T147. */
export const WAYS = ['credential', 'connection', 'binding', 'access'] as const satisfies readonly Way[];

// Every way in has a code: one missing here fails to compile.
const everyWay: [Exclude<Way, (typeof WAYS)[number]>] extends [never] ? true : never = true;
void everyWay;

export function purposeCode(request: Pick<UseRequest, 'purpose' | 'keepsSensitive' | 'way'>): number {
  return PURPOSES.indexOf(request.purpose) + (request.keepsSensitive ? 256 : 0) + 512 * WAYS.indexOf(request.way ?? 'credential');
}

/** The purpose, keepsSensitive and way in a row's code stores; null for a code no release writes. */
export function purposeOf(code: number): Pick<UseRequest, 'purpose' | 'keepsSensitive' | 'way'> | null {
  const purpose = PURPOSES[code % 256];
  const way = WAYS[Math.floor(code / 512)];
  if (!Number.isInteger(code) || code < 0 || purpose === undefined || way === undefined) return null;
  return { purpose, keepsSensitive: code % 512 >= 256, ...(way === 'credential' ? {} : { way }) };
}

/** The log replayed: the rows it says the tables hold, each object's newest seal, every principal's bulk rows, and what does not hold. */
export type Replayed = {
  /** Each object, with the seal its newest change left. */
  rows: Map<string, { row: Input; seal: Buffer | null }>;
  newest: Map<string, Buffer | null>;
  /** The cap the policy's newest change logged: what moves the bulk rows. */
  limit: BulkLimit | null;
  bulk: Map<string, BulkRows>;
  /** The highest entry number seen: a replay resumed on this state goes on from it. */
  last: bigint;
  /** Entries out of number order, changes that do nothing, and seals that are not their object's. */
  faults: string[];
};

export function emptyReplay(): Replayed {
  return { rows: new Map(), newest: new Map(), limit: null, bulk: new Map(), last: -1n, faults: [] };
}

/**
 * Replay `entries`, in the order given, on `replayed` (an empty replay for
 * a whole log), calling `decided` with each use's decision.
 */
export function replay(
  keys: SealKeys,
  entries: Iterable<Logged>,
  decided?: (use: LoggedUse, code: UseCode | null) => void,
  replayed: Replayed = emptyReplay(),
): Replayed {
  for (const entry of entries) {
    // Against the highest number seen: after 10, both 5 and 7 are out of order.
    if (entry.number <= replayed.last) replayed.faults.push(`${entry.number}: after ${replayed.last}, out of number order`);
    else replayed.last = entry.number;
    if (entry.kind === 'change') {
      // The log's own changes (a retention's, the cutover's) change no input: passed over.
      if (!LOGS_OWN.has((entry.op as { op: string }).op)) change(keys, replayed, entry);
      continue;
    }
    const code = decideUse(keys, readUse(replayed.rows, replayed.newest, replayed.limit, replayed.bulk, entry.request), entry.request);
    decided?.(entry, code);
  }
  return replayed;
}

/** The ops of the log's own changes, which change no input: a retention's (PR 7), the cutover's (PR 9). */
const LOGS_OWN = new Set(['retention', 'cutover']);

function change(keys: SealKeys, replayed: Replayed, entry: LoggedChange): void {
  const key = objectKey(entry.ref);
  const after = applyOp(replayed.rows.get(key)?.row ?? null, entry.ref, entry.op);
  if (after === undefined) {
    replayed.faults.push(`${entry.number}: ${entry.op.op} on ${entry.ref.kind} ${entry.ref.id} does nothing`);
    return;
  }
  // The seal the vault wrote must be the vault's over the object the replay has: a gone object leaves none.
  if (after === null ? entry.seal !== null : !sealed(keys, entry.ref, after, entry.seal)) {
    replayed.faults.push(`${entry.number}: its seal is not the vault's over ${entry.ref.kind} ${entry.ref.id} as the replay has it`);
  }
  if (after === null) replayed.rows.delete(key);
  else replayed.rows.set(key, { row: after, seal: entry.seal });
  if (after?.kind === 'policy' && entry.ref.id === POLICY_REF.id) replayed.limit = after.bulk;
  replayed.newest.set(key, entry.seal);
}

/**
 * The log as stored, read whole and replayed with the seal keys of
 * `signingKeys` (the vault's): each use's decision by its entry number,
 * and what does not hold, an entry that names no object or no purpose
 * among `replay`'s faults. The verifier of plan PR 8 walks the log a
 * stretch at a time; this reads all of it, for the suites that hold every
 * live answer to it (R53).
 */
export async function replayStored(db: Queryable, signingKeys: readonly Uint8Array[]): Promise<{ decided: Map<string, UseCode | null>; faults: string[] }> {
  const { changes, uses } = await loggedRows(db);
  const faults: string[] = [];
  const entries: Logged[] = [];
  for (const row of changes) {
    // The log's own changes (a retention's, the cutover's), which name no input, `replay` passes over.
    if (row.object === RETENTION_OBJECT || row.object === CUTOVER_OBJECT) continue;
    const change = loggedChange({ number: BigInt(row.number), at: Number(row.at), object: row.object, payload: row.payload, seal: row.seal === null ? null : Buffer.from(row.seal) });
    if (change === null) faults.push(`${row.number}: names no object it is of`);
    else entries.push(change);
  }
  for (const row of uses) {
    const purpose = purposeOf(Number(row.purpose));
    if (purpose === null) faults.push(`${row.number}: no purpose ${row.purpose}`);
    else entries.push({ kind: 'use', number: BigInt(row.number), request: { credential: row.credential, secretId: row.secret, place: row.place, at: Number(row.at), ...purpose } });
  }
  entries.sort((a, b) => (a.number < b.number ? -1 : a.number > b.number ? 1 : 0));
  const decided = new Map<string, UseCode | null>();
  const replayed = replay(signingKeys.map(sealKey), entries, (use, code) => decided.set(use.number.toString(), code));
  return { decided, faults: [...faults, ...replayed.faults] };
}
