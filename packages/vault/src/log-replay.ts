import { bulkStep, type BulkRows } from './bulk.ts';
import type { BulkLimit } from './config.ts';
import { decideUse, useEnvironments, type Read, type UseCode, type UseRequest, type UseView } from './decide.ts';
import { applyOp, objectKey, POLICY_REF, ROLES_REF, sealed, type Input, type Kind, type Op, type Ref, type SealKeys } from './inputs.ts';

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
  const credential = read('credential', request.credential);
  const secret = read('secret', request.secretId);
  const policy = read('policy', POLICY_REF.id);
  const principal = credential.row === null ? null : read('principal', credential.row.principal);
  const source = secret.row?.source == null ? null : read('secret', secret.row.source);
  const environments = new Map<string, Read<Extract<Input, { kind: 'environment' }>>>();
  // Each environment the rows read so far name, until no new one: the statement's joins, in order.
  for (let named = useEnvironments({ secret, source, environments }, request); named.some((id) => !environments.has(id)); named = useEnvironments({ secret, source, environments }, request)) {
    for (const id of named) if (!environments.has(id)) environments.set(id, read('environment', id));
  }
  let cap = null;
  if (credential.row !== null) {
    const held = bulk.get(credential.row.principal) ?? new Map<string, number>();
    bulk.set(credential.row.principal, held);
    // No policy in the log, no cap to move: the decision refuses the use (`no_policy`).
    cap = limit === null ? { inSet: false, others: 0 } : bulkStep(held, request.secretId, request.at, limit);
  }
  return { credential, principal, roles: read('roles', ROLES_REF.id), policy, secret, source, environments, bulk: cap };
}

/**
 * A use's purpose and keepsSensitive as its row stores them, in one
 * smallint (schema 0022): the purpose's code, plus 256 when a copy keeps
 * values sensitive.
 */
export const PURPOSES = ['reveal', 'run', 'compare', 'copy', 'use', 'expose'] as const satisfies readonly UseRequest['purpose'][];

// Every purpose has a code: one missing here fails to compile.
const everyPurpose: [Exclude<UseRequest['purpose'], (typeof PURPOSES)[number]>] extends [never] ? true : never = true;
void everyPurpose;

export function purposeCode(request: Pick<UseRequest, 'purpose' | 'keepsSensitive'>): number {
  return PURPOSES.indexOf(request.purpose) + (request.keepsSensitive ? 256 : 0);
}

/** The purpose and keepsSensitive a row's code stores; null for a code no release writes. */
export function purposeOf(code: number): Pick<UseRequest, 'purpose' | 'keepsSensitive'> | null {
  const purpose = PURPOSES[code % 256];
  return Number.isInteger(code) && code >= 0 && code < 512 && purpose !== undefined ? { purpose, keepsSensitive: code >= 256 } : null;
}

/** The log replayed: the rows it says the tables hold, each object's newest seal, every principal's bulk rows, and what does not hold. */
export type Replayed = {
  /** Each object, with the seal its newest change left. */
  rows: Map<string, { row: Input; seal: Buffer | null }>;
  newest: Map<string, Buffer | null>;
  /** The cap the policy's newest change logged: what moves the bulk rows. */
  limit: BulkLimit | null;
  bulk: Map<string, BulkRows>;
  /** The last entry's number: a replay resumed on this state goes on from it. */
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
    if (entry.number <= replayed.last) replayed.faults.push(`${entry.number}: after ${replayed.last}, out of number order`);
    replayed.last = entry.number;
    if (entry.kind === 'change') {
      change(keys, replayed, entry);
      continue;
    }
    const code = decideUse(keys, readUse(replayed.rows, replayed.newest, replayed.limit, replayed.bulk, entry.request), entry.request);
    decided?.(entry, code);
  }
  return replayed;
}

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
  if (after?.kind === 'policy') replayed.limit = after.bulk;
  replayed.newest.set(key, entry.seal);
}
