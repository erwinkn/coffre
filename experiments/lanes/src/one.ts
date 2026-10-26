import { createHash, createHmac, randomUUID } from 'node:crypto';

import { unwrap, type Keys } from './model.ts';
import type { Db } from './simple.ts';

/**
 * Variant `one` (W208): the simple hot path in one round trip, with no
 * revision (schema-one.sql, formal/HotPathOne.tla).
 *
 *   use     the vault MACs the request (who, which credential, the request
 *           id, its time, what it asks for), then makes one call,
 *           `use_credential`: the fence lock shared, then one statement
 *           that reads everything the decision needs and inserts the entry,
 *           numbered from the sequence, and the commit. Then it decides,
 *           opens the key and releases the value. A denial is logged as
 *           much as an allowance: the entry is the request.
 *   change  one read (the member, to seal its next state), then one call,
 *           `change_member`: the lock exclusive, the write, its entry, the
 *           commit; then it answers.
 *
 * No revision: a use holds the lock shared and a change holds it exclusive,
 * each takes its number under it and keeps it to its commit, so no use
 * overlaps a change. The number alone orders them, and the outcome of a use
 * is a function of the changes numbered before it and of its time
 * (`decide`), which a replay recomputes (verify-one.ts).
 */

/** Whether the call is named (prepared once per connection), as `simple.ts`'s statements. */
let named = false;
export function nameStatements(on: boolean): void {
  named = on;
}
const run = (db: Db, name: string, text: string, values: unknown[]) => (named ? db.query({ name, text, values }) : db.query(text, values));

/**
 * A request: its id and, once stamped, its time. A retry of the same request (its answer lost)
 * passes both unchanged, so that its call finds the entry the first one wrote.
 */
export type UseInput = { principal: string; credential: string; environmentId: string; secretId: string; requestId: string; at?: number };
export type UseAnswer =
  | { ok: true; value: string; number: string; statements: number; covered?: true }
  | { ok: false; code: string; number?: string; retryAfter?: number; statements: number };

/** An entry, as the vault MACs it: everything but its number. */
export type Entry = { at: number; kind: 'use' | 'change'; principal: string; credential: string | null; requestId: string; payload: string; seal: Buffer | null };

export function entryMac(key: Buffer, e: Entry): Buffer {
  return createHmac('sha256', key)
    .update('one.entry.v1')
    .update(JSON.stringify([String(e.at), e.kind, e.principal, e.credential, e.requestId, e.payload, e.seal === null ? null : e.seal.toString('hex')]))
    .digest();
}

export type Member = { principal: string; status: string; role: string | null };
export type Grant = { environment_id: string; role: string };

/** A member's seal: the vault's MAC over it and its grants. */
export function memberSeal(key: Buffer, m: Member, grants: readonly Grant[]): Buffer {
  const held = grants.map((g) => `${g.environment_id}:${g.role}`).sort();
  return createHmac('sha256', key).update('one.member.v1').update(JSON.stringify([m.principal, m.status, m.role, held])).digest();
}

/** Everything a decision reads: what `use_credential` returns, or what a replay has built from the log. */
export type View = {
  member: (Member & { seal: string }) | null;
  grants: Grant[];
  /** The seal the member's newest change wrote. */
  lastSeal: string | null;
  credential: { principal: string; revoked: boolean; expiresAt: string | null } | null;
  environment: { id: string; deleted: boolean } | null;
  secret: { id: string; environmentId: string; nature: string; wrapped?: string; iv?: string } | null;
};

/**
 * The decision: why a use is refused, or null to allow it. A function of the
 * view and the entry's time alone, so a replay of the log decides the same.
 */
export function decide(keys: Keys, v: View, input: Pick<UseInput, 'principal' | 'credential' | 'environmentId' | 'secretId'>, at: number): string | null {
  const c = v.credential;
  if (c === null || c.revoked || c.principal !== input.principal) return 'credential';
  if (c.expiresAt !== null && at >= Number(c.expiresAt)) return 'expired';
  const m = v.member;
  if (m === null || m.status !== 'active') return 'not_member';
  if (!memberSeal(keys.row, m, v.grants).equals(Buffer.from(m.seal, 'hex'))) return 'tampered';
  // A member row put back from before its newest change (with the grants of then) seals true, but not to that change.
  if (v.lastSeal !== m.seal) return 'stale';
  if (v.environment === null || v.environment.deleted) return 'deleted';
  if (!v.grants.some((g) => g.environment_id === input.environmentId)) return 'forbidden';
  if (v.secret === null || v.secret.environmentId !== input.environmentId) return 'missing';
  return null;
}

export const usePayload = (input: Pick<UseInput, 'environmentId' | 'secretId'>) => JSON.stringify({ environment: input.environmentId, secret: input.secretId });

const USE = 'SELECT use_credential($1, $2, $3, $4, $5, $6, $7, $8) AS v';

/**
 * An isolate's covers (fewer rows): for each credential and secret, its last
 * allowed entry, until `window` ms after it or the credential's expiry. A
 * repeat passes it, and writes nothing if no change came after it.
 */
export type Covers = { window: number; held: Map<string, { number: string; until: number }> };

/** A use's deadline is at most this long after its time (schema-one.sql's deadline_max()). */
export const DEADLINE_MAX = 3000;

/**
 * One use: one call, then the decision, and the value only once the call
 * has returned, which is once its entry has committed. `deadline` (ms since
 * the epoch, set when the request came in, by default the latest allowed): a
 * call that gets its lock later does nothing (the pool or Hyperdrive held it
 * while the Worker gave up).
 */
export async function use(db: Db, keys: Keys, input: UseInput, deadline?: number, covers?: Covers): Promise<UseAnswer> {
  const at = input.at ?? Date.now();
  deadline ??= at + DEADLINE_MAX;
  const key = `${input.credential}\n${input.secretId}`;
  const held = covers?.held.get(key);
  const cover = held !== undefined && at < held.until ? held.number : null;
  const payload = usePayload(input);
  const mac = entryMac(keys.log, { at, kind: 'use', principal: input.principal, credential: input.credential, requestId: input.requestId, payload, seal: null });
  let rows: { v: (View & { number: string }) | null }[];
  try {
    ({ rows } = await run(db, 'use_credential', USE, [input.principal, input.credential, input.requestId, String(at), payload, mac, String(deadline), cover]));
  } catch (error) {
    // A replay of a call whose answer was lost: its entry stands, its value never left. Not decided again.
    if ((error as { constraint?: string }).constraint === 'entries_uses_request' || /entries_uses_\d+_at_request_id_idx/.test((error as { constraint?: string }).constraint ?? '')) {
      return { ok: false, code: 'replayed', retryAfter: 1, statements: 1 };
    }
    throw error;
  }
  const v = rows[0]!.v as (View & { number: string | null; covered: string | null }) | null;
  if (v === null) return { ok: false, code: 'late', retryAfter: 1, statements: 1 };
  const refused = decide(keys, v, input, at);
  if (v.covered !== null && refused !== null) {
    // Refused on a cover (its expiry, or a change the cover could not see): logged as an entry of its own.
    covers!.held.delete(key);
    const fresh = await use(db, keys, { ...input, at }, deadline, covers);
    return { ...fresh, statements: fresh.statements + 1 };
  }
  if (refused !== null) {
    covers?.held.delete(key);
    return { ok: false, code: refused, number: v.number!, statements: 1 };
  }
  if (covers !== undefined && v.covered === null) {
    const expires = v.credential!.expiresAt === null ? Infinity : Number(v.credential!.expiresAt);
    covers.held.set(key, { number: v.number!, until: Math.min(at + covers.window, expires) });
  }
  const dek = unwrap(keys.kek, Buffer.from(v.secret!.wrapped!, 'hex'), Buffer.from(v.secret!.iv!, 'hex'));
  const value = dek.toString('base64');
  dek.fill(0);
  return v.covered === null ? { ok: true, value, number: v.number!, statements: 1 } : { ok: true, value, number: v.covered, statements: 1, covered: true };
}

/** What a change does, as logged and as `change_member` applies it. */
export type Op =
  | { op: 'access.grant'; environment: string; role: string }
  | { op: 'access.revoke'; environment: string }
  | { op: 'credential.revoke'; credential: string }
  | { op: 'credential.restore'; credential: string };

/** A member's grants after a change. */
export function grantsAfter(grants: readonly Grant[], op: Op): Grant[] {
  if (op.op === 'access.grant') return [...grants.filter((g) => g.environment_id !== op.environment), { environment_id: op.environment, role: op.role }];
  if (op.op === 'access.revoke') return grants.filter((g) => g.environment_id !== op.environment);
  return [...grants];
}

const MEMBER = `
  SELECT json_build_object('principal', principal, 'status', status, 'role', role, 'seal', encode(seal, 'hex')) AS member,
    (SELECT coalesce(json_agg(json_build_object('environment_id', environment_id, 'role', role)), '[]') FROM grants g WHERE g.principal = m.principal) AS grants
  FROM members m WHERE principal = $1`;

/**
 * A change: the member read (no lock), its next state sealed and the entry
 * MAC'd, then one call that makes it under the lock exclusive, refused if
 * another change moved the member's seal in between (then read again). It
 * answers only once committed.
 */
export async function change(db: Db, keys: Keys, principal: string, op: Op, request?: { requestId: string; at: number }): Promise<{ number: string; tries: number }> {
  for (let tries = 1; tries <= 20; tries += 1) {
    const { rows: [r] } = await db.query(MEMBER, [principal]);
    if (r === undefined) throw new Error(`no member ${principal}`);
    const seal = memberSeal(keys.row, r.member, grantsAfter(r.grants, op));
    // A retry of the same change (`request`) finds its entry; a try refused on a moved seal wrote nothing.
    const at = request?.at ?? Date.now();
    const requestId = request?.requestId ?? randomUUID();
    const payload = JSON.stringify(op);
    const credential = 'credential' in op ? op.credential : null;
    const mac = entryMac(keys.log, { at, kind: 'change', principal, credential, requestId, payload, seal });
    const { rows: [done] } = await db.query('SELECT change_member($1, $2, $3, $4, $5, $6, $7)::text AS number',
      [principal, requestId, String(at), payload, Buffer.from(r.member.seal, 'hex'), seal, mac]);
    if (done.number !== null) return { number: done.number, tries };
  }
  throw new Error('the member kept changing');
}

/* The checkpointer: as simple.ts's, with no lag. */

export type Checkpoint = { upto: string; from: string; entries: number; statements: number; dbMs: number; verifyMs: number; signed: boolean; failures: string[] };
/** Where the last checkpoint ended, its hash, and the floor of `at` its barrier set. */
export type CheckpointState = { upto: string; hash: Buffer; atFloor: string };

export type Row = {
  number: string; at: string; kind: 'use' | 'change'; principal: string; credential: string | null; request_id: string; payload: string;
  seal: Buffer | null; mac: Buffer;
};
/**
 * The entries numbered in ($1, $2], in number order. Changes by their
 * number; uses, which have no index on it, through their (at, request_id)
 * index from $3: the floor of `at` the barrier that closed $1 set. A use
 * numbered after that barrier was written after it, and a use below the
 * floor writes nothing, so none is missed (schema-one.sql).
 */
export const ENTRIES = `SELECT number::text, at::text, kind, principal, credential, request_id, payload, seal, mac FROM (
    SELECT * FROM entries_changes c WHERE c.number > $1 AND c.number <= $2
    UNION ALL
    SELECT * FROM entries_uses u WHERE u.at >= $3 AND u.number > $1 AND u.number <= $2
  ) w ORDER BY w.number`;

export const rowEntry = (r: Row): Entry => ({
  at: Number(r.at), kind: r.kind, principal: r.principal, credential: r.credential, requestId: r.request_id, payload: r.payload, seal: r.seal,
});

/** A checkpoint's hash: every entry in (from, upto], in number order, its number with its MAC, chained to the checkpoint before. */
export function checkpointHash(prev: Buffer, entries: readonly { number: string; mac: Buffer }[]): Buffer {
  const chain = createHash('sha256').update('one.checkpoint.v1').update(prev);
  for (const e of entries) chain.update(e.number).update(':').update(e.mac);
  return chain.digest();
}

/** The vault's signature over a checkpoint. A stand-in for its signing key. */
export function checkpointSignature(key: Buffer, from: string, upto: string, hash: Buffer): Buffer {
  return createHmac('sha256', key).update('one.signature.v1').update(JSON.stringify([from, upto])).update(hash).digest();
}

export async function loadCheckpointState(db: Db): Promise<CheckpointState> {
  const { rows: [last] } = await db.query('SELECT upto::text, hash, at_floor::text FROM checkpoints c ORDER BY c.upto DESC LIMIT 1');
  if (last === undefined) throw new Error('no checkpoint to go on from: seed the database');
  return { upto: last.upto, hash: last.hash, atFloor: last.at_floor };
}

/** Each entry's MAC. */
export function verifyEntries(keys: Keys, rows: readonly Row[]): string[] {
  const failures: string[] = [];
  for (const r of rows) if (!entryMac(keys.log, rowEntry(r)).equals(r.mac)) failures.push(`${r.number}: mac`);
  return failures;
}

/**
 * One checkpoint: the barrier (`close_one`, the lock exclusive for one
 * statement), then every entry since the last checkpoint up to it, read
 * and verified, then signed together with the last one's hash.
 */
export async function checkpoint(db: Db, keys: Keys, state: CheckpointState): Promise<Checkpoint> {
  const started = performance.now();
  const from = state.upto;
  const { rows: [c] } = await db.query('SELECT upto::text, at_floor::text FROM close_one()');
  const upto: string = c.upto ?? from;
  let statements = 1;
  const empty = { upto: from, from, entries: 0, statements, dbMs: performance.now() - started, verifyMs: 0, signed: false, failures: [] };
  if (BigInt(upto) <= BigInt(from)) return empty;
  const { rows } = await db.query(ENTRIES, [from, upto, state.atFloor]);
  statements += 1;
  const dbMs = performance.now() - started;
  const verifying = performance.now();
  const failures = verifyEntries(keys, rows as Row[]);
  if (failures.length > 0) return { ...empty, dbMs, entries: rows.length, failures };
  const hash = checkpointHash(state.hash, rows as Row[]);
  const signature = checkpointSignature(keys.log, from, upto, hash);
  const verifyMs = performance.now() - verifying;
  await db.query('INSERT INTO checkpoints (upto, from_number, entries, hash, signature, at_floor, at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [upto, from, rows.length, hash, signature, c.at_floor, String(Date.now())]);
  statements += 1;
  state.upto = upto;
  state.hash = hash;
  state.atFloor = c.at_floor;
  return { upto, from, entries: rows.length, statements, dbMs, verifyMs, signed: true, failures };
}
