import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';

import { unwrap, type Keys } from './model.ts';
import type { Db } from './simple.ts';

/**
 * Variant `one` (W208, then W211): the simple hot path in one round trip,
 * with no revision (schema-one.sql, formal/HotPathOne.tla).
 *
 *   use     the vault MACs the request (its time, request id, credential and
 *           secret), then makes one call, `use_credential`: the fence lock
 *           shared, then one statement that reads everything the decision
 *           needs and inserts the entry, numbered from the sequence, and the
 *           commit. Then it decides, opens the key and releases the value. A
 *           denial is logged as much as an allowance: the entry is the request.
 *   change  one read (the object, to seal its next state), then one call,
 *           `change_input`: the lock exclusive, the write, its entry, the
 *           commit; then it answers.
 *
 * No revision: a use holds the lock shared and a change holds it exclusive,
 * each takes its number under it and keeps it to its commit, so no use
 * overlaps a change. The number alone orders them, and the outcome of a use
 * is a function of the changes numbered before it, the uses before it (the
 * bulk cap) and its time (`decide`), which a replay recomputes (verify-one.ts).
 *
 * Every input a decision reads is sealed to the log (W211): its row carries
 * the vault's MAC over it, and the object's newest change records the same.
 * A row put back from before a change is refused (`stale`), so a database
 * writer cannot make the live decision differ from the log's.
 */

/** Whether the call is named (prepared once per connection), as `simple.ts`'s statements. */
let named = false;
export function nameStatements(on: boolean): void {
  named = on;
}
const run = (db: Db, name: string, text: string, values: unknown[]) => (named ? db.query({ name, text, values }) : db.query(text, values));

/** The synthetic instance's ids: one environment, `--secrets` secrets in it, a credential per principal. */
const hex12 = (n: number) => n.toString(16).padStart(12, '0');
export const ENVIRONMENT = '00000000-0000-4000-8000-000000000001';
export const secretId = (j: number) => `00000000-0000-4000-8001-${hex12(j)}`;
export const credentialId = (i: number) => `00000000-0000-4000-8002-${hex12(i)}`;

/** A request id: random, 63 bits, unique within its millisecond (schema-one.sql). */
export const newRequestId = () => (randomBytes(8).readBigUInt64BE() >> 1n).toString();

/**
 * A request: its id and, once stamped, its time. A retry of the same request (its answer lost)
 * passes both unchanged, so that its call finds the entry the first one wrote.
 */
export type UseInput = { credential: string; secretId: string; requestId: string; at?: number };
export type UseAnswer =
  | { ok: true; value: string; number: string; statements: number; covered?: true; cached?: true }
  | { ok: false; code: string; number?: string; retryAfter?: number; statements: number; cached?: true };

/** The bulk cap: `count` distinct keys per principal per rolling `windowMs` (the deployment's, R52), and how stale a key's row may get. */
export type Limits = { count: number; windowMs: number; refreshMs: number };
/** R28's default, 1000 keys per 15 minutes; the row moves on at most once a minute (or a tenth of the window). */
export function limits(count = 1000, windowMs = 15 * 60_000, refreshMs?: number): Limits {
  return { count, windowMs, refreshMs: refreshMs ?? Math.min(60_000, Math.floor(windowMs / 10)) };
}

/** HMAC-SHA256 cut to 16 bytes (W211): every entry's MAC and every row's seal. */
const mac16 = (key: Buffer, label: string, ...parts: (string | Buffer)[]) => {
  const h = createHmac('sha256', key).update(label);
  for (const p of parts) h.update(p);
  return h.digest().subarray(0, 16);
};
const uuidBytes = (u: string) => Buffer.from(u.replaceAll('-', ''), 'hex');

/** A use's entry, as the vault MACs it: everything but its number, in 48 fixed bytes. */
export type UseEntry = { at: number; requestId: string; credential: string; secret: string };
export function useMac(key: Buffer, e: UseEntry): Buffer {
  const b = Buffer.alloc(48);
  b.writeBigInt64BE(BigInt(e.at), 0);
  b.writeBigInt64BE(BigInt(e.requestId), 8);
  uuidBytes(e.credential).copy(b, 16);
  uuidBytes(e.secret).copy(b, 32);
  return mac16(key, 'one.use.v2', b);
}

/** A change's entry, as the vault MACs it: everything but its number. */
export type ChangeEntry = { at: number; requestId: string; object: string; actor: string; payload: string; seal: Buffer | null };
export function changeMac(key: Buffer, e: ChangeEntry): Buffer {
  return mac16(key, 'one.change.v2', JSON.stringify([String(e.at), e.requestId, e.object, e.actor, e.payload, e.seal === null ? null : e.seal.toString('hex')]));
}

/* The inputs, and their seals: the vault's MAC over each, by kind. */

export type Grant = { environment_id: string; role: string };
export type Member = { principal: string; status: string; role: string | null; grants: Grant[] };
export type Credential = { id: string; principal: string; revoked: boolean; expiresAt: string | null };
export type Secret = { id: string; environmentId: string; nature: string; wrapped: string; iv: string };
export type Environment = { id: string; deleted: boolean };

export const memberSeal = (key: Buffer, m: Member) =>
  mac16(key, 'one.member.v2', JSON.stringify([m.principal, m.status, m.role, m.grants.map((g) => `${g.environment_id}:${g.role}`).sort()]));
export const credentialSeal = (key: Buffer, c: Credential) => mac16(key, 'one.credential.v2', JSON.stringify([c.id, c.principal, c.revoked, c.expiresAt]));
export const secretSeal = (key: Buffer, s: Secret) => mac16(key, 'one.secret.v2', JSON.stringify([s.id, s.environmentId, s.nature, s.wrapped, s.iv]));
export const environmentSeal = (key: Buffer, e: Environment) => mac16(key, 'one.environment.v2', JSON.stringify([e.id, e.deleted]));

/** What a change does, as logged and as `change_input` applies it. */
export type Op =
  | { op: 'member.add'; status: string; role: string | null }
  | { op: 'access.grant'; environment: string; role: string }
  | { op: 'access.revoke'; environment: string }
  | { op: 'credential.issue'; principal: string; expiresAt: string | null }
  | { op: 'credential.revoke' }
  | { op: 'credential.restore' }
  | { op: 'environment.create' }
  | { op: 'environment.delete' }
  | { op: 'environment.restore' }
  | { op: 'secret.create'; environment: string; nature: string; wrapped: string; iv: string }
  | { op: 'secret.rotate'; wrapped: string; iv: string }
  | { op: 'bulk.limit'; count: number; windowMs: number; refreshMs: number };

/** The inputs as a map of objects: what the replay builds from the log, and what a change reads before it seals. */
export type State = {
  members: Map<string, Member>;
  credentials: Map<string, Credential>;
  secrets: Map<string, Secret>;
  environments: Map<string, Environment>;
  limits: Limits | null;
};
export const emptyState = (): State => ({ members: new Map(), credentials: new Map(), secrets: new Map(), environments: new Map(), limits: null });

/**
 * A change applied to the state, as change_input applies it to the rows:
 * the object's seal after it, or null if it does nothing (a create of
 * something that exists, a change to something that does not).
 */
export function applyOp(keys: Keys, s: State, object: string, op: Op): Buffer | null {
  const [kind, id] = [object.slice(0, object.indexOf(':')), object.slice(object.indexOf(':') + 1)];
  switch (op.op) {
    case 'member.add': {
      if (kind !== 'member' || s.members.has(id)) return null;
      const m = { principal: id, status: op.status, role: op.role, grants: [] };
      s.members.set(id, m);
      return memberSeal(keys.row, m);
    }
    case 'access.grant': case 'access.revoke': {
      const m = s.members.get(id);
      if (kind !== 'member' || m === undefined) return null;
      const others = m.grants.filter((g) => g.environment_id !== op.environment);
      m.grants = op.op === 'access.grant' ? [...others, { environment_id: op.environment, role: op.role }] : others;
      return memberSeal(keys.row, m);
    }
    case 'credential.issue': {
      if (kind !== 'credential' || s.credentials.has(id)) return null;
      const c = { id, principal: op.principal, revoked: false, expiresAt: op.expiresAt };
      s.credentials.set(id, c);
      return credentialSeal(keys.row, c);
    }
    case 'credential.revoke': case 'credential.restore': {
      const c = s.credentials.get(id);
      if (kind !== 'credential' || c === undefined) return null;
      c.revoked = op.op === 'credential.revoke';
      return credentialSeal(keys.row, c);
    }
    case 'environment.create': {
      if (kind !== 'environment' || s.environments.has(id)) return null;
      const e = { id, deleted: false };
      s.environments.set(id, e);
      return environmentSeal(keys.row, e);
    }
    case 'environment.delete': case 'environment.restore': {
      const e = s.environments.get(id);
      if (kind !== 'environment' || e === undefined) return null;
      e.deleted = op.op === 'environment.delete';
      return environmentSeal(keys.row, e);
    }
    case 'secret.create': {
      if (kind !== 'secret' || s.secrets.has(id)) return null;
      const x = { id, environmentId: op.environment, nature: op.nature, wrapped: op.wrapped, iv: op.iv };
      s.secrets.set(id, x);
      return secretSeal(keys.row, x);
    }
    case 'secret.rotate': {
      const x = s.secrets.get(id);
      if (kind !== 'secret' || x === undefined) return null;
      x.wrapped = op.wrapped;
      x.iv = op.iv;
      return secretSeal(keys.row, x);
    }
    case 'bulk.limit':
      s.limits = { count: op.count, windowMs: op.windowMs, refreshMs: op.refreshMs };
      return null;
  }
}

/** Each input as the decision reads it: the row, its seal, and the seal its object's newest change wrote. */
type Sealed<T> = (T & { seal: Buffer; last: Buffer | null }) | null;
/** Everything a decision reads: what `use_credential` returns, or what a replay has built from the log. */
export type View = {
  credential: Sealed<Credential>;
  member: Sealed<Member>;
  secret: Sealed<Secret>;
  environment: Sealed<Environment>;
  /** The bulk cap: whether the key is in the principal's set, and how many others are (up to the cap). */
  bulk: { inSet: boolean; others: number };
  /** Whether each input's object has a change in the log: a row missing from an object that has one was deleted. */
  logged: { credential: boolean; member: boolean; secret: boolean; environment: boolean };
};

/**
 * Why a row is refused: not a valid seal over it (`tampered`: only the
 * vault's key makes one), or a valid one that is not its object's newest
 * change's (`stale`: a row put back from before that change).
 */
function unsealed(row: { seal: Buffer; last: Buffer | null }, seal: Buffer, checkSeals: boolean): string | null {
  if (!checkSeals) return null;
  if (!seal.equals(row.seal)) return 'tampered';
  if (row.last === null || !row.last.equals(row.seal)) return 'stale';
  return null;
}

/**
 * The decision: why a use is refused, or null to allow it. A function of the
 * view, the request and the entry's time alone, so a replay of the log
 * decides the same. `checkSeals: false` exists only for fence-one.ts, to show
 * what an unsealed input lets through.
 */
export function decide(keys: Keys, v: View, input: Pick<UseInput, 'credential' | 'secretId'>, at: number, cap: Limits, checkSeals = true): string | null {
  // The seals before what the rows say (formal/HotPathOne.tla, StaleFirst): a row deleted, or put back to one that
  // refuses, is `stale`, which the replay never answers, not a refusal the log would also give.
  const gone = (logged: boolean, code: string) => (checkSeals && logged ? 'stale' : code);
  const c = v.credential;
  if (c === null) return gone(v.logged.credential, 'credential');
  if (c.id !== input.credential) return 'credential';
  const sc = unsealed(c, credentialSeal(keys.row, c), checkSeals);
  if (sc !== null) return sc;
  if (c.revoked) return 'credential';
  if (c.expiresAt !== null && at >= Number(c.expiresAt)) return 'expired';
  const m = v.member;
  if (m === null) return gone(v.logged.member, 'not_member');
  if (m.principal !== c.principal) return 'not_member';
  const sm = unsealed(m, memberSeal(keys.row, m), checkSeals);
  if (sm !== null) return sm;
  if (m.status !== 'active') return 'not_member';
  const s = v.secret;
  if (s === null) return gone(v.logged.secret, 'missing');
  if (s.id !== input.secretId) return 'missing';
  const ss = unsealed(s, secretSeal(keys.row, s), checkSeals);
  if (ss !== null) return ss;
  const e = v.environment;
  if (e === null) return gone(v.logged.environment, 'deleted');
  if (e.id !== s.environmentId) return 'deleted';
  const se = unsealed(e, environmentSeal(keys.row, e), checkSeals);
  if (se !== null) return se;
  if (e.deleted) return 'deleted';
  if (!m.grants.some((g) => g.environment_id === s.environmentId)) return 'forbidden';
  if (!v.bulk.inSet && v.bulk.others >= cap.count) return 'bulk';
  return null;
}

/**
 * The bulk cap's rule, as use_credential applies it to `bulk` (schema-one.sql) and the replay to its
 * map: a key in the set passes; one not in it passes if fewer than `count` others are, and enters;
 * a key whose row is older than `refresh` moves on. `rows`: the principal's keys and their `last`.
 */
export function bulkStep(rows: Map<string, number>, secret: string, at: number, cap: Limits): { inSet: boolean; others: number } {
  const last = rows.get(secret);
  const inSet = last !== undefined && last > at - cap.windowMs - cap.refreshMs;
  let others = 0;
  // Others over the longer bound: a key that entered at a later `at` may be decided first (schema-one.sql).
  if (!inSet) for (const [k, t] of rows) if (k !== secret && t > at - cap.windowMs - cap.refreshMs - DEADLINE_MAX && others < cap.count) others += 1;
  if ((last === undefined || last <= at - cap.refreshMs) && (inSet || others < cap.count)) rows.set(secret, at);
  return { inSet, others };
}

const USE = 'SELECT * FROM use_credential($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)';

export type UseRow = {
  state: string | null; number: string | null; covered: string | null; principal: string | null; newest: string | null; newest_mac: Buffer | null; inputs: string | null;
  c_revoked: boolean | null; c_expires: string | null; c_seal: Buffer | null; c_last: Buffer | null;
  m_status: string | null; m_role: string | null; m_seal: Buffer | null; m_last: Buffer | null; grants: string[] | null;
  s_environment: string | null; s_nature: string | null; s_wrapped: Buffer | null; s_iv: Buffer | null; s_seal: Buffer | null; s_last: Buffer | null;
  e_deleted: boolean | null; e_seal: Buffer | null; e_last: Buffer | null;
  in_set: boolean; others: number;
};

/**
 * An isolate's seal cache: for each credential and secret, the seal of each
 * of the four inputs' newest change, as of `newest`, the log's newest change
 * when they were read (its number and MAC), and the highest of their numbers
 * (`inputs`, what a cover is checked against). use_credential uses them only
 * if that change is still the log's newest (schema-one.sql), in its own
 * snapshot: not merely no higher number, which a database restored from a
 * backup, or made again, would pass with older seals. Settled values only.
 */
export type SealCache = { held: Map<string, { newest: string; newestMac: Buffer; inputs: string | null; last: [Buffer | null, Buffer | null, Buffer | null, Buffer | null] }>; max: number };
export const sealCache = (max = 10_000): SealCache => ({ held: new Map(), max });

/** What use_credential read, as a view; the newest changes' seals from the cache when it skipped them. */
export function viewOf(r: UseRow, input: UseInput, cached?: [Buffer | null, Buffer | null, Buffer | null, Buffer | null]): View {
  if (cached !== undefined) [r.c_last, r.m_last, r.s_last, r.e_last] = cached;
  return {
    credential: r.c_seal === null ? null : { id: input.credential, principal: r.principal!, revoked: r.c_revoked!, expiresAt: r.c_expires, seal: r.c_seal, last: r.c_last },
    member: r.m_seal === null ? null : {
      principal: r.principal!, status: r.m_status!, role: r.m_role, seal: r.m_seal, last: r.m_last,
      grants: (r.grants ?? []).map((g) => ({ environment_id: g.slice(0, g.indexOf(':')), role: g.slice(g.indexOf(':') + 1) })),
    },
    secret: r.s_seal === null ? null : {
      id: input.secretId, environmentId: r.s_environment!, nature: r.s_nature!, wrapped: r.s_wrapped!.toString('hex'), iv: r.s_iv!.toString('hex'), seal: r.s_seal, last: r.s_last,
    },
    environment: r.e_seal === null ? null : { id: r.s_environment!, deleted: r.e_deleted!, seal: r.e_seal, last: r.e_last },
    bulk: { inSet: r.in_set, others: r.others },
    logged: { credential: r.c_last !== null, member: r.m_last !== null, secret: r.s_last !== null, environment: r.e_last !== null },
  };
}

/**
 * An isolate's covers (fewer rows): for each credential and secret, its last
 * allowed entry, until `window` ms after it or the credential's expiry. A
 * repeat passes it, and writes nothing if no change to any input came after
 * it and its key's bulk row is fresh.
 */
export type Covers = { window: number; held: Map<string, { number: string; until: number }> };

/** A use's deadline is at most this long after its time (schema-one.sql's deadline_max()). */
export const DEADLINE_MAX = 3000;

/** A use whose call failed on its (at, request_id): a replay of a call that wrote. */
const replayed = (error: unknown) => {
  const e = error as { code?: string; table?: string };
  return e.code === '23505' && /^uses_\d+$/.test(e.table ?? '');
};

/**
 * One use: one call, then the decision, and the value only once the call
 * has returned, which is once its entry has committed. `deadline` (ms since
 * the epoch, set when the request came in, at most DEADLINE_MAX after its
 * time): a call that gets its lock later does nothing (the pool or
 * Hyperdrive held it while the Worker gave up). The caller answers 503 at
 * the deadline whatever the call does (the Worker's race).
 */
export async function use(db: Db, keys: Keys, input: UseInput, deadline: number, cap: Limits, covers?: Covers, seals?: SealCache): Promise<UseAnswer> {
  const at = input.at ?? Date.now();
  const key = `${input.credential}\n${input.secretId}`;
  const known = seals?.held.get(key);
  const held = covers?.held.get(key);
  // A cover a change we know of came after is no cover; one we cannot judge, the statement judges.
  const cover = held !== undefined && at < held.until && (known === undefined || known.inputs === null || BigInt(held.number) > BigInt(known.inputs)) ? held.number : null;
  const mac = useMac(keys.log, { at, requestId: input.requestId, credential: input.credential, secret: input.secretId });
  let rows: UseRow[];
  try {
    ({ rows } = await run(db, 'use_credential', USE,
      [input.credential, input.secretId, input.requestId, String(at), mac, String(deadline), cover, cap.count, String(cap.windowMs), String(cap.refreshMs), known?.newest ?? null, known?.newestMac ?? null]));
  } catch (error) {
    // A replay of a call whose answer was lost: its entry stands, its value never left. Not decided again.
    if (replayed(error)) return { ok: false, code: 'replayed', retryAfter: 1, statements: 1 };
    // Past its deadline by Postgres's clock (the function's own check, or the login's statement_timeout): nothing written.
    if ((error as { code?: string }).code === '57014') return { ok: false, code: 'late', retryAfter: 1, statements: 1 };
    throw error;
  }
  const r = rows[0]!;
  if (r.state !== null) return { ok: false, code: 'late', retryAfter: 1, statements: 1 };
  // Probed (inputs is set): what it read is the cache's now. Else the statement found no change since the cache's.
  const probed = known === undefined || r.newest !== known.newest || r.newest_mac === null || !r.newest_mac.equals(known.newestMac);
  if (probed && seals !== undefined && r.newest !== null) {
    if (seals.held.size >= seals.max) seals.held.clear();
    seals.held.set(key, { newest: r.newest, newestMac: r.newest_mac!, inputs: r.inputs, last: [r.c_last, r.m_last, r.s_last, r.e_last] });
  }
  const v = viewOf(r, input, probed ? undefined : known!.last);
  const refused = decide(keys, v, input, at, cap);
  if (r.covered !== null && refused !== null) {
    // Refused on a cover (its expiry): logged as an entry of its own.
    covers!.held.delete(key);
    const fresh = await use(db, keys, { ...input, at }, deadline, cap, covers, seals);
    return { ...fresh, statements: fresh.statements + 1 };
  }
  const cached = probed ? {} : { cached: true as const };
  if (refused !== null) {
    covers?.held.delete(key);
    return { ok: false, code: refused, number: r.number!, statements: 1, ...cached };
  }
  if (covers !== undefined && r.covered === null) {
    const expires = v.credential!.expiresAt === null ? Infinity : Number(v.credential!.expiresAt);
    covers.held.set(key, { number: r.number!, until: Math.min(at + covers.window, expires) });
  }
  const dek = unwrap(keys.kek, r.s_wrapped!, r.s_iv!);
  const value = dek.toString('base64');
  dek.fill(0);
  return r.covered === null ? { ok: true, value, number: r.number!, statements: 1, ...cached } : { ok: true, value, number: r.covered, statements: 1, covered: true, ...cached };
}

/** The object's row as it stands, into a state of its own: what a change seals its next state from. */
async function readObject(db: Db, object: string): Promise<{ state: State; seal: Buffer | null }> {
  const s = emptyState();
  const [kind, id] = [object.slice(0, object.indexOf(':')), object.slice(object.indexOf(':') + 1)];
  if (kind === 'member') {
    const { rows: [r] } = await db.query(`SELECT status, role, seal, (SELECT coalesce(array_agg(environment_id::text || ':' || role), '{}') FROM grants g WHERE g.principal = m.principal) AS grants
      FROM members m WHERE principal = $1`, [id]);
    if (r === undefined) return { state: s, seal: null };
    s.members.set(id, { principal: id, status: r.status, role: r.role, grants: (r.grants as string[]).map((g) => ({ environment_id: g.slice(0, g.indexOf(':')), role: g.slice(g.indexOf(':') + 1) })) });
    return { state: s, seal: r.seal };
  }
  if (kind === 'credential') {
    const { rows: [r] } = await db.query('SELECT principal, revoked, expires_at::text, seal FROM credentials WHERE id = $1', [id]);
    if (r === undefined) return { state: s, seal: null };
    s.credentials.set(id, { id, principal: r.principal, revoked: r.revoked, expiresAt: r.expires_at });
    return { state: s, seal: r.seal };
  }
  if (kind === 'secret') {
    const { rows: [r] } = await db.query('SELECT environment_id::text, nature, wrapped, iv, seal FROM secrets WHERE id = $1', [id]);
    if (r === undefined) return { state: s, seal: null };
    s.secrets.set(id, { id, environmentId: r.environment_id, nature: r.nature, wrapped: r.wrapped.toString('hex'), iv: r.iv.toString('hex') });
    return { state: s, seal: r.seal };
  }
  if (kind === 'environment') {
    const { rows: [r] } = await db.query('SELECT deleted, seal FROM environments WHERE id = $1', [id]);
    if (r === undefined) return { state: s, seal: null };
    s.environments.set(id, { id, deleted: r.deleted });
    return { state: s, seal: r.seal };
  }
  return { state: s, seal: null };
}

/**
 * A change: the object read (no lock), its next state sealed and the entry
 * MAC'd, then one call that makes it under the lock exclusive, refused if
 * another change moved the object's seal in between (then read again). It
 * answers only once committed.
 */
export async function change(db: Db, keys: Keys, object: string, op: Op, request?: { requestId: string; at: number }, actor = 'root'): Promise<{ number: string; tries: number }> {
  for (let tries = 1; tries <= 20; tries += 1) {
    const { state, seal: from } = await readObject(db, object);
    const seal = applyOp(keys, state, object, op);
    if (seal === null && op.op !== 'bulk.limit') throw new Error(`${op.op} does nothing to ${object}`);
    // A retry of the same change (`request`) finds its entry; a try refused on a moved seal wrote nothing.
    const at = request?.at ?? Date.now();
    const requestId = request?.requestId ?? randomUUID();
    const payload = JSON.stringify(op);
    const mac = changeMac(keys.log, { at, requestId, object, actor, payload, seal });
    const { rows: [done] } = await db.query('SELECT change_input($1, $2, $3, $4, $5, $6, $7, $8)::text AS number',
      [object, requestId, String(at), actor, payload, from, seal, mac]);
    if (done.number !== null) return { number: done.number, tries };
  }
  throw new Error(`${object} kept changing`);
}

/* The checkpointer: as simple.ts's, with no lag. */

export type Checkpoint = { upto: string; from: string; entries: number; statements: number; dbMs: number; verifyMs: number; signed: boolean; failures: string[] };
/** Where the last checkpoint ended, its hash, and the floor of `at` its barrier set. */
export type CheckpointState = { upto: string; hash: Buffer; atFloor: string };

/** An entry as ENTRIES reads it: a change's columns, or a use's, the other's null. */
export type Row = {
  number: string; at: string; kind: 'use' | 'change'; request_id: string;
  object: string | null; actor: string | null; payload: string | null; seal: Buffer | null;
  credential: string | null; secret: string | null; mac: Buffer;
};
/**
 * The entries numbered in ($1, $2], in number order. Changes by their
 * number; uses, which have no index on it, through their (at, request_id)
 * index from $3: the floor of `at` the barrier that closed $1 set. A use
 * numbered after that barrier was written after it, and a use below the
 * floor writes nothing, so none is missed (schema-one.sql).
 */
export const ENTRIES = `SELECT * FROM (
    SELECT c.number::text, c.at::text, 'change' AS kind, c.request_id, c.object, c.actor, c.payload, c.seal, NULL::text AS credential, NULL::text AS secret, c.mac
    FROM changes c WHERE c.number > $1 AND c.number <= $2
    UNION ALL
    SELECT u.number::text, u.at::text, 'use', u.request_id::text, NULL, NULL, NULL, NULL, u.credential::text, u.secret::text, u.mac
    FROM uses u WHERE u.at >= $3 AND u.number > $1 AND u.number <= $2
  ) w ORDER BY w.number::bigint`;

/** An entry's MAC, recomputed from its row. */
export const rowMac = (keys: Keys, r: Row): Buffer =>
  r.kind === 'use'
    ? useMac(keys.log, { at: Number(r.at), requestId: r.request_id, credential: r.credential!, secret: r.secret! })
    : changeMac(keys.log, { at: Number(r.at), requestId: r.request_id, object: r.object!, actor: r.actor!, payload: r.payload!, seal: r.seal });

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
  for (const r of rows) if (!rowMac(keys, r).equals(r.mac)) failures.push(`${r.number}: mac`);
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
