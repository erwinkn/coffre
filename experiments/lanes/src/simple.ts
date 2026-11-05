import { createHash, createHmac } from 'node:crypto';

import type { Fields } from './chain.ts';
import { memberMac, refusal, unwrap, type Grant, type Keys, type Snapshot } from './model.ts';

/**
 * The simple hot path (W201): Postgres only, no Durable Object, no cache.
 * A use is one read and one append, each a statement of its own, so each a
 * round trip; no lock is held across a round trip. One audit entry per use
 * (the vault's; the app writes none). Three ways to give the entry its place:
 *
 *   head  the head row is locked by the append statement alone, and the
 *         chain link is a plain hash computed in SQL. The MAC covers what
 *         the entry says and its revision, not its place.
 *   seq   no head: the read takes the entry's number from a sequence, and
 *         the MAC covers it. The append holds a shared advisory lock, which
 *         changes and checkpoints take exclusively; checkpoints chain the
 *         entries they close.
 *   cas   today's chain (the MAC covers the hash before), kept in one
 *         round trip: the read returns the head, the append moves it only
 *         if nobody else did (compare-and-swap), and retries otherwise.
 *
 * Revocation: every change raises the revision; the read returns it, and
 * the append writes nothing unless it is still current. A change commits
 * before it answers, so a use that reads after the answer is refused, and a
 * use that read before it and appends after it is refused at its append.
 */
export type Variant = 'head' | 'seq' | 'cas';

/** What a statement needs: a `pg` Client or Pool. */
export type Db = { query(query: string | { name: string; text: string; values: unknown[] }, params?: unknown[]): Promise<{ rows: any[] }> };

/**
 * Whether the hot path's statements are named (prepared once per
 * connection, then only bound and executed), as Hyperdrive allows, or
 * unnamed (parsed and planned at every call), as coffre sends them today.
 */
let named = false;
export function nameStatements(on: boolean): void {
  named = on;
}
const run = (db: Db, name: string, text: string, values: unknown[]) => (named ? db.query({ name, text, values }) : db.query(text, values));

export type UseInput = { principal: string; credential: string; environmentId: string; secretId: string; requestId: string };
export type UseAnswer =
  | { ok: true; value: string; seq: string; statements: number; tries: number }
  | { ok: false; code: string; retryAfter?: number; statements: number; tries: number };

const MEMBER = `(SELECT json_build_object('principal', principal, 'status', status, 'role', role, 'access_seq', access_seq::text, 'mac', encode(mac, 'hex')) FROM members WHERE principal = $1)`;
const GRANTS = `(SELECT coalesce(json_agg(json_build_object('principal', principal, 'environment_id', environment_id, 'role', role)), '[]') FROM grants WHERE principal = $1)`;

/**
 * The one read: everything the decision reads, and the revision, in one
 * snapshot. `seq` takes the entry's number; `cas` returns the head.
 */
const READ = `
  SELECT json_build_object(
    'revision', h.revision::text,
    'seq', CASE WHEN $5::boolean THEN nextval('audit_seq')::text END,
    'head', CASE WHEN $6::boolean THEN json_build_object('nextSeq', h.next_seq::text, 'hash', encode(h.hash, 'hex')) END,
    'member', ${MEMBER}, 'grants', ${GRANTS},
    'credential', (SELECT json_build_object('principal', principal, 'revoked', revoked) FROM credentials WHERE id = $4),
    'access', (SELECT json_build_object('seq', revision::text) FROM audit WHERE subject = $1 AND action LIKE 'access.%' ORDER BY seq DESC LIMIT 1),
    'policy', NULL,
    'environment', (SELECT json_build_object('id', id, 'deleted', deleted) FROM environments WHERE id = $2),
    'secret', (SELECT json_build_object('id', id, 'nature', nature, 'wrapped', encode(wrapped, 'hex'), 'iv', encode(iv, 'hex')) FROM secrets WHERE id = $3),
    'control', NULL
  ) AS s FROM audit_head h WHERE only_row`;

type Read = Snapshot & { revision: string; seq: string | null; head: { nextSeq: string; hash: string } | null; credential: { principal: string; revoked: boolean } | null };

/** head: the append, and the head moved past it, in one statement; nothing if a change moved the revision. */
const APPEND_HEAD = `
  WITH h AS (SELECT next_seq, hash FROM audit_head WHERE only_row AND revision = $1 FOR UPDATE),
  e AS (
    INSERT INTO audit (seq, revision, actor, action, decision, subject, environment_id, occurred_at, metadata, mac, prev_hash, hash)
    SELECT h.next_seq, $1, $2, $3, $4, $5, $6, $7, $8, $9, h.hash, sha256(h.hash || $9) FROM h
    RETURNING seq, hash
  ),
  moved AS (UPDATE audit_head SET next_seq = e.seq + 1, hash = e.hash FROM e WHERE only_row)
  SELECT seq::text AS seq FROM e`;

const APPEND_SEQ = 'SELECT append_use($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) AS ok';

/** cas: the head moves only from where the read saw it, and only at the revision the decision read. */
const APPEND_CAS = `
  WITH moved AS (
    UPDATE audit_head SET next_seq = $1::bigint + 1, hash = $12 WHERE only_row AND next_seq = $1::bigint AND hash = $11 AND revision = $2::bigint RETURNING 1
  ),
  e AS (
    INSERT INTO audit (seq, revision, actor, action, decision, subject, environment_id, occurred_at, metadata, mac, prev_hash, hash)
    SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 WHERE EXISTS (SELECT 1 FROM moved)
    RETURNING 1
  )
  SELECT EXISTS (SELECT 1 FROM e) AS ok`;

const HEAD = `SELECT revision::text AS revision, next_seq::text AS next_seq, encode(hash, 'hex') AS hash FROM audit_head WHERE only_row`;

/** What an entry's MAC covers: its number (seq, cas), the hash before it (cas), its revision and what it says. */
export function entryMac(key: Buffer, seq: string | null, prevHash: Buffer | null, revision: string, f: Fields): Buffer {
  const body = JSON.stringify([seq, revision, f.actor, f.action, f.decision, f.subject, f.environmentId, f.occurredAt, f.metadata]);
  const mac = createHmac('sha256', key).update('simple.mac.v1');
  if (prevHash !== null) mac.update(prevHash);
  return mac.update(body).digest();
}

/** The link a chain entry carries: sha256(prev_hash || mac), as SQL computes it (`head`). */
export function link(prevHash: Buffer, mac: Buffer): Buffer {
  return createHash('sha256').update(prevHash).update(mac).digest();
}

function why(keys: Keys, read: Read, input: UseInput): string | null {
  if (read.credential === null || read.credential.revoked || read.credential.principal !== input.principal) return 'credential';
  return refusal(keys, read, input.environmentId);
}

function fieldsOf(input: UseInput, refused: string | null): Fields {
  return {
    actor: input.principal, action: 'secret.use', decision: refused === null ? 'allow' : 'deny', subject: input.principal,
    environmentId: input.environmentId, controlSeq: null, occurredAt: Date.now(),
    metadata: JSON.stringify({ requestId: input.requestId, secretId: input.secretId, credential: input.credential, ...(refused === null ? {} : { code: refused }) }),
  };
}

const params = (seq: string, revision: string, f: Fields, mac: Buffer) =>
  [seq, revision, f.actor, f.action, f.decision, f.subject, f.environmentId, String(f.occurredAt), f.metadata, mac];

/** Tries at most: a fence that failed (a change committed between the read and the append) reads and appends once more. */
const TRIES = { head: 2, seq: 2, cas: 6 } as const;

/** One use: read, decide, append; the value only once its entry has committed. */
export async function use(db: Db, keys: Keys, variant: Variant, input: UseInput): Promise<UseAnswer> {
  let statements = 0;
  let read: Read | null = null;
  for (let tries = 1; tries <= TRIES[variant]; tries += 1) {
    if (read === null || variant !== 'cas') {
      const { rows } = await run(db, 'read', READ, [input.principal, input.environmentId, input.secretId, input.credential, variant === 'seq', variant === 'cas']);
      statements += 1;
      read = rows[0].s as Read;
    }
    const refused = why(keys, read, input);
    const f = fieldsOf(input, refused);
    let seq: string | null = null;
    if (variant === 'head') {
      const mac = entryMac(keys.log, null, null, read.revision, f);
      const { rows } = await run(db, 'append_head', APPEND_HEAD, params(read.revision, read.revision, f, mac).slice(1));
      statements += 1;
      seq = rows[0]?.seq ?? null;
    } else if (variant === 'seq') {
      const mac = entryMac(keys.log, read.seq, null, read.revision, f);
      const { rows } = await run(db, 'append_seq', APPEND_SEQ, params(read.seq!, read.revision, f, mac));
      statements += 1;
      seq = rows[0].ok ? read.seq : null;
    } else {
      const prev = Buffer.from(read.head!.hash, 'hex');
      const mac = entryMac(keys.log, read.head!.nextSeq, prev, read.revision, f);
      const hash = link(prev, mac);
      const { rows } = await run(db, 'append_cas', APPEND_CAS, [...params(read.head!.nextSeq, read.revision, f, mac), prev, hash]);
      statements += 1;
      seq = rows[0].ok ? read.head!.nextSeq : null;
      if (seq === null && tries < TRIES.cas) {
        // Someone else moved the head (or a change the revision): read where it is now, and try again.
        const { rows: [head] } = await db.query(HEAD);
        statements += 1;
        if (head.revision !== read.revision) read = null;
        else read = { ...read, head: { nextSeq: head.next_seq, hash: head.hash } };
        continue;
      }
    }
    if (seq === null) {
      read = null;
      continue;
    }
    if (refused !== null) return { ok: false, code: refused, statements, tries };
    const key = unwrap(keys.kek, Buffer.from(read.secret!.wrapped, 'hex'), Buffer.from(read.secret!.iv, 'hex'));
    const value = key.toString('base64');
    key.fill(0);
    return { ok: true, value, seq, statements, tries };
  }
  return { ok: false, code: 'changing', retryAfter: 1, statements, tries: TRIES[variant] };
}

/**
 * A change: a principal's grant taken away or given back, its entry, and
 * the member row sealed over it, at the next revision. One read (the
 * revision; `seq` also takes the entry's number), then one statement that
 * does it all under the head's lock (`head`) or the exclusive lock (`seq`),
 * refused if another change moved the revision in between. It answers only
 * once committed.
 */
export async function change(
  db: Db, keys: Keys, mode: 'head' | 'seq', principal: string, give: boolean, environmentId: string, kind: 'grant' | 'credential' = 'grant',
): Promise<{ seq: string; revision: string; tries: number }> {
  for (let tries = 1; tries <= 20; tries += 1) {
    const { rows: [r] } = await db.query(
      `SELECT h.revision::text AS revision, CASE WHEN $1::boolean THEN nextval('audit_seq')::text END AS seq,
         (SELECT json_build_object('principal', principal, 'status', status, 'role', role) FROM members WHERE principal = $2) AS member
       FROM audit_head h WHERE only_row`,
      [mode === 'seq', principal],
    );
    const revision = String(BigInt(r.revision) + 1n);
    const f: Fields = {
      actor: 'user:root@acme.example',
      action: kind === 'credential' ? (give ? 'credential.restore' : 'credential.revoke') : give ? 'access.grant' : 'access.revoke',
      decision: 'allow', subject: principal,
      environmentId, controlSeq: null, occurredAt: Date.now(), metadata: '{}',
    };
    const mac = entryMac(keys.log, mode === 'seq' ? r.seq : null, null, revision, f);
    const grants: Grant[] = give ? [{ principal, environment_id: environmentId, role: 'viewer' }] : [];
    const memberSeal = memberMac(keys.row, { ...r.member, access_seq: revision }, grants);
    const { rows: [done] } = await db.query(
      'SELECT change_grant($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)::text AS seq',
      [mode, kind, r.revision, r.seq, principal, give, environmentId, f.actor, String(f.occurredAt), mac, memberSeal],
    );
    if (done.seq !== null) return { seq: done.seq, revision, tries };
  }
  throw new Error('the revision kept moving');
}

export type Checkpoint = {
  upto: string; from: string; entries: number; statements: number; dbMs: number; verifyMs: number; bytes: number;
  /** Whether a checkpoint was signed: not when the window was empty, nor when an entry failed its check. */
  signed: boolean;
  failures: string[];
};

type Row = { seq: string; revision: string; actor: string; action: string; decision: 'allow' | 'deny'; subject: string | null; environment_id: string | null; occurred_at: string; metadata: string; mac: Buffer; prev_hash: Buffer | null; hash: Buffer | null };

const fieldsOfRow = (row: Row): Fields => ({
  actor: row.actor, action: row.action, decision: row.decision, subject: row.subject, environmentId: row.environment_id,
  controlSeq: null, occurredAt: Number(row.occurred_at), metadata: row.metadata,
});

/**
 * The checkpointer's state between ticks: the last signed checkpoint (where
 * it ended, its hash, and for `head` the hash of the entry it ended on), and
 * (seq) what the last ticks saw of the sequence, oldest first. Loaded from
 * the last checkpoint row, so a checkpointer that restarts carries on from
 * what was signed, and signs a window that was closed but not yet signed.
 */
export type CheckpointState = { upto: string; hash: Buffer; seen: string[]; tip: Buffer | null };

/**
 * seq: a checkpoint closes the numbers the sequence had given out this many
 * ticks ago. A use slower than that between its read and its append is
 * refused (and reads again); an entry is sealed by a checkpoint this many
 * ticks after it was written, at most one more.
 */
export const LAG_TICKS = 5;

const ENTRIES = 'SELECT seq::text, revision::text, actor, action, decision, subject, environment_id, occurred_at::text, metadata, mac, prev_hash, hash FROM audit a WHERE a.seq > $1 AND a.seq <= $2 ORDER BY a.seq';

/** A checkpoint's hash: every entry in (from, upto], in number order, chained to the checkpoint before. */
export function checkpointHash(prev: Buffer, entries: readonly { seq: string; mac: Buffer }[]): Buffer {
  const chain = createHash('sha256').update('simple.checkpoint.v1').update(prev);
  for (const e of entries) chain.update(e.seq).update(':').update(e.mac);
  return chain.digest();
}

/** The vault's signature over a checkpoint: the window it covers, the revision, and the hash. A stand-in for its signing key. */
export function checkpointSignature(key: Buffer, from: string, upto: string, revision: string, hash: Buffer): Buffer {
  return createHmac('sha256', key).update('simple.signature.v1').update(JSON.stringify([from, upto, revision])).update(hash).digest();
}

/** The state to go on from: the last checkpoint row (the seed writes the first). */
export async function loadCheckpointState(db: Db): Promise<CheckpointState> {
  const { rows: [last] } = await db.query(
    'SELECT c.upto::text, c.hash, (SELECT hash FROM audit WHERE seq = c.upto) AS tip FROM checkpoints c ORDER BY c.upto DESC LIMIT 1',
  );
  if (last === undefined) throw new Error('no checkpoint to go on from: seed the database');
  return { upto: last.upto, hash: last.hash, seen: [], tip: last.tip };
}

/**
 * One checkpoint: every entry since the last one, read and verified (MAC,
 * and for `head` the link), then signed together with the last one's hash,
 * and the state moved on only once its row is in. `head`: up to the head,
 * which names a committed prefix. `seq`: up to the floor, once
 * `close_checkpoint` has made sure no append at or below it can still
 * commit. An entry that fails its check stops it: nothing is signed over it.
 */
export async function checkpoint(db: Db, keys: Keys, mode: 'head' | 'seq', state: CheckpointState): Promise<Checkpoint> {
  const started = performance.now();
  let statements = 0;
  const from = state.upto;
  let upto: string;
  let revision: string;
  if (mode === 'head') {
    const { rows: [h] } = await db.query(HEAD);
    statements += 1;
    upto = String(BigInt(h.next_seq) - 1n);
    revision = h.revision;
  } else {
    // Until LAG_TICKS ticks have passed, nothing to close: '0' leaves the floor where it is. The floor may be past the
    // last checkpoint already: closed, then not signed before a restart. This one signs up to it.
    const closing = state.seen.length >= LAG_TICKS ? state.seen.shift()! : '0';
    const { rows: [c] } = await db.query('SELECT floor_to::text, revision::text, next_upto::text FROM close_checkpoint($1)', [closing]);
    statements += 1;
    upto = c.floor_to;
    revision = c.revision;
    state.seen.push(c.next_upto);
  }
  const empty = { upto: from, from, entries: 0, statements, dbMs: performance.now() - started, verifyMs: 0, bytes: 0, signed: false, failures: [] };
  if (BigInt(upto) <= BigInt(from)) return empty;
  const { rows } = await db.query(ENTRIES, [from, upto]);
  statements += 1;
  const dbMs = performance.now() - started;
  const verifying = performance.now();
  const failures = verifyEntries(keys, mode, state.tip, rows as Row[]);
  let bytes = 0;
  for (const row of rows as Row[]) bytes += row.metadata.length + 200;
  if (failures.length > 0) return { ...empty, dbMs, entries: rows.length, failures };
  const hash = checkpointHash(state.hash, rows as Row[]);
  const signature = checkpointSignature(keys.log, from, upto, revision, hash);
  const verifyMs = performance.now() - verifying;
  await db.query(
    'INSERT INTO checkpoints (upto, from_seq, revision, entries, hash, signature, at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [upto, from, revision, rows.length, hash, signature, String(Date.now())],
  );
  statements += 1;
  state.upto = upto;
  state.hash = hash;
  if (mode === 'head' && rows.length > 0) state.tip = (rows.at(-1) as Row).hash;
  return { upto, from, entries: rows.length, statements, dbMs, verifyMs, bytes, signed: true, failures };
}

/** Each entry's MAC, and for `head` its link to the one before (from `tip`, the hash of the entry before the first). */
export function verifyEntries(keys: Keys, mode: 'head' | 'seq', tip: Buffer | null, rows: readonly Row[]): string[] {
  const failures: string[] = [];
  let prev = tip;
  for (const row of rows) {
    const f = fieldsOfRow(row);
    if (mode === 'head') {
      if (!entryMac(keys.log, null, null, row.revision, f).equals(row.mac)) failures.push(`${row.seq}: mac`);
      if (prev !== null && (row.prev_hash === null || !row.prev_hash.equals(prev))) failures.push(`${row.seq}: prev`);
      if (row.prev_hash === null || row.hash === null || !link(row.prev_hash, row.mac).equals(row.hash)) failures.push(`${row.seq}: link`);
      prev = row.hash;
    } else if (!entryMac(keys.log, row.seq, null, row.revision, f).equals(row.mac)) {
      failures.push(`${row.seq}: mac`);
    }
  }
  return failures;
}

export type AuditRow = Row;
export { ENTRIES };
