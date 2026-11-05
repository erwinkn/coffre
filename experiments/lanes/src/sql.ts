import type { Client } from 'pg';

import type { Sealed } from './chain.ts';
import type { Snapshot } from './model.ts';

/**
 * The statements each protocol sends. A statement is a round trip through
 * Hyperdrive; the protocols differ in how many they send, and in which
 * locks they hold across them.
 */

export type Head = { nextSeq: bigint; hash: Buffer };

const MEMBER = `(SELECT json_build_object('principal', principal, 'status', status, 'role', role, 'access_seq', access_seq::text, 'mac', encode(mac, 'hex')) FROM members WHERE principal = $1)`;
const GRANTS = `(SELECT coalesce(json_agg(json_build_object('principal', principal, 'environment_id', environment_id, 'role', role)), '[]') FROM grants WHERE principal = $1)`;
const ENVIRONMENT = `(SELECT json_build_object('id', id, 'deleted', deleted) FROM environments WHERE id = $2)`;
const SECRET = `(SELECT json_build_object('id', id, 'nature', nature, 'wrapped', encode(wrapped, 'hex'), 'iv', encode(iv, 'hex')) FROM secrets WHERE id = $3)`;
const NOW = `(extract(epoch from clock_timestamp()) * 1000)::bigint`;

/**
 * Today's decision read, from the one chain: with the head locked in the
 * same statement, `SKIP LOCKED` (0.14) or waiting for it (W185), or not at
 * all.
 */
export function chainSnapshotQuery(head: 'skip' | 'wait' | 'none'): string {
  const lock = head === 'skip' ? 'FOR UPDATE SKIP LOCKED' : 'FOR UPDATE';
  return `
    ${head === 'none' ? '' : `WITH h AS (SELECT next_seq, head_hash FROM head WHERE only_row ${lock})`}
    SELECT json_build_object(
      'at', ${NOW}, 'member', ${MEMBER}, 'grants', ${GRANTS},
      'access', (SELECT json_build_object('seq', seq::text, 'mac', encode(mac, 'hex')) FROM log WHERE subject = $1 AND action LIKE 'access.%' ORDER BY seq DESC LIMIT 1),
      'policy', (SELECT json_build_object('seq', seq::text) FROM log WHERE action = 'policy.change' ORDER BY seq DESC LIMIT 1),
      'environment', ${ENVIRONMENT}, 'secret', ${SECRET}, 'control', NULL,
      'head', ${head === 'none' ? 'NULL' : `(SELECT json_build_object('nextSeq', next_seq::text, 'hash', encode(head_hash, 'hex')) FROM h)`},
      'last', ${head === 'none' ? 'NULL' : `(SELECT json_build_object('seq', seq::text, 'hash', encode(hash, 'hex')) FROM log ORDER BY seq DESC LIMIT 1)`}
    ) AS s`;
}

/** The lanes' decision read: no lock; the control lane's head instead, which the append holds it to. */
export const LANES_SNAPSHOT = `
  SELECT json_build_object(
    'at', ${NOW}, 'member', ${MEMBER}, 'grants', ${GRANTS},
    'access', (SELECT json_build_object('seq', seq::text, 'mac', encode(mac, 'hex')) FROM lane_log WHERE lane = 0 AND subject = $1 AND action LIKE 'access.%' ORDER BY seq DESC LIMIT 1),
    'policy', (SELECT json_build_object('seq', seq::text) FROM lane_log WHERE lane = 0 AND action = 'policy.change' ORDER BY seq DESC LIMIT 1),
    'environment', ${ENVIRONMENT}, 'secret', ${SECRET},
    'control', (SELECT next_seq::text FROM lanes WHERE lane = 0)
  ) AS s`;

export type ChainRead = Snapshot & { head: { nextSeq: string; hash: string } | null; last: { seq: string; hash: string } | null };

export async function snapshot<T = Snapshot>(client: Client, query: string, principal: string, environmentId: string, secretId: string): Promise<T> {
  const { rows } = await client.query(query, [principal, environmentId, secretId]);
  return rows[0].s as T;
}

const COLUMNS = 'seq, author, actor, action, decision, subject, environment_id, control_seq, occurred_at, metadata, prev_hash, mac, hash';
const UNNEST = `unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::uuid[], $8::bigint[], $9::bigint[], $10::text[], $11::bytea[], $12::bytea[], $13::bytea[])`;

function columns(author: string, entries: readonly Sealed[]): unknown[] {
  return [
    entries.map((e) => String(e.seq)),
    entries.map(() => author),
    entries.map((e) => e.fields.actor),
    entries.map((e) => e.fields.action),
    entries.map((e) => e.fields.decision),
    entries.map((e) => e.fields.subject),
    entries.map((e) => e.fields.environmentId),
    entries.map((e) => e.fields.controlSeq),
    entries.map((e) => String(e.fields.occurredAt)),
    entries.map((e) => e.fields.metadata),
    entries.map((e) => e.prevHash),
    entries.map((e) => e.mac),
    entries.map((e) => e.hash),
  ];
}

/** Today's append, in one statement: the entries, and the head that names the last of them. */
export async function appendChain(client: Client, author: string, entries: readonly Sealed[]): Promise<void> {
  const last = entries.at(-1)!;
  await client.query(
    `WITH appended AS (INSERT INTO log (${COLUMNS}) SELECT * FROM ${UNNEST})
     UPDATE head SET next_seq = $14, head_hash = $15 WHERE only_row`,
    [...columns(author, entries), String(last.seq + 1n), last.hash],
  );
}

export const LOCK_HEAD = 'SELECT next_seq, head_hash FROM head WHERE only_row FOR UPDATE';

/** `underHead`: the head again, the log's last entry and the clock, as the app's append reads them. */
export const UNDER_HEAD = `SELECT h.next_seq::text AS next_seq, h.head_hash, (SELECT hash FROM log ORDER BY seq DESC LIMIT 1) AS last_hash, ${NOW} AS now FROM head h WHERE only_row FOR UPDATE`;

export async function readHead(client: Client, lane: number | null): Promise<Head> {
  const { rows } = lane === null
    ? await client.query('SELECT next_seq::text AS next_seq, head_hash FROM head WHERE only_row')
    : await client.query('SELECT next_seq::text AS next_seq, head_hash FROM lanes WHERE lane = $1', [lane]);
  return { nextSeq: BigInt(rows[0].next_seq), hash: rows[0].head_hash };
}

/**
 * A lane's append, in one statement, committed on its own: the entries go
 * in, and the lane's head moves past them, only if the head is still where
 * the writer had it and the control lane still where every entry's
 * decision read it. Otherwise nothing is written, and the answer says which
 * moved. No lock is held across a round trip: the head's row is locked
 * for this statement and its commit, inside the database.
 */
export async function appendLane(
  client: Client,
  lane: number,
  from: Head,
  control: string,
  entries: readonly Sealed[],
): Promise<{ written: boolean; control: string; head: string }> {
  const last = entries.at(-1)!;
  const { rows } = await client.query(
    `WITH control AS (SELECT next_seq FROM lanes WHERE lane = 0),
     moved AS (
       UPDATE lanes SET next_seq = $15, head_hash = $16
       WHERE lane = $14 AND next_seq = $17 AND head_hash = $18 AND (SELECT next_seq FROM control) = $19
       RETURNING 1
     ),
     appended AS (
       INSERT INTO lane_log (lane, ${COLUMNS}) SELECT $14, * FROM ${UNNEST} WHERE EXISTS (SELECT 1 FROM moved) RETURNING 1
     )
     SELECT EXISTS (SELECT 1 FROM moved) AS written, (SELECT next_seq::text FROM control) AS control,
       (SELECT next_seq::text FROM lanes WHERE lane = $14) AS head, (SELECT count(*) FROM appended) AS n`,
    [...columns('vault', entries), lane, String(last.seq + 1n), last.hash, String(from.nextSeq), from.hash, control],
  );
  return { written: rows[0].written, control: rows[0].control, head: rows[0].head };
}

/** Today's lanes without a writer of their own: lock the lane's head for one round trip (BEGIN and the lock in one). */
export async function lockLane(client: Client, lane: number): Promise<Head> {
  const results = (await client.query(`BEGIN; SELECT next_seq::text AS next_seq, head_hash FROM lanes WHERE lane = ${Number(lane)} FOR UPDATE`)) as unknown as { rows: { next_seq: string; head_hash: Buffer }[] }[];
  const row = results[1]!.rows[0]!;
  return { nextSeq: BigInt(row.next_seq), hash: row.head_hash };
}
