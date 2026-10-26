import type { StoredEntry } from '@coffre/core/audit';
import type { Queryable, Transaction } from '@coffre/db';
import { LogHeadMismatch } from '@coffre/db/log';
import { engineOf, rowsOf } from '@coffre/db/dialect';
import type { GrantRow } from '@coffre/db/grants';
import type { SQL } from 'drizzle-orm';

import { snapshotQuery as postgresQuery, stillQuery } from './snapshot.postgres.ts';
import { snapshotQuery as sqliteQuery } from './snapshot.sqlite.ts';
import * as store from './store.ts';
import type { EnvironmentRow, Member } from './store.ts';

/**
 * What a decision reads, or `access`, in one statement: one round trip, and
 * one snapshot of the database, so its parts agree with each other.
 *
 * In a decision, the same statement locks the log's head, waiting for it
 * while another transaction holds it. Postgres takes a statement's snapshot
 * when it starts, so one that waited read everything but the head as it was
 * before the wait. Whether it did, the read says itself: the head names the
 * last entry the statement saw (`current`), or an append committed while it
 * waited. Every change a decision reads commits with an entry under the
 * head, the vault's decisions and the app's writes to places alike, each
 * `audited` with its entry, so a head that names the last entry seen means
 * nothing it read has changed: it stands until the decision commits. One
 * that does not is held to the database as it is when the decision appends,
 * in the append's own statement (`unchanged`): the same read again, the
 * same text, or nothing is written (`ReadsChanged`) and the decision is
 * made again, holding the head as it reads. So the head is held for the
 * append and its commit, never for a second read, however many wait.
 */
export type Snapshot = {
  /** The database's clock, milliseconds since the epoch: once the head is held, when asked for it. */
  at: number;
  /** The rows of `asked.members`, by principal; those with none are not in the map. */
  members: Map<string, Member>;
  /** Every grant of each asked principal, lapsed ones too. */
  grants: Map<string, GrantRow[]>;
  /** The newest allowed access entry in the vault's name about each asked principal, unchecked. */
  newestAccess: Map<string, StoredEntry>;
  /** The newest allowed `policy.change` in the vault's name, unchecked. */
  newestPolicy: StoredEntry | null;
  /**
   * The asked environments, the environments each personal config among
   * them is a config of, and those the newest `policy.change` names, by id.
   */
  environments: Map<string, EnvironmentRow>;
  /** Of the asked `reference.create` entries, those a `reference.end` of the vault's names, allowed. */
  ended: Set<bigint>;
  /**
   * How many distinct keys `asked.released.principal` holds released within
   * its window once it is given `asked.released.keys` too: a key released
   * again, or asked for again, counts once.
   */
  released: number;
  /** The log's head, locked, with the last entry and the newest `key.rotate`; null unless asked. */
  head: LockedHead | null;
  /**
   * Null when this read stands as long as the head is held: it holds none,
   * or it read after every append before its lock. Otherwise, what the
   * append must find for it to stand still (`appendEntries`, `unchanged`):
   * the same read again, and the keys released still within the bulk limit.
   */
  unchanged: SQL | null;
};

export type LockedHead = {
  nextSeq: bigint;
  headHash: Buffer;
  /** The log's last entry, as this statement's snapshot has it. */
  last: { seq: bigint; hash: Buffer } | null;
  /** The vault's newest `key.rotate`, allowed, unchecked. */
  rotation: StoredEntry | null;
};

/** What to read. */
export type Asked = {
  /** Whose grants and newest access entry; with `members`, their rows too, unlocked. */
  principals: readonly string[];
  members?: boolean;
  environments?: readonly string[];
  references?: readonly bigint[];
  /**
   * One principal's releases within the last `windowMs` of the clock, moved
   * on by `clockOffsetMs` as the vault's is, with `keys`, secret ids,
   * besides; `count` the most they may hold (`unchanged`).
   */
  released?: { principal: string; keys: readonly string[]; windowMs: number; clockOffsetMs: number; count: number };
  /** Lock the log's head, waiting for it. */
  head?: boolean;
  /**
   * With the head, on Postgres: wait for it no longer than this, as
   * `boundLockWaits` would, set by the statement itself, for the rest of
   * the transaction.
   */
  waitMs?: number;
  /** The transaction held the head before this read: it waits for nothing, and reads as of the lock. */
  held?: boolean;
};

/** One statement's read, as `Snapshot` says. */
export async function snapshot(tx: Transaction, asked: Asked): Promise<Snapshot>;
export async function snapshot(db: Queryable, asked: Asked & { head?: false }): Promise<Snapshot>;
export async function snapshot(db: Queryable, asked: Asked): Promise<Snapshot> {
  const read = await readOnce(db, asked);
  if (read.head === null || current(read.head) || read.unchanged !== null) return read;
  // Held as it began, or on SQLite, where nothing waits: a head that names another last entry was moved, or the log
  // written, around it (`appendEntries`).
  throw new LogHeadMismatch(`the log's head says entry ${read.head.nextSeq} comes next, but the log ends ${read.head.last === null ? 'empty' : `at entry ${read.head.last.seq}`}, or with another hash`);
}

/** Whether the head names the last entry the same statement saw: nothing was appended between its snapshot and its lock. */
export function current(head: LockedHead): boolean {
  if (head.last === null) return head.nextSeq === 0n;
  return head.nextSeq === head.last.seq + 1n && head.headHash.equals(head.last.hash);
}

async function readOnce(db: Queryable, asked: Asked): Promise<Snapshot> {
  const postgres = engineOf(db) === 'postgres';
  const [row] = await rowsOf<{ snapshot: string | Raw; stable: string }>(db, (postgres ? postgresQuery : sqliteQuery)(asked));
  const raw: Raw = typeof row!.snapshot === 'string' ? (JSON.parse(row!.snapshot) as Raw) : row!.snapshot;
  const kept = JSON.parse(row!.stable) as Stable;
  const head = raw.head === null ? null : {
    nextSeq: BigInt(raw.head.nextSeq),
    headHash: Buffer.from(raw.head.hash, 'hex'),
    last: raw.last === null ? null : { seq: BigInt(raw.last.seq), hash: Buffer.from(raw.last.hash, 'hex') },
    rotation: kept.rotation === null ? null : entryOf(kept.rotation),
  };
  const at = Number(raw.at);
  return {
    at,
    members: new Map(kept.members.map((member) => [member.principal, memberOf(member)])),
    grants: new Map(asked.principals.map((principal) => [principal, kept.grants.filter((grant) => grant.principal === principal).map(grantOf)])),
    newestAccess: new Map(kept.access.map((entry) => [entry.subjectPrincipal!, entryOf(entry)])),
    newestPolicy: kept.policy === null ? null : entryOf(kept.policy),
    environments: new Map(kept.environments.map(({ id, ...environment }) => [id, {
      ...environment,
      deleted: Boolean(environment.deleted),
      archived: Boolean(environment.archived),
    }])),
    ended: new Set(kept.ended.map((seq) => BigInt(seq))),
    released: Number(raw.released ?? 0),
    head,
    unchanged: postgres && asked.held !== true && head !== null && !current(head)
      ? stillQuery(asked, row!.stable, head.last === null ? 0n : head.last.seq + 1n, Number(raw.released ?? 0), asked.released?.count ?? 0)
      : null,
  };
}

/** Whole numbers come as JSON numbers or text, bytes as hex, as each dialect's query writes them. */
type Int = number | string;

/** An entry's columns, as both dialects' queries write them (`entryJson`). */
export type RawEntry = {
  seq: Int; author: string; keyId: string; occurredAt: Int; actor: string; action: string; decision: string; code: string | null;
  subjectPrincipal: string | null; projectId: string | null; environmentId: string | null; secretId: string | null;
  secretVersionId: string | null; operationId: string | null; requestId: string | null; sourceIp: string | null;
  relatedSeq: Int | null; metadata: string; prevHash: string; mac: string; hash: string;
};

/** What the statement reads besides `Stable`. */
type Raw = {
  at: Int;
  head: { nextSeq: Int; hash: string } | null;
  last: { seq: Int; hash: string } | null;
  released: Int | null;
};

/** What nothing but a change, with its entry, changes: the statement's `stable`, as text. */
type Stable = {
  rotation: RawEntry | null;
  members: {
    principal: string; status: 'active' | 'removed'; owner: boolean | number; role: string | null; scope: string | null; generation: Int;
    createdAt: Int; createdBy: string; statusChangedAt: Int; statusChangedBy: string; accessSeq: Int; mac: string;
  }[];
  grants: { principal: string; projectId: string | null; environmentId: string | null; environmentSlug: string | null; role: string; expiresAt: Int | null; grantedAt: Int; grantedBy: string }[];
  access: RawEntry[];
  policy: RawEntry | null;
  environments: { id: string; projectId: string; slug: string; owner: string | null; parentId: string | null; deleted: boolean | number; archived: boolean | number }[];
  ended: Int[];
};

/** An entry as the chain's codec reads it, from what `entryJson` wrote. */
export function entryOf(raw: RawEntry): StoredEntry {
  return {
    ...raw,
    seq: BigInt(raw.seq),
    author: raw.author as StoredEntry['author'],
    occurredAt: Number(raw.occurredAt),
    relatedSeq: raw.relatedSeq === null ? null : BigInt(raw.relatedSeq),
    prevHash: Buffer.from(raw.prevHash, 'hex'),
    mac: Buffer.from(raw.mac, 'hex'),
    hash: Buffer.from(raw.hash, 'hex'),
  };
}

function grantOf(raw: Stable['grants'][number]): GrantRow {
  return { ...raw, expiresAt: raw.expiresAt === null ? null : Number(raw.expiresAt), grantedAt: Number(raw.grantedAt) };
}

function memberOf({ owner, ...raw }: Stable['members'][number]): Member {
  return store.memberOf({
    ...raw,
    owner: owner === true || owner === 1,
    generation: Number(raw.generation),
    createdAt: Number(raw.createdAt),
    statusChangedAt: Number(raw.statusChangedAt),
    accessSeq: BigInt(raw.accessSeq),
    mac: Buffer.from(raw.mac, 'hex'),
  });
}
