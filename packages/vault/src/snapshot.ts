import type { StoredEntry } from '@coffre/core/audit';
import type { Queryable, Transaction } from '@coffre/db';
import { LogHeadMismatch, lockLogHead, lockLogHeadQueued } from '@coffre/db/log';
import { engineOf, rowsOf } from '@coffre/db/dialect';
import type { GrantRow } from '@coffre/db/grants';

import { snapshotQuery as postgres } from './snapshot.postgres.ts';
import { snapshotQuery as sqlite } from './snapshot.sqlite.ts';
import { objectKey } from './inputs.ts';
import * as store from './store.ts';
import type { EnvironmentRow, Member } from './store.ts';

/**
 * What a decision reads, or `access`, in one statement: one round trip, and
 * one snapshot of the database, so its parts agree with each other.
 *
 * In a decision, the same statement locks the log's head, but only if it
 * is free (`SKIP LOCKED`). Postgres takes a statement's snapshot when it
 * starts, so one that waited for the lock would have read everything but
 * the head as it was before the wait: a policy changed, a place deleted, a
 * grant written around the vault while it waited would be missed. A
 * statement that never waits reads all of it as of the lock. When another
 * transaction holds the head, the decision waits for it in a statement of
 * its own, then reads again, holding it. The read checks that the head names
 * the last entry it saw, too (`current`): one taken between the snapshot and
 * the lock, by an append that committed in that instant, is read again. That
 * check sees a commit only through the head it moved, which holds because
 * every change a decision reads commits with an entry under the head: the
 * vault's own decisions, and the app's writes to places, each `audited`
 * with its entry.
 */
export type Snapshot = {
  /** The database's clock, milliseconds since the epoch. */
  at: number;
  /** The rows of `asked.members`, by principal; those with none are not in the map. */
  members: Map<string, Member>;
  /** Every grant of each asked principal, lapsed ones too. */
  grants: Map<string, GrantRow[]>;
  /** The newest allowed access entry in the vault's name about each asked principal, unchecked. */
  newestAccess: Map<string, StoredEntry>;
  /** The newest allowed `policy.change` in the vault's name, unchecked. */
  newestPolicy: StoredEntry | null;
  /** With `asked.settings`, the newest allowed `settings.change` in the vault's name, unchecked, or null for none; not asked, undefined. */
  newestSettings: StoredEntry | null | undefined;
  /**
   * The asked environments, the environments each personal config among
   * them is a config of, and those the newest `policy.change` names, by id;
   * with `asked.seals`, those the asked principals' grants are on too, each
   * with what 0.15's log holds it to (`EnvironmentRow.sealed`).
   */
  environments: Map<string, EnvironmentRow>;
  /** Of the asked `reference.create` entries, those a `reference.end` of the vault's names, allowed. */
  ended: Set<bigint>;
  /**
   * How many distinct keys `asked.released.principal` holds released within
   * its window once it is given `asked.released.keys` too: a key released
   * again, or asked for again, counts once. Those released before are
   * counted up to one past `asked.released.cap`, which is enough to say
   * whether the read goes past it.
   */
  released: number;
  /** The log's head, locked, with the last entry and the newest `key.rotate`; null unless asked, or held by another. */
  head: LockedHead | null;
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
  /** The newest `settings.change` too (`newestSettings`). */
  settings?: boolean;
  environments?: readonly string[];
  /**
   * Each environment read with what 0.15's log holds it to, and the asked
   * principals' grants' too, whose projects their grants are read with
   * (T159): asked once 0.15's log is cut over, before which no row is sealed.
   */
  seals?: boolean;
  references?: readonly bigint[];
  /**
   * One principal's releases within the last `windowMs` of the clock, moved
   * on by `clockOffsetMs` as the vault's is, with `keys`, secret ids, besides;
   * read from `vault_releases`, which the database keeps from the log, up to
   * `cap` + 1 of them.
   */
  released?: { principal: string; keys: readonly string[]; windowMs: number; clockOffsetMs: number; cap: number };
  /** Lock the log's head first. */
  head?: boolean;
  /**
   * Held by another, wait for the head only in one of this many places in
   * line, and refuse at once when none is free (`lockLogHeadQueued`); with
   * none, wait as long as the transaction's bound lets.
   */
  waiters?: number;
};

/** One statement's read, as `Snapshot` says; with the head, two more when another holds it. */
export async function snapshot(tx: Transaction, asked: Asked): Promise<Snapshot>;
export async function snapshot(db: Queryable, asked: Asked & { head?: false }): Promise<Snapshot>;
export async function snapshot(db: Queryable, asked: Asked): Promise<Snapshot> {
  const read = () => readOnce(db, asked);
  const first = await read();
  if (asked.head !== true || (first.head !== null && current(first.head))) return first;
  // Held by another, or moved in the instant before the lock: everything again, once the head is this transaction's.
  // Asked for the head, `db` is a transaction (the overloads above).
  if (first.head === null) await (asked.waiters === undefined ? lockLogHead(db as Transaction) : lockLogHeadQueued(db as Transaction, asked.waiters));
  const again = await read();
  if (again.head === null) throw new Error("the log's head, held by this transaction, was read as held by another");
  // Held, nothing appends: a head that names another last entry was moved, or the log written, around it (`appendEntries`).
  if (!current(again.head)) {
    throw new LogHeadMismatch(`the log's head says entry ${again.head.nextSeq} comes next, but the log ends ${again.head.last === null ? 'empty' : `at entry ${again.head.last.seq}`}, or with another hash`);
  }
  return again;
}

/** Whether the head names the last entry the same statement saw: nothing was appended between its snapshot and its lock. */
export function current(head: LockedHead): boolean {
  if (head.last === null) return head.nextSeq === 0n;
  return head.nextSeq === head.last.seq + 1n && head.headHash.equals(head.last.hash);
}

async function readOnce(db: Queryable, asked: Asked): Promise<Snapshot> {
  const engine = engineOf(db);
  const query = (engine === 'postgres' ? postgres : sqlite)(asked);
  const [row] = await rowsOf<{ snapshot: string | Raw }>(db, query);
  const raw: Raw = typeof row!.snapshot === 'string' ? (JSON.parse(row!.snapshot) as Raw) : row!.snapshot;
  // SQLite has no `log_object`: the environments' newest changes in a statement of their own, by the keys the vault
  // computes, the places asked with no row among them (`gone`, which Postgres's statement answers itself).
  const rowless = asked.seals === true && engine !== 'postgres' ? (raw.placeIds ?? []).filter((id) => !raw.environments.some((row) => row.id === id)) : [];
  const newest = asked.seals === true && engine !== 'postgres'
    ? await store.newestSeals(db, [...raw.environments.map(({ id }) => id), ...rowless].map((id) => ({ kind: 'environment' as const, id })))
    : null;
  const gone = newest === null
    ? (raw.gone ?? []).map(({ id, newest: last }) => [id, hex(last)] as const)
    : rowless.flatMap((id) => (newest.has(objectKey({ kind: 'environment', id })) ? [[id, newest.get(objectKey({ kind: 'environment', id })) ?? null] as const] : []));
  return {
    at: Number(raw.at),
    members: new Map(raw.members.map((member) => [member.principal, memberOf(member)])),
    grants: new Map(asked.principals.map((principal) => [principal, raw.grants.filter((grant) => grant.principal === principal).map(grantOf)])),
    newestAccess: new Map(raw.access.map((entry) => [entry.subjectPrincipal!, entryOf(entry)])),
    newestPolicy: raw.policy === null ? null : entryOf(raw.policy),
    newestSettings: asked.settings !== true ? undefined : raw.settings == null ? null : entryOf(raw.settings),
    environments: new Map<string, EnvironmentRow>([...gone.map(([id, last]) => [id, store.goneEnvironment(id, last)] as const), ...raw.environments.map(({ id, projectId, slug, owner, parentId, deleted, archived, ...sealed }) => [id, {
      projectId, slug, owner, parentId,
      deleted: Boolean(deleted),
      archived: Boolean(archived),
      ...(asked.seals === true ? {
        sealed: store.environmentSeal(
          { id, projectId, slug, owner, parentId, protected: sealed.protected == null ? null : Boolean(sealed.protected), archived: Boolean(sealed.ownArchived), projectArchived: Boolean(sealed.projectArchived) },
          hex(sealed.seal),
          newest === null ? hex(sealed.newest) : newest.get(objectKey({ kind: 'environment', id })) ?? null,
        ),
      } : {}),
    }] as const)]),
    ended: new Set(raw.ended.map((seq) => BigInt(seq))),
    released: Number(raw.released ?? 0),
    head: raw.head === null ? null : {
      nextSeq: BigInt(raw.head.nextSeq),
      headHash: Buffer.from(raw.head.hash, 'hex'),
      last: raw.last === null ? null : { seq: BigInt(raw.last.seq), hash: Buffer.from(raw.last.hash, 'hex') },
      rotation: raw.rotation === null ? null : entryOf(raw.rotation),
    },
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

type Raw = {
  at: Int;
  head: { nextSeq: Int; hash: string } | null;
  last: { seq: Int; hash: string } | null;
  rotation: RawEntry | null;
  members: {
    principal: string; status: 'active' | 'removed'; owner: boolean | number; role: string | null; scope: string | null; generation: Int;
    createdAt: Int; createdBy: string; statusChangedAt: Int; statusChangedBy: string; accessSeq: Int; mac: string;
  }[];
  grants: { principal: string; projectId: string | null; environmentId: string | null; environmentSlug: string | null; role: string; expiresAt: Int | null; grantedAt: Int; grantedBy: string }[];
  access: RawEntry[];
  policy: RawEntry | null;
  settings?: RawEntry | null;
  environments: {
    id: string; projectId: string; slug: string; owner: string | null; parentId: string | null; deleted: boolean | number; archived: boolean | number;
    /** With `asked.seals`: the object's own columns, the row's seal and, on Postgres, its newest change's, as hex. */
    protected?: boolean | number | null; ownArchived?: boolean | number; projectArchived?: boolean | number; seal?: string | null; newest?: string | null;
  }[];
  /** With `asked.seals`, on Postgres: the places asked that the log holds a change of and no row answers to. */
  gone?: { id: string; newest: string | null }[];
  /** With `asked.seals`, on SQLite: every place id asked, row or none. */
  placeIds?: string[];
  ended: Int[];
  released: Int | null;
};

function hex(value: string | null | undefined): Buffer | null {
  return value == null ? null : Buffer.from(value, 'hex');
}

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

function grantOf(raw: Raw['grants'][number]): GrantRow {
  return { ...raw, expiresAt: raw.expiresAt === null ? null : Number(raw.expiresAt), grantedAt: Number(raw.grantedAt) };
}

function memberOf({ owner, ...raw }: Raw['members'][number]): Member {
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
