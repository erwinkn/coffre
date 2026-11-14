import { createHash } from 'node:crypto';

import { HASH_SIZE, inclusionProof, nodesFrom, leafHash, tileKey, tilesFor, verifyInclusion, WIDTH, type Edge } from '@coffre/core/log';
import { credentials, deviceLogins, enrollmentCodes } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { change, drop, part, type Running } from './change.ts';
import type { Entry } from './entry.ts';
import type { Finding, Signing, Tree } from './signer.ts';

/**
 * What the signer's minute does after its check (docs/design/0.16.md, "How
 * long the log is kept"): it finds how far the oldest uses can be pruned,
 * and holds a slice of the log to what it signed. Functions of the database
 * and the signer's trees: the signer keeps what they decide, and prunes as
 * it moves entries, by one statement it can run again.
 *
 * Both read the log by block: the 256 entries of a level-0 tile, from leaf
 * 256·block. A block is held to the signer's own root through the tiles as
 * stored, and each entry to its hash in the block's tile. So what it reads
 * is what was signed, whatever the database says, or it is a finding.
 */

/** The most blocks one minute prunes: about 10,000 uses, so a run costs the same whatever the backlog. */
const PRUNE_MOST = 40;
/**
 * The blocks one minute re-checks: 768 entries, so a walk of a log of a
 * million takes 1,303 minutes, under a day, and a minute reads the same
 * however long the log.
 */
const RECHECK = 3;
const DAY_MS = 24 * 60 * 60_000;
/** The most rows of each kind one minute deletes: a CI run leaves a session and a spent ID token, so 144,000 runs a day. */
const DELETE_MOST = 100;
/** An exchange refuses an ID token issued over an hour ago, so one spent two hours ago guards nothing. */
const SPENT_MS = 2 * 60 * 60_000;

/** A statement of the signer's, bounded as its own are. */
type Ask = <Row>(statement: SQL) => Promise<Row[]>;

/** Where in the log, by tree and block. */
type Block = { tree: Tree; block: number };
/**
 * Where the re-check goes on, when the walk it is in began, and where that
 * walk ends: each tree's size then, so that a log growing faster than it
 * reads does not keep it from coming round to the changes again.
 */
export type Walk = Block & { since: number; ends: Record<Tree, number> };

/**
 * A block as read: the bodies of its entries, and what of it is not there as
 * signed, each entry by the hash it was signed under, or the block by its
 * leaves when its tiles do not prove or none of its entries is there; and
 * its tile, once proven.
 */
type Held = { bodies: string[]; lost: string[]; tile?: Buffer };

/**
 * The blocks, in one statement: their entries and the tiles that prove
 * them, each by index. Held to `trees`, the signer's own.
 */
async function read(ask: Ask, trees: Record<Tree, Edge>, blocks: readonly Block[]): Promise<Held[]> {
  const ranges = blocks.map(({ tree, block }) => ({ kept: tree === 'kept', first: block * WIDTH, last: Math.min((block + 1) * WIDTH, trees[tree].size) - 1 }));
  // The block's own tile, which a proof of one leaf alone does not read, and those the proof reads.
  const tiles = blocks.flatMap(({ tree, block }) => [{ level: 0, index: block }, ...tilesFor((nodes) => inclusionProof(nodes, block * WIDTH, trees[tree].size))].map(({ level, index }) => sql`(${tree === 'kept'}, ${level}, ${index})`));
  // Lists of keys, not joins on a list: each one probe of an index, which the planner counts, where a join on a list
  // it cannot count reads all of a table or costs it a compilation.
  const rows = await ask<{ kept: boolean; level: number; place: number; body: string | null; hashes: Buffer | null }>(sql`
    SELECT l.kept, 0 AS level, l.leaf::float8 AS place, l.body, NULL::bytea AS hashes FROM log l
      WHERE ${sql.join(ranges.map(({ kept, first, last }) => sql`(l.kept = ${kept} AND l.leaf BETWEEN ${first} AND ${last})`), sql` OR `)}
    UNION ALL
    SELECT t.kept, t.level, t.number::float8, NULL, t.hashes FROM log_tiles t WHERE (t.kept, t.level, t.number) IN (${sql.join(tiles, sql`, `)})`);
  const stored = { kept: new Map<string, Buffer>(), aging: new Map<string, Buffer>() };
  const entries = { kept: new Map<number, string>(), aging: new Map<number, string>() };
  for (const row of rows) {
    const tree = row.kept ? 'kept' : 'aging';
    if (row.hashes === null) entries[tree].set(row.place, row.body!);
    else stored[tree].set(tileKey(row.level, row.place), Buffer.from(row.hashes));
  }
  return blocks.map(({ tree, block }, i): Held => {
    const { first, last } = ranges[i]!;
    const { size } = trees[tree];
    const tile = stored[tree].get(tileKey(0, block));
    let proven = false;
    try {
      proven = tile !== undefined && tile.length >= (last - first + 1) * HASH_SIZE && verifyInclusion(tile.subarray(0, HASH_SIZE), first, size, inclusionProof(nodesFrom(stored[tree]), first, size), trees[tree].root());
    } catch {
      // A tile on the way up is missing or short: not as signed.
    }
    const bodies = Array.from({ length: last - first + 1 }, (_, n) => entries[tree].get(first + n));
    if (!proven || bodies.every((body) => body === undefined)) return { bodies: [], lost: [`${tree} ${first}-${last}`] };
    const lost = bodies.flatMap((body, n) => {
      const hash = tile!.subarray(n * HASH_SIZE, (n + 1) * HASH_SIZE);
      return body !== undefined && leafHash(Buffer.from(body)).equals(hash) ? [] : [hash.toString('hex')];
    });
    return { bodies: bodies.filter((body) => body !== undefined), lost, tile };
  });
}

/**
 * The first use to keep, from `from`, the first kept now: past each block
 * whose every entry is there as signed, and older than the keep by its date
 * as signed. 40 blocks at most, and never the block of the tree's last
 * entry, which the check reads where the log ends. One block read first,
 * the rest only if it goes: most minutes have none to prune. With it, each
 * pruned block's tile as proven, by its SHA-256, hex: the delete takes only
 * the entries that hash to it, so a body swapped since this read stays,
 * and is never parsed.
 */
export async function pruned(ask: Ask, { keepUsesDays, now }: Signing, trees: Record<Tree, Edge>, from: number): Promise<{ to: number; tiles: string[] }> {
  const tiles: string[] = [];
  if (keepUsesDays === null) return { to: from, tiles };
  const before = now() - keepUsesDays * DAY_MS;
  const end = Math.floor((trees.aging.size - 1) / WIDTH);
  let block = from / WIDTH;
  for (const count of [1, PRUNE_MOST - 1]) {
    const next = Array.from({ length: Math.max(0, Math.min(block + count, end) - block) }, (_, n) => ({ tree: 'aging' as const, block: block + n }));
    if (next.length === 0) break;
    for (const held of await read(ask, trees, next)) {
      if (held.lost.length > 0 || held.bodies.some((body) => (JSON.parse(body) as Entry).at >= before)) return { to: block * WIDTH, tiles };
      tiles.push(createHash('sha256').update(held.tile!).digest('hex'));
      block += 1;
    }
  }
  return { to: block * WIDTH, tiles };
}

/**
 * The next slice of the walk, from `walk`: the kept tree, then the aging
 * one from its first use kept, each as far as it was when the walk began,
 * and round again, a walk a day at most. What it finds is `lost`, each
 * entry by the hash it was signed under, or a block by its leaves when its
 * tiles do not prove: said once a walk, while it stays so.
 */
export async function recheck(ask: Ask, now: number, trees: Record<Tree, Edge>, agingFrom: number, walk: Walk): Promise<{ found: Finding[]; walk: Walk }> {
  const blocks: Block[] = [];
  let { tree, block, since, ends } = walk;
  while (blocks.length < RECHECK) {
    if (tree === 'kept' && block === 0) {
      // A walk starts: not before a day after the last, so that a small log is not read, nor its findings said, every minute.
      if (now < since + DAY_MS) break;
      [since, ends] = [now, { kept: trees.kept.size, aging: trees.aging.size }];
    }
    block = Math.max(block, tree === 'aging' ? agingFrom / WIDTH : 0);
    if (block * WIDTH < ends[tree]) blocks.push({ tree, block: block++ });
    else [tree, block] = [tree === 'kept' ? 'aging' : 'kept', 0];
  }
  const held = blocks.length === 0 ? [] : await read(ask, trees, blocks);
  return { found: held.flatMap(({ lost }) => lost.map((of) => ({ found: 'lost' as const, of }))), walk: { tree, block, since, ends } };
}

/**
 * The rows that lapsed, the oldest first, a batch of each: credentials,
 * device logins and enrollment codes a day past their expiry, in one change
 * whose entry the signer holds to its mirror, as any other; an enrollment
 * code once no credential names it. Then, by a statement with no entry, the
 * rows that carry no MAC and that nothing reads again: ID tokens spent two
 * hours ago, MCP approvals a day past their expiry. The change's entry, if
 * it made one, waits to be signed: its hash.
 */
export async function expire(vault: Omit<Running, 'wake'>, ask: Ask): Promise<Buffer | null> {
  const at = vault.now();
  const before = sql`${new Date(at - DAY_MS).toISOString()}::timestamptz`;
  // By the expiry a row's MAC covers: one a writer moved back is not the vault's, and stays.
  const oldest = <T extends typeof credentials | typeof deviceLogins | typeof enrollmentCodes>(table: T, more = sql``) =>
    part(table, sql`${table.id} IN (SELECT e.id FROM ${table} e WHERE e.expires_at < ${before}${more} ORDER BY e.expires_at, e.id LIMIT ${DELETE_MOST})`);
  const read = { credentials: oldest(credentials), logins: oldest(deviceLogins), codes: oldest(enrollmentCodes, sql` AND NOT EXISTS (SELECT 1 FROM credentials c WHERE c.enrollment_id = e.id)`) };
  let hash: Buffer | null = null;
  await change({ ...vault, wake: (committed) => (hash = committed) }, {
    read,
    decide: ({ credentials: sessions, logins, codes }) => {
      const writes = [...sessions.map((row) => drop(credentials, row)), ...logins.map((row) => drop(deviceLogins, row)), ...codes.map((row) => drop(enrollmentCodes, row))];
      if (writes.length === 0) return { refused: 'none' };
      const objects = [...sessions.map(({ id }) => `credential:${id}`), ...logins.map(({ id }) => `device_login:${id}`), ...codes.map(({ id }) => `enrollment_code:${id}`)];
      return { writes, entry: { kept: false, action: 'upkeep.expire', actor: null, credential: null, request: null, ip: null, objects, detail: {} }, answer: null };
    },
  });
  await ask(sql`WITH spent AS (DELETE FROM spent_id_tokens WHERE hash IN (SELECT hash FROM spent_id_tokens WHERE spent_at < ${new Date(at - SPENT_MS).toISOString()}::timestamptz LIMIT ${DELETE_MOST})),
    approvals AS (DELETE FROM mcp_approvals WHERE id IN (SELECT id FROM mcp_approvals WHERE expires_at < ${before} LIMIT ${DELETE_MOST}))
    SELECT 1`);
  return hash;
}
