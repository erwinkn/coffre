import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Tamper-evidence for the audit log.
 *
 * CDR (EU) 2024/1774 Article 12(2)(d) requires measures protecting log
 * information against "tampering, deletion, and unauthorised access". Revoking
 * UPDATE and DELETE from the application's database role is necessary but not
 * sufficient: the migration role, the database owner, and anyone with the
 * Postgres superuser can still rewrite history.
 *
 * We had hoped Scaleway Key Manager would provide an independent trail the
 * application could not touch, but Scaleway Audit Trail logs only Key Manager
 * management operations (CreateKey, RotateKey, ...) and no Decrypt at all.
 * So the chain below carries that load instead.
 *
 * Each row commits to the row before it. Changing retained entries or their
 * order breaks the chain, and repairing it requires the chain key, which
 * lives outside the database. This authenticates what is retained, not its
 * freshness: rolling back both the log and its head needs no key. A separate
 * checkpoint can anchor a prefix; the tail since it remains open to rollback.
 */

/** Length of a chain hash, in bytes (SHA-256). */
export const CHAIN_HASH_BYTES = 32;

/** The `prev_hash` of the first row in a chain. */
export const GENESIS_HASH: Buffer = Buffer.alloc(CHAIN_HASH_BYTES, 0);

/**
 * The fields of an audit row that are covered by the chain.
 *
 * Order is part of the format. Adding a field means appending it here and
 * bumping the version prefix, never inserting it in the middle.
 */
export type ChainedAuditRow = {
  seq: bigint;
  occurredAt: string;
  actorType: string;
  actorId: string;
  action: string;
  decision: string;
  projectId: string | null;
  environmentId: string | null;
  secretId: string | null;
  bundleId: string | null;
  requestId: string | null;
  sourceIp: string | null;
  metadata: string;
};

const CHAIN_VERSION = 'coffre.audit.v1';

const FIELD_ORDER = [
  'seq',
  'occurredAt',
  'actorType',
  'actorId',
  'action',
  'decision',
  'projectId',
  'environmentId',
  'secretId',
  'bundleId',
  'requestId',
  'sourceIp',
  'metadata',
] as const satisfies readonly (keyof ChainedAuditRow)[];

/**
 * Serialise a row injectively.
 *
 * Every field is length-prefixed, so no two distinct rows can produce the same
 * bytes regardless of what the values contain. A `null` is encoded as length
 * -1, which is distinct from the empty string.
 */
function canonicalise(row: ChainedAuditRow): Buffer {
  const parts: Buffer[] = [Buffer.from(CHAIN_VERSION, 'utf8')];

  for (const field of FIELD_ORDER) {
    const raw = row[field];
    const header = Buffer.alloc(4);

    if (raw === null || raw === undefined) {
      header.writeInt32BE(-1, 0);
      parts.push(header);
      continue;
    }

    const value = Buffer.from(typeof raw === 'bigint' ? raw.toString(10) : raw, 'utf8');
    header.writeInt32BE(value.length, 0);
    parts.push(header, value);
  }

  return Buffer.concat(parts);
}

/** Compute the chain hash for a row, given the previous row's hash. */
export function chainHash(
  chainKey: Buffer,
  prevHash: Buffer,
  row: ChainedAuditRow,
): Buffer {
  if (prevHash.length !== CHAIN_HASH_BYTES) {
    throw new Error(`prevHash must be ${CHAIN_HASH_BYTES} bytes, got ${prevHash.length}`);
  }
  return createHmac('sha256', chainKey)
    .update(prevHash)
    .update(canonicalise(row))
    .digest();
}

export type ChainVerification =
  | { ok: true; rows: number; head: Buffer }
  | { ok: false; failedAtSeq: bigint; reason: string };

/**
 * Verify a contiguous run of audit rows.
 *
 * `rows` must be ordered by `seq` ascending and start from `startPrevHash`
 * (GENESIS_HASH for the very beginning of the log).
 */
export function verifyChain(
  chainKey: Buffer,
  rows: readonly (ChainedAuditRow & { prevHash: Buffer; hash: Buffer })[],
  startPrevHash: Buffer = GENESIS_HASH,
): ChainVerification {
  let expectedPrev = startPrevHash;
  let expectedSeq: bigint | null = null;

  for (const row of rows) {
    if (expectedSeq !== null && row.seq !== expectedSeq) {
      return {
        ok: false,
        failedAtSeq: row.seq,
        reason: `sequence gap: expected seq ${expectedSeq}, found ${row.seq}`,
      };
    }
    if (row.prevHash.length !== CHAIN_HASH_BYTES || !equalHash(row.prevHash, expectedPrev)) {
      return {
        ok: false,
        failedAtSeq: row.seq,
        reason: 'prev_hash does not match the preceding row',
      };
    }

    const recomputed = chainHash(chainKey, row.prevHash, row);
    if (!equalHash(recomputed, row.hash)) {
      return {
        ok: false,
        failedAtSeq: row.seq,
        reason: 'row hash does not match its contents',
      };
    }

    expectedPrev = row.hash;
    expectedSeq = row.seq + 1n;
  }

  return { ok: true, rows: rows.length, head: expectedPrev };
}

function equalHash(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
