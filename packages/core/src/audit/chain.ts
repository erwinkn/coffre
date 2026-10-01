import { createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

/**
 * The audit log's format: one chain, written by two authors, the app and the
 * vault (docs/design/single-database.md, question 6).
 *
 *   mac  = HMAC-SHA256(author's key, "coffre.audit.mac.v2"   ‖ prev_hash ‖ fields)
 *   hash = SHA-256(                  "coffre.audit.chain.v2" ‖ prev_hash ‖ fields ‖ mac)
 *
 * The MAC says which author wrote an entry: only the holder of its key can
 * make it. The hash is public: anyone who can read the table can check that
 * each entry follows the one before, MACs included, so a signed checkpoint
 * pins a prefix byte for byte. Because each MAC covers the previous hash, an
 * author can rewrite only its own entries since the other's last one.
 *
 * This authenticates what is retained, not its freshness: rolling back the
 * log and its head together needs no key. That limit is accepted (question 7).
 *
 * Both authors encode through this module, and test/vectors/audit-v2.json
 * pins the bytes, so they cannot drift apart. A change to what is encoded is
 * a new format version, never an edit of this one.
 */

/** Part of the format: a change to the encoding changes these. */
export const LOG_FORMAT = 'coffre.audit.v2';
const MAC_DOMAIN = Buffer.from('coffre.audit.mac.v2', 'utf8');
const CHAIN_DOMAIN = Buffer.from('coffre.audit.chain.v2', 'utf8');

/** Length of a chain hash, and of a MAC, in bytes. */
export const HASH_BYTES = 32;

/** The `prev_hash` of the first entry. */
export const GENESIS_HASH: Buffer = Buffer.alloc(HASH_BYTES, 0);

export type Author = 'app' | 'vault';

/**
 * Every field an entry's MAC and hash cover, in their order. Times are
 * milliseconds since the epoch, from the database's clock; sequence numbers
 * are bigints, encoded in decimal; `metadata` is JSON text, covered as
 * stored.
 */
export type LogFields = {
  seq: bigint;
  author: Author;
  keyId: string;
  occurredAt: number;
  actor: string;
  action: string;
  decision: string;
  code: string | null;
  subjectPrincipal: string | null;
  projectId: string | null;
  environmentId: string | null;
  secretId: string | null;
  secretVersionId: string | null;
  operationId: string | null;
  requestId: string | null;
  sourceIp: string | null;
  relatedSeq: bigint | null;
  metadata: string;
};

const FIELD_ORDER = [
  'seq',
  'author',
  'keyId',
  'occurredAt',
  'actor',
  'action',
  'decision',
  'code',
  'subjectPrincipal',
  'projectId',
  'environmentId',
  'secretId',
  'secretVersionId',
  'operationId',
  'requestId',
  'sourceIp',
  'relatedSeq',
  'metadata',
] as const satisfies readonly (keyof LogFields)[];

/**
 * The fields as bytes, injectively: each is length-prefixed, a null is
 * length -1, distinct from the empty string, and numbers are decimal text.
 * Strings contain Unicode scalar values: lone UTF-16 surrogates are refused,
 * not replaced on conversion to UTF-8. Undefined is not a wire value.
 */
export function encodeFields(fields: LogFields): Buffer {
  const parts: Buffer[] = [];
  for (const name of FIELD_ORDER) {
    const raw = fields[name];
    const header = Buffer.alloc(4);
    if (raw === undefined) throw new Error(`${name} cannot be undefined`);
    if (raw === null) {
      header.writeInt32BE(-1, 0);
      parts.push(header);
      continue;
    }
    if (typeof raw === 'number' && !Number.isSafeInteger(raw)) throw new Error(`${name} must be a whole number`);
    if (typeof raw === 'string' && /[\uD800-\uDFFF]/u.test(raw)) throw new Error(`${name} must be well-formed Unicode`);
    const value = Buffer.from(typeof raw === 'string' ? raw : raw.toString(10), 'utf8');
    header.writeInt32BE(value.length, 0);
    parts.push(header, value);
  }
  return Buffer.concat(parts);
}

/** A key one author MACs its entries with, and the id each entry records. */
export type LogKey = { author: Author; keyId: string; key: Buffer };

/**
 * An author's log key, derived from one of its secrets: `auditChainKey` for
 * the app. The id is a fingerprint of the key, so a rotation shows in every
 * entry, and an old key can be kept for verification by its id.
 */
export function deriveLogKey(author: Author, secret: Uint8Array): LogKey {
  if (secret.length < 32) throw new Error('a log key needs at least 32 bytes of secret');
  const key = Buffer.from(hkdfSync('sha256', secret, new Uint8Array(0), `coffre.audit.${author}.v2`, 32));
  const fingerprint = createHash('sha256').update(key).digest('hex').slice(0, 16);
  return { author, keyId: `${author}:${fingerprint}`, key };
}

/** The MAC of an entry, under its author's key. */
export function entryMac(key: Buffer, prevHash: Buffer, fields: LogFields): Buffer {
  checkHash(prevHash, 'prevHash');
  return createHmac('sha256', key).update(MAC_DOMAIN).update(prevHash).update(encodeFields(fields)).digest();
}

/** The public hash of an entry, which the next one chains to. */
export function entryHash(prevHash: Buffer, fields: LogFields, mac: Buffer): Buffer {
  checkHash(prevHash, 'prevHash');
  checkHash(mac, 'mac');
  return createHash('sha256').update(CHAIN_DOMAIN).update(prevHash).update(encodeFields(fields)).update(mac).digest();
}

/** An entry's MAC and hash, as `key` writes it after `prevHash`. */
export function sealEntry(key: LogKey, prevHash: Buffer, fields: LogFields): { mac: Buffer; hash: Buffer } {
  if (fields.author !== key.author || fields.keyId !== key.keyId) {
    throw new Error(`an entry by ${fields.author} under ${fields.keyId} cannot be sealed with ${key.keyId}`);
  }
  const mac = entryMac(key.key, prevHash, fields);
  return { mac, hash: entryHash(prevHash, fields, mac) };
}

export type StoredEntry = LogFields & { prevHash: Buffer; mac: Buffer; hash: Buffer };

export type ChainVerification =
  /** `authenticated` is below `entries` only for a `chainOnly` author's entries. */
  | { ok: true; entries: number; head: Buffer; nextSeq: bigint; authenticated: number }
  | { ok: false; failedAtSeq: bigint; reason: string };

/**
 * Check a run of entries, oldest first: that the numbers run on from
 * `startSeq` without a gap, that each links to the hash before it, that each
 * hash is its entry's, and that each entry carries a MAC from one of `keys`.
 *
 * An author whose key the verifier does not hold fails every entry it wrote,
 * unless it is named in `chainOnly`: then its entries are checked for their
 * place in the chain only, and `authenticated` counts the rest. That is a
 * partial verdict, for a caller that has the other author check its own
 * entries over the same prefix; the public chain alone proves nothing about
 * who wrote an entry, since anyone who can insert a row can link it.
 */
export function verifyEntries(
  entries: readonly StoredEntry[],
  {
    startSeq = 0n,
    startPrevHash = GENESIS_HASH,
    keys,
    chainOnly = [],
  }: { startSeq?: bigint; startPrevHash?: Buffer; keys: readonly LogKey[]; chainOnly?: readonly Author[] },
): ChainVerification {
  const authors = new Set(keys.map((key) => key.author));
  let expectedSeq = startSeq;
  let previous = startPrevHash;
  let authenticated = 0;
  for (const entry of entries) {
    const fail = (reason: string) => ({ ok: false as const, failedAtSeq: entry.seq, reason });
    if (entry.seq !== expectedSeq) return fail(`sequence gap: expected seq ${expectedSeq}, found ${entry.seq}`);
    if (!equal(entry.prevHash, previous)) return fail('prev_hash does not match the entry before');
    if (entry.mac.length !== HASH_BYTES || !equal(entryHash(entry.prevHash, entry, entry.mac), entry.hash)) {
      return fail('hash does not match the entry');
    }
    if (authors.has(entry.author)) {
      const key = keys.find((candidate) => candidate.keyId === entry.keyId && candidate.author === entry.author);
      if (key === undefined) return fail(`written under ${entry.keyId}, a key this verifier does not hold`);
      if (!equal(entryMac(key.key, entry.prevHash, entry), entry.mac)) return fail(`not written by the ${entry.author}: its MAC does not match`);
      authenticated += 1;
    } else if (!chainOnly.includes(entry.author)) {
      return fail(`written as the ${entry.author}, whose keys this verifier does not hold`);
    }
    previous = entry.hash;
    expectedSeq = entry.seq + 1n;
  }
  return { ok: true, entries: entries.length, head: previous, nextSeq: expectedSeq, authenticated };
}

function checkHash(value: Buffer, what: string): void {
  if (value.length !== HASH_BYTES) throw new Error(`${what} must be ${HASH_BYTES} bytes, got ${value.length}`);
}

function equal(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
