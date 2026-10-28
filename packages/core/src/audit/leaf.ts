import type { TreeName } from './pair.ts';
import { MAX_NUMBER } from './note.ts';
import { leafHash, type Hash } from './tree.ts';

/**
 * A leaf is a whole entry: its tree, its number, then every column of its row
 * in the table's order, its MAC included. The number is sealed with the
 * entry, so a sealed entry cannot be renumbered, and the tree is too, so an
 * entry moved from one tree to the other is no longer its leaf. Anyone who
 * holds the public keys can check rows against the trees; the MAC key matters
 * only until an entry is sealed.
 *
 *   "coffre.audit.leaf.v1" 0x0a tree 0x0a number(8 bytes, big-endian) count(4)
 *   then per column: tag(1) length(4) bytes
 *     tag 0 null (length 0), 1 bytes, 2 text (UTF-8), 3 integer (decimal text)
 *
 * Every column is tagged and length-prefixed, so the encoding is injective:
 * no two rows share their bytes, whatever their values. A change to it is a
 * new format, never an edit of this one (test/vectors/audit-tree.json pins it).
 */
export const LEAF_FORMAT = 'coffre.audit.leaf.v1';

export type LeafValue = Uint8Array | string | bigint | number | null;

export function leafData(tree: TreeName, number: bigint, columns: readonly LeafValue[]): Buffer {
  if (number < 0n || number > MAX_NUMBER) throw new Error(`entry number ${number} is out of range`);
  return encode(`${LEAF_FORMAT}\n${tree}\n`, number, columns);
}

/**
 * What an entry's MAC covers: its tree and every column but its number,
 * which the database takes, and the MAC itself, the same tagged encoding as
 * a leaf's. The tree is in it (Seal.tla's KindInMac): a change moved into
 * the uses table before its tick would otherwise be sealed into the uses
 * tree, and pruned with the uses.
 *
 *   "coffre.log.mac.v1" 0x0a tree 0x0a column count(4), then the columns as a leaf's
 */
export const MAC_FORMAT = 'coffre.log.mac.v1';

export function macData(tree: TreeName, columns: readonly LeafValue[]): Buffer {
  return encode(`${MAC_FORMAT}\n${tree}\n`, null, columns);
}

/**
 * The prefix, the number if any (8 bytes), the column count, then each
 * column tagged and length-prefixed: sized first, then written into one
 * buffer, which a walk does for every entry it checks.
 */
function encode(prefix: string, number: bigint | null, columns: readonly LeafValue[]): Buffer {
  const tags: number[] = [];
  const values: (Uint8Array | string | null)[] = [];
  let size = Buffer.byteLength(prefix, 'utf8') + (number === null ? 0 : 8) + 4;
  for (const [i, value] of columns.entries()) {
    let tag: number;
    let bytes: Uint8Array | string | null;
    if (value === null) [tag, bytes] = [0, null];
    else if (value instanceof Uint8Array) [tag, bytes] = [1, value];
    else if (typeof value === 'string') {
      if (/[\uD800-\uDFFF]/u.test(value)) throw new Error(`column ${i} is not well-formed Unicode`);
      [tag, bytes] = [2, value];
    } else if (typeof value === 'bigint' || Number.isSafeInteger(value)) [tag, bytes] = [3, value.toString(10)];
    else throw new Error(`column ${i} is not a whole number`);
    tags.push(tag);
    values.push(bytes);
    size += 5 + (bytes === null ? 0 : typeof bytes === 'string' ? Buffer.byteLength(bytes, 'utf8') : bytes.length);
  }
  const out = Buffer.allocUnsafe(size);
  let at = out.write(prefix, 0, 'utf8');
  if (number !== null) at = out.writeBigUInt64BE(number, at);
  at = out.writeUInt32BE(columns.length, at);
  for (const [i, bytes] of values.entries()) {
    at = out.writeUInt8(tags[i]!, at);
    const length = bytes === null ? 0 : typeof bytes === 'string' ? out.write(bytes, at + 4, 'utf8') : (out.set(bytes, at + 4), bytes.length);
    at = out.writeUInt32BE(length, at) + length;
  }
  return out;
}

/** The leaf hash of an entry. */
export const entryLeaf = (tree: TreeName, number: bigint, columns: readonly LeafValue[]): Hash => leafHash(leafData(tree, number, columns));
