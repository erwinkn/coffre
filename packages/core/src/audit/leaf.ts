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
  const head = Buffer.alloc(12);
  head.writeBigUInt64BE(number, 0);
  head.writeUInt32BE(columns.length, 8);
  const parts: Buffer[] = [Buffer.from(`${LEAF_FORMAT}\n${tree}\n`, 'utf8'), head];
  for (const [i, value] of columns.entries()) {
    let tag: number;
    let bytes: Buffer;
    if (value === null) [tag, bytes] = [0, Buffer.alloc(0)];
    else if (value instanceof Uint8Array) [tag, bytes] = [1, Buffer.from(value)];
    else if (typeof value === 'string') {
      if (/[\uD800-\uDFFF]/u.test(value)) throw new Error(`column ${i} is not well-formed Unicode`);
      [tag, bytes] = [2, Buffer.from(value, 'utf8')];
    } else if (typeof value === 'bigint' || Number.isSafeInteger(value)) [tag, bytes] = [3, Buffer.from(value.toString(10), 'utf8')];
    else throw new Error(`column ${i} is not a whole number`);
    const header = Buffer.alloc(5);
    header.writeUInt8(tag, 0);
    header.writeUInt32BE(bytes.length, 1);
    parts.push(header, bytes);
  }
  return Buffer.concat(parts);
}

/** The leaf hash of an entry. */
export const entryLeaf = (tree: TreeName, number: bigint, columns: readonly LeafValue[]): Hash => leafHash(leafData(tree, number, columns));
