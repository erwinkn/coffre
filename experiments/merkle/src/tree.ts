import { createHash } from 'node:crypto';

/**
 * RFC 9162's Merkle tree (Certificate Transparency 2.0, the same tree as
 * RFC 6962), byte for byte: a leaf hashes as SHA-256(0x00 || data), a node
 * as SHA-256(0x01 || left || right), and a tree of n leaves splits at the
 * largest power of two below n. Go's golang.org/x/mod/sumdb/tlog and
 * transparency-dev's verifiers check what this produces (go/verify.go).
 *
 * Every hash here comes from `Nodes`, which answers for perfect subtrees
 * only (2^level leaves starting at index·2^level). Tiles store those; a
 * proof never needs another kind.
 */
export type Hash = Buffer;

export const HASH_SIZE = 32;

export function leafHash(data: Uint8Array): Hash {
  return createHash('sha256').update(LEAF).update(data).digest();
}

export function nodeHash(left: Hash, right: Hash): Hash {
  return createHash('sha256').update(NODE).update(left).update(right).digest();
}

const LEAF = Buffer.from([0]);
const NODE = Buffer.from([1]);

/** The hash of the perfect subtree of 2^level leaves starting at leaf index·2^level. */
export type Nodes = (level: number, index: number) => Hash;

/** The largest power of two strictly below n (n ≥ 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

const log2 = (n: number) => Math.round(Math.log2(n));

/** Whether n is a power of two. Not `n & (n - 1)`: JavaScript's bitwise operators cut to 32 bits, and a log passes 2^32 leaves in 50 days at 1,000 a second. */
const isPowerOfTwo = (n: number) => n > 0 && 2 ** log2(n) === n;

/** MTH(D[start:start+n]): the hash of any range, from the perfect subtrees it decomposes into. */
export function rangeHash(nodes: Nodes, start: number, n: number): Hash {
  if (n === 0) return createHash('sha256').digest();
  if (isPowerOfTwo(n) && start % n === 0) return nodes(log2(n), start / n);
  const k = split(n);
  return nodeHash(rangeHash(nodes, start, k), rangeHash(nodes, start + k, n - k));
}

/** The tree head: MTH of the first `size` leaves. */
export function treeHash(nodes: Nodes, size: number): Hash {
  return rangeHash(nodes, 0, size);
}

/** RFC 9162 2.1.3.1, PATH(m, D[n]): the inclusion proof of leaf m in the tree of n leaves, leaf to root. */
export function inclusionProof(nodes: Nodes, m: number, n: number): Hash[] {
  if (m < 0 || m >= n) throw new Error(`leaf ${m} is not in a tree of ${n}`);
  const path = (m: number, start: number, n: number): Hash[] => {
    if (n === 1) return [];
    const k = split(n);
    return m < k
      ? [...path(m, start, k), rangeHash(nodes, start + k, n - k)]
      : [...path(m - k, start + k, n - k), rangeHash(nodes, start, k)];
  };
  return path(m, 0, n);
}

/** RFC 9162 2.1.4.1, PROOF(m, D[n]): that the tree of m leaves is a prefix of the tree of n. */
export function consistencyProof(nodes: Nodes, m: number, n: number): Hash[] {
  if (m < 0 || m > n) throw new Error(`no consistency from ${m} to ${n}`);
  if (m === 0 || m === n) return [];
  const sub = (m: number, start: number, n: number, whole: boolean): Hash[] => {
    if (m === n) return whole ? [] : [rangeHash(nodes, start, n)];
    const k = split(n);
    return m <= k
      ? [...sub(m, start, k, whole), rangeHash(nodes, start + k, n - k)]
      : [...sub(m - k, start + k, n - k, false), rangeHash(nodes, start, k)];
  };
  return sub(m, 0, n, true);
}

/** RFC 9162 2.1.3.2: whether `proof` shows `leaf` at index m of the tree of n leaves whose head is `root`. */
export function verifyInclusion(leaf: Hash, m: number, n: number, proof: readonly Hash[], root: Hash): boolean {
  if (m >= n) return false;
  let fn = m;
  let sn = n - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.equals(root);
}

/** RFC 9162 2.1.4.2: whether `proof` shows the tree of m leaves (head `first`) a prefix of the tree of n (head `second`). */
export function verifyConsistency(m: number, n: number, first: Hash, second: Hash, proof: readonly Hash[]): boolean {
  if (m > n) return false;
  if (m === n) return proof.length === 0 && first.equals(second);
  if (m === 0) return proof.length === 0;
  let path = [...proof];
  if (isPowerOfTwo(m)) path = [first, ...path];
  if (path.length === 0) return false;
  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0]!;
  let sr = path[0]!;
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return fr.equals(first) && sr.equals(second) && sn === 0;
}

/** The reference: MTH over every leaf hash, by the RFC's recursion. For tests only. */
export function referenceHash(leaves: readonly Hash[]): Hash {
  if (leaves.length === 0) return createHash('sha256').digest();
  if (leaves.length === 1) return leaves[0]!;
  const k = split(leaves.length);
  return nodeHash(referenceHash(leaves.slice(0, k)), referenceHash(leaves.slice(k)));
}
