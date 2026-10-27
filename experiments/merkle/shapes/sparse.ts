import { randomBytes } from 'node:crypto';

import { HASH_SIZE, nodeHash, type Hash } from '../src/tree.ts';

/**
 * Proofs in trees too large to build (a year at 1,000 a second is 31.5
 * billion leaves). A proof's length depends only on the leaf's index and the
 * tree's size, by RFC 9162's recursion; its hashes can be anything. So a
 * random proof of the right length, and the root it implies, give a real
 * verification of a real-sized proof: what a verifier spends on it.
 */

/** The largest power of two strictly below n (n ≥ 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** RFC 9162 2.1.3.1: how many hashes PATH(m, D[n]) holds. */
export function inclusionLength(m: number, n: number): number {
  if (n <= 1) return 0;
  const k = split(n);
  return 1 + (m < k ? inclusionLength(m, k) : inclusionLength(m - k, n - k));
}

/** RFC 9162 2.1.4.1: how many hashes PROOF(m, D[n]) holds. */
export function consistencyLength(m: number, n: number): number {
  if (m === 0 || m === n) return 0;
  const sub = (m: number, n: number, whole: boolean): number => {
    if (m === n) return whole ? 0 : 1;
    const k = split(n);
    return 1 + (m <= k ? sub(m, k, whole) : sub(m - k, n - k, false));
  };
  return sub(m, n, true);
}

const random = (count: number): Hash[] => Array.from({ length: count }, () => randomBytes(HASH_SIZE));

export function sparseInclusion(m: number, n: number): { leaf: Hash; proof: Hash[] } {
  return { leaf: randomBytes(HASH_SIZE), proof: random(inclusionLength(m, n)) };
}

/** The root a verifier reaches from `leaf` at m in a tree of n with `proof` (RFC 9162 2.1.3.2's loop). */
export function inclusionRoot(leaf: Hash, m: number, n: number, proof: readonly Hash[]): Hash {
  let fn = m;
  let sn = n - 1;
  let r = leaf;
  for (const p of proof) {
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
  return r;
}

const isPowerOfTwo = (n: number) => n > 0 && 2 ** Math.round(Math.log2(n)) === n;

/** A random consistency proof from m to n leaves, and the two heads it implies (RFC 9162 2.1.4.2's loop). */
export function sparseConsistency(m: number, n: number): { first: Hash; second: Hash; proof: Hash[] } {
  const proof = random(consistencyLength(m, n));
  const path = isPowerOfTwo(m) ? [randomBytes(HASH_SIZE), ...proof] : proof;
  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0]!;
  let sr = path[0]!;
  for (const c of path.slice(1)) {
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
  return { first: fr, second: sr, proof };
}
