import type { AuditEntryView, RouteOutput } from '@coffre/client';

/**
 * What the audit page says of each entry it shows (docs/design/0.16.md,
 * "Pages"): `GET /audit` proves it against the head the vault signed, in
 * the same answer, and the page shows that, one state a row:
 *
 *   proven     the vault signed it as it is, where it is
 *   unproven   past the head: signed since the vault read it, or put
 *              there by a writer; the page cannot tell which, and a
 *              check against a newer head settles the first
 *   failed     within the head and not what it signed
 */
export type Proof = AuditEntryView['proof'];
export type Head = RouteOutput<'GET /audit'>['head'];

/** A batch's, or a read's: its worst entry's. */
export function proofOf(proofs: readonly Proof[]): Proof {
  return proofs.includes('failed') ? 'failed' : proofs.includes('unproven') ? 'unproven' : 'proven';
}

/**
 * The entries the page has seen proven, by the head that proved them: a
 * head is its size and signing time, which its MAC covers.
 */
export type Proved = Map<string, Set<number>>;

const headKey = (head: NonNullable<Head>) => `${head.size}@${head.signedAt}`;

/**
 * Each entry's proof as the page shows it: the answer's, except that one
 * proven before under this same head and now not is failed. Under one head
 * an entry proves or does not for good: only its tree and leaf, columns a
 * writer edits, can move it past the head, so the page never shows an entry
 * proven and later not proven against the same head. Another head is
 * another answer: one put back from before covers less, and the page shows
 * what it covers.
 */
export function shownProofs(proved: Proved, head: Head, entries: readonly AuditEntryView[]): Map<number, Proof> {
  const seen = head === null ? undefined : proved.get(headKey(head));
  return new Map(entries.map((entry) => [entry.seq, entry.proof === 'unproven' && seen?.has(entry.seq) ? 'failed' : entry.proof]));
}

/** Notes what an answer proved, under its head. */
export function remember(proved: Proved, head: Head, entries: readonly AuditEntryView[]): void {
  if (head === null) return;
  const key = headKey(head);
  const seen = proved.get(key) ?? new Set<number>();
  for (const entry of entries) if (entry.proof === 'proven') seen.add(entry.seq);
  proved.set(key, seen);
}
