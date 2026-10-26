import { append, proveNumber, type Checkpointer, type Db, type Fields, type InclusionProof, type Keys } from './log.ts';

/**
 * A change (a revoke, a grant, a role edit), under the rule Erwin approved for
 * W209: it answers only once its entry is sealed and, where witnesses are set
 * up, witnessed. Until then a database writer could delete the entry and put
 * the member row back (W208's rollback), and the admin who saw "revoked" would
 * never learn otherwise. The change asks the checkpointer to seal now (on
 * Workers, one call to its Durable Object) rather than waiting for the next
 * tick, and answers with the signed head and the inclusion proof: the admin's
 * client can check both, and keep them.
 *
 * A witness slower than the deadline does not hold the answer: the change has
 * committed and is in force either way, so it answers with `witnessed: false`,
 * which the UI shows and an alert repeats, and the checkpointer keeps
 * publishing. Without witnesses (R40: the anchor is an optional plugin), a
 * change waits for the seal alone, and the undo window stays open to whoever
 * can also reset the checkpointer's own memory.
 */
export type ChangeAnswer = {
  number: string; witnessed: boolean; failures: string[]; proof: InclusionProof;
  commitMs: number; sealMs: number; totalMs: number;
};

export async function changeAndSeal(db: Db, keys: Keys, cp: Checkpointer, f: Fields, witnessTimeoutMs = 2000): Promise<ChangeAnswer> {
  const t0 = performance.now();
  const number = await append(db, keys, { ...f, kind: 'change' });
  const t1 = performance.now();
  const sealed = await cp.sealThrough(number, witnessTimeoutMs);
  const t2 = performance.now();
  const proof = (await proveNumber(db, number))!;
  return { number, witnessed: sealed.witnessed, failures: sealed.failures, proof, commitMs: t1 - t0, sealMs: t2 - t1, totalMs: performance.now() - t0 };
}
