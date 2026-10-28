import { pairSigners, pairVerifiers, verifyLog, type LogEntry, type PairNotes, type PairVerifiers } from '@coffre/core/merkle';
import type { TreeVerification } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';

import { loggedChange } from './changes.ts';
import { logOrigin } from './checkpointer.ts';
import { authentic, logMacKey, retentionCut } from './log-entry.ts';
import { purposeOf } from './log-replay.ts';
import { logStore } from './log-store.ts';
import { requestsUnique } from './store.ts';

/**
 * 0.15's verifier (docs/design/0.15-plan.md, PR 8): what holds 0.15's log
 * to itself, for the audit page, `coffre verify instance` and conformance,
 * on every visit (R25), and keeps nothing between calls. It checks the
 * newest signed pair, its signatures and the pairs held outside (the
 * signer's memory), then every entry above it by its MAC and its request:
 * a tick's worth of entries, whatever the log's size, in four statements,
 * and never more than `ABOVE_NEWEST` of them.
 *
 * Below the newest pair, the pair vouches for what it sealed: it is not
 * walked again. A row a decision reads is held to its object's newest
 * change by every use (decide.ts, `stale`), never by this check, which
 * reads no row. What is not checked, by design (D145): an edit a database
 * writer makes to old entries, or to rows nobody uses, until an offline
 * scan exists; the signed pairs let one rebuild the trees later without the
 * MAC key. There is no walk of the whole log on a request: its cost is
 * shaped by what the database holds, which its writer chooses, and a
 * Worker's call has a limit on its CPU time. Nor can this check see an
 * entry deleted or reordered before its tick (R51's window; a change
 * answers only once sealed, so this is a use's).
 */

/** The keys a check needs: the trees' public keys, and the entries' MAC key. */
export type VerifierKeys = { verifiers: PairVerifiers; mac: Buffer };

/** The verifier's keys from the vault's first signing seed, as the checkpointer has them (log-checkpointer.ts). */
export async function verifierKeys(seeds: readonly Uint8Array[]): Promise<VerifierKeys> {
  const seed = seeds[0]!;
  const signers = await pairSigners(await logOrigin(seed), seed);
  return {
    verifiers: await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey }),
    mac: logMacKey(seed),
  };
}

export type VerifyOptions = {
  /**
   * Pairs held outside the database: the signer's memory, a witness's
   * (`VaultOptions.heldOutside`). Each check must reach each: a database
   * rolled back whole to an earlier pair, rows with it, otherwise passes
   * until the signer's next tick refuses it.
   */
  anchors?: readonly PairNotes[];
};

/**
 * The most entries above the newest pair a check reads: four ticks' worth
 * at R44's 1,000 uses a second, 14 ms measured on a developer's machine
 * (verifier-cost.test.ts). More is a checkpointer behind, or rows a writer
 * planted, and is said (`capped`), never read (reviews r1, r4).
 */
export const ABOVE_NEWEST = 2_000;

/** The verdict as the vault gives it, and whether the database ended behind a pair held outside (`Verdict.behind`). */
export type Walked = Extract<TreeVerification, { kept: true }> & { behind: boolean };

export async function verifyTrees(db: Database, keys: VerifierKeys, options: VerifyOptions): Promise<Walked> {
  const walked = await db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const store = logStore(tx);
    // From the newest pair, which its signatures and the pairs held outside vouch for. It walks no use below it, so
    // retention's cut is not its to check: the newest pair and the signer's are at or above every cut.
    const newest = await store.newest();
    // Each entry's request, seen once (RequestIdChecked): a change's by its id, a use's by its time and id, which its MAC
    // covers. A copy below the start is what the database's unique indexes refuse, which every check holds to standing.
    const requests = new Set<string>();
    const macHolds = authentic(keys.mac);
    const check = (entry: LogEntry): string | null => {
      if (!macHolds(entry)) return 'its MAC does not hold';
      const request = entry.tree === 'changes' ? `c:${String(entry.columns[1])}` : `u:${entry.at}:${String(entry.columns[1])}`;
      if (requests.has(request)) return 'a second entry under the request of another: a replay';
      requests.add(request);
      return malformed(entry);
    };
    const verdict = await verifyLog(store, {
      verifiers: keys.verifiers,
      check,
      ...(newest === null ? {} : { newest }),
      ...(options.anchors === undefined ? {} : { anchors: options.anchors }),
      above: ABOVE_NEWEST,
    });
    const problems = [...verdict.problems];
    if (!(await requestsUnique(tx))) problems.push('the indexes that keep each request to one entry are gone: a copy of an entry would pass');
    return { verdict, problems };
  }, SNAPSHOT);
  const { verdict, problems } = walked;
  const head = verdict.headPair;
  return {
    kept: true,
    ok: problems.length === 0 && !verdict.capped,
    problems,
    // The genesis pair seals nothing and is signed at time 0: no checkpoint yet.
    checkpoint: head === null || head.upto === 0n ? null : { upto: head.upto.toString(), at: head.at },
    unsealed: verdict.unsealed,
    capped: verdict.capped,
    behind: verdict.behind,
  };
}

/**
 * Why an entry is none a release writes, from the columns its tree seals
 * (log-entry.ts): a change whose payload names no object, or another than
 * its own; a use of no purpose. Null for one that reads, a retention
 * change, the log's own, included.
 */
function malformed(entry: LogEntry): string | null {
  const c = entry.columns;
  if (retentionCut(entry) !== null) return null;
  if (entry.tree === 'changes') {
    // [at, request, object, actor, payload, seal, mac]
    const [object, payload, seal] = [c[2], c[4], c[5]];
    let change = null;
    try {
      if (typeof object === 'string' && typeof payload === 'string' && (seal === null || seal instanceof Uint8Array)) {
        change = loggedChange({ number: entry.number, at: entry.at, object, payload, seal: seal === null ? null : Buffer.from(seal) });
      }
    } catch {}
    return change === null ? 'a change whose payload names no object, or another than its own' : null;
  }
  // [at, request, credential, secret, purpose, place, mac]
  const [credential, secret, code, place] = [c[2], c[3], c[4], c[5]];
  const purpose = typeof code === 'number' ? purposeOf(code) : null;
  return purpose === null || typeof credential !== 'string' || typeof secret !== 'string' || (place !== null && typeof place !== 'string') ? 'a use no release writes' : null;
}
