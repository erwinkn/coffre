import { openPair, verifyLog, type LogEntry, type PairNotes, type StoredPair } from '@coffre/core/merkle';
import type { TreeVerification } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';

import { loggedChange } from './changes.ts';
import { entryVouched, ringOf, signedUnder, type VerifierKeys } from './keyring.ts';
import { authentic, retentionCut, rotationOf } from './log-entry.ts';
import { purposeOf } from './log-replay.ts';
import { logStore } from './log-store.ts';
import { requestsUnique } from './store.ts';

/**
 * 0.15's verifier (docs/design/0.15-plan.md, PR 8): what holds 0.15's log
 * to itself, for the audit page, `coffre verify instance` and conformance,
 * on every visit (R25), and keeps nothing between calls. It checks the
 * newest signed pair, its signatures and the pairs held outside (the
 * signer's memory), then every entry above it by its MAC and its request:
 * a tick's worth of entries, whatever the log's size, in three statements,
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
 *
 * Across a rotation of the vault's signing key (T168, formal/Rotation.tla):
 * the newest pair may be under a key the vault replaced while the log moves
 * on from it, never at or past that key's rotation (RotationProbed), nor
 * at or past a pair held outside under the current key (AnchorKeyHeld); above
 * the newest pair, a replaced key's entry counts below its rotation, or
 * while there is none yet and the newest pair is under it (PendingAccepted,
 * BoundaryChecked, KeyringBound: keyring.ts), whichever key the newest
 * pair's signatures hold under (SignerVerified).
 */

export { verifierKeys, type KeyCheck, type VerifierKeys } from './keyring.ts';

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
 * The most entries above the newest pair a check reads: a bound on its work
 * (a defensive bound, W331's limits audit, #18), not on a rate. More is a
 * checkpointer behind, or rows a writer planted, and is said (`capped`),
 * never read (reviews r1, r4).
 *
 * Its budget, a policy: the check at the cap within 20 ms of a Worker's CPU,
 * R27's p99 bound, at the median, and at about that bound at p90; only a
 * log past honest operation reaches the cap. Not at p99, an exception to
 * R27: 40 checks show none, and their most at 1,000 was 27 to 42 ms; a cap
 * that held the most under 20 ms would sit below the floor (the most at 500
 * was 15 to 24 ms).
 * The rest of the audit page (the app's render, 0.14's chain) is not in it.
 * Measured on 2026-11-06 with test/bench/verifier.ts, the cap lifted: local
 * workerd, its isolate's thread less a request that does nothing, Postgres
 * 16.14 on Debian, an AMD EPYC 9454P shared with other work (load 19 to 33),
 * 50,000 uses sealed below, the median of three runs of 40 checks: 4.3 ms at
 * 0 entries (a new connection, its login and three statements), 8.1 at 250,
 * 11.3 at 500, 17.0 at 1,000 (p90 20.2), 31.4 at 2,000. A line through the
 * medians (4.5 ms fixed, 13.4 µs an entry) fits 1,150 in 20 ms; 1,000 is
 * below it, where the p90 reaches 20 ms (20.0 to 20.8 in the three runs). V8's helper threads (concurrent GC,
 * compilation) add to the tail, 38 ms at p90 at 1,000 with them; Cloudflare
 * does not say whether it counts them. Of an entry's cost, HMAC-SHA256 is
 * 3.4 µs and the encoding of its MAC data 3.1 µs; reading the row (some 144
 * bytes on the wire) most of the rest. Memory does not bind: some 300 bytes
 * of heap an entry held while checked (Node), 0.3 MB at the cap, beside a
 * Worker's 128 MB.
 *
 * Its floor, a check of the budget's answer, not its source: an honest log
 * holds a tick's worth above the pair (`TICK_MS`), 500 entries at R44's
 * 1,000 uses a second, 1,000 when one tick is late; a cap below that would
 * call a checkpointer on time behind. On Workers Free (10 ms an invocation)
 * a check past some 400 entries fails instead (the page: "Sealed log not
 * checked"), which a burst of uses or a late tick can bring; the cap does
 * not change that.
 */
export const ABOVE_NEWEST = 1_000;

/** The verdict as the vault gives it, and whether the database ended behind a pair held outside (`Verdict.behind`). */
export type Walked = Extract<TreeVerification, { kept: true }> & { behind: boolean };

export async function verifyTrees(db: Database, keys: VerifierKeys, options: VerifyOptions): Promise<Walked> {
  const walked = await db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const store = logStore(tx);
    // From the newest pair, which its signatures and the pairs held outside vouch for. It walks no use below it, so
    // retention's cut is not its to check: the newest pair and the signer's are at or above every cut.
    const newest = await store.newest();
    const keyed = await underKeys(store, keys, newest, options.anchors ?? []);
    // Each entry's request, seen once (RequestIdChecked): a change's by its id, a use's by its time and id, which its MAC
    // covers. A copy below the start is what the database's unique indexes refuse, which every check holds to standing.
    const requests = new Set<string>();
    const check = (entry: LogEntry): string | null => {
      const refused = keyed.vouch(entry);
      if (refused !== null) return refused;
      const request = entry.tree === 'changes' ? `c:${String(entry.columns[1])}` : `u:${entry.at}:${String(entry.columns[1])}`;
      if (requests.has(request)) return 'a second entry under the request of another: a replay';
      requests.add(request);
      return malformed(entry);
    };
    const verdict = await verifyLog(store, {
      verifiers: [keys.current, ...keys.previous].map((key) => key.verifiers),
      check,
      ...(newest === null ? {} : { newest }),
      ...(options.anchors === undefined ? {} : { anchors: options.anchors }),
      above: ABOVE_NEWEST,
    });
    const problems = [...keyed.problems, ...verdict.problems];
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
 * The key the newest pair is under, held to the rotations (T168; keyring.ts,
 * the rule every reader holds to): a key the vault replaced is taken only
 * below its own rotation (RotationProbed), and never at or above a pair held
 * outside under the current key (AnchorKeyHeld); and which keys vouch for an
 * entry above it, each previous one below its own rotation whatever key the
 * newest pair is under (KeyringBound: a tick seals its window in parts). The
 * newest pair's key is the one its signatures hold under (SignerVerified).
 * The rotations are read in the check's own snapshot, and only when the
 * vault holds a replaced key: a statement more for a deployment that rotated.
 * They are not capped as the entries above the newest pair are: an honest
 * log has one per key the vault has replaced, so only a writer planting rows
 * of the key object grows them, and that writer can deny a check in cheaper
 * ways; a cap would turn its slow check into a refused one, no safer (Muse's
 * review r8).
 */
async function underKeys(
  store: ReturnType<typeof logStore>,
  keys: VerifierKeys,
  newest: StoredPair | null,
  anchors: readonly PairNotes[],
): Promise<{ problems: string[]; vouch: (entry: LogEntry) => string | null }> {
  const problems: string[] = [];
  if (keys.previous.length === 0) {
    const current = authentic(keys.current.mac);
    return { problems, vouch: (entry) => (current(entry) ? null : 'its MAC does not hold') };
  }
  const under = newest === null ? null : await signedUnder(newest.notes, [keys.current, ...keys.previous]);
  const ring = ringOf(keys, await store.rotations(), under);
  if (newest !== null && under !== null && under !== keys.current) {
    const retired = ring.previous.find((p) => p.key === under)!.until;
    if (newest.upto >= retired) problems.push(`checkpoint ${newest.upto}: under ${under.origin}, at or past the rotation that retired it (${retired})`);
    for (const notes of anchors) {
      // The held pair's own place, from the pair its signatures open: one not under the current key is no anchor here.
      // At its very place too, as the signer refuses it: the walk takes a pair with the held one's heads, time and floor
      // for that pair, whichever key signed it (Muse's review r7 of #444).
      const at = (await openPair(notes, keys.current.verifiers))?.upto;
      if (at !== undefined && at <= newest.upto) problems.push(`checkpoint ${newest.upto}: under ${under.origin}, a replaced key, at or past the pair held outside under the current key (up to ${at})`);
    }
  }
  return {
    problems,
    vouch(entry) {
      const vouched = entryVouched(ring, entry);
      return vouched === 'held' ? null : vouched === 'past' ? 'under a key the log moved on from, past its rotation' : 'its MAC does not hold';
    },
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
  if (retentionCut(entry) !== null || rotationOf(entry) !== null) return null;
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
