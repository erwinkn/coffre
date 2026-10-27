// W212: proofs, witness checks and walks, for each tree shape, at a day and a
// year of log (1,000 entries a second, 500 ms ticks). Sizes come from RFC
// 9162's recursion (sparse.ts); every verification time is a real verification
// of a proof of that size, hashed in this process. Chains are walked link by
// link: up to 200,000 links, or all of a year's with --chain-year.
//
//   node experiments/merkle/shapes/proofs.ts [--chain-year]
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

import { signerFrom, verifierFrom, signNote, checkpointBody, openNote } from '../src/note.ts';
import { Edge } from '../src/tiles.ts';
import { leafHash, verifyConsistency, verifyInclusion, type Hash } from '../src/tree.ts';
import { link, LINK_BYTES, Mmr } from './shapes.ts';
import { consistencyLength, inclusionLength, inclusionRoot, sparseConsistency, sparseInclusion } from './sparse.ts';

const { values } = parseArgs({ options: { 'chain-year': { type: 'boolean', default: false }, 'walk-leaves': { type: 'string', default: '10000000' } } });

const RATE = 1000;
const TICK = 500;
const DAY = 86_400 * RATE;
const YEAR = 365 * DAY;
const TICKS_PER_SECOND = RATE / TICK;
/** Changes per entry: one a second at 1,000 entries a second, a heavy admin load (the stress case for `split`). */
const CHANGE_RATE = 0.001;
const AGES = { '1 min': 60, '1 day': 86_400, '1 year': 365 * 86_400 } as const;

/** Microseconds to run `f`, best of a few rounds of `n` runs (what one run costs, hot). */
function micros(f: () => unknown, n = 2000): number {
  let best = Infinity;
  for (let round = 0; round < 5; round += 1) {
    const t0 = performance.now();
    for (let i = 0; i < n; i += 1) f();
    best = Math.min(best, ((performance.now() - t0) * 1000) / n);
  }
  return best;
}

/** One inclusion proof, of leaf m in a tree of n: its hashes and what verifying it costs. */
function inclusion(m: number, n: number) {
  const { leaf, proof } = sparseInclusion(m, n);
  const root = inclusionRoot(leaf, m, n, proof);
  if (!verifyInclusion(leaf, m, n, proof, root)) throw new Error(`inclusion ${m}/${n}`);
  return { hashes: proof.length, us: micros(() => verifyInclusion(leaf, m, n, proof, root)) };
}

function consistency(m: number, n: number) {
  if (m === n || m === 0) return { hashes: 0, us: 0 };
  const { first, second, proof } = sparseConsistency(m, n);
  if (!verifyConsistency(m, n, first, second, proof)) throw new Error(`consistency ${m}/${n}`);
  return { hashes: proof.length, us: micros(() => verifyConsistency(m, n, first, second, proof)) };
}

type Cost = { hashes: number; us: number; bytes?: number; note?: string };
const sum = (...parts: Cost[]): Cost => ({ hashes: parts.reduce((s, p) => s + p.hashes, 0), us: parts.reduce((s, p) => s + p.us, 0) });

/** Walks `links` chain links from a random start: what a chain verifier does between two heads. */
function walkChain(links: number): Cost {
  let h: Hash = randomBytes(32);
  const root = randomBytes(32);
  const t0 = performance.now();
  for (let i = 0; i < links; i += 1) h = link(h, root, TICK, i * TICK);
  return { hashes: links, us: (performance.now() - t0) * 1000, bytes: links * LINK_BYTES };
}

const results: Record<string, Record<string, Cost>> = {};
const put = (shape: string, what: string, c: Cost) => {
  (results[shape] ??= {})[what] = { ...c, bytes: c.bytes ?? c.hashes * 32 };
};

// The log at a year, the newest head at N.
for (const [label, N] of [['year', YEAR]] as const) {
  const ticks = N / TICK;
  const changes = Math.round(N * CHANGE_RATE);
  const uses = N - changes;
  // `day`: the log is at noon of its last day, which holds half a day; earlier days are closed.
  const closed = Math.max(1, Math.floor(N / DAY));
  const today = DAY / 2;
  for (const [age, seconds] of Object.entries(AGES)) {
    if (seconds * RATE > N) continue;
    const back = seconds * RATE;
    put('one', `${label}: inclusion ${age}`, inclusion(Math.max(0, N - back), N));
    put('split', `${label}: inclusion ${age} (use)`, inclusion(Math.max(0, uses - Math.round(back * (1 - CHANGE_RATE))), uses));
    put('split', `${label}: inclusion ${age} (change)`, inclusion(Math.max(0, changes - Math.round(back * CHANGE_RATE)), changes));
    // In today's tree (signed directly), or in a closed day's tree plus that day's place in the top tree.
    if (seconds * RATE <= today) put('day', `${label}: inclusion ${age}`, inclusion(today - back, today));
    else {
      const daysBack = Math.min(closed - 1, Math.floor((back - today) / DAY));
      put('day', `${label}: inclusion ${age}`, sum(inclusion(DAY / 2, DAY), inclusion(closed - 1 - daysBack, closed)));
    }
    const k = Math.max(0, ticks - seconds * TICKS_PER_SECOND);
    put('tick', `${label}: inclusion ${age}`, sum(inclusion(TICK / 2, TICK), inclusion(k, ticks)));
    const chain = walkChain(Math.min(seconds * TICKS_PER_SECOND, 200_000));
    const scale = (seconds * TICKS_PER_SECOND) / Math.min(seconds * TICKS_PER_SECOND, 200_000);
    const batch = inclusion(TICK / 2, TICK);
    put('chain', `${label}: inclusion ${age}`, {
      hashes: batch.hashes + seconds * TICKS_PER_SECOND, us: batch.us + chain.us * scale, bytes: batch.hashes * 32 + seconds * TICKS_PER_SECOND * LINK_BYTES,
      note: scale > 1 ? `links walked: 200,000 of ${seconds * TICKS_PER_SECOND}, the rest at the same rate` : undefined,
    });
  }
  for (const [gap, seconds] of [['1 tick', 0.5], ['1 day', 86_400], ['1 year', 365 * 86_400]] as const) {
    if (seconds * RATE > N) continue;
    const back = seconds * RATE;
    const from = Math.max(TICK, N - back);
    put('one', `${label}: consistency ${gap}`, consistency(from, N));
    if (gap === '1 tick') {
      // A real tick adds whole entries: 500 uses, or 499 uses and a change (one tick in two, at one change a second).
      put('split', `${label}: consistency ${gap} (no change)`, consistency(uses - TICK, uses));
      put('split', `${label}: consistency ${gap} (one change)`, sum(consistency(uses - TICK + 1, uses), consistency(changes - 1, changes)));
    } else {
      put('split', `${label}: consistency ${gap}`, sum(
        consistency(Math.max(1, uses - Math.round(back * (1 - CHANGE_RATE))), uses),
        consistency(Math.max(0, changes - Math.round(back * CHANGE_RATE)), changes),
      ));
    }
    if (gap === '1 tick') put('day', `${label}: consistency ${gap}`, consistency(today - TICK, today));
    else {
      // The old head (also at noon) had its own open day, half full: carried to that day's final root, which is a leaf
      // of the new top tree, which extends the old top tree (empty a year back: nothing to prove).
      const oldClosed = Math.max(0, closed - Math.round(seconds / 86_400));
      put('day', `${label}: consistency ${gap}`, sum(
        consistency(today, DAY), { hashes: 1, us: 0 }, inclusion(oldClosed, closed), consistency(oldClosed, closed),
      ));
    }
    put('tick', `${label}: consistency ${gap}`, consistency(Math.max(1, ticks - seconds * TICKS_PER_SECOND), ticks));
    const links = seconds * TICKS_PER_SECOND;
    const walked = links <= 200_000 || (values['chain-year'] && label === 'year') ? walkChain(links) : null;
    const sample = walked ?? walkChain(200_000);
    put('chain', `${label}: consistency ${gap}`, {
      hashes: links, us: walked === null ? (sample.us * links) / 200_000 : walked.us, bytes: links * LINK_BYTES,
      note: walked === null ? `links walked: 200,000 of ${links}, the rest at the same rate` : undefined,
    });
  }
}

// The MMR's proofs: a mountain range bagged right to left is the RFC tree (shapes.test.ts), so its proofs are the
// RFC's: the leaf's path to its peak, the bag of the peaks to its right, and each peak to its left.
for (const [what, c] of Object.entries(results.one!)) results.mmr = { ...results.mmr, [what]: { ...c, note: 'the RFC 9162 tree is a mountain range: the same proof' } };

// A witness, per checkpoint: open the signed note, check one consistency proof (or one link) from the head it holds.
const signer = await signerFrom('coffre.example/audit', randomBytes(32));
const verifier = await verifierFrom(signer.verifierKey);
const note = await signNote(checkpointBody({ origin: signer.name, size: YEAR, root: randomBytes(32), upto: String(YEAR), at: Date.now() }), [signer]);
let t0 = performance.now();
for (let i = 0; i < 2000; i += 1) await openNote(note, verifier);
const openUs = ((performance.now() - t0) * 1000) / 2000;
const witness = {
  noteBytes: note.length, openNoteUs: openUs,
  one: consistency(YEAR - TICK, YEAR),
  // Each tree's own sizes: a tick of 500 uses, or of 499 uses and a change.
  splitNoChange: consistency(YEAR * (1 - CHANGE_RATE) - TICK, YEAR * (1 - CHANGE_RATE)),
  splitOneChange: sum(consistency(YEAR * (1 - CHANGE_RATE) - TICK + 1, YEAR * (1 - CHANGE_RATE)), consistency(YEAR * CHANGE_RATE - 1, YEAR * CHANGE_RATE)),
  tick: consistency(YEAR / TICK - 1, YEAR / TICK),
  chain: walkChain(1),
};

// The walk: a verifier rebuilding the tree from every entry's leaf hash, per entry, in memory.
const W = Number(values['walk-leaves']);
const raw = randomBytes(W * 32);
const leaves = Array.from({ length: W }, (_, i) => raw.subarray(i * 32, (i + 1) * 32));
const per = (f: () => void) => {
  const t = performance.now();
  f();
  return ((performance.now() - t) * 1000) / W;
};
const walk = {
  one: per(() => {
    const e = Edge.empty();
    for (let i = 0; i < W; i += TICK) e.append(leaves.slice(i, i + TICK));
    e.root();
  }),
  split: per(() => {
    const e = [Edge.empty(), Edge.empty()];
    for (let i = 0; i < W; i += TICK) {
      const batch = leaves.slice(i, i + TICK);
      e[0]!.append(batch.filter((_, j) => (i + j) % 1000 !== 0));
      e[1]!.append(batch.filter((_, j) => (i + j) % 1000 === 0));
    }
  }),
  // A day's tree at a time (days of a million leaves here), each closed root into the top tree.
  day: per(() => {
    const top = Edge.empty();
    let today = Edge.empty();
    for (let i = 0; i < W; i += TICK) {
      if (i > 0 && i % 1_000_000 === 0) {
        top.append([today.root()]);
        today = Edge.empty();
      }
      today.append(leaves.slice(i, i + TICK));
    }
  }),
  tick: per(() => {
    const top = Edge.empty();
    for (let i = 0; i < W; i += TICK) {
      const b = Edge.empty();
      b.append(leaves.slice(i, i + TICK));
      top.append([b.root()]);
    }
  }),
  chain: per(() => {
    let h: Hash = Buffer.alloc(32);
    for (let i = 0; i < W; i += TICK) {
      const b = Edge.empty();
      b.append(leaves.slice(i, i + TICK));
      h = link(h, b.root(), TICK, i);
    }
  }),
  mmr: per(() => {
    const m = Mmr.empty();
    for (let i = 0; i < W; i += TICK) m.append(leaves.slice(i, i + TICK));
  }),
  // What every shape does first, the same in all: an entry's leaf hash, from an entry of a use's size.
  leafHash: (() => {
    const entry = Buffer.from(JSON.stringify(['coffre.audit.v1', '2000000009183', 1793048700000, 'svc-17', 'cred-17', 'use', 'load-1234-5678', '{"secret":"DFNS_KEY","environment":"production","decision":"allow"}', null, randomBytes(16).toString('base64')]));
    return micros(() => leafHash(entry), 100_000);
  })(),
};
console.log(JSON.stringify({ results, witness, walk }, null, 1));
