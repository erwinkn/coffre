// The 0.15 checkpointer behind its seam, over an in-memory database a writer
// can tamper with: W209's attacks (docs/design/audit-tree.md, "What it
// catches"), the pair's rules (W212), and R51's change rule with witnesses.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { decodePair, encodePair, leafHash, noteSigner, openPair, proveConsistency, signPair, verifyInclusion, verifyLog, type PairNotes } from '@coffre/core/merkle';
import { isUnsealed } from '@coffre/core/vault';

import { Checkpointer, Fence, FRESH_MS, heldIn, localWitness, Refused, Stalled, Unsealed, WINDOW_ENTRY_MS, type Witness } from '../src/checkpointer.ts';
import { upkeep } from '../src/log-checkpointer.ts';
import { checkpointerObject, durableHeldOutside } from '../src/checkpointer-workers.ts';
import { authentic, entry, keys, MemoryStore, variableMemory, type Keys } from './audit-tree.ts';

async function setup(seed = 1) {
  const k = await keys(seed);
  const store = new MemoryStore(k.macKey);
  const memory = variableMemory();
  const alerts: string[] = [];
  const open = (opts: { witnesses?: Witness[]; memory?: typeof memory; now?: () => number } = {}) =>
    Checkpointer.open(store, k.signers, { memory: opts.memory ?? memory, witnesses: opts.witnesses, authentic: authentic(k.macKey), alert: (m) => alerts.push(m), now: opts.now });
  return { k, store, memory, alerts, open };
}

/** `n` ticks of traffic: about 20 uses and one change a tick, with an aborted append now and then. */
async function traffic(store: MemoryStore, cp: Checkpointer, ticks: number) {
  for (let t = 0; t < ticks; t += 1) {
    for (let i = 0; i < 20; i += 1) store.append('uses', `u-${store.next}`);
    if (t % 3 === 0) store.skip();
    store.append('changes', `c-${store.next}`, '{"action":"member.revoke"}');
    const tick = await cp.tick();
    assert.ok(tick.signed, tick.failures.join('; '));
  }
}

const verify = (store: MemoryStore, k: Keys, opts: { anchors?: PairNotes[]; from?: PairNotes; above?: number } = {}) =>
  verifyLog(store, { verifiers: k.verifiers, check: (e) => (authentic(k.macKey)(e) ? null : 'mac'), ...opts });

test('an honest log: both trees sealed every tick as one pair, verified, and every entry provable', async () => {
  const { k, store, memory, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 12);
  const unsealed = store.append('uses', 'late');
  const v = await verify(store, k, { anchors: [decodePair(memory.record!)!] });
  assert.ok(v.ok, v.problems.join('\n'));
  assert.deepEqual([v.checkpoints, v.sealed, v.unsealed], [12, 12 * 21, 1]);
  assert.equal(encodePair(v.head!), memory.record, 'the newest row is the pair the signer remembers');
  // Every row is one pair: two notes, one upto, one at, each signed under its tree's origin.
  for (const notes of store.rows.values()) assert.ok(await openPair(notes, k.verifiers));
  assert.deepEqual(cp.pair.pair.changes.size, 12);
  assert.deepEqual(cp.pair.pair.uses.size, 240);
  for (const { number } of [store.log[0]!, store.log[20]!, store.log[100]!, store.log.at(-2)!]) {
    const p = (await cp.prove(number))!;
    assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair[p.tree].root), `${number}`);
  }
  assert.equal(await cp.prove(unsealed), null, 'not sealed yet');
  // An incremental walk from the head verified before reads only what came after (R25).
  await traffic(store, cp, 2);
  const again = await verify(store, k, { from: v.head! });
  assert.ok(again.ok && again.checkpoints === 2 && again.sealed === 43, again.problems.join('\n'));
  assert.deepEqual(alerts, []);
});

test('(a) a sealed entry deleted from the middle is caught by the next pair', async () => {
  const { k, store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 5);
  store.deleteEntry(30n);
  const v = await verify(store, k);
  assert.ok(!v.ok && v.problems.some((p) => /uses head differ/.test(p)), v.problems.join('\n'));
  await assert.rejects(cp.prove(31n), /database changed it/);
});

test('review r6: tiles that do not give their head are reported, and the walk goes on to report a tail cut too', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 8);
  const held = decodePair(memory.record!)!;
  store.deleteEntry(store.log[30]!.number);
  const tile = Buffer.from(store.tileStore.uses.get('0/0')!);
  tile[100] = tile[100]! ^ 1;
  store.tileStore.uses.set('0/0', tile);
  store.rollBack([...store.rows.keys()].sort((a, b) => (a < b ? -1 : 1)).at(-3)!);
  const v = await verify(store, k, { anchors: [held] });
  assert.ok(v.problems.some((p) => /tiles at its edge/.test(p)), v.problems.join('\n'));
  assert.ok(v.problems.some((p) => /the database ends up to/.test(p)), v.problems.join('\n'));
  assert.ok(v.checkpoints > 1);
});

test('(b) a tail cut, rows and entries, is caught against the pair held outside and at the signer\'s next start', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 8);
  const held = decodePair(memory.record!)!;
  const keep = [...store.rows.keys()].sort((a, b) => (a < b ? -1 : 1)).at(-4)!;
  store.rollBack(keep);
  assert.ok((await verify(store, k)).ok, 'the database alone shows a consistent, shorter log');
  const v = await verify(store, k, { anchors: [held] });
  assert.ok(!v.ok && v.problems.some((p) => /the database ends up to/.test(p)), v.problems.join('\n'));
  await assert.rejects(open(), /lost entries the signer sealed/);
});

test('(c) a split view: rolled back, one entry dropped, sealed again by a signer without memory, then refused', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 6);
  const self = await noteSigner('witness.test', Buffer.alloc(32, 9));
  const witness = localWitness('w', k.verifiers, self);
  const watched = await open({ witnesses: [witness] });
  await traffic(store, watched, 1);
  await watched.sealThrough(store.next - 1n);
  const keep = [...store.rows.keys()].sort((a, b) => (a < b ? -1 : 1)).at(-3)!;
  const dropped = keep + 3n;
  const after = store.log.filter((e) => e.number > keep && e.number !== dropped);
  store.rollBack(keep);
  store.log.push(...after);
  // A signer whose memory is gone takes the database's word, and signs a second history.
  const forgetful = variableMemory();
  const stateless = await open({ memory: forgetful, witnesses: [witness] });
  const t = await stateless.tick();
  assert.ok(t.signed);
  const sealed = await stateless.sealThrough(stateless.pair.pair.upto, 300);
  assert.equal(sealed.witnessed, false, 'the witness refuses the second history');
  assert.match(sealed.failures.join(), /split view/, JSON.stringify(sealed.failures));
  // The signer with its memory refuses to sign on top of it.
  await assert.rejects(open(), /not the pair the signer signed|does not extend|lost entries/);
  void memory;
});

test('(e) a crash after remembering a pair, before writing it: written again at restart; with an entry of it deleted, refused', async () => {
  for (const tamper of [false, true]) {
    const { k, store, memory, open } = await setup();
    const cp = await open();
    await traffic(store, cp, 3);
    store.append('uses', 'x');
    store.append('changes', 'y');
    store.beforeWrite = () => {
      throw new Error('crash');
    };
    await assert.rejects(cp.tick(), /crash/);
    store.beforeWrite = null;
    assert.equal(decodePair(memory.record!) !== null && (await openPair(decodePair(memory.record!)!, k.verifiers))!.upto, store.next - 1n, 'remembered first');
    if (tamper) {
      store.deleteEntry(store.next - 1n);
      await assert.rejects(open(), /lost entries the signer sealed/);
    } else {
      const reopened = await open();
      assert.equal(reopened.pair.pair.upto, store.next - 1n);
      assert.ok((await verify(store, k)).ok);
    }
  }
});

test('a failed write or memory leaves the signer at the pair the database holds; the next tick seals on', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  const before = cp.pair;
  store.append('uses', 'a');
  memory.failNext = true;
  await assert.rejects(cp.tick(), /storage unavailable/);
  assert.equal(cp.pair, before);
  store.beforeWrite = () => {
    throw new Error('connection reset');
  };
  await assert.rejects(cp.tick(), /connection reset/);
  store.beforeWrite = null;
  assert.equal(cp.pair, before);
  await traffic(store, cp, 2);
  const v = await verify(store, k, { anchors: [decodePair(memory.record!)!] });
  assert.ok(v.ok, v.problems.join('\n'));
});

test('(g) every row deleted: the signer refuses to start a new log', async () => {
  const { store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  store.rows.clear();
  await assert.rejects(open(), /holds no checkpoint/);
});

test('(j) another pair at the same place, signed by a signer without memory, is refused at the next start', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  // A forged pair at the newest row's place: the same upto, another uses head.
  const row = (await store.newest())!;
  const pair = (await openPair(row.notes, k.verifiers))!;
  const forged = await signPair(k.signers, pair.upto, pair.at + 1, { changes: pair.changes, uses: { size: pair.uses.size, root: Buffer.alloc(32, 7) } }, pair.floor);
  store.rows.set(row.upto, forged.notes);
  await assert.rejects(open(), /the newest checkpoint|not the pair the signer signed|tiles at its edge/);
  void memory;
});

test('(m) the newest row deleted under a running signer is caught at the next tick, with no traffic', async () => {
  const { store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  store.rows.delete(cp.pair.pair.upto);
  const t = await cp.tick();
  assert.ok(!t.signed);
  assert.match(t.failures.join(), /newest checkpoint is \d+, the signer's is at/);
  assert.ok(alerts.some((a) => /refused/.test(a)));
});

test('nothing is sealed over a forged entry, a replay older than the signer\'s pair, or an entry out of its window', async () => {
  const cases: [string, (store: MemoryStore, k: Keys, cp: Checkpointer) => void, RegExp][] = [
    ['forged', (store) => store.log.push({ ...store.log.at(-1)!, number: store.next++, columns: [1n, 'f', '{}', Buffer.alloc(16)] }), /MAC does not hold/],
    // A change, read by number: a use that old lies below the floor, where the window does not read (FloorChecked keeps
    // such a use out; one slipped in shows to the verifier, as an entry its pair does not hold).
    ['replay', (store, k, cp) => store.log.push(entry(k.macKey, 'changes', store.next++, 'old', '{}', cp.pair.pair.at - FRESH_MS - 1)), /a replay/],
    ['renumbered', (store) => store.log.push({ ...store.log[store.log.length - 1 - 0]!, number: store.append('uses', 'twin') }), /outside the window/],
  ];
  for (const [name, tamper, error] of cases) {
    const { k, store, open } = await setup();
    const cp = await open();
    await traffic(store, cp, 2);
    tamper(store, k, cp);
    const t = await cp.tick();
    assert.ok(!t.signed && t.failures.some((f) => error.test(f)), `${name}: ${t.failures.join('; ')}`);
    // A change that waits for its seal fails with the alarm instead of waiting forever.
    const change = store.append('changes', `${name}-change`);
    await assert.rejects(cp.sealThrough(change), error);
  }
});

test('the pair is one value: a row or a memory holding notes of two ticks is refused, and so is an entry moved between trees', async () => {
  {
    const { k, store, open } = await setup();
    const cp = await open();
    await traffic(store, cp, 3);
    const rows = [...store.rows.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
    const [upto, newest] = rows.at(-1)!;
    const [, older] = rows.at(-2)!;
    store.rows.set(upto, { changes: newest.changes, uses: older.uses });
    await assert.rejects(open(), /not a pair signed by this log/);
    const v = await verify(store, k);
    assert.ok(!v.ok && v.problems.some((p) => /not a pair signed by the log/.test(p)), v.problems.join('\n'));
  }
  {
    const { store, memory, open } = await setup();
    const cp = await open();
    await traffic(store, cp, 3);
    const older = decodePair(memory.record!)!;
    await traffic(store, cp, 1);
    memory.record = encodePair({ changes: decodePair(memory.record!)!.changes, uses: older.uses });
    await assert.rejects(open(), /remembers a pair it did not sign/);
  }
  {
    const { k, store, open } = await setup();
    const cp = await open();
    await traffic(store, cp, 3);
    const moved = store.log.find((e) => e.tree === 'uses' && e.number === 5n)!;
    moved.tree = 'changes';
    const v = await verify(store, k);
    assert.ok(!v.ok && v.problems.some((p) => /changes and uses heads differ/.test(p)), v.problems.join('\n'));
  }
});

test('a memory restored from before the newest rows is accepted when it is a prefix of them, in both trees, and refused otherwise', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  const old = memory.record;
  await traffic(store, cp, 3);
  memory.record = old;
  const reopened = await open();
  assert.equal(encodePair(reopened.pair.notes), memory.record, 'and remembers the newest row');
  // A pair from another history at an older place: not a prefix.
  const other = await signPair(k.signers, 3n, 1, { changes: { size: 1, root: Buffer.alloc(32, 1) }, uses: { size: 1, root: Buffer.alloc(32, 2) } });
  memory.record = encodePair(other.notes);
  await assert.rejects(open(), /does not extend the one the signer remembers/);
});

test('review r3: a memory behind the database is checked by a consistency proof, not a head recomputed from planted tiles', async () => {
  // The signer remembers 256 uses. A rollback and a signer without memory make a fork of 65,792 uses whose first 256
  // differ; the writer plants the remembered root at tile 1/0, which the fork's own head never reads (it reads 2/0).
  const { k, store, memory, open } = await setup();
  const cp = await open();
  for (let i = 0; i < 256; i += 1) store.append('uses', `real-${i}`);
  assert.ok((await cp.tick()).signed);
  const remembered = memory.record!;
  const mine = (await openPair(decodePair(remembered)!, k.verifiers))!;
  store.rollBack(0n);
  const forked = await open({ memory: variableMemory() });
  for (let i = 0; i < 65_792; i += 1) store.append('uses', `fork-${i}`);
  // A part of the window a tick (T169, WINDOW_MAX), until it is all sealed.
  for (let t = await forked.tick(); t.more; t = await forked.tick()) assert.ok(t.signed);
  const tile = Buffer.from(store.tileStore.uses.get('1/0')!);
  mine.uses.root.copy(tile, 0);
  store.tileStore.uses.set('1/0', tile);
  memory.record = remembered;
  await assert.rejects(open(), /does not extend the one the signer remembers/);
});

test('a signer with no memory on an existing log starts from the database, says so, and remembers it', async () => {
  const { store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  const fresh = variableMemory();
  await open({ memory: fresh });
  assert.equal(fresh.record, encodePair(cp.pair.notes));
  assert.ok(alerts.some((a) => /remembers no pair/.test(a)));
});

test('review r1: a write that commits, then throws, is adopted at the next tick instead of wedging the signer', async () => {
  const { k, store, memory, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  store.append('uses', 'a');
  store.afterWrite = () => {
    store.afterWrite = null;
    throw new Error('reply lost');
  };
  await assert.rejects(cp.tick(), /reply lost/);
  await traffic(store, cp, 2);
  assert.ok((await verify(store, k, { anchors: [decodePair(memory.record!)!] })).ok);
  assert.deepEqual(alerts, []);
});

test('review r1: a pair remembered but not written is written as it was at the next tick, never signed again for its place', async () => {
  const { k, store, memory, open } = await setup();
  let clock = 100_000;
  const cp = await open({ now: () => clock });
  await traffic(store, cp, 2);
  const deleted = store.append('uses', 'a');
  store.append('uses', 'b');
  store.beforeWrite = () => {
    store.beforeWrite = null;
    throw new Error('connection reset');
  };
  await assert.rejects(cp.tick(), /connection reset/);
  const remembered = memory.record!;
  // Time passes and a writer deletes an entry the pending pair sealed: the next tick still writes that pair, at its
  // first `at`, rather than a second one without the entry.
  clock += 5000;
  store.deleteEntry(deleted);
  const pending = (await openPair(decodePair(remembered)!, k.verifiers))!;
  const t = await cp.tick();
  assert.ok(t.signed && t.upto === pending.upto, 'the tick reports the pair it finished');
  assert.deepEqual(store.rows.get(pending.upto), decodePair(remembered), 'the pair the signer remembered is the row at its place');
  const v = await verify(store, k);
  assert.ok(!v.ok && v.problems.some((p) => /uses head differ/.test(p)), 'and the deleted entry shows');
});

test('review r1: a row replaced by another pair at the same place, under a running signer, is caught at the next tick', async () => {
  const { k, store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  const { pair } = cp.pair;
  const fork = await signPair(k.signers, pair.upto, pair.at + 1, { changes: pair.changes, uses: { size: pair.uses.size, root: Buffer.alloc(32, 5) } }, pair.floor);
  store.rows.set(pair.upto, fork.notes);
  const t = await cp.tick();
  assert.ok(!t.signed && /newest checkpoint is another pair/.test(t.failures.join()), t.failures.join());
});

test('review r1: a change whose entry was deleted before its tick is refused, not answered', async () => {
  const { store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 1);
  const number = store.append('changes', 'revoke');
  store.deleteEntry(number);
  await assert.rejects(cp.sealThrough(number), /lost before its seal/);
  assert.ok(alerts.some((a) => /lost before its seal/.test(a)));
});

test('PR 8 review r4: a change whose proof the database answers wrongly for is refused and alarmed, as one lost before its seal', async () => {
  const { store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 1);
  const number = store.append('changes', 'revoke');
  // As `locate` refuses a use changed since its tick that holds the change's number.
  store.locate = async () => {
    throw new Refused("use 9 is in none of its window's leaves: the database changed it since its tick");
  };
  await assert.rejects(cp.sealThrough(number), /cannot be proved in the signed changes tree: use 9 is in none/);
  assert.ok(alerts.some((a) => /cannot be proved in the signed changes tree/.test(a)));
  // A failure of the database's to answer at all (a connection dropped) is no refusal: the change, committed, is not
  // sealed in time (T169), the app's 503, and no alarm.
  const before = alerts.length;
  store.locate = async () => {
    throw new Error('Connection terminated unexpectedly');
  };
  await assert.rejects(cp.sealThrough(number), (error: Error) => error instanceof Unsealed && isUnsealed(error) && /Connection terminated unexpectedly/.test(error.message));
  assert.equal(alerts.length, before);
});

test('review r1: prove() refuses an answer for another entry than the one asked', async () => {
  const { store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  const locate = store.locate.bind(store);
  store.locate = async (number) => locate(number - 1n);
  await assert.rejects(cp.prove(store.log[5]!.number), /another entry/);
  store.locate = async (number) => {
    const found = await locate(number);
    return found && { ...found, entry: { ...found.entry, tree: 'other' as never } };
  };
  await assert.rejects(cp.prove(store.log[5]!.number), /another entry/);
});

test('review r1: a pair held outside below the start must be a prefix of it, even when the row at its place agrees', async () => {
  const { k, store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 6);
  const from = cp.pair.notes;
  const older = [...store.rows.keys()].sort((a, b) => (a < b ? -1 : 1)).at(-4)!;
  const pair = (await openPair(store.rows.get(older)!, k.verifiers))!;
  const fork = await signPair(k.signers, older, pair.at, { changes: pair.changes, uses: { size: pair.uses.size, root: Buffer.alloc(32, 6) } }, pair.floor);
  store.rows.set(older, fork.notes);
  const v = await verify(store, k, { from, anchors: [fork.notes] });
  assert.ok(!v.ok && v.problems.some((p) => /not a prefix of the start/.test(p)), v.problems.join('\n'));
});

test('review r2, KindInMac: a change deleted and a use renumbered into its place is refused, not answered from the uses tree', async () => {
  const { store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 1);
  const number = store.append('changes', 'revoke');
  const use = store.append('uses', 'u');
  store.deleteEntry(number);
  store.log.find((e) => e.number === use)!.number = number;
  await assert.rejects(cp.sealThrough(number), /signed changes tree: entry \d+ is in the uses tree, not the changes: a use holds its number/);
  assert.ok(alerts.some((a) => /signed changes tree/.test(a)));
});

test('KindInMac: an entry moved from one tree to the other before its tick fails its MAC, and nothing is sealed', async () => {
  const { store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 1);
  const number = store.append('changes', 'revoke');
  store.log.find((e) => e.number === number)!.tree = 'uses';
  const t = await cp.tick();
  assert.ok(!t.signed && /MAC does not hold/.test(t.failures.join()), t.failures.join());
});

test('PairChecked: one tree\'s newest note gone under a running signer (its previous note shows instead) is caught at the next tick', async () => {
  const { store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  const rows = [...store.rows.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  const [upto, newest] = rows.at(-1)!;
  store.rows.set(upto, { changes: newest.changes, uses: rows.at(-2)![1].uses });
  const t = await cp.tick();
  assert.ok(!t.signed && /newest checkpoint is another pair/.test(t.failures.join()), t.failures.join());
});

test('review r2: a remembered genesis with every row gone is written back as it was, not signed again', async () => {
  const { store, memory, open } = await setup();
  let clock = 1000;
  await open({ now: () => clock });
  const genesis = memory.record;
  store.rows.clear();
  clock = 2000;
  await open({ now: () => clock });
  assert.equal(memory.record, genesis);
  assert.deepEqual(store.rows.get(0n), decodePair(genesis!));
});

test('review r4: a witness that hangs once, or throws before it returns, does not stop its pump', async () => {
  const { k, store, open } = await setup();
  const self = await noteSigner('witness.test', Buffer.alloc(32, 9));
  const honest = localWitness('honest', k.verifiers, self);
  let calls = 0;
  const hangsOnce: Witness = {
    name: 'hangs-once',
    publish(notes, proofs, signal) {
      calls += 1;
      return calls === 1 ? new Promise(() => {}) : honest.publish(notes, proofs, signal);
    },
  };
  const cp = await open({ witnesses: [hangsOnce] });
  assert.equal((await cp.sealThrough(store.append('changes', 'c1'), 500)).witnessed, false);
  const s = await cp.sealThrough(store.append('changes', 'c2'), 3000);
  assert.equal(s.witnessed, true, s.failures.join());
  assert.ok(calls >= 2);

  let thrown = 0;
  const throwsAtOnce: Witness = {
    name: 'throws',
    publish() {
      thrown += 1;
      throw new Error('bad config');
    },
  };
  const t = await open({ witnesses: [throwsAtOnce] });
  const answer = await t.sealThrough(store.append('changes', 'c3'), 300);
  assert.equal(answer.witnessed, false);
  assert.match(answer.failures.join(), /bad config/);
  const before = thrown;
  await t.sealThrough(store.append('changes', 'c4'), 300);
  assert.ok(thrown > before, 'asked again for the next change');
});

test('review r4: prove() refuses an index past the tree; open() re-syncs a memory holding the same heads signed at another time', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  const locate = store.locate.bind(store);
  store.locate = async (number) => {
    const found = await locate(number);
    return found && { ...found, index: 10_000 };
  };
  await assert.rejects(cp.prove(store.log[3]!.number), /past the/);
  store.locate = locate;
  const { pair } = cp.pair;
  // The memory holds the same heads signed earlier: it takes the row's notes. Signed later, or at a higher floor, than
  // the row: time would run back, refused (review r11).
  const earlier = await signPair(k.signers, pair.upto, pair.at - 7, { changes: pair.changes, uses: pair.uses }, pair.floor);
  memory.record = encodePair(earlier.notes);
  await open();
  assert.equal(memory.record, encodePair(cp.pair.notes));
  for (const [at, floor] of [[pair.at + 7, pair.floor], [pair.at, pair.floor + 7]]) {
    memory.record = encodePair((await signPair(k.signers, pair.upto, at!, { changes: pair.changes, uses: pair.uses }, floor)).notes);
    await assert.rejects(open(), /time runs back/);
  }
});

test('review r11: two pairs held outside for one place, below the start, must be one signing', async () => {
  const { k, store, open } = await setup();
  const cp = await open();
  const notes: PairNotes[] = [];
  for (let i = 0; i < 5; i += 1) {
    await traffic(store, cp, 1);
    notes.push(cp.pair.notes);
  }
  const p3 = (await openPair(notes[2]!, k.verifiers))!;
  const again = await signPair(k.signers, p3.upto, p3.at + 1, { changes: p3.changes, uses: p3.uses }, p3.floor);
  store.rows.delete(p3.upto);
  const v = await verify(store, k, { from: notes[4]!, anchors: [notes[2]!, again.notes] });
  assert.ok(!v.ok && v.problems.some((p) => /two pairs held outside up to/.test(p)), v.problems.join('\n'));
});

test('review r11: a use below the floor the signer holds is not in its window, and a lowered floor refuses the tick that would miss it', async () => {
  const { store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  const signed = cp.pair.pair.floor;
  store.floor = signed - 60_000;
  const late = store.append('uses', 'late', '{}', signed - 30_000);
  assert.ok(!(await cp.tick()).signed);
  assert.ok(!(await store.close(cp.pair.pair.upto, signed)).entries.some((e) => e.number === late), 'read from the signed floor, the late use is missed');
});

test('Fable review: a tick on a signer clock an hour ahead signs at most one bound past its entries, and sealing goes on once the clock heals', async () => {
  const { store, open } = await setup();
  let ahead = 0;
  const cp = await open({ now: () => Date.now() + ahead });
  await traffic(store, cp, 1);
  ahead = 3_600_000;
  const stamped = Date.now();
  store.append('uses', 'u1', '{}', stamped);
  assert.ok((await cp.tick()).signed);
  assert.ok(cp.pair.pair.at <= stamped + FRESH_MS, 'held to the newest entry plus the bound');
  ahead = 0;
  await traffic(store, cp, 2);
  const s = await cp.sealThrough(store.append('changes', 'c1'));
  assert.ok(s.pair.upto >= 1n);
});

test('review r6: a signer that stalled past the bound on a quiet log seals on resume', async () => {
  const { store, open, alerts } = await setup();
  let clock = 1_800_000_000_000;
  const cp = await open({ now: () => clock });
  store.append('uses', 'u', '{}', clock);
  await cp.tick();
  const number = store.append('changes', 'c', '{}', clock + 1000);
  clock += 11 * 60_000;
  const s = await cp.sealThrough(number);
  assert.ok(s.pair.upto >= number && s.pair.at <= clock);
  assert.deepEqual(alerts, []);
});

test('time never runs back along one history: open() refuses a newer pair signed earlier; a witness refuses it too', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  const { pair, notes } = cp.pair;
  const remembered = encodePair(notes);
  await traffic(store, cp, 1);
  // The newest row re-signed with a time before the remembered pair's.
  const row = (await store.newest())!;
  const newest = (await openPair(row.notes, k.verifiers))!;
  const back = await signPair(k.signers, newest.upto, pair.at - 1, { changes: newest.changes, uses: newest.uses }, newest.floor);
  store.rows.set(newest.upto, back.notes);
  memory.record = remembered;
  await assert.rejects(open(), /behind in time or floor/);
  const self = await noteSigner('witness.test', Buffer.alloc(32, 9));
  const witness = localWitness('w', k.verifiers, self);
  const none = async () => ({ changes: [], uses: [] });
  assert.ok((await witness.publish(decodePair(remembered)!, none, new AbortController().signal)).ok);
  const answer = await witness.publish(back.notes, async () => ({
    changes: await proveConsistency(store, 'changes', pair.changes.size, newest.changes.size),
    uses: await proveConsistency(store, 'uses', pair.uses.size, newest.uses.size),
  }), new AbortController().signal);
  assert.ok(!answer.ok && /time runs back/.test(answer.reason), JSON.stringify(answer));
});

test('a window of gaps alone keeps the time last signed', async () => {
  const { store, open } = await setup();
  let clock = 1_800_000_000_000;
  const cp = await open({ now: () => clock });
  store.append('uses', 'u', '{}', clock);
  await cp.tick();
  const at = cp.pair.pair.at;
  store.skip();
  clock += 3_600_000;
  const t = await cp.tick();
  assert.ok(t.signed && cp.pair.pair.at === at);
});

test('review r7: time never runs back at the memory-ahead start, nor in the verifier\'s walk', async () => {
  {
    // The signer remembers P4 (a write that failed); the database's P3 was re-signed later, by another signer's clock.
    const { k, store, open } = await setup();
    const cp = await open();
    await traffic(store, cp, 3);
    store.append('uses', 'x');
    store.beforeWrite = () => {
      store.beforeWrite = null;
      throw new Error('connection reset');
    };
    await assert.rejects(cp.tick(), /connection reset/);
    const p3 = cp.pair.pair;
    const later = await signPair(k.signers, p3.upto, Date.now() + 3_600_000, { changes: p3.changes, uses: p3.uses }, p3.floor);
    store.rows.set(p3.upto, later.notes);
    await assert.rejects(open(), /time runs back/);
  }
  {
    const { k, store, open } = await setup();
    const cp = await open();
    await traffic(store, cp, 5);
    const middle = [...store.rows.keys()].sort((a, b) => (a < b ? -1 : 1)).at(-3)!;
    const pair = (await openPair(store.rows.get(middle)!, k.verifiers))!;
    store.rows.set(middle, (await signPair(k.signers, middle, pair.at + 3_600_000, { changes: pair.changes, uses: pair.uses }, pair.floor)).notes);
    const v = await verify(store, k);
    assert.ok(!v.ok && v.problems.some((p) => /time runs back/.test(p)), v.problems.join('\n'));
  }
});

test('review r8: a pair held outside with a row\'s heads but another time is reported', async () => {
  const { k, store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 4);
  const { pair } = cp.pair;
  const resigned = await signPair(k.signers, pair.upto, pair.at + 3_600_000, { changes: pair.changes, uses: pair.uses }, pair.floor);
  const v = await verify(store, k, { anchors: [resigned.notes] });
  assert.ok(!v.ok && v.problems.some((p) => /same heads signed at another time/.test(p)), v.problems.join('\n'));
});

test('BarrierChecksFloor: a floor of at a writer lowered is refused at the next tick, alerted; the floor is signed into each pair', async () => {
  const { k, store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  const signed = cp.pair.pair.floor;
  assert.ok(signed > 0 && signed === store.floor, 'the pair carries the floor its barrier set');
  assert.equal((await openPair(store.rows.get(cp.pair.pair.upto)!, k.verifiers))!.floor, signed);
  store.floor = signed - 60_000;
  store.append('uses', 'late', '{}', signed - 30_000);
  const t = await cp.tick();
  assert.ok(!t.signed && /floor of at is .* lowered by a writer/.test(t.failures.join()), t.failures.join());
  assert.ok(alerts.some((a) => /lowered by a writer/.test(a)));
});

test('review r9–r10, BarrierChecksFloor: a floor lowered or raised is refused at every tick until reopened; quiet ticks raise no alarm', async () => {
  for (const delta of [-60_000, 3_600_000]) {
    const { store, open, alerts } = await setup();
    const cp = await open();
    await traffic(store, cp, 2);
    for (let i = 0; i < 3; i += 1) assert.ok(!(await cp.tick()).signed, 'quiet');
    await traffic(store, cp, 1);
    assert.deepEqual(alerts, [], 'quiet ticks find the floor where the signer\'s own barrier left it');
    const signed = cp.pair.pair.floor;
    const left = store.floor;
    store.floor += delta;
    store.append('uses', 'late', '{}', delta < 0 ? signed - 30_000 : Date.now());
    for (let i = 0; i < 3; i += 1) {
      const t = await cp.tick();
      assert.ok(!t.signed && /floor of at is .* by a writer/.test(t.failures.join()), `tick ${i}: ${t.failures.join()}`);
      // Even a row landed back exactly where the signer's barrier left it (a barrier in the same millisecond) stays refused.
      store.floor = left;
    }
    assert.equal(cp.pair.pair.floor, signed, 'nothing adopted');
    assert.ok(store.froms.every((f) => f <= signed), 'windows read from the signed floor');
    // Reopened, once an operator has looked: the floor found is no lower than the newest pair's, so it seals on.
    if (delta > 0) {
      const reopened = await open();
      assert.ok((await reopened.tick()).signed);
    }
  }
});

test('review r9: a floor that runs back is refused by open(), witnesses and the verifier', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  const remembered = memory.record!;
  await traffic(store, cp, 1);
  const row = (await store.newest())!;
  const newest = (await openPair(row.notes, k.verifiers))!;
  const lower = await signPair(k.signers, newest.upto, newest.at, { changes: newest.changes, uses: newest.uses }, 1);
  store.rows.set(newest.upto, lower.notes);
  memory.record = remembered;
  await assert.rejects(open(), /behind in time or floor/);
  const v = await verify(store, k);
  assert.ok(!v.ok && v.problems.some((p) => /floor of at .* is below/.test(p)), v.problems.join('\n'));
  const self = await noteSigner('witness.test', Buffer.alloc(32, 9));
  const witness = localWitness('w', k.verifiers, self);
  const none = async () => ({ changes: [], uses: [] });
  assert.ok((await witness.publish(decodePair(remembered)!, none, new AbortController().signal)).ok);
  const held = (await openPair(decodePair(remembered)!, k.verifiers))!;
  const answer = await witness.publish(lower.notes, async () => ({
    changes: await proveConsistency(store, 'changes', held.changes.size, newest.changes.size),
    uses: await proveConsistency(store, 'uses', held.uses.size, newest.uses.size),
  }), new AbortController().signal);
  assert.ok(!answer.ok && /floor of at/.test(answer.reason), JSON.stringify(answer));
});

test('review r10: pairs held outside below the start are held to time and floor among themselves', async () => {
  const { k, store, open } = await setup();
  const cp = await open();
  const notes: PairNotes[] = [];
  for (let i = 0; i < 6; i += 1) {
    await traffic(store, cp, 1);
    notes.push(cp.pair.notes);
  }
  const p5 = (await openPair(notes[4]!, k.verifiers))!;
  const forged = await signPair(k.signers, p5.upto, p5.at, { changes: p5.changes, uses: p5.uses }, 1);
  store.rows.delete(p5.upto);
  const v = await verify(store, k, { from: notes[5]!, anchors: [notes[2]!, forged.notes] });
  assert.ok(!v.ok && v.problems.some((p) => /time runs back/.test(p)), v.problems.join('\n'));
});

test('6b review r1: a pending pair the database stands at neither side of is alerted once, not every tick', async () => {
  const { store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  store.append('uses', 'x');
  store.beforeWrite = () => {
    store.beforeWrite = null;
    throw new Error('connection reset');
  };
  await assert.rejects(cp.tick(), /connection reset/);
  store.rows.delete(cp.pair.pair.upto);
  for (let i = 0; i < 3; i += 1) await assert.rejects(cp.tick(), /reopen the checkpointer/);
  assert.equal(alerts.filter((a) => /reopen the checkpointer/.test(a)).length, 1, alerts.join('\n'));
});

test('6b review r3: a closed checkpointer ends its tick in flight, then refuses every tick and every change', async () => {
  const { store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 1);
  store.append('uses', 'x');
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let writing = false;
  const write = store.write.bind(store);
  store.write = async (row, tiles) => {
    writing = true;
    await held;
    return write(row, tiles);
  };
  const ticking = cp.tick();
  while (!writing) await new Promise((resolve) => setTimeout(resolve, 1));
  let closed = false;
  const closing = cp.close().then(() => (closed = true));
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(closed, false, 'close waits for the tick in flight');
  // Its write lands, and its answer, come after the fence closed, is not read (T169): the tick fails, and the next
  // checkpointer finds the pair it remembered in the database.
  const writes = store.writes;
  release();
  await assert.rejects(ticking, /was closed/);
  assert.equal(store.writes, writes + 1, 'the write landed');
  await closing;
  await assert.rejects(cp.tick(), /was closed/);
  await assert.rejects(cp.sealThrough(store.append('changes', 'c')), /was closed/);
});

// R51: a change answers once sealed and, with a witness, witnessed, or unwitnessed after 2 s.

test('a change answers once sealed: witnessed null without a witness, and its proof checks against the pair', async () => {
  const { store, open } = await setup();
  const cp = await open();
  const number = store.append('changes', 'revoke-1');
  const s = await cp.sealThrough(number);
  assert.equal(s.witnessed, null);
  assert.ok(s.pair.upto >= number);
  const p = s.proof;
  assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, s.pair.changes.root));
  assert.equal(p.number, number);
});

test('a change waits for the witness, then answers unwitnessed at the deadline, alerted; a refusal is retried within it', async () => {
  const { k, store, open, alerts } = await setup();
  const self = await noteSigner('witness.test', Buffer.alloc(32, 9));
  const honest = localWitness('honest', k.verifiers, self);
  let refusals = 1;
  let calls = 0;
  const flaky: Witness = {
    name: 'flaky',
    async publish(notes, proofs, signal) {
      calls += 1;
      if (refusals-- > 0) return { ok: false, reason: 'busy' };
      return honest.publish(notes, proofs, signal);
    },
  };
  const cp = await open({ witnesses: [flaky] });
  const s = await cp.sealThrough(store.append('changes', 'c1'), 2000);
  assert.equal(s.witnessed, true, s.failures.join());
  assert.equal(s.cosigned.length, 1);
  assert.ok(calls >= 2, 'asked again within the deadline');

  const silent: Witness = { name: 'silent', publish: () => new Promise(() => {}) };
  const slow = await open({ witnesses: [silent] });
  const t0 = performance.now();
  const late = await slow.sealThrough(store.append('changes', 'c2'), 200);
  assert.ok(performance.now() - t0 >= 190);
  assert.equal(late.witnessed, false);
  assert.match(late.failures.join(), /no answer within 200 ms/);
  assert.ok(alerts.some((a) => /answered unwitnessed/.test(a)));

  // A witness that always refuses is not asked again once the change has answered.
  let asked = 0;
  const refusing: Witness = { name: 'refusing', publish: async () => ((asked += 1), { ok: false, reason: 'no' }) };
  const r = await open({ witnesses: [refusing] });
  await r.sealThrough(store.append('changes', 'c3'), 250);
  const after = asked;
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(asked, after);
});

test('review r11: a signer\'s memory that does not read as a pair is refused, never held as none; none yet is none', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  assert.deepEqual(heldIn(null), []);
  assert.deepEqual(heldIn(memory.record), [decodePair(memory.record!)]);
  assert.throws(() => heldIn('{ damaged pair'), /the signer's memory does not read as a pair/);
  // The Durable Object's answer, read from its storage: refused, so a walk is not checked against nothing.
  const Object_ = checkpointerObject(() => {
    throw new Error('the memory is read without the database');
  });
  const held = (record: string | null) => {
    const object = new Object_({ storage: { get: async () => record ?? undefined } } as never, {} as never);
    return durableHeldOutside({ idFromName: () => 'checkpointer', get: () => ({ fetch: (request: Request) => object.fetch(request) }) } as never)();
  };
  assert.deepEqual(await held(memory.record), [decodePair(memory.record!)]);
  assert.deepEqual(await held(null), []);
  await assert.rejects(held('{ damaged pair'), /the signer's memory does not read as a pair/);
  // What it guards: a log rolled back to its start verifies without the anchor, never with it.
  const remembered = decodePair(memory.record!)!;
  store.rollBack(0n);
  assert.ok((await verify(store, k)).ok);
  assert.ok(!(await verify(store, k, { anchors: [remembered] })).ok);
});

test('PR 8 reviews r1, r4 (W240): above the newest pair a walk reads at most `above` entries, `capped` and no problem past them, and nothing above a database behind a pair held outside', async () => {
  const { k, store, memory, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 3);
  const signed = decodePair(memory.record!)!;
  // A checkpointer stalled: five entries above its pair, three checked, the rest never read: not to the head, no problem.
  const late: bigint[] = [];
  for (let i = 0; i < 5; i += 1) late.push(store.append('uses', `late-${i}`));
  const capped = await verify(store, k, { from: signed, above: 3 });
  assert.deepEqual([capped.unsealed, capped.capped, capped.problems], [3, true, []]);
  const whole = await verify(store, k, { from: signed, above: 5 });
  assert.ok(whole.ok && !whole.capped);
  // A forged entry among the three checked is a problem still, capped or not.
  const forged = store.log.find((e) => e.number === late[1])!;
  (forged.columns as unknown[])[1] = 'forged';
  const named = await verify(store, k, { from: signed, above: 3 });
  assert.ok(named.capped && named.problems.includes(`${late[1]}: mac`), named.problems.join('\n'));
  (forged.columns as unknown[])[1] = 'late-1';
  // Every checkpoint but the genesis deleted, the entries kept: behind the signer's pair, and not one entry read.
  for (const upto of [...store.rows.keys()]) if (upto > 0n) store.rows.delete(upto);
  let read = 0;
  const entries = store.entries.bind(store);
  store.entries = async (...args) => {
    const found = await entries(...args);
    read += found.length;
    return found;
  };
  const behind = await verify(store, k, { anchors: [signed], above: 3 });
  assert.ok(behind.behind && !behind.ok, behind.problems.join('\n'));
  assert.deepEqual([read, behind.unsealed], [0, 0]);
});

test('T169: a tick whose barrier never answers stalls within its bound; a change answers unsealed, the stalled tick lands nothing once the database answers, and another checkpointer seals on, its late barrier no alarm', async () => {
  const { k, store, memory, alerts } = await setup();
  const open = () => Checkpointer.open(store, k.signers, { memory, authentic: authentic(k.macKey), alert: (m) => alerts.push(m), tickBoundMs: 100, sealWaitMs: 300 });
  const cp = await open();
  await traffic(store, cp, 2);
  // The next barrier does not answer until let go: a connection gone dead, a lock never let go.
  let release!: () => void;
  let gate: Promise<void> | null = new Promise<void>((resolve) => (release = resolve));
  const close = store.close.bind(store);
  store.close = async (after, from) => {
    const held = gate;
    gate = null;
    if (held !== null) await held;
    return close(after, from);
  };
  const change = store.append('changes', 'revoke');
  let t0 = performance.now();
  await assert.rejects(cp.tick(), Stalled);
  assert.ok(performance.now() - t0 < 1000, `stalled after ${performance.now() - t0} ms`);
  // Stalled, it seals nothing more: the change, committed, answers unsealed, at once.
  t0 = performance.now();
  await assert.rejects(cp.sealThrough(change), (error: Error) => error instanceof Unsealed && isUnsealed(error));
  assert.ok(performance.now() - t0 < 100);
  // Another opens over the same memory while the stalled tick still waits, and seals the change.
  const next = await open();
  assert.equal((await next.sealThrough(change)).proof.number, change);
  const [record, writes] = [memory.record, store.writes];
  // The database answers: the stalled tick reads its window and raises the floor (a late barrier), and is refused at
  // its fence before it remembers or writes anything.
  await new Promise((resolve) => setTimeout(resolve, 5));
  release();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(memory.record, record, 'its memory is the new checkpointer\'s');
  assert.equal(store.writes, writes, 'nothing written');
  // The floor it raised is no higher than the next barrier's own, and the answer it got came too late to be read: no
  // alarm of any kind (review r1), and the next tick seals.
  store.append('uses', 'after');
  const t = await next.tick();
  assert.ok(t.signed, t.failures.join('; '));
  assert.deepEqual(alerts, []);
  const v = await verify(store, k, { anchors: [decodePair(memory.record!)!] });
  assert.ok(v.ok, v.problems.join('\n'));
});

test('T169: a seal waits at most its bound on ticks that do not end, and a tick queued behind a stalled one answers as soon as it stalls', async () => {
  const { k, store, memory, alerts } = await setup();
  const cp = await Checkpointer.open(store, k.signers, { memory, authentic: authentic(k.macKey), alert: (m) => alerts.push(m), tickBoundMs: 400, sealWaitMs: 150 });
  await traffic(store, cp, 1);
  store.close = () => new Promise(() => {});
  const change = store.append('changes', 'revoke');
  const ticking = cp.tick();
  const queued = cp.tick();
  let t0 = performance.now();
  await assert.rejects(cp.sealThrough(change), (error: Error) => error instanceof Unsealed && /did not end within/.test(error.message));
  assert.ok(performance.now() - t0 < 300, `the seal answered after ${performance.now() - t0} ms`);
  t0 = performance.now();
  await assert.rejects(ticking, Stalled);
  await assert.rejects(queued, Stalled);
  assert.ok(performance.now() - t0 < 600);
  // Closed by its host: at once, the stalled tick's work fenced.
  t0 = performance.now();
  await cp.close();
  assert.ok(performance.now() - t0 < 100);
});

test('T169, review r1: a fence closed refuses every call after it and every answer that comes after it, and its close waits for the memory writes already sent', async () => {
  const fence = new Fence();
  let answer!: (value: string) => void;
  const store = fence.store({ newest: () => new Promise<string>((resolve) => (answer = resolve)), now: async () => 'now' });
  let landed!: () => void;
  let wrote = false;
  const memory = fence.memory({ last: async () => null, remember: () => new Promise<void>((resolve) => (landed = () => ((wrote = true), resolve()))) });
  const asked = store.newest();
  const remembering = memory.remember('pair');
  let closed = false;
  const closing = fence.close('stalled').then(() => (closed = true));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(closed, false, 'the memory write already sent has not landed');
  landed();
  await closing;
  assert.ok(wrote && closed);
  await remembering;
  answer('late');
  await assert.rejects(asked, /closed \(stalled\)/);
  assert.throws(() => store.now(), /closed \(stalled\)/);
  assert.throws(() => memory.remember('another'), /closed \(stalled\)/);
});

test('T169, review by Fable: a tick is bounded by the work its window asks, so a long drain goes on where a short window that took as long stalls', async () => {
  const { k, store, memory, alerts } = await setup();
  const open = () => Checkpointer.open(store, k.signers, { memory, authentic: authentic(k.macKey), alert: (m) => alerts.push(m), tickBoundMs: 250, windowMax: 2000 });
  const cp = await open();
  await traffic(store, cp, 1);
  // A window read that sorts what is left, 6 µs a number: 300 ms for a backlog of 50,000, past the bound alone, and
  // inside it with the window's own allowance (WINDOW_ENTRY_MS), the rest of the bound left for the part's own work.
  let fixed: number | null = null;
  const close = store.close.bind(store);
  store.close = async (after, from, limit, barrier) => {
    const read = await close(after, from, limit, barrier);
    await new Promise((resolve) => setTimeout(resolve, fixed ?? Number(read.upto - after) * 0.006));
    return read;
  };
  for (let i = 0; i < 50_000; i += 1) store.append('uses', `drain-${i}`);
  assert.ok(50_000 * 0.006 > 250 && 0.006 < WINDOW_ENTRY_MS);
  const t = await cp.tick();
  assert.ok(t.signed && t.more, t.failures.join('; '));
  while ((await cp.tick()).more);
  assert.equal(cp.pair.pair.uses.size, 50_000 + 20);
  // One entry whose read takes twice as long: no window asks for that, and the tick stalls.
  fixed = 600;
  store.append('uses', 'one');
  await assert.rejects(cp.tick(), Stalled);
});

test('T169, review by Fable: the first barrier after an open refuses a floor raised past its own clock less the deadline, as every barrier after does', async () => {
  const { store, open, alerts } = await setup();
  const cp = await open();
  await traffic(store, cp, 2);
  await cp.close();
  store.floor = Date.now() + 3_600_000;
  const reopened = await open();
  store.append('uses', 'after');
  const t = await reopened.tick();
  assert.ok(!t.signed && /floor of at is .* raised by a writer/.test(t.failures.join()), t.failures.join());
  assert.ok(alerts.some((a) => /raised by a writer/.test(a)));
});

test('T169, review by Fable: an upkeep whose checkpointer was closed under it raises no alarm: the next one does the work', async () => {
  const { store, open } = await setup();
  const cp = await open();
  await traffic(store, cp, 1);
  const fence = new Fence();
  await fence.close('replaced');
  const alerts: string[] = [];
  const keep = upkeep(cp, fence.store({ ...store, makeDays: async () => {}, pruneBulk: async () => 0 } as never), { keepDays: 1, seed: Buffer.alloc(32, 9), alert: (m) => alerts.push(m) });
  await keep();
  assert.deepEqual(alerts, []);
});
