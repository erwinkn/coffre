// What a database writer without the keys can and cannot hide (W209). Each
// scenario runs on a fresh log: 8 checkpoints of 25 entries, then the attack,
// then the verifier, with and without a head held outside the database, and
// with a signer that remembers its last head or one that starts from the
// database's (W201's).
//
//   node experiments/merkle/attacks.ts --url postgresql://…
import { mkdtempSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { append, Checkpointer, createLog, keysFrom, type Keys } from './src/log.ts';
import { openNote, parseCheckpoint, verifierFrom } from './src/note.ts';
import { verifyLog } from './src/verify.ts';
import { fileMemory } from './src/memory.ts';
import { localWitness } from './src/witness.ts';
import { verifyConsistency } from './src/tree.ts';
import { proveConsistency } from './src/log.ts';

const { values } = parseArgs({ options: { url: { type: 'string' } } });
const pool = new pg.Pool({ connectionString: values.url, max: 10 });
const keys: Keys = await keysFrom('w209-synthetic');
const verifier = await verifierFrom(keys.signer.verifierKey);
const scratch = mkdtempSync(join(homedir(), 'scratch', 'w209', 'memory-'));
let fails = 0;

let i = 0;
const use = () => append(pool, keys, { at: Date.now(), principal: `svc-${i % 5}`, credential: `cred-${i % 5}`, kind: 'use', requestId: `r${i++}`, payload: '{"secret":"DFNS_KEY"}' });

async function fresh(memory: boolean) {
  await createLog(pool);
  const path = join(scratch, `memory-${Math.random()}`);
  const witness = localWitness('witness.example', verifier, keys.witness);
  const cp = await Checkpointer.open(pool, keys, { memory: memory ? fileMemory(path) : undefined, witnesses: [witness] });
  for (let c = 0; c < 8; c += 1) {
    for (let e = 0; e < 25; e += 1) await use();
    await cp.tick({ witnessTimeoutMs: 2000 });
  }
  return { witness, path };
}

const latestNote = async () => (await pool.query('SELECT note FROM checkpoints ORDER BY upto DESC LIMIT 1')).rows[0].note as string;
const head = async (note: string) => parseCheckpoint((await openNote(note, verifier))!);

function expect(label: string, detected: boolean, want: boolean, how: string, words = ['detected', 'not detected']) {
  const ok = detected === want;
  if (!ok) fails += 1;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}: ${detected ? words[0] : words[1]}${how ? ` (${how})` : ''}`);
}

async function verdict(anchors: string[] = []) {
  return verifyLog(pool, { verifierKey: keys.signer.verifierKey, macKey: keys.mac, anchors });
}

// (a) One sealed entry deleted from the middle, everything else left.
{
  console.log('(a) delete one sealed entry from the middle');
  const { witness } = await fresh(true);
  const { rows: [{ number }] } = await pool.query('SELECT a.number::text FROM audit a ORDER BY a.number OFFSET 60 LIMIT 1');
  await pool.query('DELETE FROM audit WHERE number = $1', [number]);
  const without = await verdict();
  expect('verifier, database alone', !without.ok, true, without.problems[0] ?? '');
  const withAnchor = await verdict([witness.held()!.note]);
  expect('verifier, with the witness head', !withAnchor.ok, true, '');
}

// (a') An unsealed entry deleted: the window. Nothing can see it.
{
  console.log("(a') delete one entry not sealed yet");
  const { witness } = await fresh(true);
  for (let e = 0; e < 10; e += 1) await use();
  const { rows: [{ number }] } = await pool.query('SELECT max(number)::text AS number FROM audit');
  await pool.query('DELETE FROM audit WHERE number = $1', [number]);
  const v = await verdict([witness.held()!.note]);
  expect('verifier, with the witness head (expected: the window)', !v.ok, false, `${v.unsealed} unsealed entries left`);
}

// (b) The newest checkpoints deleted with every entry they sealed, and after: a tail cut.
for (const memory of [false, true]) {
  console.log(`(b) delete the newest 3 checkpoints and their entries; signer ${memory ? 'remembers its last head' : 'starts from the database'}`);
  const { witness, path } = await fresh(memory);
  const { rows: [keep] } = await pool.query('SELECT c.upto::text FROM checkpoints c ORDER BY c.upto DESC OFFSET 3 LIMIT 1');
  await pool.query('DELETE FROM checkpoints WHERE upto > $1', [keep.upto]);
  await pool.query('DELETE FROM audit WHERE number > $1', [keep.upto]);
  const alone = await verdict();
  expect('verifier, database alone', !alone.ok, false, 'a shorter log, every checkpoint holds');
  const held = await verdict([witness.held()!.note]);
  expect('verifier, with the witness head', !held.ok, true, held.problems[0] ?? '');
  if (memory) {
    const refused = await Checkpointer.open(pool, keys, { memory: fileMemory(path) }).then(() => '', (e: Error) => e.message);
    expect('signer, at its next start', refused !== '', true, refused);
  }
}

// (c) A split view: the writer rolls the log back, drops one entry, and lets the checkpointer seal again. Reader A
// was shown the head before; reader B is shown the one after.
for (const mode of ['stateless', 'witness', 'memory'] as const) {
  console.log(`(c) split view; ${mode === 'stateless' ? "signer starts from the database, no witness (W201's)" : mode === 'witness' ? 'signer starts from the database, a witness' : 'signer remembers its last head'}`);
  await createLog(pool);
  const witness = localWitness('witness.example', verifier, keys.witness);
  const opts = { memory: mode === 'memory' ? fileMemory(join(scratch, `split-${mode}`)) : undefined, witnesses: mode === 'witness' ? [witness] : [] };
  let cp = await Checkpointer.open(pool, keys, opts);
  for (let c = 0; c < 6; c += 1) {
    for (let e = 0; e < 25; e += 1) await use();
    await cp.tick({ witnessTimeoutMs: 2000 });
  }
  const readerA = await latestNote();
  const { rows: [keep] } = await pool.query('SELECT c.upto::text FROM checkpoints c ORDER BY c.upto DESC OFFSET 2 LIMIT 1');
  const { rows: [victim] } = await pool.query('SELECT a.number::text FROM audit a WHERE a.number > $1 ORDER BY a.number OFFSET 7 LIMIT 1', [keep.upto]);
  await pool.query('DELETE FROM checkpoints WHERE upto > $1', [keep.upto]);
  await pool.query('DELETE FROM audit WHERE number = $1', [victim.number]);
  let refused = '';
  try {
    cp = await Checkpointer.open(pool, keys, opts);
    for (let e = 0; e < 5; e += 1) await use();
    const t = await cp.tick({ witnessTimeoutMs: 500 });
    if (t.failures.length > 0) refused = t.failures.join('; ');
  } catch (error) {
    refused = (error as Error).message;
  }
  const readerB = await latestNote();
  const a = await head(readerA);
  const b = await head(readerB);
  const db = await verdict();
  const inconsistent = !(b.size >= a.size && verifyConsistency(a.size, b.size, a.root, b.root, await proveConsistency(pool, a.size, b.size).catch(() => [])));
  const detected = refused !== '' || !db.ok;
  expect(`readers shown two histories (A ${a.size} leaves, B ${b.size}), ${inconsistent ? 'inconsistent' : 'consistent'}`, detected, mode !== 'stateless',
    refused || db.problems[0] || (inconsistent ? 'the database verifies alone; only A and B comparing heads would see it' : ''));
}

// (d) A forged entry (no valid MAC) slipped into the window: the checkpointer refuses to seal over it.
{
  console.log('(d) insert a forged entry into the window');
  const { path } = await fresh(true);
  await use();
  await pool.query("INSERT INTO audit (number, at, principal, credential, kind, request_id, payload, mac) VALUES (nextval('audit_number'), 0, 'svc-0', 'cred-0', 'use', 'forged', '{}', '\\x00')");
  const cp = await Checkpointer.open(pool, keys, { memory: fileMemory(path) });
  const t = await cp.tick();
  expect('checkpointer', t.failures.length > 0, true, t.failures.join('; '));
}

// (e) The checkpointer crashes after remembering a head and before writing it: at its next start it writes it again.
// The same crash, then a writer deleting one entry of that window: refused (formal/Seal.tla, RememberFirst).
for (const tamper of [false, true]) {
  console.log(`(e) crash between remembering a head and writing it${tamper ? ', then one entry of its window deleted' : ''}`);
  const { path } = await fresh(true);
  for (let e = 0; e < 25; e += 1) await use();
  const crashing = { query: (q: string | { name: string }, p?: unknown[]) => (typeof q === 'object' && q.name === 'write_checkpoint' ? Promise.reject(new Error('crash')) : pool.query(q as string, p)) };
  const cp = await Checkpointer.open(crashing, keys, { memory: fileMemory(path) });
  await cp.tick().catch(() => {});
  if (tamper) await pool.query('DELETE FROM audit WHERE number = (SELECT max(number) FROM audit)');
  const reopened = await Checkpointer.open(pool, keys, { memory: fileMemory(path) }).then((c) => c, (e: Error) => e);
  if (tamper) expect('signer, at its next start', reopened instanceof Error, true, reopened instanceof Error ? reopened.message : '');
  else {
    const v = await verdict();
    expect('signer wrote the remembered head again; verifier', !(reopened instanceof Error) && v.ok, true, reopened instanceof Error ? reopened.message : `${v.sealed} sealed, problems: ${v.problems.length}`, ['holds', 'broken']);
  }
}

// (f) A replay: an entry copied under a fresh number before it is sealed (its MAC still holds: it does not cover the
// number). Both are sealed; the verifier sees one request logged twice.
{
  console.log('(f) copy an unsealed entry under a fresh number, then let both be sealed');
  const { path } = await fresh(true);
  await use();
  await pool.query("INSERT INTO audit (number, at, principal, credential, kind, request_id, payload, seal, mac) SELECT nextval('audit_number'), at, principal, credential, kind, request_id, payload, seal, mac FROM audit WHERE number = (SELECT max(number) FROM audit)");
  const cp = await Checkpointer.open(pool, keys, { memory: fileMemory(path) });
  const t = await cp.tick();
  const v = await verdict();
  expect(`sealed (${t.failures.length === 0 ? 'the checkpointer saw nothing' : t.failures[0]}); verifier`, !v.ok, true, v.problems[0] ?? '');
}

// Review r1's reproductions, each now caught.
{
  console.log('(g) every checkpoint row deleted; the signer restarts with its memory');
  const { path } = await fresh(true);
  await pool.query('DELETE FROM checkpoints');
  const refused = await Checkpointer.open(pool, keys, { memory: fileMemory(path) }).then(() => '', (e: Error) => e.message);
  expect('signer', refused !== '', true, refused);
  const v = await verdict();
  expect('verifier, database alone', !v.ok, true, v.problems.at(-1) ?? '');
}
{
  console.log('(h) a sealed change deleted, a forged retention entry naming the rest as kept');
  await createLog(pool);
  const cp = await Checkpointer.open(pool, keys);
  await append(pool, keys, { at: Date.now(), principal: 'svc-0', credential: null, kind: 'change', requestId: 'c-1', payload: '{"action":"access.revoke"}' });
  for (let e = 0; e < 20; e += 1) await use();
  await cp.tick();
  await pool.query("DELETE FROM audit WHERE number = 1");
  const remaining = (await pool.query("SELECT count(*)::int AS n FROM audit WHERE number <= 1")).rows[0].n;
  const fake = JSON.stringify({ action: 'audit.retention', day: 0, mode: 'number', prevCutUpto: '1', cutUpto: '1', cutSize: 1, kept: remaining, keptRoot: (await import('./src/tree.ts')).referenceHash([]).toString('base64') });
  await pool.query("INSERT INTO audit (number, at, principal, kind, request_id, payload, mac) VALUES (1, 0, 'vault', 'change', 'fake', $1, '\\x00')", [fake]);
  for (const mac of [true, false]) {
    const v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, macKey: mac ? keys.mac : undefined });
    expect(`verifier${mac ? ', with the MAC key' : ', public key only'}`, !v.ok, true, v.problems[0] ?? '');
  }
}
{
  console.log('(i) a sealed entry deleted, and every checkpoint up to the one after it');
  await fresh(true);
  const { rows: [{ number }] } = await pool.query('SELECT a.number::text FROM audit a ORDER BY a.number OFFSET 60 LIMIT 1');
  await pool.query('DELETE FROM audit WHERE number = $1', [number]);
  await pool.query('DELETE FROM checkpoints WHERE size <= 75');
  const v = await verdict();
  expect('verifier, database alone', !v.ok, true, v.problems[0] ?? '');
}
{
  console.log('(j) an equal-size fork signed by a stateless signer, then the signer with memory restarts');
  const { path } = await fresh(true);
  const { rows: [keep] } = await pool.query('SELECT c.upto::text FROM checkpoints c ORDER BY c.upto DESC OFFSET 1 LIMIT 1');
  await pool.query('DELETE FROM checkpoints WHERE upto > $1', [keep.upto]);
  await pool.query('DELETE FROM audit WHERE number = (SELECT max(number) FROM audit)');
  await use();
  const stateless = await Checkpointer.open(pool, keys);
  await stateless.tick();
  const refused = await Checkpointer.open(pool, keys, { memory: fileMemory(path) }).then(() => '', (e: Error) => e.message);
  expect('signer with memory', refused !== '', true, refused);
}
{
  console.log('(k) a change sealed by a background tick, the witness slower than the deadline');
  await createLog(pool);
  const slow: import('./src/log.ts').Witness = {
    name: 'slow', publish: async (note, proofFrom) => {
      await new Promise((r) => setTimeout(r, 1500));
      return localWitness('w', verifier, keys.witness).publish(note, proofFrom);
    },
  };
  const cp = await Checkpointer.open(pool, keys, { witnesses: [slow] });
  const n = await append(pool, keys, { at: Date.now(), principal: 'svc-0', credential: null, kind: 'change', requestId: 'k-1', payload: '{}' });
  void cp.tick();
  await new Promise((r) => setTimeout(r, 100));
  const t0 = performance.now();
  const r = await cp.sealThrough(n, 300);
  expect(`sealThrough after ${(performance.now() - t0).toFixed(0)} ms reports witnessed`, r.witnessed === true, false, r.failures[0] ?? '', ['yes', 'no']);
  await new Promise((r) => setTimeout(r, 1600));
}
{
  console.log('(l) a forged entry in the window, then a change waits for its seal');
  await createLog(pool);
  const cp = await Checkpointer.open(pool, keys);
  await pool.query("INSERT INTO audit (number, at, principal, credential, kind, request_id, payload, mac) VALUES (nextval('audit_number'), 0, 'svc-0', 'cred-0', 'use', 'forged', '{}', '\\x00')");
  const n = await append(pool, keys, { at: Date.now(), principal: 'svc-0', credential: null, kind: 'change', requestId: 'l-1', payload: '{}' });
  const failed = await Promise.race([cp.sealThrough(n, 300).then(() => 'answered', (e: Error) => e.message), new Promise<string>((r) => setTimeout(() => r('still spinning after 3 s'), 3000))]);
  expect('the change', failed.startsWith('cannot seal'), true, failed, ['fails with the alarm', 'did not fail']);
}

{
  console.log('(m) the newest checkpoint row and its entries deleted under a running signer, with no traffic after');
  await createLog(pool);
  const cp = await Checkpointer.open(pool, keys);
  for (let e = 0; e < 20; e += 1) await use();
  await cp.tick();
  const { rows: [top] } = await pool.query('SELECT c.upto::text FROM checkpoints c ORDER BY c.upto DESC LIMIT 1');
  await pool.query('DELETE FROM checkpoints WHERE upto = $1', [top.upto]);
  await pool.query('DELETE FROM audit WHERE number > 0');
  const t = await cp.tick();
  expect('the next tick', t.failures.length > 0, true, t.failures[0] ?? '');
}

// Review r2's reproductions, each now caught.
{
  console.log('(n) a replay of an entry sealed before the head an incremental check starts from');
  await createLog(pool);
  const cp = await Checkpointer.open(pool, keys);
  for (let e = 0; e < 10; e += 1) await use();
  await cp.tick();
  const head1 = await latestNote();
  await pool.query("INSERT INTO audit (number, at, principal, credential, kind, request_id, payload, seal, mac) SELECT nextval('audit_number'), at, principal, credential, kind, request_id, payload, seal, mac FROM audit WHERE number = 4");
  await cp.tick();
  const v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, from: head1 });
  expect('verifier, from the earlier head', !v.ok, true, v.problems[0] ?? '');
}
{
  console.log('(o) a fork below where the walk starts, held outside');
  await createLog(pool);
  const cp = await Checkpointer.open(pool, keys);
  for (let c = 0; c < 4; c += 1) {
    for (let e = 0; e < 10; e += 1) await use();
    await cp.tick();
  }
  const { rows: [h2] } = await pool.query('SELECT c.note FROM checkpoints c ORDER BY c.upto OFFSET 2 LIMIT 1');
  // The fork: the same place, a head over different leaves, as a stateless signer would sign after a rollback.
  const forked = parseCheckpoint((await openNote(h2.note, verifier))!);
  const { checkpointBody, signNote } = await import('./src/note.ts');
  const fork = await signNote(checkpointBody({ ...forked, root: Buffer.alloc(32, 1) }), [keys.signer]);
  const newest = await latestNote();
  let v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, from: newest, anchors: [fork] });
  expect('verifier, from the newest head', !v.ok, true, v.problems[0] ?? '');
  await pool.query('DELETE FROM checkpoints WHERE upto = $1', [forked.upto]);
  v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, from: newest, anchors: [fork] });
  expect('the same, its row deleted too', !v.ok, true, v.problems[0] ?? '');
}
{
  console.log('(p) a garbage checkpoint row, then a malformed retention entry');
  await fresh(true);
  await pool.query("INSERT INTO checkpoints (upto, size, root, note) VALUES (999999, 1, '\\x00', 'garbage')");
  let v = await verdict();
  expect('verifier returns a verdict', !v.ok, true, v.problems[0] ?? '', ['and fails', 'and passes']);
  await pool.query('DELETE FROM checkpoints WHERE upto = 999999');
  await pool.query("INSERT INTO audit (number, at, principal, kind, request_id, payload, mac) VALUES (nextval('audit_number'), 0, 'vault', 'change', 'bad-retention', '{\"action\":\"audit.retention\"}', '\\x00')");
  v = await verdict();
  expect('verifier returns a verdict', !v.ok, true, v.problems[0] ?? '', ['and fails', 'and passes']);
}
{
  console.log('(q) a witness that refuses once, then recovers, while a change waits');
  await createLog(pool);
  let refusals = 1;
  const inner = localWitness('w', verifier, keys.witness);
  const flaky: import('./src/log.ts').Witness = {
    name: 'flaky', publish: async (note, proofFrom) => (refusals-- > 0 ? { ok: false, reason: 'refused once' } : inner.publish(note, proofFrom)),
  };
  const cp = await Checkpointer.open(pool, keys, { witnesses: [flaky] });
  const n = await append(pool, keys, { at: Date.now(), principal: 'svc-0', credential: null, kind: 'change', requestId: 'q-1', payload: '{}' });
  const r = await cp.sealThrough(n, 1000);
  expect('the change', r.witnessed === true, true, `${r.cosigned.length} cosigned head(s)`, ['answers witnessed', 'answers unwitnessed']);
}
{
  console.log('(r) no witness set up');
  await createLog(pool);
  const cp = await Checkpointer.open(pool, keys);
  const n = await append(pool, keys, { at: Date.now(), principal: 'svc-0', credential: null, kind: 'change', requestId: 'r-1', payload: '{}' });
  const r = await cp.sealThrough(n);
  expect('the change answers witnessed: null', r.witnessed === null, true, '', ['yes', 'no']);
}

// Review r3's reproductions, each now caught.
{
  console.log('(s) a use copied before its day is dropped, replayed after the retention cut');
  for (const variant of ['after a tick, the rows between deleted', "into the retention entry's own tick, on a log quiet since the day closed"]) {
    await createLog(pool);
    // The demo's day lasts a second; a real one is dropped weeks later. The bound is 10 minutes, here 200 ms.
    const cp = await Checkpointer.open(pool, keys, { freshMs: 200 });
    for (let e = 0; e < 20; e += 1) await use();
    await cp.tick();
    await pool.query('DROP TABLE IF EXISTS saved; CREATE TABLE saved AS SELECT * FROM audit WHERE number = 20');
    await pool.query('SELECT new_day(1)');
    await cp.tick({ nextDay: 1 });
    await cp.tick();
    await new Promise((r) => setTimeout(r, 500));
    const { retainDay } = await import('./src/retention.ts');
    const r = await retainDay(pool, keys, 0, cp);
    if (variant.startsWith('after')) {
      await cp.tick();
      await pool.query('DELETE FROM checkpoints WHERE upto > $1', [r.retention.cutUpto]);
    }
    await pool.query("INSERT INTO audit (number, at, principal, credential, kind, request_id, payload, seal, mac) SELECT nextval('audit_number'), at, principal, credential, kind, request_id, payload, seal, mac FROM saved");
    const t = await cp.tick().catch((e: Error) => ({ failures: [e.message] }));
    expect(`${variant}: the signer`, t.failures.some((f) => /replay/.test(f)), true, t.failures.find((f) => /replay/.test(f)) ?? t.failures[0] ?? '', ['refuses to seal it', 'seals it']);
  }
}
{
  console.log('(t) a witness that always refuses: how often it is asked once the change has answered');
  await createLog(pool);
  let calls = 0;
  const refusing: import('./src/log.ts').Witness = { name: 'refusing', publish: async () => { calls += 1; return { ok: false, reason: 'no' }; } };
  const cp = await Checkpointer.open(pool, keys, { witnesses: [refusing] });
  const n = await append(pool, keys, { at: Date.now(), principal: 'svc-0', credential: null, kind: 'change', requestId: 't-1', payload: '{}' });
  await cp.sealThrough(n, 300);
  const answered = calls;
  await new Promise((r) => setTimeout(r, 700));
  expect(`asked ${answered} times until the answer, ${calls - answered} after`, calls - answered <= 1, true, '', ['stops', 'keeps asking']);
}
{
  console.log('(u) remembering a head fails once, and the checkpointer carries on');
  const { path } = await fresh(true);
  const real = fileMemory(path);
  let fail = true;
  const flaky = { last: () => real.last(), remember: async (note: string) => { if (fail) { fail = false; throw new Error('disk'); } return real.remember(note); } };
  const cp = await Checkpointer.open(pool, keys, { memory: flaky });
  for (let e = 0; e < 5; e += 1) await use();
  await cp.tick().catch(() => {});
  for (let e = 0; e < 5; e += 1) await use();
  await cp.tick();
  const v = await verdict();
  expect('the next head', v.ok, true, v.problems[0] ?? `${v.sealed} sealed`, ['holds', 'is wrong']);
}

// Review r4's reproduction.
{
  console.log('(v) writing a head fails, then putting the tree back fails too, then the database recovers');
  const { path } = await fresh(true);
  let down = false;
  const flaky = { query: (q: string | { name: string }, p?: unknown[]) => {
    if (typeof q === 'object' && q.name === 'write_checkpoint') { down = true; return Promise.reject(new Error('down')); }
    if (down && typeof q === 'object' && q.name === 'read_tiles') return Promise.reject(new Error('still down'));
    return pool.query(q as string, p);
  } };
  const cp = await Checkpointer.open(flaky, keys, { memory: fileMemory(path) });
  for (let e = 0; e < 5; e += 1) await use();
  await cp.tick().catch(() => {});
  down = false;
  for (let e = 0; e < 5; e += 1) await use();
  const again = await cp.tick().then(() => '', (e: Error) => e.message);
  expect('the same checkpointer', again !== '', true, again, ['refuses until reopened', 'signs on']);
  const reopened = await Checkpointer.open(pool, keys, { memory: fileMemory(path) });
  await reopened.tick();
  const v = await verdict();
  expect('reopened, the log', v.ok, true, v.problems[0] ?? `${v.sealed} sealed`, ['holds', 'is wrong']);
}

rmSync(scratch, { recursive: true, force: true });
await pool.end();
console.log(fails === 0 ? 'every scenario as expected' : `${fails} UNEXPECTED`);
process.exitCode = fails === 0 ? 0 : 1;
