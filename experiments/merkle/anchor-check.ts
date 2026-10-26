// The Cloudflare anchors against the log bench.ts left (W209): the R2 archive
// under its bucket lock and the Durable Object witness. Checks that the log
// verifies against both, that the archive refuses an overwrite and a delete,
// then attacks the database (a tail cut, then a rollback re-sealed by a
// stateless signer: a split view) and checks what each anchor catches.
//
//   node experiments/merkle/anchor-check.ts --url postgresql://… --anchor https://coffre-w209-anchor.….workers.dev
import { parseArgs } from 'node:util';

import pg from 'pg';

import { append, Checkpointer, keysFrom } from './src/log.ts';
import { verifyLog } from './src/verify.ts';
import { httpArchive, httpWitness } from './src/witness.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, anchor: { type: 'string' } } });
const A = values.anchor!;
const pool = new pg.Pool({ connectionString: values.url, max: 4 });
const keys = await keysFrom('w209-synthetic');
const get = async (path: string) => (await fetch(`${A}${path}`)).text();
const archived = async () => (JSON.parse(await get('/archive')) as { keys: string[] }).keys;

const heads = async () => {
  const keys = await archived();
  return { keys, newest: await get(`/archive?key=${encodeURIComponent(keys.at(-1)!)}`), witness: await get('/witness') };
};
let h = await heads();
console.log(`archive: ${h.keys.length} heads, newest ${h.keys.at(-1)}`);
let v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, macKey: keys.mac, anchors: [h.newest, h.witness] });
console.log(`verifier against the archive's newest head and the witness's: ${v.ok ? 'holds' : v.problems.join('; ')} (${v.checkpoints} checkpoints, ${v.sealed} entries, ${v.ms.toFixed(0)} ms)`);
console.log(`overwrite the newest archived head (no precondition, only the lock): ${await get(`/archive?key=${encodeURIComponent(h.keys.at(-1)!)}&overwrite=1`)}`);
console.log(`delete it: ${(await (await fetch(`${A}/archive?key=${encodeURIComponent(h.keys.at(-1)!)}`, { method: 'DELETE' })).text())}`);
console.log(`after both, still the signed head: ${(await get(`/archive?key=${encodeURIComponent(h.keys.at(-1)!)}`)) === h.newest}`);
console.log(`archive the same head again: ${(await (await fetch(`${A}/archive`, { method: 'PUT', body: h.newest })).text())}`);

// A split view: roll back three checkpoints, drop one entry, and let a stateless signer seal again, publishing.
const { rows: [keep] } = await pool.query('SELECT c.upto::text FROM checkpoints c ORDER BY c.upto DESC OFFSET 3 LIMIT 1');
const { rows: [victim] } = await pool.query('SELECT a.number::text FROM audit a WHERE a.number > $1 ORDER BY a.number OFFSET 7 LIMIT 1', [keep.upto]);
await pool.query('DELETE FROM checkpoints WHERE upto > $1', [keep.upto]);
await pool.query('DELETE FROM audit WHERE number = $1', [victim.number]);
v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, macKey: keys.mac });
console.log(`rolled back 3 checkpoints, deleted ${victim.number}: database alone ${v.ok ? 'holds (a consistent shorter log)' : 'fails'}`);
v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, anchors: [h.newest] });
console.log(`  against the archive's newest head: ${v.ok ? 'holds' : `caught: ${v.problems[0]}`}`);
const stateless = await Checkpointer.open(pool, keys, { witnesses: [httpWitness('do-witness', `${A}/witness`), httpArchive('r2-archive', `${A}/archive`)] });
for (let i = 0; i < 3; i += 1) await append(pool, keys, { at: Date.now(), principal: 'svc-x', credential: 'cred-x', kind: 'use', requestId: `split-${i}`, payload: '{}' });
const t = await stateless.tick({ witnessTimeoutMs: 10_000 });
console.log(`  a stateless signer seals again (${t.size} leaves at ${t.upto}) and publishes: ${t.failures.length === 0 ? 'accepted everywhere' : t.failures.join('; ')}`);
h = await heads();
const all = await Promise.all(h.keys.slice(-8).map((k) => get(`/archive?key=${encodeURIComponent(k)}`)));
v = await verifyLog(pool, { verifierKey: keys.signer.verifierKey, anchors: all });
console.log(`  verifier against the archive's 8 newest heads: ${v.ok ? 'holds' : `caught: ${v.problems.slice(0, 2).join('; ')}`}`);
await pool.end();
