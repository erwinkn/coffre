// The simple design's log (W201), verified from the database alone: the
// checkpoints tile (each starts where the one before ended), each one's hash
// is the entries it covers, chained to the one before, and its signature is
// the vault's; every entry under them carries its MAC (and for `head` its
// link). Entries above the last checkpoint are not sealed yet: their MACs are
// checked and they are counted, nothing more can be said of them.
//
//   node experiments/lanes/verify-simple.ts --url postgresql://… --variant seq
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import { checkpointHash, checkpointSignature, ENTRIES, verifyEntries, type AuditRow } from './src/simple.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, variant: { type: 'string', default: 'seq' }, seed: { type: 'string', default: 'w194-synthetic' } } });
const mode = values.variant as 'head' | 'seq';
const keys = keysFrom(values.seed);
const client = new pg.Client({ connectionString: values.url });
await client.connect();
const started = performance.now();
const failures: string[] = [];
try {
  const { rows: checkpoints } = await client.query('SELECT upto::text, from_seq::text, revision::text, entries, hash, signature FROM checkpoints c ORDER BY c.upto');
  if (checkpoints.length === 0) throw new Error('no checkpoint');
  const [genesis, ...rest] = checkpoints;
  if (genesis.from_seq !== genesis.upto || genesis.entries !== 0) failures.push('the first checkpoint is not an empty one');
  if (!checkpointSignature(keys.log, genesis.from_seq, genesis.upto, genesis.revision, genesis.hash).equals(genesis.signature)) failures.push('genesis: signature');
  let prev = genesis;
  let tip: Buffer | null = null;
  let sealed = 0;
  for (const c of rest) {
    if (c.from_seq !== prev.upto) failures.push(`checkpoint ${c.upto}: starts at ${c.from_seq}, not at ${prev.upto}`);
    const { rows } = await client.query(ENTRIES, [c.from_seq, c.upto]);
    const entries = rows as AuditRow[];
    if (entries.length !== c.entries) failures.push(`checkpoint ${c.upto}: ${entries.length} entries, signed ${c.entries}`);
    failures.push(...verifyEntries(keys, mode, tip, entries).map((f) => `checkpoint ${c.upto}: ${f}`));
    const hash = checkpointHash(prev.hash, entries);
    if (!hash.equals(c.hash)) failures.push(`checkpoint ${c.upto}: hash`);
    if (!checkpointSignature(keys.log, c.from_seq, c.upto, c.revision, c.hash).equals(c.signature)) failures.push(`checkpoint ${c.upto}: signature`);
    if (mode === 'head' && entries.length > 0) tip = entries.at(-1)!.hash;
    sealed += entries.length;
    prev = c;
  }
  const { rows: open } = await client.query(ENTRIES, [prev.upto, '9223372036854775807']);
  failures.push(...verifyEntries(keys, mode, tip, open as AuditRow[]).map((f) => `unsealed: ${f}`));
  console.log(`${checkpoints.length} checkpoints tiling ${genesis.upto}..${prev.upto}, ${sealed} entries sealed, ${open.length} above the last checkpoint, verified in ${(performance.now() - started).toFixed(0)} ms: ${failures.length === 0 ? 'all hold' : `${failures.length} FAILURES: ${failures.slice(0, 8).join('; ')}`}`);
  process.exitCode = failures.length === 0 ? 0 : 1;
} finally {
  await client.end();
}
