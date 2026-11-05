// Walk every chain in the prototype's database and check each entry's MAC
// and hash, lane by lane, and the one chain: what a full verification costs,
// and whether the load left any entry out of place.
//
//   node experiments/lanes/verify.ts --url postgresql://… [--seed w194-synthetic]
import { parseArgs } from 'node:util';

import pg from 'pg';

import { GENESIS, verify, type Sealed } from './src/chain.ts';
import { keysFrom } from './src/model.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, seed: { type: 'string', default: 'w194-synthetic' } } });
const keys = keysFrom(values.seed);
const client = new pg.Client({ connectionString: values.url });
await client.connect();

type Row = {
  seq: string; actor: string; action: string; decision: 'allow' | 'deny'; subject: string | null; environment_id: string | null;
  control_seq: string | null; occurred_at: string; metadata: string; prev_hash: Buffer; mac: Buffer; hash: Buffer;
};
const sealedOf = (lane: number, row: Row): Sealed => ({
  lane, seq: BigInt(row.seq), prevHash: row.prev_hash, mac: row.mac, hash: row.hash,
  fields: {
    actor: row.actor, action: row.action, decision: row.decision, subject: row.subject, environmentId: row.environment_id,
    controlSeq: row.control_seq, occurredAt: Number(row.occurred_at), metadata: row.metadata,
  },
});

try {
  const started = performance.now();
  let total = 0;
  const failures: string[] = [];
  const { rows: lanes } = await client.query('SELECT lane, next_seq::text AS next_seq, head_hash FROM lanes ORDER BY lane');
  for (const { lane, next_seq: next, head_hash: head } of lanes) {
    const { rows } = await client.query('SELECT *, seq::text AS seq FROM lane_log l WHERE lane = $1 ORDER BY l.seq', [lane]);
    const entries = (rows as Row[]).map((row) => sealedOf(lane, row));
    const result = verify(keys.log, lane, GENESIS, entries);
    if (!result.ok) failures.push(`lane ${lane}: entry ${result.seq} ${result.why}`);
    const last = entries.at(-1);
    if (String(entries.length) !== next || (last !== undefined && !last.hash.equals(head))) failures.push(`lane ${lane}: head does not name its last entry`);
    // Gaps: seqs run 0..n-1.
    if (entries.some((entry, i) => entry.seq !== BigInt(i))) failures.push(`lane ${lane}: a gap`);
    total += entries.length;
  }
  // Every read names a control head that existed: the decision was made under a head the control lane had.
  // Lanes 1-99 (v2) name the control lane's head; shard lanes (100 and up, v5) name the revision.
  const { rows: [{ ahead }] } = await client.query(`SELECT count(*)::int AS ahead FROM lane_log WHERE
    (lane BETWEEN 1 AND 99 AND control_seq > (SELECT next_seq FROM lanes WHERE lane = 0))
    OR (lane >= 100 AND control_seq > (SELECT value FROM revision WHERE only_row))`);
  if (ahead > 0) failures.push(`${ahead} reads name a control head ahead of the control lane`);
  const { rows: chain } = await client.query("SELECT *, seq::text AS seq FROM log l ORDER BY l.seq");
  const one = verify(keys.log, 0, GENESIS, (chain as Row[]).map((row) => sealedOf(0, row)));
  if (!one.ok) failures.push(`the one chain: entry ${one.seq} ${one.why}`);
  console.log(`${lanes.length} lanes, ${total} lane entries, ${chain.length} chain entries, verified in ${(performance.now() - started).toFixed(0)} ms: ${failures.length === 0 ? 'all hold' : failures.join('; ')}`);
  process.exitCode = failures.length === 0 ? 0 : 1;
} finally {
  await client.end();
}
