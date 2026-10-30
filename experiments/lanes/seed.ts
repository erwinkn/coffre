// Make the prototype's database: the schema, one environment, one secret,
// `--principals` service members each granted viewer there, each grant an
// `access.grant` entry on the one chain and on the control lane alike, and
// `--lanes` empty read lanes. Synthetic keys and data.
//
//   node experiments/lanes/seed.ts --url postgresql://… [--principals 50] [--lanes 16] [--seed w194-synthetic]
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { GENESIS, sealAll, type Fields } from './src/chain.ts';
import { keysFrom, memberMac, wrap } from './src/model.ts';
import { checkpointHash, checkpointSignature, entryMac, link } from './src/simple.ts';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    principals: { type: 'string', default: '50' },
    lanes: { type: 'string', default: '16' },
    seed: { type: 'string', default: 'w194-synthetic' },
    shards: { type: 'string', default: '64' },
    // The simple design's log (W201): members sealed at the revision of their grant, which `audit` holds.
    simple: { type: 'string' },
    // Entries already in the simple log before the run: a log that has grown (R48).
    history: { type: 'string', default: '0' },
  },
});
if (values.url === undefined) throw new Error('--url names the database');
const PRINCIPALS = Number(values.principals);
const LANES = Number(values.lanes);
const SHARDS = Number(values.shards);
const ENVIRONMENT = '00000000-0000-4000-8000-000000000001';
const SECRET = '00000000-0000-4000-8000-0000000000a1';
const keys = keysFrom(values.seed);

const client = new pg.Client({ connectionString: values.url });
await client.connect();
try {
  await client.query(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  await client.query('INSERT INTO environments (id) VALUES ($1)', [ENVIRONMENT]);
  const { wrapped, iv } = wrap(keys.kek, randomBytes(32));
  await client.query("INSERT INTO secrets VALUES ($1, $2, 'secret', $3, $4)", [SECRET, ENVIRONMENT, wrapped, iv]);

  const principals = Array.from({ length: PRINCIPALS }, (_, i) => `svc-${i}`);
  const now = Date.now();
  const grants: Fields[] = principals.map((principal) => ({
    actor: 'user:root@acme.example', action: 'access.grant', decision: 'allow', subject: principal, environmentId: ENVIRONMENT,
    controlSeq: null, occurredAt: now, metadata: '{}',
  }));
  const sealed = sealAll(keys.log, 0, { nextSeq: 0n, hash: GENESIS }, grants);
  for (const [table, lane] of [['log', null], ['lane_log', 0]] as const) {
    for (const entry of sealed) {
      await client.query(
        `INSERT INTO ${table} (${lane === null ? '' : 'lane, '}seq, author, actor, action, decision, subject, environment_id, control_seq, occurred_at, metadata, prev_hash, mac, hash)
         VALUES (${lane === null ? '' : `${lane}, `}$1, 'vault', $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10, $11)`,
        [String(entry.seq), entry.fields.actor, entry.fields.action, entry.fields.decision, entry.fields.subject, entry.fields.environmentId,
          String(entry.fields.occurredAt), entry.fields.metadata, entry.prevHash, entry.mac, entry.hash],
      );
    }
  }
  const last = sealed.at(-1)!;
  await client.query('INSERT INTO head VALUES (true, $1, $2)', [String(last.seq + 1n), last.hash]);
  await client.query('INSERT INTO lanes VALUES (0, $1, $2)', [String(last.seq + 1n), last.hash]);
  for (let lane = 1; lane <= LANES; lane += 1) await client.query('INSERT INTO lanes VALUES ($1, 0, $2)', [lane, GENESIS]);
  // The shards' lanes (v5), 100 and up.
  for (let shard = 0; shard < SHARDS; shard += 1) await client.query('INSERT INTO lanes VALUES ($1, 0, $2)', [100 + shard, GENESIS]);

  // The simple log: an access.grant at revision i + 1 for each principal, as entry i + 1, then `--history` uses.
  const simple = values.simple as 'head' | 'seq' | 'cas' | undefined;
  let prev = GENESIS;
  const history = Number(values.history);
  await client.query(`
    INSERT INTO audit (seq, revision, actor, action, decision, subject, environment_id, occurred_at, metadata, mac)
    SELECT n, $1, 'svc-0', 'secret.use', 'allow', 'svc-' || (n % 100), $2, $3, '{"requestId":"history"}', sha256(n::text::bytea)
    FROM generate_series($4::bigint, $5::bigint) n`, [PRINCIPALS, ENVIRONMENT, String(now), PRINCIPALS + 1, PRINCIPALS + history]);
  for (const [i, entry] of grants.entries()) {
    const seq = String(i + 1);
    const revision = String(i + 1);
    const mac = entryMac(keys.log, simple === 'head' ? null : seq, simple === 'cas' ? prev : null, revision, entry);
    const hash = simple === 'seq' ? null : link(prev, mac);
    await client.query(
      `INSERT INTO audit (seq, revision, actor, action, decision, subject, environment_id, occurred_at, metadata, mac, prev_hash, hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [seq, revision, entry.actor, entry.action, entry.decision, entry.subject, entry.environmentId, String(entry.occurredAt), entry.metadata, mac,
        simple === 'seq' ? null : prev, hash],
    );
    if (hash !== null) prev = hash;
  }
  // History entries are not chained: a checkpoint starts after them.
  const lastSeq = String(PRINCIPALS + history);
  await client.query("INSERT INTO audit_head VALUES (true, $1, $2, $3, $4, gen_random_uuid()::text)", [String(PRINCIPALS + history + 1), prev, String(PRINCIPALS), lastSeq]);
  await client.query("SELECT setval('audit_seq', $1)", [lastSeq]);
  // The first checkpoint, empty, where the checkpointer starts: every later one tiles on from it.
  const genesis = checkpointHash(GENESIS, []);
  await client.query('INSERT INTO checkpoints VALUES ($1, $1, $2, 0, $3, $4, $5)',
    [lastSeq, String(PRINCIPALS), genesis, checkpointSignature(keys.log, lastSeq, lastSeq, String(PRINCIPALS), genesis), String(now)]);

  for (const [i, principal] of principals.entries()) {
    const member = { principal, status: 'active', role: null, access_seq: simple === undefined ? String(sealed[i]!.seq) : String(i + 1) };
    const held = [{ principal, environment_id: ENVIRONMENT, role: 'viewer' }];
    await client.query("INSERT INTO members VALUES ($1, 'active', NULL, $2, $3)", [principal, member.access_seq, memberMac(keys.row, member, held)]);
    await client.query("INSERT INTO grants VALUES ($1, $2, 'viewer')", [principal, ENVIRONMENT]);
    await client.query('INSERT INTO credentials VALUES ($1, $2)', [`cred-${principal}`, principal]);
  }
  await client.query('ANALYZE');
  console.log(`seeded ${PRINCIPALS} principals, ${LANES} lanes`);
} finally {
  await client.end();
}
