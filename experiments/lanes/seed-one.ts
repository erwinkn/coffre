// Make variant `one`'s database (W208, W211): schema-one.sql, a partition of
// uses per day, and the state, made by changes through `change_input` as any
// change is, so that a replay starts from them: the bulk cap's limits, one
// environment, `--secrets` secrets in it, `--principals` members each granted
// viewer there, each with a credential (svc-1's expiring `--expire-after`
// seconds from now, so that a replay must decide at each entry's time). Then
// `--history` uses before them, in the days before today (synthetic, not
// MAC'd: the log a long-lived instance has), and the first checkpoint after
// them all. Synthetic keys and data.
//
// The uses' login, `--login`, gets the hot path's limits on its role:
// statements that wait longer for a lock than `--lock-timeout`, or run
// longer than `--statement-timeout`, fail (503) rather than run on after
// their Worker gave up; and generic plans (below).
//
//   node experiments/lanes/seed-one.ts --url postgresql://… [--principals 100] [--secrets 1] [--history 0] [--history-days 10]
//     [--expire-after 60] [--bulk-count 1000] [--bulk-window-ms 900000] [--bulk-refresh-ms …]
//     [--login w208_vault] [--lock-timeout 1s] [--statement-timeout 2s]
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom, wrap } from './src/model.ts';
import { change, checkpointHash, checkpointSignature, credentialId, ENVIRONMENT, limits, secretId } from './src/one.ts';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    principals: { type: 'string', default: '100' },
    secrets: { type: 'string', default: '1' },
    seed: { type: 'string', default: 'w194-synthetic' },
    history: { type: 'string', default: '0' },
    'history-days': { type: 'string', default: '10' },
    'expire-after': { type: 'string' },
    'bulk-count': { type: 'string', default: '1000' },
    'bulk-window-ms': { type: 'string', default: '900000' },
    'bulk-refresh-ms': { type: 'string' },
    login: { type: 'string', default: 'w208_vault' },
    password: { type: 'string', default: 'local-dev-only' },
    'lock-timeout': { type: 'string', default: '1s' },
    'statement-timeout': { type: 'string', default: '2s' },
  },
});
if (values.url === undefined) throw new Error('--url names the database');
const PRINCIPALS = Number(values.principals);
const SECRETS = Number(values.secrets);
const HISTORY = Number(values.history);
const HISTORY_DAYS = Number(values['history-days']);
const keys = keysFrom(values.seed);
const DAY = 86_400_000;
const cap = limits(Number(values['bulk-count']), Number(values['bulk-window-ms']), values['bulk-refresh-ms'] === undefined ? undefined : Number(values['bulk-refresh-ms']));

const client = new pg.Client({ connectionString: values.url });
await client.connect();
try {
  await client.query(readFileSync(new URL('./schema-one.sql', import.meta.url), 'utf8'));
  const now = Date.now();
  const today = Math.floor(now / DAY) * DAY;
  for (let day = today - HISTORY_DAYS * DAY; day <= today + 2 * DAY; day += DAY) {
    await client.query('SELECT make_day($1::date)', [new Date(day).toISOString().slice(0, 10)]);
  }

  // History: uses spread over the days before today, not MAC'd, numbered before everything else; the
  // first checkpoint starts after them all.
  const perDay = Math.ceil(HISTORY / Math.max(1, HISTORY_DAYS));
  for (let d = 0; d < HISTORY_DAYS && HISTORY > 0; d += 1) {
    const count = Math.min(perDay, HISTORY - d * perDay);
    if (count <= 0) break;
    const dayStart = today - (HISTORY_DAYS - d) * DAY;
    await client.query(`
      INSERT INTO uses (number, at, request_id, credential, secret, mac)
      SELECT nextval('entry_number'), $1::bigint + (i * ($2::bigint / $3::bigint)), i, gen_random_uuid(), $4::uuid, substring(sha256(i::text::bytea) FROM 1 FOR 16)
      FROM generate_series(1, $3::bigint) i`, [String(dayStart), String(DAY), String(count), secretId(0)]);
    process.stdout.write(`history day ${d + 1}/${HISTORY_DAYS}: ${count}\n`);
  }

  // The state, as the changes that made it.
  const expiring = values['expire-after'] === undefined ? null : now + Number(values['expire-after']) * 1000;
  let changes = 0;
  const made = async (object: string, op: Parameters<typeof change>[3]) => {
    changes += 1;
    await change(client, keys, object, op, { requestId: `seed-${changes}`, at: now });
  };
  await made('config:bulk', { op: 'bulk.limit', ...cap });
  await made(`environment:${ENVIRONMENT}`, { op: 'environment.create' });
  for (let j = 0; j < SECRETS; j += 1) {
    const { wrapped, iv } = wrap(keys.kek, randomBytes(32));
    await made(`secret:${secretId(j)}`, { op: 'secret.create', environment: ENVIRONMENT, nature: 'secret', wrapped: wrapped.toString('hex'), iv: iv.toString('hex') });
  }
  for (let i = 0; i < PRINCIPALS; i += 1) {
    const principal = `svc-${i}`;
    await made(`member:${principal}`, { op: 'member.add', status: 'active', role: null });
    await made(`member:${principal}`, { op: 'access.grant', environment: ENVIRONMENT, role: 'viewer' });
    await made(`credential:${credentialId(i)}`, { op: 'credential.issue', principal, expiresAt: i === 1 && expiring !== null ? String(expiring) : null });
  }

  const { rows: [{ last }] } = await client.query("SELECT pg_sequence_last_value('entry_number')::text AS last");
  const genesis = checkpointHash(Buffer.alloc(32), []);
  // The floor of `at` (schema-one.sql makes its row) starts below every use to come; the first barrier raises it.
  await client.query('INSERT INTO checkpoints SELECT $1, $1, 0, $2, $3, at_floor, $4 FROM fence',
    [last, genesis, checkpointSignature(keys.log, last, last, genesis), String(now)]);

  // The uses' login, with the hot path's limits.
  const login = values.login;
  await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${login}') THEN CREATE ROLE ${login} LOGIN; END IF; END $$`);
  await client.query(`ALTER ROLE ${login} PASSWORD '${values.password}'`);
  await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${login}`);
  await client.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${login}`);
  await client.query(`ALTER ROLE ${login} SET lock_timeout = '${values['lock-timeout']}'`);
  await client.query(`ALTER ROLE ${login} SET statement_timeout = '${values['statement-timeout']}'`);
  // One generic plan per connection for use_credential's statement, made again only when a table it reads is
  // analyzed or vacuumed (fence and bulk, about once a minute): its custom plans cost ~1.6 ms each to make, unloaded,
  // and auto mode makes five per connection after every such invalidation (measured: 411 plans in 15 s at 1,000/s).
  await client.query(`ALTER ROLE ${login} SET plan_cache_mode = 'force_generic_plan'`);
  // As autovacuum leaves a settled instance: statistics, and the visibility map that lets a use read each
  // input's newest change from the index alone.
  await client.query('VACUUM ANALYZE');
  console.log(`seeded ${PRINCIPALS} principals, ${SECRETS} secrets, ${changes} changes, ${HISTORY} history entries; bulk cap ${cap.count} keys per ${cap.windowMs} ms (refresh ${cap.refreshMs}); genesis checkpoint at ${last}${expiring === null ? '' : `; svc-1's credential expires at ${new Date(expiring).toISOString()}`}`);
} finally {
  await client.end();
}
