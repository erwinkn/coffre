// Make variant `one`'s database (W208): schema-one.sql, a partition of uses
// per day, and the state as change entries a replay starts from: one
// environment and one secret, `--principals` members each granted viewer
// there, each with a credential (svc-1's expiring `--expire-after` seconds
// from now, so that a replay must decide at each entry's time). Then
// `--history` uses before them, in the days before today (synthetic, not
// MAC'd: the log a long-lived instance has), and the first checkpoint after
// them all. Synthetic keys and data.
//
// The uses' login, `--login`, gets the hot path's limits on its role:
// statements that wait longer for the fence than `--lock-timeout`, or run
// longer than `--statement-timeout`, fail (503) rather than run on after
// their Worker gave up.
//
//   node experiments/lanes/seed-one.ts --url postgresql://… [--principals 100] [--history 0] [--history-days 10]
//     [--expire-after 60] [--login w208_vault] [--lock-timeout 1s] [--statement-timeout 2s]
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom, wrap } from './src/model.ts';
import { checkpointHash, checkpointSignature, entryMac, memberSeal, type Grant } from './src/one.ts';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    principals: { type: 'string', default: '100' },
    seed: { type: 'string', default: 'w194-synthetic' },
    history: { type: 'string', default: '0' },
    'history-days': { type: 'string', default: '10' },
    'expire-after': { type: 'string' },
    login: { type: 'string', default: 'w208_vault' },
    password: { type: 'string', default: 'local-dev-only' },
    'lock-timeout': { type: 'string', default: '1s' },
    'statement-timeout': { type: 'string', default: '2s' },
  },
});
if (values.url === undefined) throw new Error('--url names the database');
const PRINCIPALS = Number(values.principals);
const HISTORY = Number(values.history);
const HISTORY_DAYS = Number(values['history-days']);
const ENVIRONMENT = '00000000-0000-4000-8000-000000000001';
const SECRET = '00000000-0000-4000-8000-0000000000a1';
const keys = keysFrom(values.seed);
const DAY = 86_400_000;

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
      INSERT INTO entries (number, at, kind, principal, credential, request_id, payload, mac)
      SELECT nextval('entry_number'), $1::bigint + (i * ($2::bigint / $3::bigint)), 'use', 'svc-' || (i % 100), 'cred-svc-' || (i % 100), 'history-' || i,
        '{"environment":"${ENVIRONMENT}","secret":"${SECRET}"}', sha256(i::text::bytea)
      FROM generate_series(1, $3::bigint) i`, [String(dayStart), String(DAY), String(count)]);
    process.stdout.write(`history day ${d + 1}/${HISTORY_DAYS}: ${count}\n`);
  }

  // The state, as the changes that made it.
  let n = 0;
  const changes: { principal: string; credential: string | null; payload: object; seal: Buffer | null }[] = [];
  changes.push({ principal: 'root', credential: null, payload: { op: 'environment.create', environment: ENVIRONMENT }, seal: null });
  changes.push({ principal: 'root', credential: null, payload: { op: 'secret.create', secret: SECRET, environment: ENVIRONMENT, nature: 'secret' }, seal: null });
  const expiring = values['expire-after'] === undefined ? null : now + Number(values['expire-after']) * 1000;
  const sealed: { principal: string; seal: Buffer }[] = [];
  for (let i = 0; i < PRINCIPALS; i += 1) {
    const principal = `svc-${i}`;
    const member = { principal, status: 'active', role: null };
    const held: Grant[] = [{ environment_id: ENVIRONMENT, role: 'viewer' }];
    const seal = memberSeal(keys.row, member, held);
    changes.push({ principal, credential: null, payload: { op: 'member.add', status: 'active', role: null }, seal: memberSeal(keys.row, member, []) });
    changes.push({ principal, credential: null, payload: { op: 'access.grant', environment: ENVIRONMENT, role: 'viewer' }, seal });
    const expiresAt = i === 1 && expiring !== null ? String(expiring) : null;
    changes.push({ principal, credential: `cred-${principal}`, payload: { op: 'credential.issue', credential: `cred-${principal}`, expiresAt }, seal });
    sealed.push({ principal, seal });
  }
  await client.query('BEGIN');
  for (const c of changes) {
    n += 1;
    const payload = JSON.stringify(c.payload);
    const requestId = `seed-${n}`;
    const mac = entryMac(keys.log, { at: now, kind: 'change', principal: c.principal, credential: c.credential, requestId, payload, seal: c.seal });
    await client.query(
      "INSERT INTO entries (number, at, kind, principal, credential, request_id, payload, seal, mac) VALUES (nextval('entry_number'), $1, 'change', $2, $3, $4, $5, $6, $7)",
      [String(now), c.principal, c.credential, requestId, payload, c.seal, mac]);
  }
  // The rows those changes leave.
  await client.query('INSERT INTO environments (id) VALUES ($1)', [ENVIRONMENT]);
  const { wrapped, iv } = wrap(keys.kek, randomBytes(32));
  await client.query("INSERT INTO secrets VALUES ($1, $2, 'secret', $3, $4)", [SECRET, ENVIRONMENT, wrapped, iv]);
  for (const [i, { principal, seal }] of sealed.entries()) {
    await client.query("INSERT INTO members VALUES ($1, 'active', NULL, $2)", [principal, seal]);
    await client.query("INSERT INTO grants VALUES ($1, $2, 'viewer')", [principal, ENVIRONMENT]);
    await client.query('INSERT INTO credentials VALUES ($1, $2, false, $3)', [`cred-${principal}`, principal, i === 1 && expiring !== null ? String(expiring) : null]);
  }
  await client.query('COMMIT');

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
  await client.query('ANALYZE');
  console.log(`seeded ${PRINCIPALS} principals, ${changes.length} changes, ${HISTORY} history entries; genesis checkpoint at ${last}${expiring === null ? '' : `; svc-1's credential expires at ${new Date(expiring).toISOString()}`}`);
} finally {
  await client.end();
}
