// Why `use_credential` is a function and not one statement (W208),
// deterministically, in a scratch database: a change holds the lock
// exclusive; a use for svc-0 starts and waits for it; the change revokes
// svc-0's grant and commits; then the use gets the lock. It must see the
// revocation. Two ways to write the use, each started the moment Postgres
// shows it waiting for the lock (pg_locks), not after a sleep:
//
//   bare CTE   `WITH l AS (SELECT pg_advisory_xact_lock_shared(…)) INSERT … SELECT … FROM l`, then the
//              reads: one statement, whose one snapshot is from before the wait. Allows (wrong).
//   function   use_credential: the lock, then the reads and the insert in a statement of their own,
//              with a snapshot from after the lock. Refuses.
//
// Either way the use's number is above the revocation's, so a replay of the
// log refuses it: the bare CTE is a use the log says was refused and that
// released the value.
//
// Then a replayed call (its answer lost, sent again as it was): a use's
// retry (through one.use, with the same request id and time) fails on its
// (at, request_id) and answers 503 `replayed` (it must not decide again); a
// change's retry (one.change with the same request) answers its number;
// neither writes a second entry. Last, a use whose `at` is below the floor
// the last barrier set writes nothing (else a checkpoint could miss it).
//
//   node experiments/lanes/fence-one.ts --url postgresql://user:password@host:port/db (a server where a scratch database may be made)
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import { change, decide, entryMac, use, usePayload, type View } from './src/one.ts';

const { values } = parseArgs({ options: { url: { type: 'string' } } });
if (values.url === undefined) throw new Error('--url names a database on the server to use');
const scratch = new URL(values.url);
scratch.pathname = '/w208_fence';
const ENVIRONMENT = '00000000-0000-4000-8000-000000000001';
const SECRET = '00000000-0000-4000-8000-0000000000a1';
const keys = keysFrom('w194-synthetic');

const BARE = `
  WITH l AS MATERIALIZED (SELECT pg_advisory_xact_lock_shared(208) AS locked),
  e AS (
    INSERT INTO entries (number, at, kind, principal, credential, request_id, payload, mac)
    SELECT nextval('entry_number'), $4, 'use', $1, $2, $3, $5, $6 FROM l
    RETURNING number
  )
  SELECT json_build_object(
    'number', e.number::text,
    'member', (SELECT json_build_object('principal', principal, 'status', status, 'role', role, 'seal', encode(seal, 'hex')) FROM members WHERE principal = $1),
    'grants', (SELECT coalesce(json_agg(json_build_object('environment_id', environment_id, 'role', role)), '[]') FROM grants WHERE principal = $1),
    'lastSeal', (SELECT encode(seal, 'hex') FROM entries_changes WHERE principal = $1 ORDER BY number DESC LIMIT 1),
    'credential', (SELECT json_build_object('principal', principal, 'revoked', revoked, 'expiresAt', expires_at::text) FROM credentials WHERE id = $2),
    'environment', (SELECT json_build_object('id', id, 'deleted', deleted) FROM environments WHERE id = ($5::json->>'environment')::uuid),
    'secret', (SELECT json_build_object('id', id, 'environmentId', environment_id, 'nature', nature) FROM secrets WHERE id = ($5::json->>'secret')::uuid)
  ) AS v FROM e`;

const admin = new pg.Client({ connectionString: values.url });
await admin.connect();
await admin.query('DROP DATABASE IF EXISTS w208_fence');
await admin.query('CREATE DATABASE w208_fence');

let wrong = 0;
try {
  const input = { principal: 'svc-0', credential: 'cred-svc-0', environmentId: ENVIRONMENT, secretId: SECRET };
  for (const way of ['bare CTE', 'function'] as const) {
    execFileSync(process.execPath, [new URL('./seed-one.ts', import.meta.url).pathname, '--url', scratch.toString(), '--principals', '2'], { stdio: 'ignore' });
    const changer = new pg.Client({ connectionString: scratch.toString() });
    const user = new pg.Client({ connectionString: scratch.toString() });
    const watch = new pg.Client({ connectionString: scratch.toString() });
    await Promise.all([changer.connect(), user.connect(), watch.connect()]);
    const { rows: [{ pid }] } = await user.query('SELECT pg_backend_pid() AS pid');
    await changer.query('BEGIN');
    await changer.query('SELECT pg_advisory_xact_lock(208)');
    // The use starts now, and waits for the lock.
    const requestId = `fence-${way}`;
    const used: Promise<{ number: string; allowed: boolean; code: string | null }> =
      way === 'function'
        ? use(user, keys, { ...input, requestId }).then((a) => ({ number: a.number ?? '?', allowed: a.ok, code: a.ok ? null : a.code }))
        : (async () => {
            const at = Date.now();
            const payload = usePayload(input);
            const mac = entryMac(keys.log, { at, kind: 'use', principal: input.principal, credential: input.credential, requestId, payload, seal: null });
            const { rows: [{ v }] } = await user.query(BARE, [input.principal, input.credential, requestId, String(at), payload, mac]);
            const code = decide(keys, v as View, input, at);
            return { number: v.number, allowed: code === null, code };
          })();
    for (;;) {
      const { rows: [w] } = await watch.query('SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted) AS waiting', [pid]);
      if (w.waiting) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    // The revocation, under the lock this transaction holds already, then its commit.
    const revoked = await change(changer, keys, 'svc-0', { op: 'access.revoke', environment: ENVIRONMENT });
    await changer.query('COMMIT');
    const got = await used;
    const after = BigInt(got.number) > BigInt(revoked.number);
    const holds = !got.allowed;
    if (holds !== (way === 'function')) wrong += 1;
    console.log(`${way.padEnd(9)} revocation #${revoked.number} committed while the use waited; the use is #${got.number} (${after ? 'after it' : 'BEFORE it'}) and was ${got.allowed ? 'ALLOWED: it read the grant as of before the wait' : `refused (${got.code})`}${holds === (way === 'function') ? '' : '  UNEXPECTED'}`);
    await Promise.all([changer.end(), user.end(), watch.end()]);
  }
  // Replays.
  execFileSync(process.execPath, [new URL('./seed-one.ts', import.meta.url).pathname, '--url', scratch.toString(), '--principals', '2'], { stdio: 'ignore' });
  const db = new pg.Client({ connectionString: scratch.toString() });
  await db.connect();
  // Through the API, as a Worker retrying a request whose answer it lost: the same request id and time.
  const at = Date.now();
  const request = { ...input, requestId: 'replay-1', at };
  const first = await use(db, keys, request);
  const again = await use(db, keys, request);
  const revoke = { op: 'credential.revoke', credential: 'cred-svc-1' } as const;
  const c1 = (await change(db, keys, 'svc-1', revoke, { requestId: 'replay-2', at })).number;
  const c2 = (await change(db, keys, 'svc-1', revoke, { requestId: 'replay-2', at })).number;
  const { rows: [{ uses, changes }] } = await db.query("SELECT count(*) FILTER (WHERE request_id = 'replay-1')::int AS uses, count(*) FILTER (WHERE request_id = 'replay-2')::int AS changes FROM entries");
  const replays = !again.ok && again.code === 'replayed' && c1 === c2 && uses === 1 && changes === 1;
  if (!replays) wrong += 1;
  console.log(`replay   a use retried answered ${again.ok ? 'a fresh decision' : again.code} (the first is #${first.number}); a change's #${c2} (first #${c1}); entries: ${uses} use, ${changes} change${replays ? '' : '  UNEXPECTED'}`);
  // A retry that comes after its deadline answers `late`, and writes nothing more: the first entry stands.
  const lateAt = Date.now() - 2_900;
  const lateRequest = { ...input, requestId: 'replay-late', at: lateAt };
  const early = await use(db, keys, lateRequest);
  await new Promise((resolve) => setTimeout(resolve, 300));
  const tooLate = await use(db, keys, lateRequest);
  const { rows: [{ n: lateEntries }] } = await db.query("SELECT count(*)::int AS n FROM entries WHERE request_id = 'replay-late'");
  const lateHolds = early.number !== undefined && !tooLate.ok && tooLate.code === 'late' && lateEntries === 1;
  if (!lateHolds) wrong += 1;
  console.log(`late     a use retried after its deadline answered ${tooLate.ok ? 'a fresh decision' : tooLate.code} (the first is #${early.number}); entries: ${lateEntries}${lateHolds ? '' : '  UNEXPECTED'}`);
  // The floor of `at`, as a barrier taken before Postgres's clock stepped back leaves it: above the
  // time of a use whose deadline still passes. The use must write nothing, or a checkpoint would miss it.
  await db.query('UPDATE fence SET at_floor = $1', [String(Date.now() + 60_000)]);
  const below = await use(db, keys, { ...input, requestId: 'floor-1' });
  const { rows: [{ n: floored }] } = await db.query("SELECT count(*)::int AS n FROM entries WHERE request_id = 'floor-1'");
  const floorHolds = !below.ok && below.code === 'late' && floored === 0;
  if (!floorHolds) wrong += 1;
  console.log(`floor    a use below the barrier's floor of \`at\` answered ${below.ok ? 'allowed' : below.code}, entries: ${floored}${floorHolds ? '' : '  UNEXPECTED'}`);
  // With no floor row at all, a use is refused, not written where no checkpoint would look.
  await db.query('DELETE FROM fence');
  const unfenced = await use(db, keys, { ...input, requestId: 'floor-2' });
  const { rows: [{ n: unfencedEntries }] } = await db.query("SELECT count(*)::int AS n FROM entries WHERE request_id = 'floor-2'");
  const unfencedHolds = !unfenced.ok && unfenced.code === 'late' && unfencedEntries === 0;
  if (!unfencedHolds) wrong += 1;
  console.log(`no floor a use with no floor row answered ${unfenced.ok ? 'allowed' : unfenced.code}, entries: ${unfencedEntries}${unfencedHolds ? '' : '  UNEXPECTED'}`);
  await db.end();
} finally {
  await admin.query('DROP DATABASE IF EXISTS w208_fence WITH (FORCE)');
  await admin.end();
}
process.exitCode = wrong === 0 ? 0 : 1;
