// Variant `one` on Postgres (W208, W211), deterministically, each case in a
// scratch database seeded by seed-one.ts. Every wait is seen in pg_locks, not
// slept through. Exits non-zero if any case goes otherwise.
//
// 1. Why `use_credential` is a function and not one statement: a change holds
//    the lock exclusive; a use starts and waits for it; the change revokes
//    the grant and commits; then the use gets the lock and must see the
//    revocation.
//      bare CTE   `WITH l AS (SELECT pg_advisory_xact_lock_shared(…)) INSERT … SELECT … FROM l`, then the
//                 reads: one statement, whose one snapshot is from before the wait. Allows (wrong).
//      function   use_credential: the lock, then the reads and the insert in a statement of their own,
//                 with a snapshot from after the lock. Refuses.
//    Either way the use's number is above the revocation's, so a replay of
//    the log refuses it: the bare CTE is a use the log says was refused and
//    that released the value.
// 2. Replays: a use's retry (the same request id and time) answers 503
//    `replayed` (it must not decide again); a change's retry answers its
//    number, another change under its id is refused; a use retried after
//    its deadline answers `late`; a use whose `at` is below the floor the
//    last barrier set, or with no floor row at all, writes nothing.
// 3. Rollback of each decision input (W211): a change to the member (its
//    grant revoked), a credential (revoked), a secret (its key rotated) and an
//    environment (deleted); then a database writer puts each row back as it
//    was before, validly sealed. A use must be refused `stale` (without the
//    seal check: allowed, or released the old key), the isolate's seal cache
//    warm from after the change. The verifier must flag
//    each row, and each live answer the replay disagrees with.
// 4. The bulk cap at count 10 over a day (R52): ten keys, the eleventh
//    refused `bulk`, repeats of the ten still allowed (on a cover too); six
//    new keys at once with room for two admit exactly two; the replay
//    agrees with every answer. Then a 1.5 s window: a key refused, then
//    admitted once the window, its refresh and the deadline have passed.
// 5. Covers (W211): after a change to any of a use's four inputs, the next
//    repeat is an entry of its own; so is one whose key's bulk row is stale.
//    With the isolate's seal cache, as the Worker runs: its seals are from
//    before the change, which the statement sees and probes again.
// 6. The deadline in Postgres (R54): a use that waits for its principal's
//    lock past its deadline rolls back and writes nothing.
//
//   node experiments/lanes/fence-one.ts --url postgresql://user:password@host:port/db (a server where a scratch database may be made)
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom, wrap } from './src/model.ts';
import {
  change, credentialId, decide, ENVIRONMENT, limits, newRequestId, sealCache, secretId, use, useMac, viewOf, type Covers, type Limits, type UseInput, type UseRow,
} from './src/one.ts';

const { values } = parseArgs({ options: { url: { type: 'string' } } });
if (values.url === undefined) throw new Error('--url names a database on the server to use');
const scratch = new URL(values.url);
scratch.pathname = '/w208_fence';
const keys = keysFrom('w194-synthetic');
const here = (file: string) => new URL(file, import.meta.url).pathname;
const seed = (...args: string[]) => execFileSync(process.execPath, [here('./seed-one.ts'), '--url', scratch.toString(), ...args], { stdio: 'ignore' });
const verify = (outcomes: string) => spawnSync(process.execPath, [here('./verify-one.ts'), '--url', scratch.toString(), '--outcomes', outcomes], { encoding: 'utf8' }).stdout;
// A use's deadline: 3 s after its own time, so that a retry keeps the first's.
const deadline = (u: UseInput) => u.at! + 3000;
const input = (i: number, j = 0): UseInput => ({ credential: credentialId(i), secretId: secretId(j), requestId: newRequestId(), at: Date.now() });
const until = async (db: pg.Client, pid: number) => {
  for (;;) {
    const { rows: [w] } = await db.query('SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted) AS waiting', [pid]);
    if (w.waiting) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
};
const connect = async () => {
  const c = new pg.Client({ connectionString: scratch.toString() });
  await c.connect();
  return c;
};

// The use as one statement: the same reads, in a statement that takes the lock in a CTE (its snapshot is older).
const BARE = `
  WITH l AS MATERIALIZED (SELECT pg_advisory_xact_lock_shared(208) AS locked),
  e AS (
    INSERT INTO uses (number, at, request_id, credential, secret, mac)
    SELECT nextval('entry_number'), $3, $4, $1, $2, $5 FROM l
    RETURNING number
  )
  SELECT e.number::text, NULL AS covered, c.principal, c.revoked AS c_revoked, c.expires_at::text AS c_expires, c.seal AS c_seal,
    (SELECT x.seal FROM changes x WHERE x.object = 'credential:' || $1 ORDER BY x.number DESC LIMIT 1) AS c_last,
    m.status AS m_status, m.role AS m_role, m.seal AS m_seal,
    (SELECT x.seal FROM changes x WHERE x.object = 'member:' || c.principal ORDER BY x.number DESC LIMIT 1) AS m_last,
    (SELECT array_agg(g.environment_id::text || ':' || g.role) FROM grants g WHERE g.principal = c.principal) AS grants,
    s.environment_id::text AS s_environment, s.nature AS s_nature, s.wrapped AS s_wrapped, s.iv AS s_iv, s.seal AS s_seal,
    (SELECT x.seal FROM changes x WHERE x.object = 'secret:' || $2 ORDER BY x.number DESC LIMIT 1) AS s_last,
    v.deleted AS e_deleted, v.seal AS e_seal,
    (SELECT x.seal FROM changes x WHERE x.object = 'environment:' || s.environment_id ORDER BY x.number DESC LIMIT 1) AS e_last,
    true AS in_set, 0 AS others
  FROM e, credentials c JOIN members m ON m.principal = c.principal, secrets s JOIN environments v ON v.id = s.environment_id
  WHERE c.id = $1 AND s.id = $2`;

const admin = new pg.Client({ connectionString: values.url });
await admin.connect();
await admin.query('DROP DATABASE IF EXISTS w208_fence');
await admin.query('CREATE DATABASE w208_fence');

let wrong = 0;
const check = (holds: boolean, line: string) => {
  if (!holds) wrong += 1;
  console.log(`${line}${holds ? '' : '  UNEXPECTED'}`);
};
const answer = (a: { ok: boolean; code?: string; number?: string; covered?: true }) => (a.ok ? `allowed #${a.number}${a.covered ? ' (covered)' : ''}` : `${a.code}${a.number === undefined ? '' : ` #${a.number}`}`);

try {
  // 1. The bare CTE and the function.
  const cap = limits();
  for (const way of ['bare CTE', 'function'] as const) {
    seed('--principals', '2');
    const [changer, user, watch] = await Promise.all([connect(), connect(), connect()]);
    const { rows: [{ pid }] } = await user.query('SELECT pg_backend_pid() AS pid');
    await changer.query('BEGIN');
    await changer.query('SELECT pg_advisory_xact_lock(208)');
    const request = input(0);
    const used: Promise<{ number: string; allowed: boolean; code: string | null }> =
      way === 'function'
        ? use(user, keys, request, deadline(request), cap).then((a) => ({ number: a.number ?? '?', allowed: a.ok, code: a.ok ? null : a.code }))
        : (async () => {
            const at = request.at!;
            const mac = useMac(keys.log, { at, requestId: request.requestId, credential: request.credential, secret: request.secretId });
            const { rows: [r] } = await user.query(BARE, [request.credential, request.secretId, String(at), request.requestId, mac]);
            const code = decide(keys, viewOf(r as UseRow, request), request, at, cap);
            return { number: r.number, allowed: code === null, code };
          })();
    await until(watch, pid);
    // The revocation, under the lock this transaction holds already, then its commit.
    const revoked = await change(changer, keys, 'member:svc-0', { op: 'access.revoke', environment: ENVIRONMENT });
    await changer.query('COMMIT');
    const got = await used;
    const after = BigInt(got.number) > BigInt(revoked.number);
    check(!got.allowed === (way === 'function'),
      `${way.padEnd(9)} revocation #${revoked.number} committed while the use waited; the use is #${got.number} (${after ? 'after it' : 'BEFORE it'}) and was ${got.allowed ? 'ALLOWED: it read the grant as of before the wait' : `refused (${got.code})`}`);
    await Promise.all([changer.end(), user.end(), watch.end()]);
  }

  // 2. Replays, the deadline, the floor.
  seed('--principals', '2');
  {
    const db = await connect();
    const request = input(0);
    const first = await use(db, keys, request, deadline(request), cap);
    const again = await use(db, keys, request, deadline(request), cap);
    const at = Date.now();
    const revoke = { op: 'credential.revoke' } as const;
    const c1 = (await change(db, keys, `credential:${credentialId(1)}`, revoke, { requestId: 'replay-2', at })).number;
    const c2 = (await change(db, keys, `credential:${credentialId(1)}`, revoke, { requestId: 'replay-2', at })).number;
    const other = await change(db, keys, 'member:svc-1', { op: 'access.revoke', environment: ENVIRONMENT }, { requestId: 'replay-2', at }).then(
      () => 'accepted', (error: Error) => (/names another change/.test(error.message) ? 'refused' : error.message));
    const { rows: [{ uses }] } = await db.query('SELECT count(*)::int AS uses FROM uses WHERE request_id = $1', [request.requestId]);
    const { rows: [{ changes }] } = await db.query("SELECT count(*)::int AS changes FROM changes WHERE request_id = 'replay-2'");
    check(!again.ok && again.code === 'replayed' && c1 === c2 && other === 'refused' && uses === 1 && changes === 1,
      `replay   a use retried answered ${answer(again)} (the first ${answer(first)}); a change's #${c2} (first #${c1}), another change under its id ${other}; entries: ${uses} use, ${changes} change`);
    // A create whose answer was lost, retried with its request: its number, one entry (review r1).
    const creates: [string, Parameters<typeof change>[3]][] = [
      ['member:svc-9', { op: 'member.add', status: 'active', role: null }],
      [`credential:${credentialId(9)}`, { op: 'credential.issue', principal: 'svc-9', expiresAt: null }],
      ['environment:00000000-0000-4000-8000-000000000009', { op: 'environment.create' }],
      [`secret:${secretId(9)}`, { op: 'secret.create', environment: ENVIRONMENT, nature: 'secret', wrapped: 'aa', iv: 'bb' }],
    ];
    const retried: string[] = [];
    for (const [object, op] of creates) {
      const req = { requestId: `create-${object}`, at: Date.now() };
      const one = (await change(db, keys, object, op, req)).number;
      const two = await change(db, keys, object, op, req).then((d) => d.number, (error: Error) => error.message);
      const { rows: [{ n }] } = await db.query('SELECT count(*)::int AS n FROM changes WHERE request_id = $1', [req.requestId]);
      retried.push(`${op.op} #${one} → ${two === one ? 'its number' : two}${n === 1 ? '' : `, ${n} entries`}`);
    }
    check(retried.every((r) => r.endsWith('its number')), `creates  retried with their request: ${retried.join('; ')}`);
    // A retry after its deadline answers `late` and writes nothing more.
    const old = { ...input(0), at: Date.now() - 2_900 };
    const early = await use(db, keys, old, old.at + 3000, cap);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const tooLate = await use(db, keys, old, old.at + 3000, cap);
    const { rows: [{ n: lateEntries }] } = await db.query('SELECT count(*)::int AS n FROM uses WHERE request_id = $1', [old.requestId]);
    check(early.number !== undefined && !tooLate.ok && tooLate.code === 'late' && lateEntries === 1,
      `late     a use retried after its deadline answered ${answer(tooLate)} (the first ${answer(early)}); entries: ${lateEntries}`);
    // A deadline more than 3 s after the use's time: refused, nothing written.
    const long = input(0);
    const tooLong = await use(db, keys, long, long.at! + 3001, cap);
    check(!tooLong.ok && tooLong.code === 'late', `deadline a use whose deadline is 3,001 ms after its time answered ${answer(tooLong)}`);
    // The floor of `at`, as a barrier taken before Postgres's clock stepped back leaves it.
    await db.query('UPDATE fence SET at_floor = $1', [String(Date.now() + 60_000)]);
    const low = input(0);
    const below = await use(db, keys, low, deadline(low), cap);
    const { rows: [{ n: floored }] } = await db.query('SELECT count(*)::int AS n FROM uses WHERE at > $1', [String(Date.now() - 1000)]);
    check(!below.ok && below.code === 'late', `floor    a use below the barrier's floor of \`at\` answered ${answer(below)}`);
    await db.query('DELETE FROM fence');
    const bare = input(0);
    const unfenced = await use(db, keys, bare, deadline(bare), cap);
    check(!unfenced.ok && unfenced.code === 'late', `no floor a use with no floor row answered ${answer(unfenced)} (uses in the last second: ${floored})`);
    await db.end();
  }

  // 3. Rollback of each input, put back by a database writer with no key.
  seed('--principals', '8', '--secrets', '4');
  {
    const db = await connect();
    // The environment case on an environment of its own, with a secret and a grant there.
    const ENV2 = '00000000-0000-4000-8000-000000000002';
    await change(db, keys, `environment:${ENV2}`, { op: 'environment.create' });
    const { wrapped, iv } = wrap(keys.kek, Buffer.alloc(32, 7));
    await change(db, keys, `secret:${secretId(9)}`, { op: 'secret.create', environment: ENV2, nature: 'secret', wrapped: wrapped.toString('hex'), iv: iv.toString('hex') });
    await change(db, keys, 'member:svc-5', { op: 'access.grant', environment: ENV2, role: 'viewer' });
    const fresh = wrap(keys.kek, Buffer.alloc(32, 9));
    const cases = [
      { what: 'member (grant revoked)', table: 'members', where: "principal = 'svc-2'", user: input(2, 0), also: 'grants', alsoWhere: "principal = 'svc-2'",
        change: () => change(db, keys, 'member:svc-2', { op: 'access.revoke', environment: ENVIRONMENT }) },
      { what: 'credential (revoked)', table: 'credentials', where: `id = '${credentialId(3)}'`, user: input(3, 0),
        change: () => change(db, keys, `credential:${credentialId(3)}`, { op: 'credential.revoke' }) },
      { what: 'secret (key rotated)', table: 'secrets', where: `id = '${secretId(1)}'`, user: input(4, 1),
        change: () => change(db, keys, `secret:${secretId(1)}`, { op: 'secret.rotate', wrapped: fresh.wrapped.toString('hex'), iv: fresh.iv.toString('hex') }) },
      { what: 'environment (deleted)', table: 'environments', where: `id = '${ENV2}'`, user: input(5, 9),
        change: () => change(db, keys, `environment:${ENV2}`, { op: 'environment.delete' }) },
    ];
    const live: object[] = [];
    const unsealed: object[] = [];
    // The isolate's seal cache, warm after the change: the use after the put-back takes the cached path.
    const seals = sealCache();
    for (const c of cases) {
      // The rows as they are now, validly sealed; the change; then the writer puts them back.
      const { rows: before } = await db.query(`SELECT * FROM ${c.table} WHERE ${c.where}`);
      const alsoBefore = c.also === undefined ? [] : (await db.query(`SELECT * FROM ${c.also} WHERE ${c.alsoWhere}`)).rows;
      await c.change();
      const warm = { ...c.user, requestId: newRequestId(), at: Date.now() };
      await use(db, keys, warm, deadline(warm), cap, undefined, seals);
      const cols = Object.keys(before[0]);
      await db.query(`UPDATE ${c.table} SET ${cols.map((k, i) => `${k} = $${i + 1}`).join(', ')} WHERE ${c.where}`, cols.map((k) => before[0][k]));
      for (const g of alsoBefore) await db.query(`INSERT INTO ${c.also} VALUES (${Object.keys(g).map((_, i) => `$${i + 1}`).join(', ')})`, Object.values(g));
      const u = { ...c.user, at: Date.now() };
      const got = await use(db, keys, u, deadline(u), cap, undefined, seals);
      // The same read decided without the seal check: what an unsealed input lets through.
      const look = { ...u, requestId: newRequestId(), at: Date.now() };
      const { rows: [r] } = await db.query('SELECT * FROM use_credential($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9)',
        [look.credential, look.secretId, look.requestId, String(look.at), useMac(keys.log, { at: look.at, requestId: look.requestId, credential: look.credential, secret: look.secretId }),
          String(look.at + 3000), cap.count, String(cap.windowMs), String(cap.refreshMs)]);
      const without = decide(keys, viewOf(r as UseRow, u), u, Date.now(), cap, false);
      live.push({ requestId: u.requestId, status: got.ok ? 200 : 403, code: got.ok ? 'ok' : got.code });
      unsealed.push({ requestId: u.requestId, status: without === null ? 200 : 403, code: without ?? 'ok' });
      check(!got.ok && got.code === 'stale' && got.cached === true,
        `rollback ${c.what.padEnd(22)} put back: the use answered ${answer(got)}${got.cached ? ' (seals from the cache)' : ' (NOT from the cache)'}; without the seal check: ${without === null ? 'ALLOWED' : without}`);
    }
    // A row deleted outright (no earlier version put back): `stale` too, not a refusal the log would give.
    await db.query('DELETE FROM credentials WHERE id = $1', [credentialId(6)]);
    const del = { ...input(6, 0), at: Date.now() };
    const deleted = await use(db, keys, del, deadline(del), cap, undefined, seals);
    check(!deleted.ok && deleted.code === 'stale', `deleted  a credential row deleted outright: the use answered ${answer(deleted)}`);
    await db.end();
    const outcomes = (rows: object[]) => {
      const file = `${process.env.HOME}/scratch/w211/fence-${rows === live ? 'live' : 'unsealed'}.jsonl`;
      writeFileSync(file, rows.map((o) => JSON.stringify(o)).join('\n') + '\n');
      return file;
    };
    const sealedOut = verify(outcomes(live));
    const flagged = (/(\d+) row\(s\) not the log's/.exec(sealedOut) ?? [])[1];
    const disagree = (/(\d+) disagree/.exec(sealedOut) ?? [])[1];
    // Each row put back named, and the credential deleted; no entry's MAC wrong.
    const named = ['member svc-2:', `credential ${credentialId(3)}:`, `secret ${secretId(1)}:`, `environment ${ENV2}:`, `credential ${credentialId(6)}: the log has it`];
    const all = named.every((n) => sealedOut.includes(n)) && !/: mac/.test(sealedOut);
    check(all && disagree === '4', `rollback verifier: ${flagged} rows not the log's, naming the 4 put back and the 1 deleted${all ? '' : ' (NOT all named)'}; live 'stale' answers the replay disagrees with: ${disagree} of 4`);
    const unsealedOut = verify(outcomes(unsealed));
    const disagreeUnsealed = (/(\d+) disagree/.exec(unsealedOut) ?? [])[1];
    // Unsealed, the secret put back is allowed live and in the replay alike (with the old key): only the rows show it.
    check(disagreeUnsealed === '3', `rollback without the seal check: the replay disagrees with ${disagreeUnsealed} of 4 live answers (the old secret's agrees: only the row audit shows it)`);
  }

  // 4. The bulk cap, count 10 over a day.
  seed('--principals', '4', '--secrets', '16', '--bulk-count', '10', '--bulk-window-ms', '86400000');
  {
    const day = limits(10, 86_400_000);
    const outcomes: object[] = [];
    const record = (u: UseInput, a: { ok: boolean; code?: string; number?: string; covered?: true }) => {
      outcomes.push({ requestId: u.requestId, status: a.ok ? 200 : a.code === 'late' || a.code === 'replayed' ? 503 : 403, code: a.ok ? 'ok' : a.code, number: a.number ?? null, covered: a.covered ?? false });
      return a;
    };
    const db = await connect();
    const covers: Covers = { window: 60_000, held: new Map() };
    const first: string[] = [];
    for (let j = 0; j < 10; j += 1) {
      const u = input(0, j);
      first.push(answer(record(u, await use(db, keys, u, deadline(u), day, covers))));
    }
    const u11 = input(0, 10);
    const eleventh = record(u11, await use(db, keys, u11, deadline(u11), day, covers));
    const repeats: string[] = [];
    for (const j of [3, 3, 9]) {
      const u = input(0, j);
      repeats.push(answer(record(u, await use(db, keys, u, deadline(u), day, covers))));
    }
    check(first.every((a) => a.startsWith('allowed')) && !eleventh.ok && eleventh.code === 'bulk' && repeats.every((a) => a.startsWith('allowed')) && repeats.some((a) => a.includes('covered')),
      `bulk     10 keys: ${first.filter((a) => a.startsWith('allowed')).length} allowed; the 11th ${answer(eleventh)}; repeats ${repeats.join(', ')}`);
    // Six new keys at once, with room for two.
    for (let j = 0; j < 8; j += 1) {
      const u = input(1, j);
      record(u, await use(db, keys, u, deadline(u), day));
    }
    const conns = await Promise.all(Array.from({ length: 6 }, connect));
    const burst = await Promise.all(conns.map(async (c, k) => {
      const u = input(1, 8 + k);
      return record(u, await use(c, keys, u, deadline(u), day));
    }));
    await Promise.all(conns.map((c) => c.end()));
    const admitted = burst.filter((a) => a.ok).length;
    check(admitted === 2 && burst.filter((a) => !a.ok && a.code === 'bulk').length === 4,
      `bulk     6 new keys at once with 8 of 10 held: ${admitted} admitted, ${burst.filter((a) => !a.ok).map((a) => a.code).join(', ')}`);
    await db.end();
    const file = `${process.env.HOME}/scratch/w211/fence-bulk.jsonl`;
    writeFileSync(file, outcomes.map((o) => JSON.stringify(o)).join('\n') + '\n');
    const out = verify(file);
    check(/all hold/.test(out), `bulk     verifier: ${out.split('\n').filter((l) => /agree|all hold|FAILURES|rows:/.test(l)).map((l) => l.trim()).join(' | ')}`);
  }
  seed('--principals', '2', '--secrets', '4', '--bulk-count', '2', '--bulk-window-ms', '1500', '--bulk-refresh-ms', '150');
  {
    const short = limits(2, 1500, 150);
    const db = await connect();
    const outcomes: object[] = [];
    const go = async (j: number) => {
      const u = input(0, j);
      const a = await use(db, keys, u, deadline(u), short);
      outcomes.push({ requestId: u.requestId, status: a.ok ? 200 : 403, code: a.ok ? 'ok' : a.code });
      return answer(a);
    };
    const seen = [await go(0), await go(1), await go(2)];
    await new Promise((resolve) => setTimeout(resolve, 4800));
    seen.push(await go(2));
    await db.end();
    const file = `${process.env.HOME}/scratch/w211/fence-window.jsonl`;
    writeFileSync(file, outcomes.map((o) => JSON.stringify(o)).join('\n') + '\n');
    const out = verify(file);
    check(seen[0]!.startsWith('allowed') && seen[1]!.startsWith('allowed') && seen[2]!.startsWith('bulk') && seen[3]!.startsWith('allowed') && /all hold/.test(out),
      `window   count 2 over 1.5 s: ${seen.slice(0, 3).join(', ')}; 4.8 s later (the window, its refresh and the 3 s deadline) the third key ${seen[3]}; verifier: ${/all hold/.test(out) ? 'all hold' : out}`);
  }

  // 5. Covers end with a change to any input, or a stale bulk row.
  seed('--principals', '2', '--secrets', '2', '--bulk-refresh-ms', '400');
  {
    const db = await connect();
    const c = limits(1000, 900_000, 400);
    const covers: Covers = { window: 60_000, held: new Map() };
    const seals = sealCache();
    const at = async () => {
      const u = input(0, 0);
      return answer(await use(db, keys, u, deadline(u), c, covers, seals));
    };
    const rotated = wrap(keys.kek, Buffer.alloc(32, 3));
    const steps: [string, () => Promise<unknown>][] = [
      ['member', async () => { await change(db, keys, 'member:svc-0', { op: 'access.grant', environment: ENVIRONMENT, role: 'editor' }); }],
      ['credential', async () => {
        await change(db, keys, `credential:${credentialId(0)}`, { op: 'credential.revoke' });
        await change(db, keys, `credential:${credentialId(0)}`, { op: 'credential.restore' });
      }],
      ['secret', async () => { await change(db, keys, `secret:${secretId(0)}`, { op: 'secret.rotate', wrapped: rotated.wrapped.toString('hex'), iv: rotated.iv.toString('hex') }); }],
      ['environment', async () => {
        await change(db, keys, `environment:${ENVIRONMENT}`, { op: 'environment.delete' });
        await change(db, keys, `environment:${ENVIRONMENT}`, { op: 'environment.restore' });
      }],
      ['bulk row stale', () => new Promise((resolve) => setTimeout(resolve, 450))],
      // As a restore to before the cover was written: its entry is gone, so a repeat is an entry of its own (review r1).
      ['cover entry gone', async () => { await db.query('DELETE FROM uses WHERE number = $1', [covers.held.values().next().value!.number]); }],
    ];
    const lines: string[] = [];
    let holds = true;
    await at();
    for (const [what, step] of steps) {
      const covered = await at();
      await step();
      const next = await at();
      holds &&= covered.includes('covered') && next.startsWith('allowed') && !next.includes('covered');
      lines.push(`${what}: ${covered} → ${next}`);
    }
    check(holds, `covers   ${lines.join('; ')}`);
    await db.end();
  }

  // A seal cache from a log made again (a restore, a reseed): the same numbers, other changes. It must not be used.
  {
    seed('--principals', '2', '--secrets', '1');
    const db = await connect();
    const seals = sealCache();
    const u0 = input(0, 0);
    await use(db, keys, u0, deadline(u0), cap, undefined, seals);
    await db.end();
    seed('--principals', '2', '--secrets', '1', '--expire-after', '600');
    const again = await connect();
    // svc-1's credential differs in this log (it expires); svc-0's rows are as before, and its use must not read old seals either.
    const u1 = input(0, 0);
    const got = await use(again, keys, u1, deadline(u1), cap, undefined, seals);
    await again.end();
    check(got.ok && got.cached === undefined, `remade   a use with a seal cache from a log made again answered ${answer(got)}${got.cached ? ' from the OLD cache' : ', the cache refreshed'}`);
  }

  // 6. The deadline holds in Postgres: a use waiting for its principal's lock past its deadline writes nothing.
  seed('--principals', '2', '--secrets', '2');
  {
    const [holder, user, watch] = await Promise.all([connect(), connect(), connect()]);
    const { rows: [{ pid }] } = await user.query('SELECT pg_backend_pid() AS pid');
    await holder.query('BEGIN');
    await holder.query("SELECT pg_advisory_xact_lock(209, hashtext('svc-0'))");
    const u = input(0, 1);
    const pending = use(user, keys, u, u.at! + 300, limits());
    await until(watch, pid);
    await new Promise((resolve) => setTimeout(resolve, 500));
    await holder.query('COMMIT');
    const got = await pending;
    const { rows: [{ n }] } = await watch.query('SELECT count(*)::int AS n FROM uses WHERE request_id = $1', [u.requestId]);
    check(!got.ok && got.code === 'late' && n === 0, `deadline a use held 500 ms past its 300 ms deadline by its principal's lock answered ${answer(got)}; entries: ${n}`);
    await Promise.all([holder.end(), user.end(), watch.end()]);
  }
} finally {
  await admin.query('DROP DATABASE IF EXISTS w208_fence WITH (FORCE)');
  await admin.end();
}
process.exitCode = wrong === 0 ? 0 : 1;
