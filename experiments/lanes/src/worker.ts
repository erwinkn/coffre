import { Client } from 'pg';

import { seal, sealAll, type Fields } from './chain.ts';
import { Lane, type Env as LaneEnv, type UseResult } from './lane.ts';
import { Shard, type ShardAnswer, type ShardEnv } from './shard.ts';
import { keysFrom, memberMac, refusal, unwrap, type Grant, type Keys, type Member } from './model.ts';
import * as one from './one.ts';
import * as simple from './simple.ts';
import {
  appendChain, chainSnapshotQuery, LANES_SNAPSHOT, LOCK_HEAD, lockLane, readHead, snapshot, UNDER_HEAD, type ChainRead, type Head,
} from './sql.ts';

export { Lane, Shard };

type Env = LaneEnv & ShardEnv & { HD_CONTROL?: Hyperdrive };

/**
 * The prototype's Worker: one cold /use, the way each protocol makes it,
 * against the same database. Every request opens its own connections, as
 * coffre's do on Workers. GET /use/<protocol>?p=<principal>:
 *
 *   v0     today (0.14.2): the vault's decision, its member row FOR NO KEY
 *          UPDATE, the head SKIP LOCKED in its read, then the app's
 *          `credential.use` in a transaction of its own under the head.
 *   v1     W185's WIP: no member row lock, the head waited for in the
 *          read; the app's entry as today.
 *   v1m    v1 with the app's entry folded into the vault's: the best one
 *          chain can do, the head held for the append and its commit.
 *   v3     lanes, written by whichever call comes: the lane's head locked
 *          for one round trip.
 *   v2     lanes, each written by its Durable Object, in batches.
 *   warm   a cache hit: the caller's one statement, which reads the control
 *          lane's head too, then the isolate's cache.
 *
 *   simple W201's Postgres-only path (simple.ts): GET /simple/<head|seq|cas>/use,
 *          one read and one append; POST /simple/<head|seq>/revoke and /grant.
 *          named=1 names (prepares) the hot path's statements.
 *   one    W208's one-call path (one.ts): GET /simple/one/use, one call;
 *          POST /simple/one/revoke and /grant. cap=<n> refuses a use at once
 *          (503) while the isolate has n in flight; deadline=<ms> answers 503
 *          a use not done by then, and its call does nothing if it gets its
 *          lock later. cover=<ms>: repeats ride on this isolate's covers.
 *
 * POST /revoke?p=&mode=lanes|chain takes a principal's grant away, and
 * POST /grant gives it back, each a control decision.
 */

const ENVIRONMENT = '00000000-0000-4000-8000-000000000001';
const SECRET = '00000000-0000-4000-8000-0000000000a1';

let keys: Keys | null = null;
const keysOf = (env: Env) => (keys ??= keysFrom(env.SEED));

function laneOf(env: Env, principal: string, lanes = Number(env.LANES)): number {
  let h = 2166136261;
  for (let i = 0; i < principal.length; i += 1) h = Math.imul(h ^ principal.charCodeAt(i), 16777619) >>> 0;
  return 1 + (h % lanes);
}

async function connect(env: Env, hyperdrive: Hyperdrive = env.HD): Promise<Client> {
  const client = new Client({ connectionString: hyperdrive.connectionString });
  await client.connect();
  return client;
}

/** Statements and time a request spent, for Server-Timing. */
class Meter {
  statements = 0;
  /** Each statement's time, in the order sent. */
  readonly times: number[] = [];
  readonly started = Date.now();
  wrap(client: Client): Client {
    const query = client.query.bind(client) as (...args: unknown[]) => Promise<unknown>;
    (client as unknown as { query: unknown }).query = (...args: unknown[]) => {
      this.statements += 1;
      const began = Date.now();
      const done = query(...args);
      (done as Promise<unknown>).then(() => this.times.push(Date.now() - began), () => {});
      return done;
    };
    return client;
  }
}

class Refused extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

/** The app's reads before it asks the vault: the path, then the values there (`resolvePath`, `valuesIn`). */
async function readApp(app: Client): Promise<void> {
  await app.query('SELECT id FROM environments WHERE id = $1', [ENVIRONMENT]);
  await app.query('SELECT id, nature FROM secrets WHERE environment_id = $1', [ENVIRONMENT]);
}

/** The vault's own read of the versions it is asked to open (`store.versions`). */
async function versions(vault: Client): Promise<void> {
  await vault.query('SELECT id, wrapped, iv FROM secrets WHERE id = $1', [SECRET]);
}

function readEntry(principal: string, read: { control: string | null }, why: string | null, requestId: string): Fields {
  return {
    actor: principal, action: 'secret.read', decision: why === null ? 'allow' : 'deny', subject: principal, environmentId: ENVIRONMENT,
    controlSeq: read.control, occurredAt: Date.now(), metadata: JSON.stringify({ requestId, secretId: SECRET }),
  };
}

/** The app's `credential.use`, as `audited` writes it today: its own transaction, the head held throughout. */
async function appEntry(env: Env, app: Client, principal: string, requestId: string): Promise<void> {
  await app.query('BEGIN');
  try {
    await app.query(LOCK_HEAD);
    await app.query("SELECT seq FROM log WHERE action = 'policy.change' ORDER BY seq DESC LIMIT 1");
    await app.query('SELECT revoked FROM credentials WHERE id = $1', [`cred-${principal}`]);
    const { rows } = await app.query(UNDER_HEAD);
    const head = { nextSeq: BigInt(rows[0].next_seq), hash: rows[0].head_hash as Buffer };
    const entry = seal(keysOf(env).log, 0, head.nextSeq, head.hash, {
      actor: principal, action: 'credential.use', decision: 'allow', subject: null, environmentId: ENVIRONMENT, controlSeq: null,
      occurredAt: Number(rows[0].now), metadata: JSON.stringify({ requestId }),
    });
    await appendChain(app, 'app', [entry]);
    await app.query('COMMIT');
  } catch (error) {
    await app.query('ROLLBACK').catch(() => {});
    throw error;
  }
}

/** v0 and v1: the vault's decision on the one chain. */
async function chainDecision(env: Env, vault: Client, principal: string, requestId: string, protocol: 'v0' | 'v1'): Promise<string> {
  await vault.query('BEGIN');
  try {
    await vault.query("SET LOCAL lock_timeout = '15s'");
    if (protocol === 'v0') await vault.query('SELECT principal FROM members WHERE principal = $1 FOR NO KEY UPDATE', [principal]);
    let read = await snapshot<ChainRead>(vault, chainSnapshotQuery(protocol === 'v0' ? 'skip' : 'wait'), principal, ENVIRONMENT, SECRET);
    if (read.head === null) {
      // 0.14: held by another; wait for it, then read again holding it.
      await vault.query(LOCK_HEAD);
      read = await snapshot<ChainRead>(vault, chainSnapshotQuery('skip'), principal, ENVIRONMENT, SECRET);
    }
    const why = refusal(keysOf(env), read, ENVIRONMENT);
    const head: Head = { nextSeq: BigInt(read.head!.nextSeq), hash: Buffer.from(read.head!.hash, 'hex') };
    const key = why === null ? unwrap(keysOf(env).kek, Buffer.from(read.secret!.wrapped, 'hex'), Buffer.from(read.secret!.iv, 'hex')) : null;
    // A read that waited for the head is held to what it read in the append (W185's `unchanged`); here, by the head
    // naming the last entry it saw, which is what its re-check costs in round trips: none.
    await appendChain(vault, 'vault', [seal(keysOf(env).log, 0, head.nextSeq, head.hash, readEntry(principal, read, why, requestId))]);
    await vault.query('COMMIT');
    if (key === null) throw new Refused(why!);
    const value = key.toString('base64');
    key.fill(0);
    return value;
  } catch (error) {
    await vault.query('ROLLBACK').catch(() => {});
    throw error;
  }
}

/** v3: lanes, the lane's head locked for one round trip by the call itself. */
async function laneDecision(env: Env, vault: Client, principal: string, requestId: string): Promise<string> {
  const lane = laneOf(env, principal);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const read = await snapshot(vault, LANES_SNAPSHOT, principal, ENVIRONMENT, SECRET);
    const why = refusal(keysOf(env), read, ENVIRONMENT);
    const key = why === null ? unwrap(keysOf(env).kek, Buffer.from(read.secret!.wrapped, 'hex'), Buffer.from(read.secret!.iv, 'hex')) : null;
    const head = await lockLane(vault, lane);
    try {
      const [entry] = sealAll(keysOf(env).log, lane, head, [readEntry(principal, read, why, requestId)]);
      const { rows } = await vault.query(
        `WITH ok AS (SELECT (SELECT next_seq FROM lanes WHERE lane = 0) = $1::bigint AS ok),
         appended AS (
           INSERT INTO lane_log (lane, seq, author, actor, action, decision, subject, environment_id, control_seq, occurred_at, metadata, prev_hash, mac, hash)
           SELECT $2, $3, 'vault', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14 WHERE (SELECT ok FROM ok) RETURNING 1
         ),
         moved AS (UPDATE lanes SET next_seq = $15, head_hash = $14 WHERE lane = $2 AND (SELECT ok FROM ok) RETURNING 1)
         SELECT (SELECT ok FROM ok) AS ok`,
        [
          read.control, lane, String(entry!.seq), entry!.fields.actor, entry!.fields.action, entry!.fields.decision, entry!.fields.subject,
          entry!.fields.environmentId, entry!.fields.controlSeq, String(entry!.fields.occurredAt), entry!.fields.metadata, entry!.prevHash,
          entry!.mac, entry!.hash, String(entry!.seq + 1n),
        ],
      );
      await vault.query('COMMIT');
      if (!rows[0].ok) {
        key?.fill(0);
        continue;
      }
      if (key === null) throw new Refused(why!);
      const value = key.toString('base64');
      key.fill(0);
      return value;
    } catch (error) {
      await vault.query('ROLLBACK').catch(() => {});
      throw error;
    }
  }
  throw new Refused('changing');
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** How long a change waits for every shard to take its fence before it rolls back. */
const FENCE_DEADLINE_MS = 5_000;

/** How often a call that is not the leader looks for its entry in the chain. */
const POLL_MS = 10;

/**
 * v4's one statement a call sends each time it looks: take the leader's
 * lock if free, and with it the head if no control decision holds it, and
 * the waiting entries with whether each one's member is as it read them;
 * and whether the call's own entry is in the chain yet. It never waits.
 */
function leadQuery(id: string): string {
  if (!/^\d+$/.test(id)) throw new Error('a pending id is a number');
  return `WITH l AS (SELECT pg_try_advisory_xact_lock(194) AS got),
    h AS (SELECT next_seq, head_hash FROM head WHERE only_row AND (SELECT got FROM l) FOR UPDATE SKIP LOCKED)
    SELECT (SELECT got FROM l) AS got,
      (SELECT json_build_object('nextSeq', next_seq::text, 'hash', encode(head_hash, 'hex')) FROM h) AS head,
      (SELECT decision FROM log WHERE pending_id = ${id}) AS mine,
      -- The last entry this statement's snapshot holds: a head past it was moved by a leader that committed after the
      -- snapshot was taken, whose batch the pending rows read here still hold.
      (SELECT l.seq::text FROM log l ORDER BY l.seq DESC LIMIT 1) AS last,
      CASE WHEN EXISTS (SELECT 1 FROM h) THEN (SELECT coalesce(json_agg(x ORDER BY x.id), '[]') FROM (
        SELECT p.id::text AS id, p.actor, p.action, p.decision, p.subject, p.environment_id, p.metadata,
          (m.access_seq IS NOT DISTINCT FROM p.access_seq) AS still
        FROM pending p LEFT JOIN members m ON m.principal = p.subject ORDER BY p.id LIMIT 500) x) END AS batch`;
}

type Waiting = { id: string; actor: string; action: string; decision: 'allow' | 'deny'; subject: string | null; environment_id: string | null; metadata: string; still: boolean };

/**
 * v4: the Postgres-only leader. The call decides on an unlocked read, opens
 * the key, and leaves its entry in \`pending\`. Then it looks, every POLL_MS,
 * until its entry is in the chain: whichever call takes the leader's lock
 * chains every waiting entry in one statement, an entry whose member
 * changed since its read chained as refused, and commits.
 */
async function leaderDecision(env: Env, vault: Client, principal: string, requestId: string): Promise<string> {
  const k = keysOf(env);
  const read = await snapshot<ChainRead>(vault, chainSnapshotQuery('none'), principal, ENVIRONMENT, SECRET);
  const why = refusal(k, read, ENVIRONMENT);
  const key = why === null ? unwrap(k.kek, Buffer.from(read.secret!.wrapped, 'hex'), Buffer.from(read.secret!.iv, 'hex')) : null;
  const { rows } = await vault.query(
    `INSERT INTO pending (actor, action, decision, subject, environment_id, access_seq, metadata) VALUES ($1, 'secret.read', $2, $1, $3, $4, $5) RETURNING id::text AS id`,
    [principal, why === null ? 'allow' : 'deny', ENVIRONMENT, read.member?.access_seq ?? '-1', JSON.stringify({ requestId, secretId: SECRET })],
  );
  const id = rows[0].id as string;
  const deadline = Date.now() + 15_000;
  let open = false;
  try {
    for (;;) {
      const results = (await vault.query(`${open ? 'ROLLBACK; ' : ''}BEGIN; ${leadQuery(id)}`)) as unknown as { rows: Record<string, unknown>[] }[];
      open = true;
      const row = results.at(-1)!.rows[0]! as { got: boolean; head: { nextSeq: string; hash: string } | null; mine: string | null; last: string | null; batch: Waiting[] | null };
      if (row.mine !== null) {
        if (row.mine !== 'allow' || key === null) throw new Refused(why ?? 'changed');
        return key.toString('base64');
      }
      const current = row.head !== null && BigInt(row.head.nextSeq) === (row.last === null ? 0n : BigInt(row.last) + 1n);
      if (current && row.batch !== null && row.batch.length > 0) {
        const head = { nextSeq: BigInt(row.head.nextSeq), hash: Buffer.from(row.head.hash, 'hex') };
        const now = Date.now();
        const sealed = sealAll(k.log, 0, head, row.batch.map((w) => ({
          actor: w.actor, action: w.action, decision: w.still ? w.decision : 'deny', subject: w.subject, environmentId: w.environment_id,
          controlSeq: null, occurredAt: now, metadata: w.still ? w.metadata : JSON.stringify({ ...JSON.parse(w.metadata), code: 'changed' }),
        })));
        const last = sealed.at(-1)!;
        await vault.query(
          `WITH appended AS (
             INSERT INTO log (seq, author, actor, action, decision, subject, environment_id, control_seq, occurred_at, metadata, prev_hash, mac, hash, pending_id)
             SELECT * FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::uuid[], $8::bigint[], $9::bigint[], $10::text[], $11::bytea[], $12::bytea[], $13::bytea[], $14::bigint[])
           ),
           gone AS (DELETE FROM pending WHERE id = ANY($14::bigint[]))
           UPDATE head SET next_seq = $15, head_hash = $16 WHERE only_row`,
          [
            sealed.map((e) => String(e.seq)), sealed.map(() => 'vault'), sealed.map((e) => e.fields.actor), sealed.map((e) => e.fields.action),
            sealed.map((e) => e.fields.decision), sealed.map((e) => e.fields.subject), sealed.map((e) => e.fields.environmentId), sealed.map(() => null),
            sealed.map((e) => String(e.fields.occurredAt)), sealed.map((e) => e.fields.metadata), sealed.map((e) => e.prevHash), sealed.map((e) => e.mac),
            sealed.map((e) => e.hash), row.batch.map((w) => w.id), String(last.seq + 1n), last.hash,
          ],
        );
        await vault.query('COMMIT');
        open = false;
        continue;
      }
      // Not the leader: end the transaction now, so that no connection is held while it waits.
      void vault.query('ROLLBACK').catch(() => {});
      open = false;
      if (Date.now() > deadline) throw new Error('timed out waiting to be chained');
      await sleep(POLL_MS);
    }
  } finally {
    key?.fill(0);
    if (open) void vault.query('ROLLBACK').catch(() => {});
  }
}

/** This isolate's calls in flight to each shard: a number, settled, never a promise another call awaits. */
const inFlight = new Map<number, number>();
/** `one`: this isolate's uses with a call in flight, answered or not. */
let oneInFlight = 0;
/** `one`: this isolate's covers, for cover=<ms>. */
const oneCovers: one.Covers = { window: 0, held: new Map() };
const LATE = Symbol('late');
const ISOLATE_IN_FLIGHT = 64;

/** The isolate's value cache: a value, and the control lane's head it was opened at. */
const cache = new Map<string, { value: string; control: string }>();

/**
 * A control decision: a grant taken away (`revoke`) or given back
 * (`grant`), on the control lane or the one chain. It locks the head, then
 * the member's row, writes, and commits before it answers: a read ordered
 * after this answer is refused.
 */
async function control(env: Env, client: Client, principal: string, mode: 'lanes' | 'chain', give: boolean): Promise<{ seq: string }> {
  await client.query('BEGIN');
  try {
    const done = await controlChange(env, client, principal, give, mode);
    await client.query('COMMIT');
    return done;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  }
}

/** The grant's change, its entry on the control lane or the one chain, and the member row sealed over it: in the caller's transaction. */
async function controlChange(env: Env, client: Client, principal: string, give: boolean, mode: 'lanes' | 'chain' = 'lanes'): Promise<{ seq: string }> {
  const k = keysOf(env);
  {
    const head = mode === 'lanes'
      ? await (async () => {
          const { rows } = await client.query('SELECT next_seq::text AS next_seq, head_hash FROM lanes WHERE lane = 0 FOR UPDATE');
          return { nextSeq: BigInt(rows[0].next_seq), hash: rows[0].head_hash as Buffer };
        })()
      : await (async () => {
          const { rows } = await client.query('SELECT next_seq::text AS next_seq, head_hash FROM head WHERE only_row FOR UPDATE');
          return { nextSeq: BigInt(rows[0].next_seq), hash: rows[0].head_hash as Buffer };
        })();
    const { rows: members } = await client.query('SELECT principal, status, role, access_seq::text AS access_seq FROM members WHERE principal = $1 FOR NO KEY UPDATE', [principal]);
    const member = members[0] as Omit<Member, 'mac'>;
    const entry = seal(k.log, 0, head.nextSeq, head.hash, {
      actor: 'user:root@acme.example', action: give ? 'access.grant' : 'access.revoke', decision: 'allow', subject: principal,
      environmentId: ENVIRONMENT, controlSeq: null, occurredAt: Date.now(), metadata: '{}',
    });
    const grants: Grant[] = give ? [{ principal, environment_id: ENVIRONMENT, role: 'viewer' }] : [];
    const mac = memberMac(k.row, { ...member, access_seq: String(entry.seq) }, grants);
    const table = mode === 'lanes' ? 'lane_log' : 'log';
    await client.query(
      `WITH appended AS (
         INSERT INTO ${table} (${mode === 'lanes' ? 'lane, ' : ''}seq, author, actor, action, decision, subject, environment_id, control_seq, occurred_at, metadata, prev_hash, mac, hash)
         VALUES (${mode === 'lanes' ? '0, ' : ''}$1, 'vault', $2, $3, 'allow', $4, $5, NULL, $6, '{}', $7, $8, $9)
       ),
       grants AS (${give ? `INSERT INTO grants VALUES ($4, $5, 'viewer') ON CONFLICT DO NOTHING` : 'DELETE FROM grants WHERE principal = $4'}),
       member AS (UPDATE members SET access_seq = $1, mac = $10 WHERE principal = $4)
       UPDATE ${mode === 'lanes' ? 'lanes' : 'head'} SET next_seq = $11, head_hash = $9 WHERE ${mode === 'lanes' ? 'lane = 0' : 'only_row'}`,
      [String(entry.seq), entry.fields.actor, entry.fields.action, principal, ENVIRONMENT, String(entry.fields.occurredAt), entry.prevHash, entry.mac, entry.hash, mac, String(entry.seq + 1n)],
    );
    return { seq: String(entry.seq) };
  }
}

function answer(status: number, body: unknown, meter: Meter, extra: Record<string, string> = {}): Response {
  return Response.json(body, {
    status,
    headers: { 'server-timing': [`total;dur=${Date.now() - meter.started}`, `statements;dur=${meter.statements}`, ...meter.times.slice(0, 4).map((t, i) => `s${i + 1};dur=${t}`)].join(', '), ...extra },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const principal = url.searchParams.get('p') ?? 'svc-0';
    // r=: the load generator's id for the request, to hold its answer to the log's replay (verify-one.ts).
    const requestId = url.searchParams.get('r') ?? crypto.randomUUID();
    const meter = new Meter();
    const clients: Client[] = [];
    // Calls still running after their request was answered (a deadline): their connection closes after them.
    const lingering: Promise<unknown>[] = [];
    const open = async (hyperdrive?: Hyperdrive) => {
      const client = meter.wrap(await connect(env, hyperdrive));
      clients.push(client);
      return client;
    };
    try {
      const [, route, protocol] = url.pathname.split('/');
      // app=0 leaves out the app's own reads before the vault's: what the protocols do apart from them.
      const appReads = url.searchParams.get('app') === '0' ? async () => {} : readApp;
      if (route === 'use') {
        if (protocol === 'v0' || protocol === 'v1' || protocol === 'v1m') {
          const [app, vault] = await Promise.all([open(), open()]);
          await appReads(app);
          await versions(vault);
          const key = await chainDecision(env, vault, principal, requestId, protocol === 'v0' ? 'v0' : 'v1');
          if (protocol !== 'v1m') await appEntry(env, app, principal, requestId);
          return answer(200, { ok: true, bytes: key.length }, meter);
        }
        if (protocol === 'v3') {
          const [app, vault] = await Promise.all([open(), open()]);
          await appReads(app);
          await versions(vault);
          const key = await laneDecision(env, vault, principal, requestId);
          return answer(200, { ok: true, bytes: key.length }, meter);
        }
        if (protocol === 'v4') {
          const [app, vault] = await Promise.all([open(), open()]);
          await appReads(app);
          await versions(vault);
          const key = await leaderDecision(env, vault, principal, requestId);
          return answer(200, { ok: true, bytes: key.length }, meter);
        }
        if (protocol === 'v2') {
          if (url.searchParams.get('app') !== '0') await appReads(await open());
          // lanes=1: one sequencer for the whole instance.
          const lanes = url.searchParams.has('lanes') ? Number(url.searchParams.get('lanes')) : undefined;
          const result = await laneUse(env, principal, requestId, lanes);
          return laneAnswer(result, meter);
        }
      }
      if (route === 'warm') {
        // The caller's one statement, as `standingSession` runs on every /use, reading the control lane's head with it.
        const check = url.searchParams.get('check') ?? 'control';
        let controlSeq = 'none';
        if (check !== 'none') {
          const app = await open();
          const { rows } = await app.query(
            `SELECT c.revoked, m.status, ${check === 'control' ? '(SELECT next_seq::text FROM lanes WHERE lane = 0)' : "'none'"} AS control
             FROM credentials c JOIN members m ON m.principal = c.principal WHERE c.id = $1`,
            [`cred-${principal}`],
          );
          if (rows.length === 0 || rows[0].revoked || rows[0].status !== 'active') return answer(401, { ok: false }, meter);
          controlSeq = rows[0].control;
        }
        const hit = cache.get(principal);
        if (hit !== undefined && hit.control === controlSeq) return answer(200, { ok: true, cached: true }, meter);
        const result = await laneUse(env, principal, requestId);
        if (result.ok) cache.set(principal, { value: result.key, control: controlSeq });
        return laneAnswer(result, meter);
      }
      if (route === 'v5') {
        const shards = Number(env.SHARDS);
        const stub = (i: number) => env.SHARD.get(env.SHARD.idFromName(`shard-${i}`));
        if (protocol === 'use') {
          // fan=K spreads one principal over K shards, each fenced by every change like the rest.
          const fan = Math.max(1, Number(url.searchParams.get('fan') ?? '1'));
          const spread = fan === 1 ? 0 : Math.floor(Math.random() * fan);
          const i = (laneOf(env, principal, shards) - 1 + spread) % shards;
          // Upstream of the shard: this isolate's own calls in flight to it, bounded, so that a hot shard is refused here,
          // fast, before Cloudflare queues it.
          if ((inFlight.get(i) ?? 0) >= ISOLATE_IN_FLIGHT) return shardAnswer({ ok: false, code: 'overloaded', retryAfter: 1 }, meter);
          inFlight.set(i, (inFlight.get(i) ?? 0) + 1);
          try {
            const result = await stub(i).use(i, { principal, credential: `cred-${principal}`, environmentId: ENVIRONMENT, secretId: SECRET, requestId });
            return shardAnswer(result, meter);
          } finally {
            inFlight.set(i, inFlight.get(i)! - 1);
          }
        }
        if (protocol === 'revoke' || protocol === 'grant' || protocol === 'revoke-credential') {
          const client = await open();
          const done = await change(env, client, shards, stub, principal, protocol);
          return answer(200, { ok: true, ...done, at: Date.now() }, meter);
        }
        if (protocol === 'reset') {
          await Promise.all(Array.from({ length: shards }, (_, i) => stub(i).reset()));
          return Response.json({ ok: true });
        }
        if (protocol === 'restore') {
          // As a restore from backup would: the revision set back, and a new epoch (pass epoch=0 to keep the old one).
          const client = await open();
          const back = Number(url.searchParams.get('to') ?? '1');
          const epoch = url.searchParams.get('epoch') === '0' ? null : crypto.randomUUID();
          await client.query(`UPDATE revision SET value = $1${epoch === null ? '' : ', epoch = $2'} WHERE only_row`, epoch === null ? [back] : [back, epoch]);
          return Response.json({ ok: true, revision: back, epoch });
        }
        if (protocol === 'stats') {
          return Response.json(await Promise.all(Array.from({ length: shards }, (_, i) => stub(i).stats())));
        }
      }
      if (route === 'simple' && protocol === 'one') {
        const [, , , action] = url.pathname.split('/');
        one.nameStatements(url.searchParams.get('named') === '1');
        if (action === 'use') {
          const cap = Number(url.searchParams.get('cap') ?? '0');
          // Admission control, per isolate: refused at once, no connection opened.
          if (cap > 0 && oneInFlight >= cap) return answer(503, { ok: false, code: 'overloaded' }, meter, { 'retry-after': '1' });
          const wait = url.searchParams.has('deadline') ? Number(url.searchParams.get('deadline')) : undefined;
          const deadline = wait === undefined ? undefined : Date.now() + wait;
          oneInFlight += 1;
          const covers = url.searchParams.has('cover') ? Object.assign(oneCovers, { window: Number(url.searchParams.get('cover')) }) : undefined;
          const call = (async () => one.use(await open(), keysOf(env), { principal, credential: `cred-${principal}`, environmentId: ENVIRONMENT, secretId: SECRET, requestId }, deadline, covers))();
          const done = call.finally(() => { oneInFlight -= 1; });
          const result = wait === undefined ? await done : await Promise.race([done, sleep(wait).then((): typeof LATE => LATE)]);
          if (result === LATE) {
            lingering.push(done.catch(() => {}));
            return answer(503, { ok: false, code: 'deadline' }, meter, { 'retry-after': '1' });
          }
          if (result.ok) return answer(200, { ok: true, bytes: result.value.length, seq: result.number, ...(result.covered ? { code: 'covered' } : {}) }, meter);
          if (result.retryAfter !== undefined) return answer(503, { ok: false, code: result.code }, meter, { 'retry-after': String(result.retryAfter) });
          return answer(403, { ok: false, code: result.code, seq: result.number }, meter);
        }
        if (action === 'revoke' || action === 'grant') {
          // Changes on a Hyperdrive config of their own (HD_CONTROL, when bound and not shared=1).
          const control = await open(env.HD_CONTROL === undefined || url.searchParams.get('shared') === '1' ? env.HD : env.HD_CONTROL);
          const op: one.Op = action === 'revoke' ? { op: 'access.revoke', environment: ENVIRONMENT } : { op: 'access.grant', environment: ENVIRONMENT, role: 'viewer' };
          const done = await one.change(control, keysOf(env), principal, op);
          return answer(200, { ok: true, seq: done.number, tries: done.tries, at: Date.now() }, meter);
        }
      }
      if (route === 'simple') {
        const [, , , action] = url.pathname.split('/');
        const variant = protocol as simple.Variant;
        // A setting of the isolate, not of the request: every request of a run asks the same, so it holds for the run.
        simple.nameStatements(url.searchParams.get('named') === '1');
        // shared=1: a change on the uses' own Hyperdrive config, to measure what a config of its own saves.
        const shared = env.HD_CONTROL === undefined || url.searchParams.get('shared') === '1';
        const db = action === 'use' || shared ? await open() : (null as unknown as Client);
        if (action === 'use') {
          const result = await simple.use(db, keysOf(env), variant, { principal, credential: `cred-${principal}`, environmentId: ENVIRONMENT, secretId: SECRET, requestId });
          if (result.ok) return answer(200, { ok: true, bytes: result.value.length, seq: result.seq, tries: result.tries }, meter);
          if (result.retryAfter !== undefined) return answer(503, { ok: false, code: result.code }, meter, { 'retry-after': String(result.retryAfter) });
          return answer(403, { ok: false, code: result.code }, meter);
        }
        if (action === 'revoke' || action === 'grant') {
          // Changes on a pool of their own (HD_CONTROL, when bound): a revocation never queues behind uses for a connection.
          const control = shared ? db : await open(env.HD_CONTROL);
          const done = await simple.change(control, keysOf(env), variant === 'seq' ? 'seq' : 'head', principal, action === 'grant', ENVIRONMENT);
          return answer(200, { ok: true, ...done, at: Date.now() }, meter);
        }
      }
      if (route === 'revoke' || route === 'grant') {
        const mode = url.searchParams.get('mode') === 'chain' ? 'chain' : 'lanes';
        const done = await control(env, await open(), principal, mode, route === 'grant');
        return answer(200, { ok: true, ...done, at: Date.now() }, meter);
      }
      if (route === 'depth') {
        const lanes = await Promise.all(
          Array.from({ length: Number(env.LANES) }, (_, i) => env.LANE.get(env.LANE.idFromName(`lane-${i + 1}`)).depth()),
        );
        return Response.json(lanes);
      }
      if (route === 'forget') {
        await Promise.all(Array.from({ length: Number(env.LANES) }, (_, i) => env.LANE.get(env.LANE.idFromName(`lane-${i + 1}`)).forget()));
        cache.clear();
        return Response.json({ ok: true });
      }
      if (route === 'rtt') {
        // Where the time goes: connecting through Hyperdrive, a statement's round trip, a call to a lane, from here.
        const t0 = performance.now();
        const client = await open();
        const connectMs = performance.now() - t0;
        const selectMs: number[] = [];
        for (let i = 0; i < 5; i += 1) {
          const started = performance.now();
          await client.query('SELECT 1');
          selectMs.push(performance.now() - started);
        }
        const stub = env.LANE.get(env.LANE.idFromName(`lane-${laneOf(env, principal)}`));
        const doMs: number[] = [];
        for (let i = 0; i < 5; i += 1) {
          const started = performance.now();
          await stub.depth();
          doMs.push(performance.now() - started);
        }
        const trace = await (await fetch('https://www.cloudflare.com/cdn-cgi/trace')).text();
        return Response.json({ colo: /colo=(\w+)/.exec(trace)?.[1], connectMs, selectMs, doMs, lane: await stub.where() });
      }
      if (route === 'colo') {
        const trace = await (await fetch('https://www.cloudflare.com/cdn-cgi/trace')).text();
        return new Response(trace);
      }
      return new Response('not found', { status: 404 });
    } catch (error) {
      if (error instanceof Refused) return answer(403, { ok: false, code: error.code }, meter);
      const code = (error as { code?: string }).code;
      // 55P03: a lock wait that ran out, which coffre answers 503.
      // 55P03: a lock wait that ran out, 57014: a statement that did, 53300: no connection left; coffre answers each 503.
      const busy = code === '55P03' || code === '57014' || code === '53300';
      return answer(busy ? 503 : 500, { ok: false, code: code ?? 'error', message: String((error as Error).message).slice(0, 200) }, meter, busy ? { 'retry-after': '1' } : {});
    } finally {
      ctx.waitUntil(Promise.allSettled(lingering).then(() => Promise.all(clients.map((client) => client.end().catch(() => {})))));
    }
  },
} satisfies ExportedHandler<Env>;

function shardAnswer(result: ShardAnswer, meter: Meter): Response {
  if (result.ok) return answer(200, { ok: true, bytes: result.value.length, shard: result.shard, seq: result.seq, loaded: result.loaded }, meter);
  if (result.retryAfter !== undefined) return answer(503, { ok: false, code: result.code }, meter, { 'retry-after': String(result.retryAfter) });
  return answer(403, { ok: false, code: result.code }, meter);
}

/**
 * A change to what uses decide on, through the shards (v5): take the
 * revision's row, fence every shard at the next revision, make the change
 * and raise the revision in the same transaction, commit, answer. A shard
 * fenced answers only from standing read at the new revision, which exists
 * only once the change has committed. Rolled back, the shards are told.
 */
async function change(
  env: Env,
  client: Client,
  shards: number,
  stub: (i: number) => DurableObjectStub<Shard>,
  principal: string,
  kind: 'revoke' | 'grant' | 'revoke-credential',
): Promise<{ revision: number; fenceMs: number }> {
  await client.query('BEGIN');
  let fenced: number | null = null;
  try {
    await client.query("SET LOCAL statement_timeout = '5s'");
    // The fence phase is no statement: bound the transaction itself, whatever it waits on.
    await client.query("SET LOCAL idle_in_transaction_session_timeout = '10s'");
    const { rows } = await client.query('SELECT value::text AS value, epoch FROM revision WHERE only_row FOR UPDATE');
    const next = Number(rows[0].value) + 1;
    const started = Date.now();
    fenced = next;
    // Each fence retried (they are idempotent and only raise the floor), all of them within a deadline.
    const fence = async (i: number) => {
      for (let attempt = 1; ; attempt += 1) {
        try {
          return await stub(i).fence(i, rows[0].epoch, next);
        } catch (error) {
          if (attempt >= 4 || Date.now() - started > FENCE_DEADLINE_MS) throw error;
          await sleep(25 * attempt);
        }
      }
    };
    await Promise.race([
      Promise.all(Array.from({ length: shards }, (_, i) => fence(i))),
      sleep(FENCE_DEADLINE_MS).then(() => { throw new Error('the shards did not all take the fence in time'); }),
    ]);
    const fenceMs = Date.now() - started;
    if (kind === 'revoke-credential') {
      await client.query('UPDATE credentials SET revoked = true WHERE principal = $1', [principal]);
    } else {
      await controlChange(env, client, principal, kind === 'grant');
    }
    await client.query('UPDATE revision SET value = $1 WHERE only_row', [next]);
    await client.query('COMMIT');
    return { revision: next, fenceMs };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    if (fenced !== null) await Promise.all(Array.from({ length: shards }, (_, i) => stub(i).unfence(fenced!).catch(() => {})));
    throw error;
  }
}

async function laneUse(env: Env, principal: string, requestId: string, lanes?: number): Promise<UseResult> {
  const lane = laneOf(env, principal, lanes);
  const stub = env.LANE.get(env.LANE.idFromName(`lane-${lane}`));
  return stub.use(lane, { principal, environmentId: ENVIRONMENT, secretId: SECRET, requestId });
}

function laneAnswer(result: UseResult, meter: Meter): Response {
  const timing = `read;dur=${result.t.read}, queued;dur=${result.t.queued}, tries;dur=${result.t.tries}`;
  if (result.ok) return answer(200, { ok: true, bytes: result.key.length, lane: result.lane, seq: result.seq }, meter, { 'x-lane-timing': timing });
  if (result.retryAfter !== undefined) {
    return answer(503, { ok: false, code: result.code }, meter, { 'retry-after': String(result.retryAfter), 'x-lane-timing': timing });
  }
  return answer(403, { ok: false, code: result.code }, meter, { 'x-lane-timing': timing });
}
