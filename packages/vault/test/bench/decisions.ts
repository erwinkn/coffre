// What vault decisions cost under concurrent load, as on Workers: each call
// its own Postgres connection (`HyperdrivePool`), each statement a round trip
// to a database far away. Locally a statement answers in well under a
// millisecond, which hides every queue; here a relay delays each chunk by
// half the round trip either way, so a lock held across round trips is held
// as long as it would be through Hyperdrive. It reports each call's wall
// time once connected, p50 and p99, its statements, and the time its
// statements spent in the database beyond the round trip: waiting on
// locks, almost all of it.
//
// Two shapes. Callers that each read, then read again as soon as answered,
// as one service or a service each (`--callers`). Or reads arriving at a
// rate from one service, whoever is answered (`--rate`, for `--seconds`), as
// a backend's calls through the credential proxy with its cache lapsed, each
// read followed, with `--app`, by the app's own entry for it, in a
// transaction that holds the head as `audited` does: the head, the policy,
// the credential, the head again, the entry, COMMIT.
//
// Not part of the suite: `pnpm bench:decisions` makes a database, runs this
// on it and drops it.
//
//   pnpm bench:decisions [--rtt 20] [--keys 1] [--callers 1,5,10,20] [--calls 20]
//   pnpm bench:decisions [--rtt 20] [--keys 1] --rate 8 [--seconds 30] [--app]
import { randomBytes } from 'node:crypto';
import { connect, createServer, type Server } from 'node:net';
import { parseArgs } from 'node:util';

import { deriveLogKey } from '@coffre/core/audit';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { SecretRef } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { appendEntries, lockLogHead } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../../src/config.ts';
import { openVault, prepareVault, type PreparedVault } from '../../src/vault.ts';
import { emptyDatabase, ENGINE, openTestDatabase, places, storedVersions, VAULT_URL } from '../database.ts';

const { values } = parseArgs({
  options: {
    rtt: { type: 'string', default: '20' },
    keys: { type: 'string', default: '1' },
    callers: { type: 'string', default: '1,5,10,20' },
    calls: { type: 'string', default: '20' },
    rate: { type: 'string' },
    seconds: { type: 'string', default: '30' },
    app: { type: 'boolean', default: false },
  },
});
const RTT = Number(values.rtt);
const KEYS = Number(values.keys);
if (ENGINE !== 'postgres') throw new Error('the bench runs on Postgres: COFFRE_TEST_ENGINE=postgres');

const ROOT = 'user:root@acme.example';

/**
 * Postgres as Hyperdrive serves it from far away: each chunk delayed by
 * half the round trip, each way, give or take half that, in order. A delay
 * that never varies lines every call up on the same instants, which a real
 * network does not: a call back at the very moment a lock is let go of
 * takes it before those waiting, again and again.
 */
async function farPostgres(rtt: number): Promise<{ port: number; close(): Promise<void> }> {
  const target = new URL(VAULT_URL);
  const server: Server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) => {
      let last = 0;
      from.on('data', (chunk) => {
        last = Math.max(last, performance.now() + (rtt / 2) * (0.5 + Math.random()));
        setTimeout(() => to.write(chunk), last - performance.now());
      });
    };
    relay(client, upstream);
    relay(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: (server.address() as { port: number }).port, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

/** What one call ran: its statements, and how long they took beyond the round trip each. */
type Cost = { statements: number; waitedMs: number };

/**
 * A call's own pool, timing each statement it runs, a transaction's
 * included. Its class name ends in `Pool`, which tells Drizzle to check a
 * client out for a transaction.
 */
class TimedPool {
  readonly #pool: HyperdrivePool;
  readonly #cost: Cost;

  constructor(pool: HyperdrivePool, cost: Cost) {
    this.#pool = pool;
    this.#cost = cost;
  }

  async #time(query: (...args: unknown[]) => Promise<unknown>, args: unknown[]): Promise<unknown> {
    const started = performance.now();
    try {
      return await query(...args);
    } finally {
      this.#cost.statements += 1;
      this.#cost.waitedMs += Math.max(0, performance.now() - started - RTT);
    }
  }

  query = ((...args: unknown[]) => this.#time(this.#pool.query as never, args)) as HyperdrivePool['query'];

  async connect() {
    const client = await this.#pool.connect();
    return { query: ((...args: unknown[]) => this.#time(client.query as never, args)) as typeof client.query, release: client.release };
  }
}

/** A call's connection, up before it is timed: on Workers, a call connects first, a round trip or a few, which no lock lengthens. */
async function connected(url: string): Promise<HyperdrivePool> {
  const pool = new HyperdrivePool(url);
  (await pool.connect()).release();
  return pool;
}

const db = await openTestDatabase();
const far = await farPostgres(RTT);
const through = (login: string) => {
  const url = new URL(VAULT_URL);
  url.username = login.split(':')[0]!;
  url.password = login.split(':')[1]!;
  url.port = String(far.port);
  return url.toString();
};
const vaultUrl = through('coffre_vault_runtime:local-vault-only');
const appUrl = through('coffre_runtime:local-runtime-only');
try {
  await emptyDatabase(db.owner);
  const config: ResolvedVaultConfig = {
    keks: new KekRegistry(LocalKekProvider.generate('bench-kek')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1_000_000, windowMs: 15 * 60_000 },
  };
  // One isolate's prepared vault, settled by its first call, as on Workers once warm.
  const prepared: PreparedVault = await prepareVault(config);
  const setup = openVault(db.vault, prepared);
  await setup.access(ROOT);
  const { project, prod, secret } = await places(db.owner);
  const services = Array.from({ length: Math.max(...values.callers.split(',').map(Number)) }, (_, i) => `token:svc-${i}`);
  for (const principal of services) {
    if (!(await setup.admit({ actor: ROOT, caller: 'person', principal })).ok) throw new Error(`admit ${principal}`);
    const given = await setup.setAccess({
      actor: ROOT, caller: 'person', principal, changes: [{ projectId: project, environmentId: prod, role: 'viewer', expiresAt: null }],
    });
    if (!given.ok) throw new Error(`grant ${principal}: ${JSON.stringify(given)}`);
  }
  const secrets: SecretRef[] = [];
  for (let i = 0; i < KEYS; i += 1) secrets.push(await secret(prod, `KEY_${i}`));
  const wrapped = await setup.wrap({ principal: ROOT, caller: 'person', items: secrets.map((s) => ({ secret: s, key: randomBytes(32).toString('base64') })) });
  if (!wrapped.ok) throw new Error('wrap');
  const items = await storedVersions(db.owner, secrets.map((s, i) => ({ secret: s, wrapped: wrapped.wrapped[i]! })));
  const appKey = deriveLogKey('app', randomBytes(32));

  type Run = { ms: number; failed: string | null } & Cost;

  /** One unwrap of every key, as `principal`, on a connection of its own; with `app`, then the app's entry for it, on another. */
  const call = async (principal: string, app = false): Promise<Run> => {
    const cost: Cost = { statements: 0, waitedMs: 0 };
    const pools = [await connected(vaultUrl), ...(app ? [await connected(appUrl)] : [])];
    const started = performance.now();
    try {
      const vault = openVault(createDatabase(new TimedPool(pools[0]!, cost)), prepared);
      const read = await vault.unwrap({ principal, caller: 'bearer', purpose: 'run', items });
      if (!read.ok) throw new Error(`unwrap: ${JSON.stringify(read.refusal)}`);
      if (app) {
        await createDatabase(new TimedPool(pools[1]!, cost)).transaction(async (tx) => {
          await tx.execute(sql`SET LOCAL lock_timeout = 15000`);
          await lockLogHead(tx);
          // The policy, then the credential, each a statement under the head (`policyStill`, `credentialStill`).
          await tx.execute(sql`SELECT 1`);
          await tx.execute(sql`SELECT 1`);
          await appendEntries(tx, appKey, [{ actor: principal, action: 'credential.use', decision: 'allow' }]);
        });
      }
      return { ms: performance.now() - started, failed: null, ...cost };
    } catch (error) {
      const code = (error as { code?: string; cause?: { code?: string } }).cause?.code ?? (error as { code?: string }).code;
      return { ms: performance.now() - started, failed: code ?? (error as Error).message.slice(0, 60), ...cost };
    } finally {
      await Promise.all(pools.map((pool) => pool.end()));
    }
  };

  const percentile = (sorted: number[], p: number) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]!;
  const report = (label: string, runs: Run[]) => {
    const ms = runs.map((run) => run.ms).sort((a, b) => a - b);
    const mean = (pick: (run: Cost) => number) => runs.reduce((sum, run) => sum + pick(run), 0) / runs.length;
    const failed = runs.filter((run) => run.failed !== null);
    const why = [...new Set(failed.map((run) => run.failed))].join(', ');
    console.log([
      label.padEnd(28),
      `p50 ${percentile(ms, 50).toFixed(0).padStart(5)} ms`,
      `p99 ${percentile(ms, 99).toFixed(0).padStart(5)} ms`,
      `statements ${mean((run) => run.statements).toFixed(1).padStart(4)}`,
      `waited ${mean((run) => run.waitedMs).toFixed(0).padStart(5)} ms`,
      ...(failed.length === 0 ? [] : [`failed ${failed.length} of ${runs.length} (${why})`]),
    ].join('  '));
  };

  // Warm the isolate and the database's caches.
  for (let i = 0; i < 3; i += 1) await call(services[0]!, values.app);
  const keys = `${KEYS} key${KEYS === 1 ? '' : 's'}`;
  if (values.rate !== undefined) {
    const rate = Number(values.rate);
    const seconds = Number(values.seconds);
    console.log(`unwrap of ${keys}${values.app ? ", then the app's entry" : ''}, ${RTT} ms a round trip, ${rate} a second from one service for ${seconds} s`);
    // Arrivals at random, at the rate on average, whether or not those before have been answered.
    const runs: Promise<Run>[] = [];
    for (let at = 0; at < seconds * 1000; at += -Math.log(1 - Math.random()) * (1000 / rate)) {
      runs.push(new Promise((resolve) => setTimeout(() => resolve(call(services[0]!, values.app)), at)));
    }
    report(`${rate} a second, one service`, await Promise.all(runs));
  } else {
    const calls = Number(values.calls);
    console.log(`unwrap of ${keys}, ${RTT} ms a round trip, ${calls} calls a caller, one after another`);
    for (const callers of values.callers.split(',').map(Number)) {
      for (const [label, who] of [['one service', () => services[0]!], ['a service each', (i: number) => services[i]!]] as const) {
        if (callers === 1 && label === 'a service each') continue;
        const runs = (await Promise.all(Array.from({ length: callers }, async (_, i) => {
          const done: Run[] = [];
          for (let n = 0; n < calls; n += 1) done.push(await call(who(i)));
          return done;
        }))).flat();
        report(`${callers} at once, ${label}`, runs);
      }
    }
  }
} finally {
  await far.close();
  await db.close();
}
