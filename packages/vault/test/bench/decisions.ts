// What vault decisions cost under concurrent load, as on Workers: each call
// its own Postgres connection (`HyperdrivePool`), each statement a round trip
// to a database far away. Locally a statement answers in well under a
// millisecond, which hides every queue; here a relay delays each chunk by
// half the round trip either way, so a lock held across round trips is held
// as long as it would be through Hyperdrive. It reports each call's wall
// time once connected, p50 and p99, its statements, and the time its
// statements spent in the database beyond the round trip: waiting on
// locks, almost all of it.
// Not part of the suite. On a migrated scratch database, as `pnpm test` makes:
//
//   COFFRE_TEST_DATABASE=<db> node --conditions=coffre:source packages/vault/test/bench/decisions.ts \
//     [--rtt 20] [--calls 20] [--keys 1] [--callers 1,5,10,20]
//
// `pnpm bench:decisions` makes the database, runs this and drops it.
import { randomBytes } from 'node:crypto';
import { connect, createServer, type Server } from 'node:net';
import { parseArgs } from 'node:util';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { SecretRef } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';

import type { ResolvedVaultConfig } from '../../src/config.ts';
import { openVault, prepareVault, type PreparedVault } from '../../src/vault.ts';
import { emptyDatabase, ENGINE, openTestDatabase, places, storedVersions, VAULT_URL } from '../database.ts';

const { values } = parseArgs({
  options: {
    rtt: { type: 'string', default: '20' },
    calls: { type: 'string', default: '20' },
    keys: { type: 'string', default: '1' },
    callers: { type: 'string', default: '1,5,10,20' },
  },
});
const RTT = Number(values.rtt);
const CALLS = Number(values.calls);
const KEYS = Number(values.keys);
const CALLERS = values.callers.split(',').map(Number);
if (ENGINE !== 'postgres') throw new Error('the bench runs on Postgres: COFFRE_TEST_ENGINE=postgres');

const ROOT = 'user:root@acme.example';

/** Postgres as Hyperdrive serves it from far away: each chunk delayed by half the round trip, each way. */
async function farPostgres(rtt: number): Promise<{ url: string; close(): Promise<void> }> {
  const target = new URL(VAULT_URL);
  const server: Server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) => from.on('data', (chunk) => setTimeout(() => to.write(chunk), rtt / 2));
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
  const url = new URL(VAULT_URL);
  url.port = String((server.address() as { port: number }).port);
  return { url: url.toString(), close: () => new Promise((resolve) => server.close(() => resolve())) };
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

const db = await openTestDatabase();
const far = await farPostgres(RTT);
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
  const services = Array.from({ length: Math.max(...CALLERS) }, (_, i) => `token:svc-${i}`);
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

  /**
   * One unwrap of every key, as `principal`, on a connection of its own,
   * timed once it is connected: on Workers, a call connects first, a round
   * trip or a few through Hyperdrive, which no lock lengthens.
   */
  const call = async (principal: string): Promise<{ ms: number } & Cost> => {
    const cost: Cost = { statements: 0, waitedMs: 0 };
    const pool = new HyperdrivePool(far.url);
    (await pool.connect()).release();
    const started = performance.now();
    try {
      const vault = openVault(createDatabase(new TimedPool(pool, cost)), prepared);
      const read = await vault.unwrap({ principal, caller: 'bearer', purpose: 'run', items });
      if (!read.ok) throw new Error(`unwrap: ${JSON.stringify(read.refusal)}`);
      return { ms: performance.now() - started, ...cost };
    } finally {
      await pool.end();
    }
  };

  const percentile = (sorted: number[], p: number) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]!;
  const report = (label: string, runs: ({ ms: number } & Cost)[]) => {
    const ms = runs.map((run) => run.ms).sort((a, b) => a - b);
    const mean = (pick: (run: Cost) => number) => runs.reduce((sum, run) => sum + pick(run), 0) / runs.length;
    console.log([
      label.padEnd(28),
      `p50 ${percentile(ms, 50).toFixed(0).padStart(5)} ms`,
      `p99 ${percentile(ms, 99).toFixed(0).padStart(5)} ms`,
      `statements ${mean((run) => run.statements).toFixed(1).padStart(4)}`,
      `waited ${mean((run) => run.waitedMs).toFixed(0).padStart(5)} ms`,
    ].join('  '));
  };

  console.log(`unwrap of ${KEYS} key${KEYS === 1 ? '' : 's'}, ${RTT} ms a round trip, ${CALLS} calls a caller, one after another`);
  // Warm the isolate and the database's caches.
  for (let i = 0; i < 3; i += 1) await call(services[0]!);
  for (const callers of CALLERS) {
    for (const [label, who] of [['one service', () => services[0]!], ['a service each', (i: number) => services[i]!]] as const) {
      if (callers === 1 && label === 'a service each') continue;
      const runs = (await Promise.all(Array.from({ length: callers }, async (_, i) => {
        const done: ({ ms: number } & Cost)[] = [];
        for (let n = 0; n < CALLS; n += 1) done.push(await call(who(i)));
        return done;
      }))).flat();
      report(`${callers} at once, ${label}`, runs);
    }
  }
} finally {
  await far.close();
  await db.close();
}
