// What a cold /use costs under an open-loop load, as on Workers: requests
// arrive at a fixed rate whether or not earlier ones are done (Poisson), so a
// queue that grows shows as latency that grows, which a closed loop (each
// caller waiting for its last answer) hides. Each request is what a cache
// miss does today: the vault's `unwrap` decision, on a connection of its own,
// then the app's `credential.use` entry in a transaction of its own, which
// holds the log's head as `audited` does (BEGIN, the head FOR UPDATE, the
// policy and credential checks, the append, COMMIT). The app's checks are
// stand-ins of the same shape: one statement each.
//
// Postgres sits behind a relay that delays each chunk by half the round trip
// either way, as W185's decisions bench does, so a lock held across round
// trips is held as long as it would be through Hyperdrive.
//
// Not part of the suite. On a migrated scratch database:
//
//   COFFRE_TEST_DATABASE=<db> node --conditions=coffre:source packages/vault/test/bench/open-loop.ts \
//     [--rtt 20] [--seconds 20] [--rates 5,10,20] [--principals 1,50] [--app] [--keys 1]
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
import { emptyDatabase, ENGINE, OWNER_URL, openTestDatabase, places, storedVersions, VAULT_URL } from '../database.ts';

const { values } = parseArgs({
  options: {
    rtt: { type: 'string', default: '20' },
    seconds: { type: 'string', default: '20' },
    rates: { type: 'string', default: '5,10,20' },
    principals: { type: 'string', default: '1,50' },
    keys: { type: 'string', default: '1' },
    app: { type: 'boolean', default: false },
    // Give up on a request after this long, as a caller would.
    timeout: { type: 'string', default: '15000' },
  },
});
const RTT = Number(values.rtt);
const SECONDS = Number(values.seconds);
const RATES = values.rates.split(',').map(Number);
const PRINCIPALS = values.principals.split(',').map(Number);
const KEYS = Number(values.keys);
const TIMEOUT = Number(values.timeout);
if (ENGINE !== 'postgres') throw new Error('the bench runs on Postgres: COFFRE_TEST_ENGINE=postgres');

const ROOT = 'user:root@acme.example';

/** Postgres as Hyperdrive serves it from far away: each chunk delayed by half the round trip, each way. */
async function farPostgres(target: string, rtt: number): Promise<{ url: string; close(): Promise<void> }> {
  const to = new URL(target);
  const sockets = new Set<import('node:net').Socket>();
  const server: Server = createServer((client) => {
    const upstream = connect(Number(to.port), to.hostname);
    sockets.add(client).add(upstream);
    const relay = (from: NodeJS.ReadableStream, into: NodeJS.WritableStream) => from.on('data', (chunk) => setTimeout(() => into.write(chunk), rtt / 2));
    relay(client, upstream);
    relay(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
      sockets.delete(client);
      sockets.delete(upstream);
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = new URL(target);
  url.port = String((server.address() as { port: number }).port);
  return {
    url: url.toString(),
    close: () => {
      for (const socket of sockets) socket.destroy();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

const db = await openTestDatabase();
const farVault = await farPostgres(VAULT_URL, RTT);
const farApp = await farPostgres(OWNER_URL, RTT);
try {
  await emptyDatabase(db.owner);
  const config: ResolvedVaultConfig = {
    keks: new KekRegistry(LocalKekProvider.generate('bench-kek')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1_000_000_000, windowMs: 15 * 60_000 },
  };
  const prepared: PreparedVault = await prepareVault(config);
  const setup = openVault(db.vault, prepared);
  await setup.access(ROOT);
  const { prod, project, secret } = await places(db.owner);
  const services = Array.from({ length: Math.max(...PRINCIPALS) }, (_, i) => `token:svc-${i}`);
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

  type Run = { at: number; ms: number; ok: boolean; error?: string };

  /** One cold /use: the vault's decision, then the app's entry, each on a connection of its own, connected first. */
  const use = async (principal: string): Promise<{ ms: number; ok: boolean; error?: string }> => {
    const vaultPool = new HyperdrivePool(farVault.url);
    const appPool = new HyperdrivePool(farApp.url);
    try {
      (await vaultPool.connect()).release();
      if (values.app) (await appPool.connect()).release();
      const started = performance.now();
      const vault = openVault(createDatabase(vaultPool), prepared);
      const read = await vault.unwrap({ principal, caller: 'bearer', purpose: 'run', items });
      if (!read.ok) return { ms: performance.now() - started, ok: false, error: read.refusal.code };
      if (values.app) {
        const app = createDatabase(appPool);
        await app.transaction(async (tx) => {
          await lockLogHead(tx);
          // `policyStill` and `credentialStill`: one statement each, under the head.
          await tx.execute(sql`SELECT seq FROM audit_log WHERE author = 'vault' AND action = 'policy.change' ORDER BY seq DESC LIMIT 1`);
          await tx.execute(sql`SELECT 1`);
          await appendEntries(tx, appKey, [{ actor: principal, action: 'credential.use', decision: 'allow', metadata: '{}' }]);
        });
      }
      return { ms: performance.now() - started, ok: true };
    } catch (error) {
      return { ms: 0, ok: false, error: (error as { code?: string }).code ?? (error as Error).message.slice(0, 60) };
    } finally {
      await Promise.all([vaultPool.end(), appPool.end()]);
    }
  };

  const percentile = (sorted: number[], p: number) => sorted.length === 0 ? NaN : sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]!;
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  /** `rate` requests a second for SECONDS, Poisson, each from one of `principals`, round robin. */
  const load = async (rate: number, principals: number) => {
    const runs: Run[] = [];
    const pending: Promise<void>[] = [];
    const start = performance.now();
    let n = 0;
    let next = 0;
    while (next < SECONDS * 1000) {
      const wait = start + next - performance.now();
      if (wait > 0) await sleep(wait);
      const principal = services[n % principals]!;
      const at = next;
      n += 1;
      pending.push((async () => {
        const run = await Promise.race([use(principal), sleep(TIMEOUT).then(() => ({ ms: TIMEOUT, ok: false, error: 'timeout' }))]);
        runs.push({ at, ...run });
      })());
      next += -Math.log(1 - Math.random()) * (1000 / rate);
    }
    await Promise.all(pending);
    const elapsed = (performance.now() - start) / 1000;
    const ok = runs.filter((run) => run.ok).map((run) => run.ms).sort((a, b) => a - b);
    const errors = new Map<string, number>();
    for (const run of runs) if (!run.ok) errors.set(run.error!, (errors.get(run.error!) ?? 0) + 1);
    // Whether the queue grows: the median of the last fifth against the first fifth.
    const fifth = (from: number) => runs.filter((run) => run.ok && run.at >= from && run.at < from + (SECONDS * 1000) / 5).map((run) => run.ms).sort((a, b) => a - b);
    console.log([
      `${String(rate).padStart(4)}/s`,
      `${String(principals).padStart(3)} principal${principals === 1 ? ' ' : 's'}`,
      `done ${(ok.length / elapsed).toFixed(1).padStart(5)}/s`,
      `p50 ${percentile(ok, 50).toFixed(0).padStart(6)}`,
      `p99 ${percentile(ok, 99).toFixed(0).padStart(6)}`,
      `max ${(ok.at(-1) ?? NaN).toFixed(0).padStart(6)} ms`,
      `first/last fifth p50 ${percentile(fifth(0), 50).toFixed(0)}/${percentile(fifth((SECONDS * 1000 * 4) / 5), 50).toFixed(0)} ms`,
      `errors ${runs.length - ok.length}${errors.size === 0 ? '' : ` ${JSON.stringify(Object.fromEntries(errors))}`}`,
    ].join('  '));
  };

  console.log(`cold /use: unwrap of ${KEYS} key${KEYS === 1 ? '' : 's'}${values.app ? ' + the app\'s credential.use' : ''}, ${RTT} ms a round trip, ${SECONDS} s a rate, open loop`);
  for (let i = 0; i < 3; i += 1) await use(services[0]!);
  for (const principals of PRINCIPALS) {
    for (const rate of RATES) {
      await load(rate, principals);
      await sleep(1000);
    }
  }
} finally {
  await Promise.all([farVault.close(), farApp.close()]);
  await db.close();
}
