// The vault in workerd, as it runs on Cloudflare: a page load fires a
// handful of calls at once, and on a fresh isolate they are its first. On
// Cloudflare, a call that waits on a promise only another call's I/O can
// settle is cancelled as hung when that call goes; local workerd lets it
// finish, so isolate.test.ts holds the vault to that rule, and this runs the
// same bursts through the entrypoint, over a database as slow as Hyperdrive
// from far away.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { connect, createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { WrappedKey } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { isUnavailable } from '@coffre/db/dialect';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { postgresSession } from '@coffre/db/connect';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { emptyDatabase, ENGINE, HOT_URL, nothingHeld, openLocalVault, openTestDatabase, OWNER_URL, places, run, sealed, storedVersions, VAULT_URL, type TestDatabase } from './database.ts';
import { resolveVaultConfig } from '../src/config.ts';
import { READ_HEAD_WAITERS } from '../src/vault.ts';

const ROOT = 'user:root@acme.example';
const skip = ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive';

let db: TestDatabase;
before(async () => {
  if (!skip) db = await openTestDatabase();
});
after(() => db?.close());
beforeEach(async () => {
  if (skip) return;
  await emptyDatabase(db.owner);
  // 0.15's trees too: each test's checkpointer starts with no memory, over a log of its own.
  for (const table of ['log_uses', 'log_bulk', 'log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
});

/**
 * Postgres as Hyperdrive serves it from far away: each chunk either way
 * delayed by `ms`. Locally a query answers in well under a millisecond,
 * which hides calls waiting on each other's I/O. `opened` counts the
 * connections made to it; `statements` the statements sent on them (each
 * Sync, or simple Query); `flushes` the Flush messages, which a client sends
 * to have a statement described before it sends its values; and `trips` the
 * round trips past the login: each time a client speaks again once answered,
 * but to say goodbye (Terminate), which waits for no answer.
 */
async function slowPostgres(ms: number): Promise<{ url: string; readonly opened: number; readonly statements: number; readonly flushes: number; readonly trips: number; close(): Promise<void> }> {
  const target = new URL(VAULT_URL);
  let opened = 0;
  let statements = 0;
  let flushes = 0;
  let trips = 0;
  const server: Server = createServer((client) => {
    opened += 1;
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) =>
      from.on('data', (chunk) => setTimeout(() => to.write(chunk), ms));
    // The client's messages, read as they come: the first, untyped, starts the connection; then a type and a length each.
    let pending = Buffer.alloc(0);
    let started = false;
    let answered = true;
    client.on('data', (chunk: Buffer) => {
      // A round trip begins: the login's (its startup, its password messages) is not a statement's.
      if (answered && started && chunk[0] !== 0x70 && chunk[0] !== 0x58) trips += 1;
      answered = false;
      pending = Buffer.concat([pending, chunk]);
      for (;;) {
        if (!started) {
          if (pending.length < 8) break;
          const length = pending.readInt32BE(0);
          if (pending.length < length) break;
          // An SSLRequest is answered before the startup message comes.
          if (pending.readInt32BE(4) !== 80877103) started = true;
          pending = pending.subarray(length);
          continue;
        }
        if (pending.length < 5) break;
        const length = pending.readInt32BE(1);
        if (pending.length < 1 + length) break;
        const type = String.fromCharCode(pending[0]!);
        if (type === 'S' || type === 'Q') statements += 1;
        if (type === 'H') flushes += 1;
        pending = pending.subarray(1 + length);
      }
    });
    upstream.on('data', () => {
      answered = true;
    });
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
  const address = server.address() as { port: number };
  const url = new URL(VAULT_URL);
  url.port = String(address.port);
  return {
    url: url.href,
    get opened() {
      return opened;
    },
    get statements() {
      return statements;
    },
    get flushes() {
      return flushes;
    },
    get trips() {
      return trips;
    },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/** A fresh isolate of the vault Worker, over the suite's database through the vault's login. */
async function freshVault(database: string): Promise<{
  call(method: string, ...args: unknown[]): Promise<{ ok: boolean; error?: string; code?: string; result?: unknown }>;
  stop(): Promise<void>;
}> {
  const key = randomBytes(32).toString('base64');
  // Cut over from 0.14 first, as the app's door has it, from another process: the isolate's calls below are its first.
  const cut = await openLocalVault(db.vault, resolveVaultConfig({ kek: { id: 'vault-workers-test', key }, owners: ['root@acme.example'] }), { log: '0.15', sealThrough: sealed, heldOutside: nothingHeld });
  await cut.close();
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-worker-'));
  const name = 'coffre-vault-workers-test';
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { VAULT_KEY: key },
      hyperdrive: [
        { binding: 'VAULT_HYPERDRIVE', id: 'vault-workers-test', localConnectionString: database },
        { binding: 'HOT_HYPERDRIVE', id: 'vault-workers-hot', localConnectionString: HOT_URL },
      ],
      durable_objects: { bindings: [{ name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }] },
      migrations: [{ tag: 'v1', new_sqlite_classes: ['CoffreCheckpointer'] }],
      services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  let worker: Unstable_DevWorker;
  try {
    worker = await unstable_dev(fileURLToPath(new URL('./workers/vault-worker.ts', import.meta.url)), {
      config: join(dir, 'wrangler.json'),
      local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
    });
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  const call = async (method: string, ...args: unknown[]) => {
    const response = await worker.fetch('/', { method: 'POST', body: JSON.stringify({ method, args }), signal: AbortSignal.timeout(20_000) });
    const text = await response.text();
    try {
      return JSON.parse(text) as { ok: boolean; error?: string; code?: string; result?: unknown };
    } catch {
      return { ok: false, error: `${response.status}: ${text}` };
    }
  };
  // Its connection the object's own, opened here rather than inside the first call counted (a call starts it too).
  const started = await call('startCheckpointer');
  assert.ok(started.ok, started.error ?? 'the checkpointer did not start');
  return {
    call,
    async stop() {
      await worker.stop();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function assertAllAnswered(results: { ok: boolean; error?: string }[]): void {
  const failed = results.filter((result) => !result.ok).map((result) => result.error);
  assert.deepEqual(failed, [], 'every call answered, none cancelled as hung');
}

test('a fresh isolate answers a page load of concurrent first calls', { skip, timeout: 120_000 }, async () => {
  const database = await slowPostgres(20);
  const vault = await freshVault(database.url);
  try {
    const results = await Promise.all([
      vault.call('access', ROOT),
      vault.call('access', ROOT),
      vault.call('access', 'user:ada@acme.example'),
      vault.call('access', 'user:bob@acme.example'),
      vault.call('about'),
      vault.call('about'),
      vault.call('verifyLog', {}),
      vault.call('verifyLog', {}),
    ]);
    assertAllAnswered(results);
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('a fresh isolate answers concurrent first key operations', { skip, timeout: 120_000 }, async () => {
  const placed = await places(db.owner);
  const secrets = await Promise.all(Array.from({ length: 6 }, () => placed.secret(placed.dev)));
  const database = await slowPostgres(20);
  const vault = await freshVault(database.url);
  try {
    // Settled by one call first, so that what is tested here is the key check before the first key operation.
    assert.ok((await vault.call('access', ROOT)).ok);
    const results = await Promise.all(
      secrets.map((secret) => vault.call('wrap', { principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] })),
    );
    assertAllAnswered(results);
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('each call opens one connection at most: on Cloudflare, a call that opened several at once was cancelled as hung', { skip, timeout: 120_000 }, async () => {
  const database = await slowPostgres(5);
  const vault = await freshVault(database.url);
  try {
    // A fresh isolate's first calls settle its keys and make root the bootstrap Owner: the most queries a call makes.
    const calls: [string, ...unknown[]][] = [
      ['access', ROOT],
      ['access', 'user:ada@acme.example'],
      ['about'],
      ['verifyLog', {}],
      ['access', ROOT],
      ['checkpoint'],
    ];
    const opened: Record<string, number> = {};
    for (const [index, [method, ...args]] of calls.entries()) {
      const before = database.opened;
      const result = await vault.call(method, ...args);
      assert.ok(result.ok || method === 'checkpoint', `${method} failed: ${result.error}`);
      opened[`${index} ${method}`] = database.opened - before;
    }
    assert.deepEqual(
      Object.entries(opened).filter(([, count]) => count > 1),
      [],
      `connections each call opened: ${JSON.stringify(opened)}`,
    );
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('in workerd, a call\'s statements cost a round trip each at most: none waits to learn its parameters\' types first', { skip, timeout: 120_000 }, async (t) => {
  const placed = await places(db.owner);
  const secret = await placed.secret(placed.dev);
  const database = await slowPostgres(2);
  const vault = await freshVault(database.url);
  try {
    // The isolate's first calls settle its keys and make root the Owner: then the calls as they come, warm.
    assert.ok((await vault.call('access', ROOT)).ok);
    const wrapped = (await vault.call('wrap', { principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] })) as { ok: boolean; result: { wrapped: WrappedKey[] } };
    assert.ok(wrapped.ok);
    const items = await storedVersions(db.owner, [{ secret, wrapped: wrapped.result.wrapped[0]! }]);
    const calls: [string, () => Promise<{ ok: boolean; error?: string }>][] = [
      ['access', () => vault.call('access', ROOT)],
      ['unwrap, a reveal', () => vault.call('unwrap', { principal: ROOT, caller: 'person', purpose: 'reveal', items })],
      ['unwrap, a use', () => vault.call('unwrap', { principal: ROOT, caller: 'person', purpose: 'use', items })],
      ['wrap, a change', () => vault.call('wrap', { principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] })],
      ['verifyLog', () => vault.call('verifyLog', {})],
    ];
    const seen: Record<string, { statements: number; trips: number }> = {};
    for (const [name, call] of calls) {
      const before = { statements: database.statements, trips: database.trips };
      const result = await call();
      assert.ok(result.ok, `${name} failed: ${result.error}`);
      seen[name] = { statements: database.statements - before.statements, trips: database.trips - before.trips };
    }
    t.diagnostic(`statements and round trips per call: ${JSON.stringify(seen)}`);
    // A statement described first is a Parse, a Describe and a Flush, then a wait for its types: none here.
    assert.equal(database.flushes, 0, 'a statement waited to be described before its values were sent');
    for (const [name, { statements, trips }] of Object.entries(seen)) {
      assert.ok(statements > 0, `${name} sent no statement`);
      // Fewer when statements of a transaction go together.
      assert.ok(trips <= statements, `${name}: ${statements} statements in ${trips} round trips`);
    }
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('in workerd too, a query on the database inside its own transaction is refused at once, not left to hang', { skip, timeout: 120_000 }, async () => {
  const database = await slowPostgres(5);
  const vault = await freshVault(database.url);
  try {
    const refused = (await vault.call('queryOutsideTransaction')) as { ok: boolean; result?: string; error?: string };
    assert.ok(refused.ok, refused.error ?? "refused");
    assert.match(refused.result!, /^QueryOutsideTransaction: query outside its transaction: use tx/);
  } finally {
    await vault.stop();
    await database.close();
  }
});

test('through the entrypoint, the credential a CI run came in on is copied into the entries it caused, never decided on', { skip, timeout: 120_000 }, async () => {
  const placed = await places(db.owner);
  const secret = await placed.secret(placed.dev);
  const credentialId = randomUUID();
  const vault = await freshVault(VAULT_URL);
  try {
    // Root signs in first: the bootstrap makes them the Owner.
    assert.ok((await vault.call('access', ROOT)).ok);
    assert.ok((await vault.call('wrap', { principal: ROOT, credentialId, items: [{ secret, key: randomBytes(32).toString('base64') }] })).ok);
    assert.ok((await vault.call('admit', { actor: ROOT, principal: 'token:ci-deploy', credentialId })).ok);
    const { auditLog } = tablesOf(db.owner);
    // Root's own row, which their bootstrap wrote, is its own: only what the calls asked for counts.
    const entries = (await db.owner.select({ action: auditLog.action, subject: auditLog.subjectPrincipal, metadata: auditLog.metadata }).from(auditLog)
      .where(and(eq(auditLog.author, 'vault'), inArray(auditLog.action, ['key.wrap', 'member.add'])))).filter((entry) => entry.subject !== ROOT);
    assert.deepEqual(entries.map((entry) => [entry.action, (JSON.parse(entry.metadata) as { credentialId?: string }).credentialId]).sort(), [
      ['key.wrap', credentialId],
      ['member.add', credentialId],
    ]);
    const refused = await vault.call('admit', { actor: ROOT, principal: 'token:other', credentialId: 'not-a-uuid' });
    assert.match(refused.error ?? '', /credentialId must be a lowercase UUID/);
  } finally {
    await vault.stop();
  }
});

test('through the entrypoint, a read past the head\'s places in line fails at once with its code, which the app answers as unavailable', { skip, timeout: 120_000 }, async () => {
  const placed = await places(db.owner);
  const secret = await placed.secret(placed.dev);
  const vault = await freshVault(VAULT_URL);
  const holder = postgresSession(OWNER_URL);
  try {
    assert.ok((await vault.call('access', ROOT)).ok);
    const wrapped = (await vault.call('wrap', { principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] })) as { ok: boolean; result: { wrapped: WrappedKey[] } };
    assert.ok(wrapped.ok);
    const items = await storedVersions(db.owner, [{ secret, wrapped: wrapped.result.wrapped[0]! }]);
    const read = () => vault.call('unwrap', { principal: ROOT, caller: 'person', purpose: 'reveal', items });
    // Once, so that what a process does once is done; then the head held, and every place in line taken.
    assert.equal(((await read()).result as { ok: boolean }).ok, true);
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT next_seq FROM audit_chain_head WHERE only_row FOR UPDATE');
    await holder.unsafe('SELECT pg_advisory_xact_lock($1, place) FROM generate_series(1, $2::int) AS place', [0x636f6668, READ_HEAD_WAITERS]);
    const started = Date.now();
    const refused = await read();
    assert.ok(Date.now() - started < 2_000, `refused after ${Date.now() - started} ms`);
    assert.equal(refused.ok, false, JSON.stringify(refused));
    assert.equal(refused.code, '55P03', 'the code crossed the binding');
    assert.ok(isUnavailable({ code: refused.code }), 'which the app answers as unavailable');
  } finally {
    await holder.unsafe('ROLLBACK').catch(() => undefined);
    await holder.end();
    await vault.stop();
  }
});
