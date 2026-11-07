import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { Agent, createServer, request } from 'node:http';
import type { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isStackOverflow, RELEASE, STACK_OVERFLOW, versioned } from '@coffre/core/vault';
import { isUnavailable } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { failureOf } from '../src/failure.ts';
import { resolveVaultConfig } from '../src/config.ts';
import { METHODS } from '../src/local.ts';
import { connectVault, localVault, serveVault } from '../src/node.ts';
import { prepareVault } from '../src/vault.ts';
import { openTestDatabase, rows, sealed } from './database.ts';

// The vault as a process of its own, which the server reaches over a Unix
// socket (src/node.ts).

/** One call as `connectVault` makes it, on `agent`: the socket it went on. */
function about(socket: string, agent: Agent): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath: socket, agent, method: 'POST', path: '/call', headers: { 'content-type': 'application/json' } }, (res) => {
      res.resume();
      res.on('end', () => (res.statusCode === 200 ? resolve(req.socket as Socket) : reject(new Error(`status ${res.statusCode}`))));
    });
    req.on('error', reject);
    req.end(JSON.stringify({ release: RELEASE, method: 'about', args: [] }));
  });
}

test('the vault leaves an idle connection open for the server to reuse: it never races the next call by ending it', async () => {
  const db = await openTestDatabase();
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-socket-'));
  const vault = await serveVault({
    socket: join(dir, 'vault.sock'),
    database: db.vault,
    // As a deployment serves it: its uses' own login, and its checkpointer, its memory a file here.
    hotDatabase: await db.hot(),
    checkpointer: { memory: join(dir, 'memory') },
    kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') },
    owners: ['root@acme.example'],
  });
  const agent = new Agent({ keepAlive: true });
  try {
    const first = await about(vault.socket, agent);
    // Past Node's default, five seconds and one more, when it ended the connection.
    await new Promise((resolve) => setTimeout(resolve, 6_500));
    assert.equal(first.destroyed, false, 'the vault ended the idle connection');
    assert.equal(await about(vault.socket, agent), first, 'the next call went on a new connection');
  } finally {
    agent.destroy();
    await vault.close();
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('over the socket, a call on another release answers this release and runs nothing; the per-method routes are gone', async () => {
  const db = await openTestDatabase();
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-socket-'));
  const served = await serveVault({
    socket: join(dir, 'vault.sock'),
    database: db.vault,
    hotDatabase: await db.hot(),
    checkpointer: { memory: join(dir, 'memory') },
    kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') },
    owners: ['root@acme.example'],
  });
  try {
    const entry = connectVault(served.socket);
    const entries = async () => (await rows<{ n: string | number }>(db.vault, sql`SELECT count(*) AS n FROM audit_log`))[0]!.n;
    const before = await entries();
    for (const [method, args] of [['about', []], ['access', ['user:root@acme.example']], ['useNamed', [{ tokenHash: 'x' }]]] as const) {
      assert.deepEqual(await entry.call('0.0.1', method, [...args] as unknown[]), { release: RELEASE }, method);
    }
    assert.equal(await entries(), before, 'nothing written');
    // The app's side: another release is `deploying`; this one is served.
    await assert.rejects(versioned(entry, '0.0.1').about(), (error: Error & { code?: string }) => error.code === 'deploying');
    assert.equal(typeof (await versioned(entry).access('user:root@acme.example')).role, 'string');
    // An app of 0.15, which posts to /<method>: no such route, before anything is read.
    const old = await new Promise<number>((resolve, reject) => {
      const req = request({ socketPath: served.socket, method: 'POST', path: '/access', headers: { 'content-type': 'application/json' } }, (res) => {
        res.resume();
        resolve(res.statusCode!);
      });
      req.on('error', reject);
      req.end(JSON.stringify(['user:root@acme.example']));
    });
    assert.equal(old, 404);
  } finally {
    await served.close();
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the vault's database not answering crosses the socket as the outage it is, with its code; a bug, as a bug", async () => {
  const lock = new Error('Failed query: select "principal" … params: fake', { cause: Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' }) });
  assert.deepEqual(failureOf(lock), { status: 503, body: { error: lock.message, code: '55P03' } });
  assert.equal(failureOf(new Error('Connection terminated unexpectedly')).body.code, '08006');
  // A bug keeps its code, which the app reads, rather than its words.
  assert.deepEqual(failureOf(Object.assign(new Error('invalid input syntax for type uuid: "connection timeout"'), { code: '22P02' })), {
    status: 500,
    body: { error: 'invalid input syntax for type uuid: "connection timeout"', code: '22P02' },
  });

  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-socket-'));
  try {
    const socket = join(dir, 'vault.sock');
    const answers = [failureOf(lock), failureOf(Object.assign(new Error('invalid input syntax for type uuid: "connection timeout"'), { code: '22P02' }))];
    const server = createServer((_req, res) => {
      const { status, body } = answers.shift()!;
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    });
    await new Promise<void>((resolve) => server.listen(socket, resolve));
    try {
      const vault = versioned(connectVault(socket));
      const busy = await vault.about().then(() => assert.fail('answered'), (error: unknown) => error);
      assert.equal(isUnavailable(busy), true);
      const bug = await vault.about().then(() => assert.fail('answered'), (error: unknown) => error);
      assert.equal(isUnavailable(bug), false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    // No vault there at all, its socket file gone with it: unreachable, as a refused connection is.
    const gone = await versioned(connectVault(join(dir, 'nobody.sock'))).about().then(() => assert.fail('answered'), (error: unknown) => error);
    assert.match(String((gone as Error).message), /is unreachable/);
    assert.equal(isUnavailable(gone), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a call nested deeper than the vault can walk is refused, 400 with a plain message, at every method; the app reads it as such', async () => {
  const db = await openTestDatabase();
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-socket-'));
  const served = await serveVault({
    socket: join(dir, 'vault.sock'),
    database: db.vault,
    hotDatabase: await db.hot(),
    checkpointer: { memory: join(dir, 'memory') },
    kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') },
    owners: ['root@acme.example'],
  });
  // 100,000 levels, 600 KB: within the socket's bound (8 MiB), and far past what any walk of it holds.
  const deep = `${'{"a":'.repeat(100_000)}0${'}'.repeat(100_000)}`;
  const post = (body: string) => new Promise<{ status: number; body: { error: string } }>((resolve, reject) => {
    const req = request({ socketPath: served.socket, method: 'POST', path: '/call', headers: { 'content-type': 'application/json' } }, (res) => {
      let text = '';
      res.on('data', (chunk: Buffer) => (text += chunk.toString()));
      res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(text) as { error: string } }));
    });
    req.on('error', reject);
    req.end(body);
  });
  try {
    const entries = async () => (await rows<{ n: string | number }>(db.vault, sql`SELECT count(*) AS n FROM audit_log`))[0]!.n;
    const before = await entries();
    for (const method of METHODS) {
      const answer = await post(`{"release":${JSON.stringify(RELEASE)},"method":"${method}","args":[${deep}]}`);
      assert.equal(answer.status, 400, method);
      assert.equal(answer.body.error, 'the call is nested too deeply to read', method);
    }
    assert.equal(await entries(), before, 'nothing written');
    // The app's side of the socket: the refusal as the error it raises, which the app answers 400 (`isStackOverflow`); an
    // overflow wrapped in another error, its words gone from the message, crosses by its code all the same.
    const refused = failureOf(new Error('could not walk the call', { cause: new RangeError(STACK_OVERFLOW) }));
    assert.equal(refused.status, 400);
    const server = createServer((_req, res) => res.writeHead(refused.status, { 'content-type': 'application/json' }).end(JSON.stringify(refused.body)));
    const socket = join(dir, 'refusing.sock');
    await new Promise<void>((resolve) => server.listen(socket, resolve));
    try {
      const error = await versioned(connectVault(socket)).about().then(() => assert.fail('answered'), (error: unknown) => error);
      assert.equal(isStackOverflow(error), true);
      assert.equal(isUnavailable(error), false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  } finally {
    await served.close();
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a vault on 0.15's log, the default, refuses a configuration without what it needs, by name", async () => {
  const db = await openTestDatabase();
  const keys = { kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') }, owners: ['root@acme.example'] };
  try {
    await assert.rejects(localVault({ database: db.vault, checkpointer: { memory: '/nowhere' }, ...keys }), /set hotDatabase .*coffre_vault_hot/);
    await assert.rejects(localVault({ database: db.vault, hotDatabase: db.vault, ...keys }), /set checkpointer: \{ memory \}/);
    // Below the deployment's entries, the vault itself: sealed and verified through a checkpointer, or not at all (T151).
    await assert.rejects(prepareVault(resolveVaultConfig(keys), { log: '0.15' }), /sealThrough/);
    await assert.rejects(prepareVault(resolveVaultConfig(keys), { log: '0.15', sealThrough: sealed }), /heldOutside/);
  } finally {
    await db.close();
  }
});
