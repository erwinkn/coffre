import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { Agent, createServer, request } from 'node:http';
import type { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isUnavailable } from '@coffre/db/dialect';

import { failureOf } from '../src/failure.ts';
import { resolveVaultConfig } from '../src/config.ts';
import { connectVault, localVault, serveVault } from '../src/node.ts';
import { prepareVault } from '../src/vault.ts';
import { openTestDatabase, sealed } from './database.ts';

// The vault as a process of its own, which the server reaches over a Unix
// socket (src/node.ts).

/** One call as `connectVault` makes it, on `agent`: the socket it went on. */
function about(socket: string, agent: Agent): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath: socket, agent, method: 'POST', path: '/about', headers: { 'content-type': 'application/json' } }, (res) => {
      res.resume();
      res.on('end', () => (res.statusCode === 200 ? resolve(req.socket as Socket) : reject(new Error(`status ${res.statusCode}`))));
    });
    req.on('error', reject);
    req.end('[]');
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
      const vault = connectVault(socket);
      const busy = await vault.about().then(() => assert.fail('answered'), (error: unknown) => error);
      assert.equal(isUnavailable(busy), true);
      const bug = await vault.about().then(() => assert.fail('answered'), (error: unknown) => error);
      assert.equal(isUnavailable(bug), false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    // No vault there at all, its socket file gone with it: unreachable, as a refused connection is.
    const gone = await connectVault(join(dir, 'nobody.sock')).about().then(() => assert.fail('answered'), (error: unknown) => error);
    assert.match(String((gone as Error).message), /is unreachable/);
    assert.equal(isUnavailable(gone), true);
  } finally {
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
