import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { Agent, request } from 'node:http';
import type { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { serveVault } from '../src/node.ts';
import { openTestDatabase } from './database.ts';

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
    kek: { id: 'test-kek-1', key: Buffer.alloc(32, 7).toString('base64') },
    rootAdmins: ['root@acme.example'],
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
