import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createConnection, createServer } from 'node:net';
import { resolve } from 'node:path';
import test from 'node:test';

const script = resolve(import.meta.dirname, 'postgres-port-available.mjs');
const check = (port) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, String(port)], { stdio: ['ignore', 'ignore', 'pipe'], timeout: 5000 });
    let error = '';
    child.stderr.on('data', (chunk) => { error += chunk; });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, error }));
});

async function listener(t) {
    const server = createServer();
    t.after(() => server.close());
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return server;
}

test('a listening socket prevents Postgres startup', async (t) => {
    const server = await listener(t);
    assert.deepEqual(await check(server.address().port), { code: 1, error: '' });
});

test('an outgoing socket also prevents startup, even though it has no listener', async (t) => {
    const server = await listener(t);
    const accepted = once(server, 'connection');
    const client = createConnection({ host: '127.0.0.1', port: server.address().port });
    const connected = once(client, 'connect');
    t.after(() => client.destroy());
    const [peer] = await accepted;
    t.after(() => peer.destroy());
    await connected;
    assert.deepEqual(await check(client.localPort), { code: 1, error: '' });
});
