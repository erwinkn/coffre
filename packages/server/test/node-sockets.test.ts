// A plugin's WebSocket on Node (`node-sockets.ts`): a message is held whole until it has all come, as a body read
// whole is, and so no larger than one (`BODY_READ_WHOLE_BYTES`, `@coffre/core/memory`).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { WebSocket } from 'ws';
import { BODY_READ_WHOLE_BYTES } from '@coffre/core/memory';

import { runtime, useMcp } from './mcp-fixture.ts';
import { upgrade } from '../src/node-sockets.ts';
import { checkPlugins } from '../src/plugins.ts';

let coffre: Server;
let at: string;

before(async () => {
  coffre = createServer((_, response) => response.writeHead(404).end());
  coffre.on('upgrade', (request, socket, head) => void upgrade(runtime, request, socket, head));
  coffre.listen(0, '127.0.0.1');
  await once(coffre, 'listening');
  at = `ws://127.0.0.1:${(coffre.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => coffre.close(() => resolve())));

useMcp(async () => {
  // A session that answers each message with its length.
  runtime.plugins = checkPlugins([{ name: 'sizes', routes: { prefix: '/sizes', fetch: async () => new Response(null, { status: 404 }), socket: async () => async (client) => {
    const writer = client.writable.getWriter();
    const reader = client.readable.getReader();
    for (let read = await reader.read(); !read.done; read = await reader.read()) await writer.write(new TextEncoder().encode(String(read.value.length)));
  } } }]);
});

test('a message of 1 MiB reaches the session whole; one byte more closes the socket, 1009, too big', async () => {
  const ws = new WebSocket(`${at}/sizes`);
  ws.on('error', () => undefined);
  await once(ws, 'open');
  ws.send(Buffer.alloc(BODY_READ_WHOLE_BYTES, 1));
  const [answer] = (await once(ws, 'message')) as [Buffer];
  assert.equal(answer.toString(), String(BODY_READ_WHOLE_BYTES));
  ws.send(Buffer.alloc(BODY_READ_WHOLE_BYTES + 1, 1));
  const [code] = (await once(ws, 'close')) as [number];
  assert.equal(code, 1009);
});
