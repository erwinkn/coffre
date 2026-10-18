// The local end of the credential proxy's database tunnel
// (docs/design/credential-proxy.md, "Postgres through a tunnel"): a listener
// on 127.0.0.1 for the app `coffre run` starts, which carries each of its
// connections over a WebSocket to coffre, with the run's handle. It holds no
// value and reads no byte: coffre logs in to the database, and the app's
// password, the handle, is checked there.
import { createServer, type Socket } from 'node:net';

import { WebSocket } from 'ws';

/** A tunnel the plan names: the key the app reads its database's URL from, and coffre's end of it. */
export type Tunnel = { key: string; url: string };

/** How much one side may hold for the other before it stops reading: a few COPY chunks. */
const HIGH_WATER = 1024 * 1024;

/** A listener, on a port of its own, for as long as the run lasts; and the URL the app connects with. */
export async function listen(tunnel: Tunnel, handle: string): Promise<{ url: string; close: () => void }> {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    // Nothing read from the app until coffre's end is open: then each side reads only as fast as the other takes.
    socket.pause();
    const ws = new WebSocket(tunnel.url, { headers: { authorization: `Bearer ${handle}` } });
    ws.on('open', () => socket.resume());
    socket.on('data', (chunk: Buffer) => {
      ws.send(chunk, { binary: true }, () => {
        if (ws.bufferedAmount < HIGH_WATER) socket.resume();
      });
      if (ws.bufferedAmount >= HIGH_WATER) socket.pause();
    });
    ws.on('message', (data: Buffer) => {
      if (!socket.write(data)) ws.pause();
    });
    socket.on('drain', () => ws.resume());
    ws.on('close', () => socket.destroy());
    ws.on('error', () => socket.destroy());
    socket.on('close', () => {
      sockets.delete(socket);
      ws.close();
    });
    socket.on('error', () => ws.terminate());
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  // A listener keeps no run alive: the run ends with its command.
  server.unref();
  const { port } = server.address() as { port: number };
  return {
    // The database's user and name are coffre's to set, from the real URL; the app's are placeholders.
    url: `postgres://app:${encodeURIComponent(handle)}@127.0.0.1:${port}/app?sslmode=disable`,
    close: () => {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}
