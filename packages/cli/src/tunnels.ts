// The local end of the credential proxy's database tunnel
// (docs/design/credential-proxy.md, "Postgres through a tunnel"): a listener
// on 127.0.0.1 for the app `coffre run` starts, which carries each of its
// connections over a WebSocket to coffre, with the run's handle. It holds no
// value and reads no byte: coffre logs in to the database, and the app's
// password, the handle, is checked there.
import { createServer, type Socket } from 'node:net';

/** A tunnel the plan names: the key the app reads its database's URL from, and coffre's end of it. */
export type Tunnel = { key: string; url: string };

/** A listener, on a port of its own, for as long as the run lasts; and the URL the app connects with. */
export async function listen(tunnel: Tunnel, handle: string): Promise<{ url: string; close: () => void }> {
  const WebSocketClass = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
  if (WebSocketClass === undefined) throw new Error(`${tunnel.key} goes through a tunnel, which takes Node 22 or later`);
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    // Node's WebSocket takes headers, as undici's does: the handle, never in the URL.
    const ws = new (WebSocketClass as unknown as new (url: string, init: { headers: Record<string, string> }) => WebSocket)(tunnel.url, { headers: { authorization: `Bearer ${handle}` } });
    ws.binaryType = 'arraybuffer';
    const early: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => (ws.readyState === ws.OPEN ? ws.send(chunk) : early.push(chunk)));
    ws.addEventListener('open', () => early.splice(0).forEach((chunk) => ws.send(chunk)));
    ws.addEventListener('message', (event) => socket.write(new Uint8Array(event.data as ArrayBuffer)));
    ws.addEventListener('close', () => socket.destroy());
    ws.addEventListener('error', () => socket.destroy());
    socket.on('close', () => {
      sockets.delete(socket);
      ws.close();
    });
    socket.on('error', () => ws.close());
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
