// `coffre run`'s listener as it speaks to a Workers coffre (packages/cli/src/tunnels.ts),
// for the workerd suites: the flow header, and each side's count of what it took.
import { once } from 'node:events';
import { connect as tcp, createServer, type AddressInfo, type Server, type Socket } from 'node:net';

import { postgresSession, type PostgresClient } from '@coffre/db/connect';
import { WebSocket } from 'ws';

/** The object's window, cloudflare-sockets.ts's `WINDOW`: what it sends that the app has not counted. */
export const WINDOW = 1024 * 1024;

/** A listener on 127.0.0.1 that carries each connection to `url` with `handle`; its port. `close` it after. */
export async function tunnelListener(url: string, handle: string): Promise<{ port: number; close(): void }> {
  const listener: Server = createServer((socket: Socket) => {
    socket.pause();
    const ws = new WebSocket(url, { headers: { authorization: `Bearer ${handle}`, 'coffre-tunnel-flow': 'credit' } });
    let uncounted = 0;
    let taken = 0;
    ws.on('open', () => socket.resume());
    socket.on('data', (chunk: Buffer) => {
      uncounted += chunk.length;
      ws.send(chunk);
      if (uncounted >= WINDOW) socket.pause();
    });
    ws.on('message', (data: Buffer, binary: boolean) => {
      if (!binary) {
        uncounted -= Number(data.toString());
        if (uncounted < WINDOW) socket.resume();
        return;
      }
      socket.write(data, () => {
        taken += data.length;
        if (taken >= 64 * 1024 && ws.readyState === WebSocket.OPEN) {
          ws.send(String(taken));
          taken = 0;
        }
      });
    });
    ws.on('close', () => socket.destroy());
    ws.on('error', () => socket.destroy());
    socket.on('close', () => ws.close());
    socket.on('error', () => ws.terminate());
  });
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  return { port: (listener.address() as AddressInfo).port, close: () => listener.close() };
}

/** The app's client on a tunnel's listener, and when the tunnel ended its connection. */
export type AppClient = PostgresClient & { ended: Promise<number> };

/**
 * The app's client on the listener at `port`, its password `password` (the
 * handle, as `coffre run` puts it in DATABASE_URL): one session, as a
 * node-postgres Client is. Once the tunnel ends its connection, every
 * statement after fails (`SessionLost`), where a postgres.js client would
 * dial again; `ended` says when its own connection closed, not a LISTEN's
 * or a cancel's, which dial connections of their own through the same
 * listener.
 */
export function appClient(port: number, password: string): AppClient {
  let ended!: (at: number) => void;
  const client = postgresSession(`postgres://app:${password}@127.0.0.1:${port}/app`, {
    socket: () => tcp({ host: '127.0.0.1', port }),
    onclose: () => ended(Date.now()),
  });
  return Object.assign(client, { ended: new Promise<number>((resolve) => (ended = resolve)) });
}
