// A database that is not there, then is: a port nothing listens on, and a
// proxy that opens on it later (node-start.test.ts, node-start-small.test.ts).
import { connect, createServer, type Server, type Socket } from 'node:net';

/** A port nothing listens on: one the system gave, closed again. */
export async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

/**
 * The database back where it was not: a proxy on `port` to `target`'s
 * Postgres, until `close`, which cuts every connection through it.
 */
export async function proxy(port: number, target: string): Promise<{ close: () => Promise<void> }> {
  const { hostname, port: to } = new URL(target);
  const sockets = new Set<Socket>();
  const server: Server = createServer((client) => {
    const upstream = connect(Number(to), hostname);
    for (const socket of [client, upstream]) {
      sockets.add(socket);
      socket.on('error', () => {});
      socket.on('close', () => sockets.delete(socket));
    }
    client.pipe(upstream).pipe(client);
  });
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  return {
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

