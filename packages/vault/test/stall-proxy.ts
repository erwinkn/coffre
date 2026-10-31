// T169: a TCP proxy in front of Postgres that can stop answering, as a
// connection that went dead, or a connect Hyperdrive never gets a slot for,
// is to its client: held, nothing goes either way and nothing is closed;
// let go, what was held goes on.
import { connect, createServer, type Socket } from 'node:net';

export type StallProxy = {
  /** The URL through the proxy: `url` with its host and port the proxy's. */
  url: string;
  hold(): void;
  release(): void;
  close(): Promise<void>;
};

export async function stallProxy(url: string): Promise<StallProxy> {
  const target = new URL(url);
  let held = false;
  const waiting: (() => void)[] = [];
  const sockets = new Set<Socket>();
  const track = (socket: Socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
  };
  // Each way, chunks written as they come, or kept while held.
  const flushes: (() => void)[] = [];
  const forward = (from: Socket, to: Socket) => {
    const kept: Buffer[] = [];
    from.on('data', (chunk: Buffer) => {
      if (held) kept.push(chunk);
      else to.write(chunk);
    });
    from.on('close', () => to.destroy());
    flushes.push(() => {
      for (const chunk of kept.splice(0)) to.write(chunk);
    });
  };
  const server = createServer((client) => {
    track(client);
    const go = () => {
      const upstream = connect(Number(target.port), target.hostname);
      track(upstream);
      forward(client, upstream);
      forward(upstream, client);
    };
    if (held) waiting.push(go);
    else go();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const { port } = server.address() as { port: number };
  const through = new URL(url);
  through.hostname = '127.0.0.1';
  through.port = String(port);
  return {
    url: through.toString(),
    hold: () => {
      held = true;
    },
    release: () => {
      held = false;
      for (const flush of flushes) flush();
      for (const go of waiting.splice(0)) go();
    },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
