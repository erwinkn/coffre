import { connect, createServer, type Server } from 'node:net';

/** Postgres as Hyperdrive serves it from far away: each chunk delayed by half the round trip, each way. */
export async function farPostgres(at: string, rtt: number): Promise<{ url: string; close(): Promise<void> }> {
  const target = new URL(at);
  const server: Server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) => from.on('data', (chunk) => setTimeout(() => to.write(chunk), rtt / 2));
    relay(client, upstream);
    relay(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = new URL(at);
  url.port = String((server.address() as { port: number }).port);
  return { url: url.toString(), close: () => new Promise((resolve) => server.close(() => resolve())) };
}

/** The p-th percentile of sorted values. */
export const percentile = (sorted: readonly number[], p: number) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))]!;
