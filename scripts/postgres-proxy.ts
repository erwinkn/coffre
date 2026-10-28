// Postgres behind a proxy that counts what crosses it, for the tests that
// hold a Worker's database to its round trips (packages/db/test/hyperdrive.test.ts,
// packages/server/test/request-cost.test.ts), and that can stand in for a
// slow network.
import { once } from 'node:events';
import { connect, createServer, type Socket } from 'node:net';

/**
 * A proxy in front of `database` that counts the connections made to it,
 * the round trips on them (each time the client speaks again after an
 * answer) and the Syncs, can cut them, can hold a COMMIT on its way, and
 * with `delayMs` holds each round trip that carries a Sync that long, as
 * Hyperdrive far from its database does: it opens a client's connection
 * itself, near it, and sends each Sync on to the database.
 *
 * A Sync is each Sync message and each simple Query, what Postgres answers
 * with ReadyForQuery. A real Hyperdrive sends the next one on only once the
 * one before has answered: statements written at once under several Syncs
 * cost a round trip each there, those under one Sync one in all. So on
 * Workers, Syncs are the round trips, which one write can hide.
 */
export async function postgresProxy(database: string, { delayMs = 0 }: { delayMs?: number } = {}) {
  const target = new URL(database);
  const open = new Set<Socket>();
  let opened = 0;
  let peak = 0;
  let trips = 0;
  let syncs = 0;
  let commits: Promise<void> | null = null;
  const server = createServer((client) => {
    opened += 1;
    open.add(client);
    peak = Math.max(peak, open.size);
    const upstream = connect(Number(target.port), target.hostname);
    let answered = true;
    let sending = Promise.resolve();
    // What the client sent of a message not yet whole; the startup message, first, has no type.
    let unread = Buffer.alloc(0);
    let started = false;
    client.on('data', (chunk: Buffer) => {
      if (answered) trips += 1;
      answered = false;
      const before = syncs;
      unread = Buffer.concat([unread, chunk]);
      for (;;) {
        const head = started ? 1 : 0;
        if (unread.length < head + 4) break;
        const length = head + unread.readUInt32BE(head);
        if (unread.length < length) break;
        if (started && (unread[0] === 0x53 || unread[0] === 0x51)) syncs += 1; // 'S', 'Q'
        started = true;
        unread = unread.subarray(length);
      }
      const synced = syncs > before;
      const held = commits !== null && /commit/i.test(chunk.toString('latin1')) ? commits : null;
      sending = sending.then(async () => {
        if (synced && delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
        await held;
        upstream.write(chunk);
      });
    });
    upstream.on('data', (chunk: Buffer) => {
      answered = true;
      client.write(chunk);
    });
    const end = () => {
      open.delete(client);
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = new URL(database);
  url.port = String((server.address() as { port: number }).port);
  return {
    url: url.href,
    get opened() {
      return opened;
    },
    get peak() {
      return peak;
    },
    get open() {
      return open.size;
    },
    get trips() {
      return trips;
    },
    get syncs() {
      return syncs;
    },
    /** Hold every COMMIT until `until` settles. */
    holdCommits(until: Promise<void>) {
      commits = until;
    },
    cut: () => {
      for (const socket of open) socket.destroy();
    },
    /** Whatever is still open goes, then the proxy. */
    close: () => {
      for (const socket of open) socket.destroy();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
