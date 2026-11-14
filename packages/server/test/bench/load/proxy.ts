// The rig's stand-in for the Worker side of Hyperdrive's hop: one proxy per
// Worker's login, in front of PgBouncer, counting connections, round trips
// (each time a client speaks again after an answer) and Syncs (each Sync
// and simple Query, what Postgres answers with ReadyForQuery: on Workers,
// the round trips Hyperdrive makes to the database), as
// scripts/postgres-proxy.ts counts them, with TCP_NODELAY on both sides. A
// process of its own, on a core of its own; its counters over HTTP.
//
// A login's open connections are capped (--most, 2000): beyond it a new one is
// closed at once and counted as refused, so a backed-up run cannot take the
// host's ports, as an unbounded one did (18,000 at once).
//
// Each Hyperdrive call opens a connection of its own, so a closed one per read
// on both hops; closed by FIN they would sit in TIME_WAIT for a minute, 20,000
// at 500 reads/s, the host's bind(0) range. So once either side ends, both are
// reset (RST leaves no TIME_WAIT): after a Terminate nothing is left to say.
//
//   node proxy.ts --pool <port> --database <name> --port <counters port> [--most <n>]
import { createServer } from 'node:http';
import { connect, createServer as createTcpServer, type Socket } from 'node:net';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: { pool: { type: 'string' }, database: { type: 'string' }, port: { type: 'string' }, most: { type: 'string', default: '2000' } } });
const most = Number(values.most);

async function counting(login: string) {
  let [opened, peak, trips, syncs, refused] = [0, 0, 0, 0, 0];
  const open = new Set<Socket>();
  const server = createTcpServer({ allowHalfOpen: true }, (client) => {
    if (open.size >= most) {
      refused += 1;
      client.resetAndDestroy();
      return;
    }
    client.setNoDelay(true);
    opened += 1;
    open.add(client);
    peak = Math.max(peak, open.size);
    const upstream = connect({ port: Number(values.pool), host: '127.0.0.1', allowHalfOpen: true });
    upstream.setNoDelay(true);
    let answered = true;
    let unread = Buffer.alloc(0);
    let started = false;
    client.on('data', (chunk: Buffer) => {
      if (answered) trips += 1;
      answered = false;
      upstream.write(chunk);
      unread = unread.length === 0 ? chunk : Buffer.concat([unread, chunk]);
      for (;;) {
        const head = started ? 1 : 0;
        if (unread.length < head + 4) break;
        const length = head + unread.readUInt32BE(head);
        if (unread.length < length) break;
        if (started && (unread[0] === 0x53 || unread[0] === 0x51)) syncs += 1;
        // The startup message, or an SSL or GSS request, has no type; the client's next is the startup message proper.
        if (!started && unread.readUInt32BE(4) >> 16 === 3) started = true;
        unread = unread.subarray(length);
      }
    });
    upstream.on('data', (chunk: Buffer) => {
      answered = true;
      client.write(chunk);
    });
    const end = () => {
      open.delete(client);
      if (!client.destroyed) client.resetAndDestroy();
      if (!upstream.destroyed) upstream.resetAndDestroy();
    };
    client.on('end', end).on('close', end).on('error', end);
    upstream.on('end', end).on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `postgresql://${login}@127.0.0.1:${(server.address() as { port: number }).port}/${values.database}`;
  return { get: () => ({ url, opened, open: open.size, peak, trips, syncs, refused }) };
}

const proxies = { app: await counting('coffre_runtime:local-runtime-only'), vault: await counting('coffre_vault_runtime:local-vault-only') };
createServer((_, response) => {
  response.setHeader('content-type', 'application/json');
  response.end(JSON.stringify({ app: proxies.app.get(), vault: proxies.vault.get() }));
}).listen(Number(values.port), '127.0.0.1', () => console.log(JSON.stringify({ ready: true })));
