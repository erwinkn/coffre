// Postgres through the credential proxy's tunnel (docs/design/credential-proxy.md,
// "Postgres through a tunnel"): the app's driver, `pg`, connects to a local
// listener with the handle as its password; the listener carries each
// connection over a WebSocket to coffre, which logs in to the real database
// with the real password (SCRAM, as this suite's Postgres asks) and pipes
// bytes. Queries, COPY both ways, LISTEN/NOTIFY, a cancel request, and a
// handle revoked mid-session. Postgres only: the database tunnelled to is
// the suite's own, as its restricted runtime login.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttp, type Server } from 'node:http';
import { connect as tcp, createServer as createTcp, type AddressInfo, type Server as TcpServer, type Socket } from 'node:net';
import { once } from 'node:events';

import pg from 'pg';
import { WebSocket } from 'ws';

import { clientFor } from './api-fixture.ts';
import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { upgrade } from '../src/node-sockets.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, postgres } from '../src/plugins/credential-proxy.ts';

const postgresOnly = { skip: TEST_ENGINE !== 'postgres' ? 'the tunnel reaches a Postgres database' : false };
// The suite's database, as the app's would name it: no TLS to a database on loopback.
const REAL = `${TEST_RUNTIME_DATABASE_URL}?sslmode=disable`;

let coffre: Server;
let listener: TcpServer;
let listenerPort: number;
let handle: string;
/** Each connection the listener carried. */
const carried: Socket[] = [];

before(async () => {
  // coffre over HTTP, its upgrades to its plugins' sockets.
  coffre = createHttp((_, response) => response.writeHead(404).end());
  coffre.on('upgrade', (request, socket, head) => void upgrade(runtime, request, socket, head));
  coffre.listen(0, '127.0.0.1');
  await once(coffre, 'listening');
  const at = `ws://127.0.0.1:${(coffre.address() as AddressInfo).port}`;
  // `coffre run`'s listener, as it is: each connection, a WebSocket to the tunnel with the handle, bytes both ways.
  listener = createTcp((socket) => {
    carried.push(socket);
    const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${handle}` } });
    const early: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => (ws.readyState === WebSocket.OPEN ? ws.send(chunk) : early.push(chunk)));
    ws.on('open', () => early.splice(0).forEach((chunk) => ws.send(chunk)));
    ws.on('message', (data: Buffer) => socket.write(data));
    ws.on('close', () => socket.destroy());
    ws.on('error', () => socket.destroy());
    socket.on('close', () => ws.close());
    socket.on('error', () => ws.terminate());
  });
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  listenerPort = (listener.address() as AddressInfo).port;
});

after(async () => {
  for (const socket of carried) socket.destroy();
  await new Promise<void>((resolve) => listener.close(() => resolve()));
  coffre.closeAllConnections();
  await new Promise<void>((resolve) => coffre.close(() => resolve()));
});

useMcp(
  async () => {
    runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') }, insecureUpstreams: true, recheckSeconds: 0.2 })]);
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.projects.create('market');
    await root.environments.create('market/dev');
    await root.secrets.set('market/dev', { DATABASE_URL: REAL, OTHER: 'x' });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
    handle = (await (await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: ['market/dev'] }) })).json() as { token: string }).token;
  },
  { people: 'stand-ins' },
);

/** The app's client, on the listener, the handle its password: what `coffre run` puts in DATABASE_URL. */
function appClient(password = handle): pg.Client {
  return new pg.Client({ connectionString: `postgres://app:${password}@127.0.0.1:${listenerPort}/app` });
}

test('the plan names the tunnel, and gives the app no database URL of its own', postgresOnly, async () => {
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; tunnels: Record<string, { key: string; url: string }>; left: string[] };
  assert.deepEqual(plan.tunnels, { db: { key: 'DATABASE_URL', url: `${ORIGIN.replace('https', 'wss')}/use/market/dev/db` } });
  assert.equal(plan.env.DATABASE_URL, undefined);
  assert.equal(JSON.stringify(plan).includes('local-runtime-only'), false, 'never the real password');
  assert.deepEqual(plan.left, ['OTHER']);
});

test('queries through the tunnel run as the real login, and the session is logged as one use', postgresOnly, async () => {
  const client = appClient();
  await client.connect();
  try {
    const { rows } = await client.query('SELECT current_user AS who, 1 + 1 AS two');
    assert.deepEqual(rows, [{ who: 'coffre_runtime', two: 2 }]);
    // An extended-protocol query with parameters, as drivers send them.
    assert.deepEqual((await client.query('SELECT $1::text || $2::text AS joined', ['a', 'b'])).rows, [{ joined: 'ab' }]);
  } finally {
    await client.end();
  }
  const uses = (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'db');
  assert.equal(uses.length, 1);
  assert.equal(uses[0]!.metadata.tunnel, true);
  assert.deepEqual(uses[0]!.metadata.keys, ['DATABASE_URL']);
});

test('a password that is not the handle is refused, before any login to the database', postgresOnly, async () => {
  const client = appClient('not-the-handle');
  await assert.rejects(client.connect(), (error: { code?: string }) => error.code === '28P01');
});

test('LISTEN and NOTIFY across two tunnelled connections', postgresOnly, async () => {
  const listening = appClient();
  const notifying = appClient();
  await listening.connect();
  await notifying.connect();
  try {
    await listening.query('LISTEN coffre_tunnel');
    const heard = new Promise<string>((resolve) => listening.on('notification', (message) => resolve(message.payload!)));
    await notifying.query("SELECT pg_notify('coffre_tunnel', 'through the tunnel')");
    assert.equal(await heard, 'through the tunnel');
  } finally {
    await listening.end();
    await notifying.end();
  }
});

test('COPY both ways, on the wire as psql sends it', postgresOnly, async () => {
  // As the database's owner, who may make the temporary table to copy into.
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: `${TEST_OWNER_DATABASE_URL}?sslmode=disable` });
  const raw = await rawSession();
  try {
    await raw.query('CREATE TEMP TABLE carried (n int)');
    // COPY FROM STDIN: CopyInResponse, then the rows as CopyData, CopyDone.
    const copyIn = await raw.send('Q', cstring('COPY carried FROM STDIN'));
    assert.equal(copyIn, 'G');
    await raw.write(message('d', Buffer.from('4\n5\n6\n')));
    await raw.write(message('c', Buffer.alloc(0)));
    await raw.until('Z');
    const copied = await raw.copyOut('COPY (SELECT sum(n) FROM carried) TO STDOUT');
    assert.equal(copied, '15\n');
  } finally {
    raw.close();
  }
});

test("a cancel request, on a connection of its own, reaches the database with the key the app was given", postgresOnly, async () => {
  const client = appClient();
  await client.connect();
  try {
    const sleeping = client.query('SELECT pg_sleep(30)');
    await new Promise((resolve) => setTimeout(resolve, 200));
    const { processID, secretKey } = client as unknown as { processID: number; secretKey: number };
    // As psql sends one: a CancelRequest, to the same listener.
    const cancel = tcp({ host: '127.0.0.1', port: listenerPort });
    await once(cancel, 'connect');
    const packet = Buffer.alloc(16);
    packet.writeInt32BE(16, 0);
    packet.writeInt32BE(80877102, 4);
    packet.writeInt32BE(processID, 8);
    packet.writeInt32BE(secretKey, 12);
    cancel.write(packet);
    const started = Date.now();
    await assert.rejects(sleeping, (error: { code?: string }) => error.code === '57014');
    assert.ok(Date.now() - started < 5000);
    cancel.destroy();
  } finally {
    await client.end();
  }
});

test('a handle revoked mid-session ends the open session at the next check, and opens no other', postgresOnly, async () => {
  const client = appClient();
  client.on('error', () => undefined);
  await client.connect();
  assert.deepEqual((await client.query('SELECT 1 AS one')).rows, [{ one: 1 }]);
  const session = await sessionFor(DEV);
  const listed = await (await route(`/api/members/user:${DEV}/tokens`, { headers: { authorization: `Bearer ${session}` } })).json() as { tokens: { id: string; hint: string }[] };
  const id = listed.tokens.find((token) => token.hint.endsWith(handle.slice(-4)))!.id;
  await route(`/api/members/user:${DEV}/tokens/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } });
  await new Promise((resolve) => setTimeout(resolve, 600));
  await assert.rejects(client.query('SELECT 1'));
  await assert.rejects(appClient().connect(), 'nor is a new one opened');
});

test('a tunnel reaches only the hosts it names, and a private database only with insecureUpstreams', postgresOnly, async () => {
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) }, insecureUpstreams: true })]);
  await assert.rejects(appClient().connect());
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') } })]);
  await assert.rejects(appClient().connect());
  assert.throws(() => credentialProxy({ credentials: { db: { upstream: 'https://x.example', inject: { kind: 'header', name: 'x', template: '{K}' } } }, tunnels: { db: postgres('DATABASE_URL') } }), /a credential and a tunnel/);
});

// --- a raw session, as psql's wire is: the simple query protocol, COPY included ---

const cstring = (text: string) => Buffer.concat([Buffer.from(text), Buffer.from([0])]);
function message(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.write(type, 0);
  head.writeInt32BE(body.length + 4, 1);
  return Buffer.concat([head, body]);
}

async function rawSession() {
  const socket = tcp({ host: '127.0.0.1', port: listenerPort });
  await once(socket, 'connect');
  let buffered = Buffer.alloc(0);
  const waiting: (() => void)[] = [];
  socket.on('data', (chunk: Buffer) => {
    buffered = Buffer.concat([buffered, chunk]);
    waiting.splice(0).forEach((wake) => wake());
  });
  const next = async (): Promise<{ type: string; body: Buffer }> => {
    while (buffered.length < 5 || buffered.length < 1 + buffered.readInt32BE(1)) await new Promise<void>((resolve) => waiting.push(resolve));
    const length = buffered.readInt32BE(1);
    const out = { type: String.fromCharCode(buffered[0]!), body: buffered.subarray(5, 1 + length) };
    buffered = buffered.subarray(1 + length);
    return out;
  };
  const write = (bytes: Buffer) => new Promise<void>((resolve) => socket.write(bytes, () => resolve()));
  const until = async (type: string) => {
    for (let got = await next(); ; got = await next()) {
      if (got.type === 'E') throw new Error(got.body.toString());
      if (got.type === type) return got;
    }
  };
  const startup = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring('user'), cstring('app'), cstring('database'), cstring('app'), Buffer.from([0])]);
  const length = Buffer.alloc(4);
  length.writeInt32BE(startup.length + 4);
  await write(Buffer.concat([length, startup]));
  await until('R');
  await write(message('p', cstring(handle)));
  await until('Z');
  return {
    write,
    until,
    async query(sql: string) {
      await write(message('Q', cstring(sql)));
      await until('Z');
    },
    /** A message sent; the type of the first answer that is no notice or parameter. */
    async send(type: string, body: Buffer) {
      await write(message(type, body));
      for (let got = await next(); ; got = await next()) if (!['N', 'S'].includes(got.type)) return got.type;
    },
    async copyOut(sql: string) {
      await write(message('Q', cstring(sql)));
      let text = '';
      for (let got = await next(); got.type !== 'Z'; got = await next()) {
        if (got.type === 'E') throw new Error(got.body.toString());
        if (got.type === 'd') text += got.body.toString();
      }
      return text;
    },
    close: () => socket.destroy(),
  };
}
