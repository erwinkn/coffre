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
import { saslprep } from '../src/plugins/postgres-tunnel.ts';

const postgresOnly = { skip: TEST_ENGINE !== 'postgres' ? 'the tunnel reaches a Postgres database' : false };
// The suite's database, as the app's would name it: no TLS to a database on loopback.
const REAL = `${TEST_RUNTIME_DATABASE_URL}?sslmode=disable`;

let coffre: Server;
let coffreAt: string;
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
  coffreAt = at;
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

test("a cancel request with a key no live session of this handle was given reaches nothing", postgresOnly, async () => {
  const client = appClient();
  await client.connect();
  try {
    const sleeping = client.query('SELECT pg_sleep(0.6) AS slept');
    await new Promise((resolve) => setTimeout(resolve, 100));
    const { processID, secretKey } = client as unknown as { processID: number; secretKey: number };
    // The database's own key is never the app's: guess one, or flip one bit of the one given.
    for (const [pid, key] of [[processID, secretKey ^ 1], [12345, 67890]]) {
      const cancel = tcp({ host: '127.0.0.1', port: listenerPort });
      await once(cancel, 'connect');
      const packet = Buffer.alloc(16);
      packet.writeInt32BE(16, 0);
      packet.writeInt32BE(80877102, 4);
      packet.writeInt32BE(pid!, 8);
      packet.writeInt32BE(key!, 12);
      cancel.write(packet);
      await once(cancel, 'close');
    }
    assert.deepEqual((await sleeping).rows, [{ slept: '' }], 'the query ran to its end');
  } finally {
    await client.end();
  }
});

test('a handle revoked while a connection waits at the password prompt does not log it in', postgresOnly, async () => {
  const socket = tcp({ host: '127.0.0.1', port: listenerPort });
  await once(socket, 'connect');
  const startup = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring('user'), cstring('app'), Buffer.from([0])]);
  const length = Buffer.alloc(4);
  length.writeInt32BE(startup.length + 4);
  socket.write(Buffer.concat([length, startup]));
  await once(socket, 'data');
  await revoke();
  const answers: Buffer[] = [];
  socket.on('data', (chunk: Buffer) => answers.push(chunk));
  socket.write(message('p', cstring(handle)));
  await once(socket, 'close');
  const said = Buffer.concat(answers).toString('latin1');
  assert.equal(said.includes('R\u0000\u0000\u0000\u0008\u0000\u0000\u0000\u0000'), false, 'no AuthenticationOk');
});

test('a password message longer than a handle is refused before it is read', postgresOnly, async () => {
  const socket = tcp({ host: '127.0.0.1', port: listenerPort });
  await once(socket, 'connect');
  const startup = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring('user'), cstring('app'), Buffer.from([0])]);
  const length = Buffer.alloc(4);
  length.writeInt32BE(startup.length + 4);
  socket.write(Buffer.concat([length, startup]));
  await once(socket, 'data');
  const head = Buffer.alloc(5);
  head.write('p', 0);
  head.writeInt32BE(0x7fffffff, 1);
  socket.write(head);
  socket.write(Buffer.alloc(64 * 1024));
  await once(socket, 'close');
});

test("an upgrade refused keeps the proxy's own headers", postgresOnly, async () => {
  const refused = await new Promise<{ status: string; headers: string }>((resolve) => {
    const socket = tcp({ host: '127.0.0.1', port: Number(new URL(coffreAt).port) });
    socket.on('connect', () => socket.write('GET /use/market/dev/db HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'));
    let text = '';
    socket.on('data', (chunk: Buffer) => (text += chunk.toString('latin1')));
    socket.on('close', () => resolve({ status: text.split('\r\n')[0]!, headers: text }));
  });
  assert.match(refused.status, / 401 /);
  assert.match(refused.headers, /coffre-proxy: refused/);
});

test("SASLprep maps as Postgres does, and falls back to the password as it is", () => {
  const soft = String.fromCharCode(0xad);
  const space = String.fromCharCode(0xa0);
  assert.equal(saslprep(`I${soft}X`), 'IX');
  assert.equal(saslprep(`a${space}b`), 'a b');
  assert.equal(saslprep(String.fromCharCode(0x2168)), 'IX', 'NFKC');
  const control = `pass${String.fromCharCode(7)}word`;
  assert.equal(saslprep(control), control, 'a prohibited character: the password as it is');
  assert.equal(saslprep(`a${String.fromCharCode(0x200b)}b`), 'a b', 'a zero-width space is a space, as Postgres maps it');
  assert.equal(saslprep(soft), soft, 'nothing left: the password as it is');
});

test('a database that ends SCRAM without its signature is no database the URL names: refused', postgresOnly, async () => {
  // A fake that asks for SCRAM, takes the proof, and says AuthenticationOk with no server-final message.
  const fake = createTcp((socket) => {
    let stage = 0;
    let buffered = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (stage === 0 && buffered.length >= 4 && buffered.length >= buffered.readInt32BE(0)) {
        buffered = buffered.subarray(buffered.readInt32BE(0));
        stage = 1;
        socket.write(message('R', Buffer.concat([Buffer.from([0, 0, 0, 10]), cstring('SCRAM-SHA-256'), Buffer.from([0])])));
      } else if (stage === 1 && buffered.length >= 5 && buffered.length >= 1 + buffered.readInt32BE(1)) {
        const first = buffered.subarray(5 + 'SCRAM-SHA-256'.length + 1 + 4, 1 + buffered.readInt32BE(1)).toString();
        buffered = buffered.subarray(1 + buffered.readInt32BE(1));
        stage = 2;
        const nonce = /r=([^,]+)/.exec(first)![1]!;
        socket.write(message('R', Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from(`r=${nonce}server,s=${Buffer.from('salt').toString('base64')},i=4096`)])));
      } else if (stage === 2 && buffered.length >= 5 && buffered.length >= 1 + buffered.readInt32BE(1)) {
        stage = 3;
        socket.write(message('R', Buffer.from([0, 0, 0, 0])));
        socket.write(message('Z', Buffer.from('I')));
      }
    });
  });
  fake.listen(0, '127.0.0.1');
  await once(fake, 'listening');
  try {
    await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: `postgres://u:p@127.0.0.1:${(fake.address() as AddressInfo).port}/d?sslmode=disable` });
    await assert.rejects(appClient().connect(), /without proving it knows the password/);
  } finally {
    fake.close();
  }
});

test("a person whose grant ends loses their open sessions at the next check", postgresOnly, async () => {
  const client = appClient();
  client.on('error', () => undefined);
  await client.connect();
  assert.deepEqual((await client.query('SELECT 1 AS one')).rows, [{ one: 1 }]);
  await clientFor(deps, ROOT).access.set(`user:${DEV}`, { market: null });
  await new Promise((resolve) => setTimeout(resolve, 600));
  await assert.rejects(client.query('SELECT 1'));
});

test('a connection the app drops while the database has not answered leaves no socket open to it', postgresOnly, async () => {
  // A database that takes the connection and says nothing: the tunnel waits on its answer to SSLRequest.
  const opened: Socket[] = [];
  const silent = createTcp((socket) => {
    opened.push(socket);
    // What the tunnel sends it is read, and never answered: a socket left unread would not say when it closes.
    socket.resume();
  });
  silent.listen(0, '127.0.0.1');
  await once(silent, 'listening');
  try {
    await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: `postgres://u:p@127.0.0.1:${(silent.address() as AddressInfo).port}/d` });
    const raw = tcp({ host: '127.0.0.1', port: listenerPort });
    await once(raw, 'connect');
    const startup = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring('user'), cstring('app'), Buffer.from([0])]);
    const length = Buffer.alloc(4);
    length.writeInt32BE(startup.length + 4);
    raw.write(Buffer.concat([length, startup]));
    await once(raw, 'data');
    raw.write(message('p', cstring(handle)));
    for (let waited = 0; opened.length === 0 && waited < 2000; waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(opened.length, 1, 'the tunnel reached the database');
    const closed = once(opened[0]!, 'close');
    raw.destroy();
    await closed;
  } finally {
    for (const socket of opened) socket.destroy();
    silent.close();
  }
});

test('a startup asks for encryption once each, and no more', postgresOnly, async () => {
  const raw = tcp({ host: '127.0.0.1', port: listenerPort });
  await once(raw, 'connect');
  const ssl = Buffer.alloc(8);
  ssl.writeInt32BE(8, 0);
  ssl.writeInt32BE(80877103, 4);
  raw.write(Buffer.concat(Array.from({ length: 1000 }, () => ssl)));
  let answered = '';
  raw.on('data', (chunk: Buffer) => (answered += chunk.toString('latin1')));
  await once(raw, 'close');
  assert.ok(answered.startsWith('NN'), answered.slice(0, 4));
  assert.ok(!answered.startsWith('NNN'));
});

/** Revoke the suite's handle, as its person would. */
async function revoke(): Promise<void> {
  const session = await sessionFor(DEV);
  const listed = (await (await route(`/api/members/user:${DEV}/tokens`, { headers: { authorization: `Bearer ${session}` } })).json()) as { tokens: { id: string; hint: string }[] };
  const id = listed.tokens.find((token) => token.hint.endsWith(handle.slice(-4)))!.id;
  await route(`/api/members/user:${DEV}/tokens/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } });
}

test('a handle revoked mid-session ends the open session at the next check, and opens no other', postgresOnly, async () => {
  const client = appClient();
  client.on('error', () => undefined);
  await client.connect();
  assert.deepEqual((await client.query('SELECT 1 AS one')).rows, [{ one: 1 }]);
  await revoke();
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
