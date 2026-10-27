// Postgres through the credential proxy's tunnel (docs/design/credential-proxy.md,
// "Postgres through a tunnel"): the app's driver, postgres.js, connects to a local
// listener with the handle as its password; the listener carries each
// connection over a WebSocket to coffre, which logs in to the real database
// with the real password (SCRAM, as this suite's Postgres asks) and pipes
// bytes. Queries, COPY both ways, LISTEN/NOTIFY, a cancel request, and a
// handle revoked mid-session. Postgres only: the database tunnelled to is
// the suite's own, as its restricted runtime login.
import test, { after, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttp, type Server } from 'node:http';
import { connect as tcp, createServer as createTcp, type AddressInfo, type Server as TcpServer, type Socket } from 'node:net';
import { once } from 'node:events';
import { Duplex } from 'node:stream';

import { WebSocket } from 'ws';


import { clientFor } from './api-fixture.ts';
import { trackBackgroundTask } from './background-tasks.ts';
import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { upgrade } from '../src/node-sockets.ts';
import { checkPlugins, pluginSocket, type CoffrePlugin } from '../src/plugins.ts';
import { credentialProxy, postgres, type Network } from '../src/plugins/credential-proxy.ts';
import { database, saslprep } from '../src/plugins/postgres-tunnel.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import type { WorkersSocket } from '../src/workers-socket.ts';
import { appClient, type AppClient } from './tunnel-listener.ts';

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
  coffre.on('upgrade', (request, socket, head) => void upgrade(tracked(runtime), request, socket, head));
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

// Each case's sessions end on coffre's side before the next case: one left open would go on checking its handle.
afterEach(async () => assert.equal(await sessionsEnded(), true, 'every session the case opened has ended'));

/** Whether every connection to coffre has closed, its session ended, within five seconds. */
async function sessionsEnded(): Promise<boolean> {
  const open = () => new Promise<number>((resolve) => coffre.getConnections((_, count) => resolve(count)));
  for (let waited = 0; (await open()) > 0 && waited < 5000; waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
  return (await open()) === 0;
}

/**
 * `runtime`, each use its plugins make the case's own work, which the next case's reset waits for: a tunnel's group
 * checks its handle on timers of its own, and a check still under way as the case ends would write the log while the
 * next case empties it, its TRUNCATE deadlocking with the check's append, or into that case's log.
 */
function tracked(runtime: CoffreRuntime): CoffreRuntime {
  const plugins = runtime.plugins.map((plugin): CoffrePlugin => {
    const socket = plugin.routes?.socket;
    if (socket === undefined) return plugin;
    return {
      ...plugin,
      routes: {
        ...plugin.routes!,
        socket: (request, context) => socket(request, {
          ...context,
          use: (caller, asked) => {
            const using = context.use(caller, asked);
            trackBackgroundTask(using);
            return using;
          },
        }),
      },
    };
  });
  return { ...runtime, plugins };
}

useMcp(
  async () => {
    runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') }, insecureUpstreams: true, recheckSeconds: 0.2 })]);
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.projects.create('market');
    await root.environments.create('market/dev');
    await root.secrets.set('market/dev', { DATABASE_URL: { value: REAL, sensitivity: 'sensitive' }, OTHER: { value: 'x', sensitivity: 'sensitive' } });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
    handle = (await (await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: ['market/dev'] }) })).json() as { token: string }).token;
  },
);

/** The tunnel's first answer on `socket`: a socket it closes first fails the case, where waiting for data would hold it forever. */
function answered(socket: Socket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    socket.once('data', resolve);
    socket.once('close', () => reject(new Error('the tunnel closed the connection before it answered')));
  });
}

/** The app's client, on the listener, the handle its password: what `coffre run` puts in DATABASE_URL. */
const appClientOf = (password = handle): AppClient => appClient(listenerPort, password);

/** Whether the tunnel ends `client`'s connection within `ms`. */
const endsWithin = (client: AppClient, ms: number): Promise<boolean> =>
  Promise.race([client.ended.then(() => true), new Promise<boolean>((resolve) => setTimeout(resolve, ms, false))]);

/** A CancelRequest, as psql sends one, with the key a session was given. */
function cancelRequest({ pid, secret }: { pid: number; secret: number }): Buffer {
  const packet = Buffer.alloc(16);
  packet.writeInt32BE(16, 0);
  packet.writeInt32BE(80877102, 4);
  packet.writeUInt32BE(pid >>> 0, 8);
  packet.writeUInt32BE(secret >>> 0, 12);
  return packet;
}

test('the plan names the tunnel, and gives the app no database URL of its own', postgresOnly, async () => {
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; tunnels: Record<string, { key: string; url: string }>; left: string[] };
  assert.deepEqual(plan.tunnels, { db: { key: 'DATABASE_URL', url: `${ORIGIN.replace('https', 'wss')}/use/market/dev/db` } });
  assert.equal(plan.env.DATABASE_URL, undefined);
  assert.equal(JSON.stringify(plan).includes('local-runtime-only'), false, 'never the real password');
  assert.deepEqual(plan.left, ['OTHER']);
});

test('queries through the tunnel run as the real login, and the session is logged as one use', postgresOnly, async () => {
  const client = appClientOf();
  try {
    assert.deepEqual([...await client.unsafe('SELECT current_user AS who, 1 + 1 AS two')], [{ who: 'coffre_runtime', two: 2 }]);
    // An extended-protocol query with parameters, as drivers send them.
    assert.deepEqual([...await client.unsafe('SELECT $1::text || $2::text AS joined', ['a', 'b'])], [{ joined: 'ab' }]);
  } finally {
    await client.end();
  }
  // The session's own: the checks its group made while it was open, a fifth of a second apart here, are logged as theirs.
  const uses = (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'db' && entry.metadata.recheck !== true);
  assert.equal(uses.length, 1);
  assert.equal(uses[0]!.metadata.tunnel, true);
  assert.deepEqual(uses[0]!.metadata.keys, ['DATABASE_URL']);
});

test('a password that is not the handle is refused, before any login to the database', postgresOnly, async () => {
  const client = appClientOf('not-the-handle');
  await assert.rejects(client.unsafe('SELECT 1'), (error: { code?: string }) => error.code === '28P01');
  await client.end();
});

test('LISTEN and NOTIFY across two tunnelled connections', postgresOnly, async () => {
  // As a driver listens: LISTEN on a session of its own, the notification coming on it unasked.
  const listening = await rawSession();
  const notifying = appClientOf();
  try {
    await listening.query('LISTEN coffre_tunnel');
    await notifying.unsafe("SELECT pg_notify('coffre_tunnel', 'through the tunnel')");
    // A NotificationResponse: the notifying backend's pid, then the channel and the payload, each ended by a NUL.
    const { body } = await listening.until('A');
    assert.deepEqual(body.subarray(4).toString().split('\0'), ['coffre_tunnel', 'through the tunnel', '']);
  } finally {
    listening.close();
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
  const client = appClientOf();
  try {
    // The key the tunnel gave the app, at its startup.
    const { state } = await client.unsafe('SELECT 1');
    const sleeping = client.unsafe('SELECT pg_sleep(30)').execute();
    await new Promise((resolve) => setTimeout(resolve, 200));
    // As psql sends one: a CancelRequest, to the same listener.
    const cancel = tcp({ host: '127.0.0.1', port: listenerPort });
    await once(cancel, 'connect');
    cancel.write(cancelRequest(state));
    const started = Date.now();
    await assert.rejects(sleeping, (error: { code?: string }) => error.code === '57014');
    assert.ok(Date.now() - started < 5000);
    cancel.destroy();
  } finally {
    await client.end();
  }
});

test("a cancel request with a key no live session of this handle was given reaches nothing", postgresOnly, async () => {
  const client = appClientOf();
  try {
    const { state } = await client.unsafe('SELECT 1');
    const sleeping = client.unsafe('SELECT pg_sleep(0.6) AS slept').execute();
    await new Promise((resolve) => setTimeout(resolve, 100));
    // The database's own key is never the app's: guess one, or flip one bit of the one given.
    for (const key of [{ pid: state.pid, secret: state.secret ^ 1 }, { pid: 12345, secret: 67890 }]) {
      const cancel = tcp({ host: '127.0.0.1', port: listenerPort });
      await once(cancel, 'connect');
      cancel.write(cancelRequest(key));
      await once(cancel, 'close');
    }
    assert.deepEqual([...await sleeping], [{ slept: '' }], 'the query ran to its end');
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
  await answered(socket);
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
  await answered(socket);
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

test('a database URL is read as Node dials it: loopback in any numeric form is loopback', () => {
  for (const host of ['127.1', '2130706433', '0x7f000001', '127.0.0.1']) assert.equal(database(`postgres://u:p@${host}:5432/d`).host, '127.0.0.1', host);
  assert.equal(database('postgres://u:p@[::1]:5432/d').host, '::1');
  assert.equal(database('postgres://u:p@DB.Acme.Example/d').host, 'db.acme.example');
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
  const arabicOne = String.fromCharCode(0x661);
  assert.equal(saslprep(`${arabicOne}${soft}a`), `${arabicOne}a`, 'a digit has no direction of a letter');
  const ideographic = `${String.fromCharCode(0x2ff0)}a${soft}`;
  assert.equal(saslprep(ideographic), ideographic, 'an ideographic description character (C.7): the password as it is');
  // Right-to-left as RFC 3454's table D.1 has it: Hebrew's maqaf (U+05BE) is no letter, and right-to-left all the same.
  const maqaf = `${String.fromCharCode(0x5be)}${space}`;
  assert.equal(saslprep(maqaf), maqaf, 'ending on a space, not right-to-left: the password as it is');
  const tatweel = String.fromCharCode(0x627, 0x640, 0xa0, 0x627);
  assert.equal(saslprep(tatweel), String.fromCharCode(0x627, 0x640, 0x20, 0x627), "Arabic's tatweel (U+0640) is right-to-left, no left-to-right letter");
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
    const client = appClientOf();
    await assert.rejects(client.unsafe('SELECT 1'), /without proving it knows the password/);
    await client.end();
  } finally {
    fake.close();
  }
});

test("a person whose grant ends loses their open sessions at the next check", postgresOnly, async () => {
  const client = appClientOf();
  assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
  await clientFor(deps, ROOT).access.set(`user:${DEV}`, { market: null });
  // New connections meanwhile, which the cache would serve: none of them stands in for the vault's answer.
  for (let tries = 0; tries < 6; tries += 1) {
    const another = appClientOf();
    await another.unsafe('SELECT 1').catch(() => undefined);
    await another.end();
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(await endsWithin(client, 0), true, 'the open session ended');
  await assert.rejects(client.unsafe('SELECT 1'));
  await client.end();
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
    await answered(raw);
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

test('sessions opened at different times end together, within one check of the revocation', postgresOnly, async () => {
  const first = appClientOf();
  await first.unsafe('SELECT 1');
  await new Promise((resolve) => setTimeout(resolve, 100));
  const second = appClientOf();
  await second.unsafe('SELECT 1');
  const revoked = Date.now();
  await revoke();
  const [a, b] = await Promise.all([first.ended, second.ended]);
  // One check is 200 ms here: both within two of it, the first that fails ending them both.
  assert.ok(Math.max(a, b) - revoked < 450, `${a - revoked} ms and ${b - revoked} ms`);
});

test('a refused upgrade leaves no socket behind, though the peer keeps its side open', postgresOnly, async () => {
  const before = await new Promise<number>((resolve) => coffre.getConnections((_, count) => resolve(count)));
  const socket = tcp({ host: '127.0.0.1', port: Number(new URL(coffreAt).port), allowHalfOpen: true });
  await once(socket, 'connect');
  socket.write('GET /use/market/dev/db HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n');
  socket.resume();
  await once(socket, 'end');
  for (let waited = 0; waited < 1500; waited += 50) {
    const count = await new Promise<number>((resolve) => coffre.getConnections((_, n) => resolve(n)));
    if (count <= before) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(await new Promise<number>((resolve) => coffre.getConnections((_, count) => resolve(count))), before);
  socket.destroy();
});

test("a group of sessions is checked once an interval, however many it holds, and a revocation just after a check ends them within one", postgresOnly, async () => {
  const clients = Array.from({ length: 10 }, () => appClientOf());
  // One after another: what is counted is the group's checks, not ten first reads at once racing for the log's head.
  for (const client of clients) await client.unsafe('SELECT 1');
  const rechecks = async () => (await entries('credential.use')).filter((entry) => entry.metadata.recheck === true).length;
  // Two and a half intervals, counted from now: two checks, or three, for all ten, never one each.
  const from = await rechecks();
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.ok((await rechecks()) - from <= 3, `${(await rechecks()) - from} checks`);
  // Revoked right after a check: the next one, an interval on, ends all ten.
  const before = await rechecks();
  for (let waited = 0; (await rechecks()) === before && waited < 500; waited += 10) await new Promise((resolve) => setTimeout(resolve, 10));
  const revoked = Date.now();
  await revoke();
  const times = await Promise.all(clients.map((client) => client.ended));
  // An interval is 200 ms here: within it and a margin for a slow machine, far short of ten intervals, one per session.
  assert.ok(Math.max(...times) - revoked < 600, `${Math.max(...times) - revoked} ms`);
});

test('a check the vault never answers is a no, by its deadline: the sessions do not outlive a stalled vault', postgresOnly, async () => {
  const client = appClientOf();
  await client.unsafe('SELECT 1');
  const unwrap = deps.vault.unwrap;
  // Stalled until the case ends, then refused: a check still waiting is the case's, which the next case waits for.
  const stalls: (() => void)[] = [];
  deps.vault.unwrap = () => new Promise((_, reject) => stalls.push(() => reject(new Error('the case ended'))));
  const stalled = Date.now();
  try {
    assert.ok((await client.ended) - stalled < 600, 'within an interval and a deadline');
  } finally {
    deps.vault.unwrap = unwrap;
    for (const stop of stalls) stop();
  }
});

test("a new group let in on a cached URL decides at once: a grant lost meanwhile ends it, not an interval later", postgresOnly, async () => {
  // Checked every 5 seconds: an interval later is seconds on, which no load makes of at once.
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') }, insecureUpstreams: true, recheckSeconds: 5 })]);
  const first = appClientOf();
  await first.unsafe('SELECT 1');
  await first.end();
  await new Promise((resolve) => setTimeout(resolve, 50));
  await clientFor(deps, ROOT).access.set(`user:${DEV}`, { market: null });
  // The URL is still in the cache: the connection is let in, and its group's own first check ends it.
  const second = appClientOf();
  const started = Date.now();
  const outcome = await second.unsafe('SELECT 1').then(() => second.ended, () => Date.now());
  await second.end();
  assert.ok(outcome - started < 2500, `${outcome - started} ms`);
});

test("a check answered once its group's last session has gone arms nothing: a newer group is let in on the URL the cache holds", postgresOnly, async () => {
  // Checked every 2 seconds, a check given as long: a group's bytes stop 4 seconds past its last good check.
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') }, insecureUpstreams: true, recheckSeconds: 2 })]);
  const opened = async () => (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'db' && entry.metadata.recheck !== true).length;
  const first = appClientOf();
  await first.unsafe('SELECT 1');
  // The group's first check, held in the vault until its one session has gone, then answered yes.
  const unwrap = deps.vault.unwrap;
  let entered!: () => void;
  const checking = new Promise<void>((resolve) => (entered = resolve));
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  deps.vault.unwrap = async (...asked: Parameters<typeof unwrap>) => {
    entered();
    await released;
    return unwrap.apply(deps.vault, asked);
  };
  try {
    await checking;
    await first.end();
    assert.equal(await sessionsEnded(), true);
  } finally {
    deps.vault.unwrap = unwrap;
    release();
  }
  // Past when the gone group's watchdog would have closed it, had the yes armed one, and dropped the URL from the cache.
  await new Promise((resolve) => setTimeout(resolve, 4500));
  const before = await opened();
  const second = appClientOf();
  await second.unsafe('SELECT 1');
  await second.end();
  assert.equal(await opened(), before, 'let in on the URL the cache holds, opened no more');
});

test('a database that asks for more SCRAM iterations than any needs is refused before the work begins', postgresOnly, async () => {
  const fake = createTcp((socket) => {
    let stage = 0;
    socket.on('data', (chunk: Buffer) => {
      if (stage === 0) {
        stage = 1;
        socket.write(message('R', Buffer.concat([Buffer.from([0, 0, 0, 10]), cstring('SCRAM-SHA-256'), Buffer.from([0])])));
      } else if (stage === 1) {
        stage = 2;
        const nonce = /r=([^,]+)/.exec(chunk.toString('latin1'))![1]!;
        socket.write(message('R', Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from(`r=${nonce}server,s=${Buffer.from('salt').toString('base64')},i=2147483647`)])));
      }
    });
  });
  fake.listen(0, '127.0.0.1');
  await once(fake, 'listening');
  try {
    await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: `postgres://u:p@127.0.0.1:${(fake.address() as AddressInfo).port}/d?sslmode=disable` });
    const started = Date.now();
    const client = appClientOf();
    await assert.rejects(client.unsafe('SELECT 1'), /SCRAM iterations/);
    await client.end();
    assert.ok(Date.now() - started < 2000);
  } finally {
    fake.close();
  }
});

test('a peer that leaves while a plugin has not decided takes its socket with it', postgresOnly, async () => {
  runtime.plugins = checkPlugins([{ name: 'stall', routes: { prefix: '/stall', fetch: async () => new Response(null, { status: 404 }), socket: () => new Promise(() => undefined) } }]);
  const before = await new Promise<number>((resolve) => coffre.getConnections((_, count) => resolve(count)));
  const socket = tcp({ host: '127.0.0.1', port: Number(new URL(coffreAt).port) });
  await once(socket, 'connect');
  socket.write('GET /stall HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n');
  await new Promise((resolve) => setTimeout(resolve, 100));
  socket.end();
  for (let waited = 0; waited < 1500; waited += 50) {
    if ((await new Promise<number>((resolve) => coffre.getConnections((_, n) => resolve(n)))) <= before) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(await new Promise<number>((resolve) => coffre.getConnections((_, count) => resolve(count))), before);
});

test("a session ended while its app floods it, and nothing reads, ends cleanly: frames still arriving are dropped", postgresOnly, async () => {
  let ended!: () => void;
  const done = new Promise<void>((resolve) => (ended = resolve));
  // A session that reads nothing, then cancels what it would have read and closes, as a revocation does mid-COPY.
  runtime.plugins = checkPlugins([{ name: 'flood', routes: { prefix: '/flood', fetch: async () => new Response(null, { status: 404 }), socket: async () => async (client) => {
    await new Promise((resolve) => setTimeout(resolve, 200));
    await client.readable.cancel();
    client.close();
    ended();
  } } }]);
  const ws = new WebSocket(`${coffreAt}/flood`);
  ws.on('error', () => undefined);
  await once(ws, 'open');
  const chunk = Buffer.alloc(64 * 1024);
  for (let i = 0; i < 200; i += 1) ws.send(chunk);
  await done;
  await new Promise((resolve) => setTimeout(resolve, 200));
  ws.terminate();
});

test('a refusal whose body never ends is said without it, and the socket goes', postgresOnly, async () => {
  runtime.plugins = checkPlugins([{ name: 'slow', routes: { prefix: '/slow', fetch: async () => new Response(null, { status: 404 }), socket: async () => new Response(new ReadableStream({ start: (controller) => controller.enqueue(new TextEncoder().encode('partial')) }), { status: 403 }) } }]);
  const answered = await new Promise<string>((resolve) => {
    const socket = tcp({ host: '127.0.0.1', port: Number(new URL(coffreAt).port) });
    let text = '';
    socket.on('connect', () => socket.write('GET /slow HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'));
    socket.on('data', (chunk: Buffer) => (text += chunk.toString('latin1')));
    socket.on('close', () => resolve(text));
  });
  assert.match(answered, /^HTTP\/1\.1 403/);
  assert.match(answered, /content-length: 0\r\n/);
  assert.equal(answered.includes('partial'), false);
});

/** Revoke the suite's handle, as its person would. */
async function revoke(): Promise<void> {
  const session = await sessionFor(DEV);
  const listed = (await (await route(`/api/members/user:${DEV}/tokens`, { headers: { authorization: `Bearer ${session}` } })).json()) as { tokens: { id: string; hint: string }[] };
  const id = listed.tokens.find((token) => token.hint.endsWith(handle.slice(-4)))!.id;
  await route(`/api/members/user:${DEV}/tokens/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } });
}

test('a handle revoked mid-session ends the open session at the next check, and opens no other', postgresOnly, async () => {
  const client = appClientOf();
  assert.deepEqual([...await client.unsafe('SELECT 1 AS one')], [{ one: 1 }]);
  await revoke();
  assert.equal(await endsWithin(client, 600), true, 'the open session ended');
  await assert.rejects(client.unsafe('SELECT 1'));
  await client.end();
  const another = appClientOf();
  await assert.rejects(another.unsafe('SELECT 1'), 'nor is a new one opened');
  await another.end();
});

test('a tunnel reaches only the hosts it names, and a private database only with insecureUpstreams', postgresOnly, async () => {
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) }, insecureUpstreams: true })]);
  const unnamed = appClientOf();
  await assert.rejects(unnamed.unsafe('SELECT 1'));
  await unnamed.end();
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') } })]);
  const loopback = appClientOf();
  await assert.rejects(loopback.unsafe('SELECT 1'));
  await loopback.end();
  // Loopback written the ways Node still dials it, with TLS asked for: refused all the same.
  for (const host of ['127.1', '2130706433', '0x7f000001', '127.0.0.1.', 'localhost.', 'LOCALHOST', '[::ffff:7f00:1]', '[0:0:0:0:0:0:0:1]']) {
    await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: `postgres://u:p@${host}:5432/d` });
    runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') } })]);
    assert.equal((await upgradeRefusal()).status, 403, host);
  }
  // A name, which may resolve to a private address, only when the tunnel's hosts list it: the value's writer picks it, not the deployment.
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: 'postgres://u:p@db.acme.example:5432/d' });
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') } })]);
  const refused = await upgradeRefusal();
  assert.equal(refused.status, 403);
  assert.match(refused.message, /names its host by name, which the tunnel db dials only when its hosts list it/);
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) } })]);
  const session = await pluginSocket(new Request(`${ORIGIN}/use/market/dev/db`, { headers: { authorization: `Bearer ${handle}` } }), runtime, null);
  assert.equal(typeof session, 'function', 'a listed name is dialled');
  // Its fully qualified spelling is the same host.
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: 'postgres://u:p@DB.Acme.Example.:5432/d' });
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) } })]);
  assert.equal(typeof await pluginSocket(new Request(`${ORIGIN}/use/market/dev/db`, { headers: { authorization: `Bearer ${handle}` } }), runtime, null), 'function');
  // An address needs no list, as before.
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: 'postgres://u:p@203.0.113.7:5432/d' });
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') } })]);
  assert.equal(typeof await pluginSocket(new Request(`${ORIGIN}/use/market/dev/db`, { headers: { authorization: `Bearer ${handle}` } }), runtime, null), 'function');
  assert.throws(() => credentialProxy({ credentials: { db: { upstream: 'https://x.example', inject: { kind: 'header', name: 'x', template: '{K}' } } }, tunnels: { db: postgres('DATABASE_URL') } }), /a credential and a tunnel/);
});

test('a tunnel through a network binding reaches the private host it names, plaintext, without insecureUpstreams', postgresOnly, async () => {
  // A VPC Network binding as Workers give one: `connect('10.9.8.7:5432')`, a socket of web streams. This one reaches the suite's database.
  const asked: string[] = [];
  const port = Number(new URL(TEST_RUNTIME_DATABASE_URL).port);
  const network: Network = {
    connect: (address) => {
      asked.push(address);
      const socket = tcp({ host: '127.0.0.1', port });
      const { readable, writable } = Duplex.toWeb(socket);
      return {
        readable: readable as ReadableStream<Uint8Array>,
        writable: writable as WritableStream<Uint8Array>,
        opened: once(socket, 'connect'),
        closed: once(socket, 'close').then(() => undefined),
        close: async () => void socket.destroy(),
        startTls: () => {
          throw new Error('plaintext only');
        },
      };
    },
  };
  const replica = (query: string) => `postgres://coffre_runtime:local-runtime-only@10.9.8.7:5432${new URL(TEST_RUNTIME_DATABASE_URL).pathname}${query}`;
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: replica('?sslmode=disable') });
  // Each connection opens the URL afresh, as the vault holds it now.
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: ['10.9.8.7'], connect: network }) }, cacheSeconds: 0 })]);
  const client = appClientOf();
  try {
    assert.deepEqual([...await client.unsafe('SELECT current_user AS who')], [{ who: 'coffre_runtime' }]);
  } finally {
    await client.end();
  }
  assert.deepEqual(asked, ['10.9.8.7:5432']);
  // TLS asked for, which the binding does not carry: refused before any dial, and said.
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: replica('') });
  const refused = await upgradeRefusal();
  assert.equal(refused.status, 409);
  assert.match(refused.message, /asks for TLS, which the tunnel db's network binding does not carry: sslmode=disable/);
  // A host the tunnel does not name, private or not, and the same private host without the binding: refused.
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: replica('?sslmode=disable').replace('10.9.8.7', '10.9.8.8') });
  assert.equal((await upgradeRefusal()).status, 403);
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: replica('?sslmode=disable') });
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') }, cacheSeconds: 0 })]);
  assert.equal((await upgradeRefusal()).status, 403);
  assert.deepEqual(asked, ['10.9.8.7:5432'], 'no other dial through the binding');
});

test('a cancel request through a network binding reaches the database, though its connector dials after the socket opens', postgresOnly, async () => {
  // A VPC Network binding as Cloudflare's is: open at once, its connector dialing the database only later; closed before
  // that, it sends nothing (W150, measured live).
  const port = Number(new URL(TEST_RUNTIME_DATABASE_URL).port);
  const network: Network = {
    connect: () => {
      let socket: Socket | null = null;
      let given = false;
      const waiting: Uint8Array[] = [];
      let readable!: ReadableStreamDefaultController<Uint8Array>;
      let ended!: () => void;
      const closed = new Promise<void>((resolve) => (ended = resolve));
      const end = () => {
        try {
          readable.close();
        } catch {}
        ended();
      };
      setTimeout(() => {
        if (given) return;
        socket = tcp({ host: '127.0.0.1', port });
        socket.on('data', (chunk: Buffer) => readable.enqueue(new Uint8Array(chunk)));
        socket.on('close', end);
        for (const chunk of waiting.splice(0)) socket.write(chunk);
      }, 300);
      return {
        readable: new ReadableStream<Uint8Array>({ start: (controller) => void (readable = controller) }),
        writable: new WritableStream<Uint8Array>({ write: (chunk) => void (socket === null ? waiting.push(chunk) : socket.write(chunk)) }),
        opened: Promise.resolve(),
        closed,
        close: async () => {
          given = true;
          if (socket === null) end();
          else socket.destroy();
        },
        startTls: () => {
          throw new Error('plaintext only');
        },
      };
    },
  };
  await clientFor(deps, ROOT).secrets.set('market/dev', {
    DATABASE_URL: `postgres://coffre_runtime:local-runtime-only@10.9.8.7:5432${new URL(TEST_RUNTIME_DATABASE_URL).pathname}?sslmode=disable`,
  });
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: ['10.9.8.7'], connect: network }) } })]);
  const client = appClientOf();
  try {
    const { state } = await client.unsafe('SELECT 1');
    const sleeping = client.unsafe('SELECT pg_sleep(30)').execute();
    await new Promise((resolve) => setTimeout(resolve, 200));
    const cancel = tcp({ host: '127.0.0.1', port: listenerPort });
    await once(cancel, 'connect');
    cancel.write(cancelRequest(state));
    const started = Date.now();
    await assert.rejects(sleeping, (error: { code?: string }) => error.code === '57014');
    assert.ok(Date.now() - started < 5000);
    cancel.destroy();
  } finally {
    await client.end();
  }
});

test("a tunnel's network binding is checked with the configuration: missing, it fails, and never falls back to a direct dial", () => {
  const tunnel = (options: Parameters<typeof postgres>[1]) => () => credentialProxy({ credentials: {}, tunnels: { replica: postgres('REPLICA_URL', options) } });
  // A binding the Worker lacks is undefined: the key is there, its value is not.
  assert.throws(tunnel({ hosts: ['10.0.1.5'], connect: undefined }), /tunnel replica's connect is undefined, as a Worker's binding is when wrangler\.jsonc lacks it/);
  assert.throws(tunnel({ hosts: ['10.0.1.5'], connect: {} as Network }), /has no connect method/);
  // A binding reaches a whole network: the hosts in it are named.
  assert.throws(tunnel({ connect: { connect: () => Promise.reject(new Error('unused')) } }), /names the hosts it reaches there/);
  assert.throws(tunnel({ hosts: [], connect: { connect: () => Promise.reject(new Error('unused')) } }), /names the hosts it reaches there/);
  // Private hosts, with a binding and without insecureUpstreams; never without it.
  assert.doesNotThrow(tunnel({ hosts: ['10.0.1.5'], connect: { connect: () => Promise.reject(new Error('unused')) } }));
  assert.throws(tunnel({ hosts: ['10.0.1.5'] }), /names a private host/);
  for (const host of ['localhost.', 'LocalHost', '127.1', '::ffff:10.0.1.5', '[fd00::5]']) assert.throws(tunnel({ hosts: [host] }), /names a private host/, host);
});

test("a dial through a network binding still under way when the app leaves is given up: the socket that comes after is closed", postgresOnly, async () => {
  // A binding that answers only when told, with a socket that says when it is closed.
  let answer!: (socket: WorkersSocket) => void;
  const asked = new Promise<void>((resolve) => {
    const network: Network = {
      connect: () => {
        resolve();
        return new Promise<WorkersSocket>((done) => (answer = done));
      },
    };
    runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: ['10.9.8.7'], connect: network }) }, cacheSeconds: 0 })]);
  });
  await clientFor(deps, ROOT).secrets.set('market/dev', { DATABASE_URL: 'postgres://u:p@10.9.8.7:5432/d?sslmode=disable' });
  const raw = tcp({ host: '127.0.0.1', port: listenerPort });
  await once(raw, 'connect');
  const startup = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring('user'), cstring('app'), Buffer.from([0])]);
  const length = Buffer.alloc(4);
  length.writeInt32BE(startup.length + 4);
  raw.write(Buffer.concat([length, startup]));
  await answered(raw);
  raw.write(message('p', cstring(handle)));
  await asked;
  raw.destroy();
  await new Promise((resolve) => setTimeout(resolve, 200));
  let closed = false;
  answer({ readable: new ReadableStream(), writable: new WritableStream(), opened: Promise.resolve(), closed: new Promise(() => undefined), close: async () => void (closed = true), startTls: () => { throw new Error('unused'); } });
  for (let waited = 0; !closed && waited < 2000; waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.ok(closed, 'the late socket was closed');
});

/** The tunnel's refusal of a WebSocket, as the plugin answers it: its status and message. */
async function upgradeRefusal(): Promise<{ status: number; message: string }> {
  const answer = await pluginSocket(new Request(`${ORIGIN}/use/market/dev/db`, { headers: { authorization: `Bearer ${handle}` } }), runtime, null)!;
  assert.ok(answer instanceof Response, 'refused');
  return { status: answer.status, message: ((await answer.json()) as { message: string }).message };
}

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
