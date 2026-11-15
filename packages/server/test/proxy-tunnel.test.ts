// Postgres through the credential proxy's tunnel on 0.16 (docs/design/credential-proxy.md,
// "Postgres through a tunnel"; docs/design/0.16.md, "The proxy"): each connection is
// admitted as the Sockets Durable Object admits a WebSocket on Workers (`admitSocket`),
// with one `use` of the vault, which opens the database's URL and logs it; the session
// then logs in to the real database with it and pipes bytes. Its group is asked again on
// a timer, a `peek` that opens nothing, and a revocation, a lost grant or a freeze ends
// it. 0.14.7's assertions (credential-proxy-tunnel.test.ts, which drives Node's upgrade
// and is left for 0.16.2), on the vault: queries as the real login, the handle as the
// password, a cancel request, the hosts a tunnel reaches, a network binding, and a
// workload's session. The database tunnelled to is the suite's own, as the app's login.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { connect as tcp, createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { Duplex } from 'node:stream';
import { after, before, beforeEach, test } from 'node:test';

import { createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import type { UseInput } from '@coffre/core/vault';
import { amend, APP_URL, binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, session, tokenOf, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { processGates, type Gates } from '../src/gate.ts';
import type { CoffrePlugin, Connect, Pipe, PluginContext } from '../src/plugins.ts';
import { credentialProxy, postgres, type CredentialProxyOptions, type Network } from '../src/plugins/credential-proxy.ts';
import { database, saslprep } from '../src/plugins/postgres-tunnel.ts';
import type { WorkersSocket } from '../src/workers-socket.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';
import { appClient, type AppClient } from './tunnel-listener.ts';

const ADA = 'user:ada';
const DEPLOY = 'token:deploy';
/** The suite's database, as the app's login, on loopback: no TLS. */
const REAL = `${APP_URL}?sslmode=disable`;
/** The same database at a private address only a network binding reaches (`network`). */
const REPLICA = '10.9.8.7';
const replicaUrl = (query: string) => `postgres://coffre_runtime:local-runtime-only@${REPLICA}:5432${new URL(APP_URL).pathname}${query}`;
/** What each other key holds: a database URL the tunnels that name it refuse, or dial only when their hosts list it. */
const URLS: Record<string, string> = {
  NAMED_URL: 'postgres://u:p@db.acme.example:5432/d',
  FQDN_URL: 'postgres://u:p@DB.Acme.Example.:5432/d',
  ADDRESS_URL: 'postgres://u:p@203.0.113.7:5432/d',
  REPLICA_URL: replicaUrl('?sslmode=disable'),
  REPLICA_TLS_URL: replicaUrl(''),
  OTHER_PRIVATE_URL: replicaUrl('?sslmode=disable').replace(REPLICA, '10.9.8.8'),
  NOT_A_URL: 'mysql://u:p@203.0.113.7/d',
  // Loopback, written the ways a dial still reads it, TLS asked for.
  ...Object.fromEntries(['127.1', '2130706433', '0x7f000001', '127.0.0.1.', 'localhost.', 'LOCALHOST', '[::ffff:7f00:1]', '[0:0:0:0:0:0:0:1]'].map((host, i) => [`LOOPBACK_${i}`, `postgres://u:p@${host}:5432/d`])),
};

/** The dials made through the network binding, by address. */
const dialled: string[] = [];
/** A VPC Network binding as Workers give one: `connect('10.9.8.7:5432')`, web streams. It reaches the suite's database. */
const network: Network = {
  connect: (address) => {
    dialled.push(address);
    if (address !== `${REPLICA}:5432`) throw new Error(`the binding reaches ${REPLICA}:5432 only`);
    const socket = tcp({ host: '127.0.0.1', port: Number(new URL(APP_URL).port) });
    const { readable, writable } = Duplex.toWeb(socket);
    return {
      readable: readable as ReadableStream<Uint8Array>,
      writable: writable as WritableStream<Uint8Array>,
      opened: once(socket, 'connect'),
      closed: new Promise<void>((resolve) => socket.once('close', () => resolve())),
      close: async () => void socket.destroy(),
      startTls: () => {
        throw new Error('plaintext only');
      },
    };
  },
};

/** The proxy this test runs, which a test may change; whether its checks hang, as a vault that never answers, and how to answer them late; and when a check said no. */
const current: { proxy: CoffrePlugin; stall: boolean; noes: number[]; stalled: Array<(stands: boolean) => void> } = { proxy: proxyOf(), stall: false, noes: [], stalled: [] };
function proxyOf(options: Partial<CredentialProxyOptions> = {}): CoffrePlugin {
  return credentialProxy({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') }, insecureUpstreams: true, recheckSeconds: 0.2, ...options });
}
const switched: CoffrePlugin = {
  name: 'credential-proxy',
  routes: {
    prefix: '/use',
    fetch: (request, coffre) => current.proxy.routes!.fetch(request, coffre),
    // Its checks asked through the vault, each no noted, until the test stalls them: then each hangs, as a vault that never answers.
    socket: (request, coffre) =>
      current.proxy.routes!.socket!(request, {
        ...coffre,
        stands: async (caller, asked) => {
          if (current.stall) return new Promise<boolean>((resolve) => current.stalled.push(resolve));
          const stands = await coffre.stands(caller, asked);
          if (!stands) current.noes.push(Date.now());
          return stands;
        },
      } satisfies PluginContext),
  },
};

let held = processGates();
const gated: string[] = [];
const gates: Gates = (service) => {
  gated.push(service);
  return held(service);
};
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } });
const app = await openApp({ auth, workloads: {}, gates, plugins: [switched] });
const { world } = app;

const market = project('market');
const prod = environment(market, 'prod');
const ON_PROD = JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'viewer' }]);

let handle: string;
let handleId: string;
let deploy: { token: string; key: ProofKey };
let deployBinding: ReturnType<typeof binding>;

/**
 * `coffre run`'s listener and the object between it and coffre, in one: each
 * connection asks for its WebSocket with `headers()`, as the listener does,
 * then carries the session's bytes, or is closed on its refusal, which is
 * kept.
 */
let listener: Server;
let port: number;
let headers: () => Promise<Record<string, string>> = async () => ({ authorization: `Bearer ${handle}` });
let path = '/use/market/prod/db';
const refusals: Response[] = [];
const carried: Socket[] = [];

/** A TCP connection as a session's pipe: its bytes as web streams, and when it closes. */
function pipeOf(socket: Socket): Pipe {
  const { readable, writable } = Duplex.toWeb(socket);
  return {
    readable: readable as ReadableStream<Uint8Array>,
    writable: writable as WritableStream<Uint8Array>,
    close: () => void socket.destroy(),
    closed: new Promise<void>((resolve) => socket.once('close', () => resolve())),
  };
}

/** TCP out, as the platform dials it: plaintext, the suite's databases being on loopback. */
const connect: Connect = async (host, port) => {
  const socket = tcp({ host, port });
  await once(socket, 'connect');
  return { ...pipeOf(socket), startTls: () => Promise.reject(new Error('plaintext only')) };
};

before(async () => {
  listener = createServer((socket) => {
    carried.push(socket);
    socket.pause();
    socket.on('error', () => undefined);
    void (async () => {
      const answer = await app.socket(path, { headers: { ...(await headers()), upgrade: 'websocket' } });
      if (answer instanceof Response) {
        refusals.push(answer);
        return socket.destroy();
      }
      await answer(pipeOf(socket), connect).catch(() => undefined);
      socket.destroy();
    })();
  });
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  port = (listener.address() as AddressInfo).port;
});

after(async () => {
  for (const socket of carried) socket.destroy();
  await new Promise<void>((resolve) => listener.close(() => resolve()));
  await app.close();
});

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  current.proxy = proxyOf();
  current.stall = false;
  current.noes.length = 0;
  current.stalled.length = 0;
  held = processGates();
  gated.length = 0;
  dialled.length = 0;
  refusals.length = 0;
  headers = async () => ({ authorization: `Bearer ${handle}` });
  path = '/use/market/prod/db';
  handle = generateToken('handle');
  const handleRow = credential(handle, ADA, { kind: 'handle', scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id, personal: false }]), expiresAt: new Date(Date.now() + 3_600_000) });
  handleId = handleRow.id;
  const key = await generateProofKey();
  const token = generateToken('workload');
  deployBinding = binding(DEPLOY, { policy: '{}', scope: ON_PROD });
  const sessionRow = session(token, deployBinding, { jkt: await thumbprint(key.jwk), scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000) });
  deploy = { token, key };
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'viewer', ['secret.read', 'secret.use']), role(false, 'none', [])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(ADA), principal(DEPLOY)),
    ...rows('grants', grant(ADA, 'developer', { project: market }), grant(DEPLOY, 'developer', { project: market })),
    ...rows('secrets', value(world, secret(prod, 'DATABASE_URL'), REAL, { sensitive: true }), ...Object.entries(URLS).map(([key, url]) => value(world, secret(prod, key), url))),
    ...rows('bindings', deployBinding),
    ...rows('credentials', handleRow, sessionRow),
  );
  await app.request('/livez');
  app.calls.length = 0;
  app.inputs.length = 0;
});

/** The app's client on the listener, the handle its password: what `coffre run` puts in DATABASE_URL. */
const appClientOf = (password = handle): AppClient => appClient(port, password);

/** What the vault and the app's database were asked for, from now until `run` is done. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}

/** The refusal of the next WebSocket, its status and words. */
async function refusal(): Promise<{ status: number; message: string }> {
  const answer = await app.socket(path, { headers: { ...(await headers()), upgrade: 'websocket' } });
  assert.ok(answer instanceof Response, 'refused');
  return { status: answer.status, message: ((await answer.json()) as { message: string }).message };
}

/** Whether the next WebSocket is let in: the proxy hands back its session. */
const admitted = async () => typeof (await app.socket(path, { headers: { ...(await headers()), upgrade: 'websocket' } })) === 'function';

const revoke = () => amend(world, 'credentials', sql`id = ${handleId}`, { revokedAt: new Date(), revokedBy: ADA });
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** How long after `from` the tunnel ended the client's connection; Infinity if it has not within five seconds, so a session left open fails rather than hangs. */
const endedAfter = async (client: AppClient, from: number) => (await Promise.race([client.ended, sleep(5_000).then(() => Infinity)])) - from;

test("queries through the tunnel run as the real login: one use opens the URL, one peek before the login, and the app's database only routes", async () => {
  // The migration door, asked once for the object's life (`admitSocket`): two statements, the first WebSocket's.
  const [, , door] = await cost(async () => {
    path = '/use/market/prod/nope';
    await refusal();
    path = '/use/market/prod/db';
  });
  assert.ok(door <= 2, `${door} statements`);
  const client = appClientOf();
  try {
    const [rows, calls, statements] = await cost(async () => [...(await client.unsafe('SELECT current_user AS who, 1 + 1 AS two'))]);
    assert.deepEqual(rows, [{ who: 'coffre_runtime', two: 2 }]);
    // Admission: the handle's row, where its run ends; the use. The login: a peek, the rows read now.
    assert.deepEqual(calls, ['use', 'peek']);
    assert.equal(statements, 1, "the handle's row, read to route it");
    const [use, peek] = app.inputs.slice(-2) as { purpose: string; upstream: UseInput['upstream']; keys: string[]; fresh?: boolean }[];
    assert.deepEqual([use!.purpose, use!.upstream, use!.keys, use!.fresh], ['use', { credential: 'db' }, ['DATABASE_URL'], undefined]);
    assert.deepEqual([peek!.purpose, peek!.upstream, peek!.keys, peek!.fresh], ['use', { credential: 'db' }, ['DATABASE_URL'], true]);
    // An extended-protocol query with parameters, as drivers send them: on the session, nothing more asked.
    const [joined, more] = await cost(async () => [...(await client.unsafe('SELECT $1::text || $2::text AS joined', ['a', 'b']))]);
    assert.deepEqual(joined, [{ joined: 'ab' }]);
    assert.deepEqual(more, []);
  } finally {
    await client.end();
  }
});

test('a password that is not the handle is refused, before any login to the database and before the vault is asked again', async () => {
  const client = appClientOf('not-the-handle');
  const [, calls] = await cost(() => assert.rejects(client.unsafe('SELECT 1'), (error: { code?: string }) => error.code === '28P01'));
  assert.deepEqual(calls, ['use']);
  await client.end();
});

test("a cancel request, on a connection of its own, reaches the database with the key the app was given", async () => {
  const client = appClientOf();
  try {
    const { state } = await client.unsafe('SELECT 1');
    const sleeping = client.unsafe('SELECT pg_sleep(30)').execute();
    await sleep(200);
    // As psql sends one: a CancelRequest, to the same listener.
    const cancel = tcp({ host: '127.0.0.1', port });
    await once(cancel, 'connect');
    cancel.write(cancelRequest(state!));
    const started = Date.now();
    await assert.rejects(sleeping, (error: { code?: string }) => error.code === '57014');
    assert.ok(Date.now() - started < 5000);
    cancel.destroy();
  } finally {
    await client.end();
  }
});

test('a cancel request with a key no live session of this handle was given reaches nothing', async () => {
  const client = appClientOf();
  try {
    const { state } = await client.unsafe('SELECT 1');
    const sleeping = client.unsafe('SELECT pg_sleep(0.6) AS slept').execute();
    await sleep(100);
    // The database's own key is never the app's: guess one, or flip one bit of the one given.
    for (const key of [{ pid: state!.pid, secret: state!.secret ^ 1 }, { pid: 12345, secret: 67890 }]) {
      const cancel = tcp({ host: '127.0.0.1', port });
      await once(cancel, 'connect');
      cancel.write(cancelRequest(key));
      await once(cancel, 'close');
    }
    assert.deepEqual([...(await sleeping)], [{ slept: '' }], 'the query ran to its end');
  } finally {
    await client.end();
  }
});

test('a handle revoked while a connection waits at the password prompt does not log it in: the peek before the login reads now', async () => {
  const socket = tcp({ host: '127.0.0.1', port });
  await once(socket, 'connect');
  socket.write(startup());
  await once(socket, 'data');
  await revoke();
  const answers: Buffer[] = [];
  socket.on('data', (chunk: Buffer) => answers.push(chunk));
  socket.write(message('p', cstring(handle)));
  await once(socket, 'close');
  const said = Buffer.concat(answers).toString('latin1');
  assert.equal(said.includes('R\u0000\u0000\u0000\u0008\u0000\u0000\u0000\u0000'), false, 'no AuthenticationOk');
  assert.match(said, /the handle ended/);
});

test('a handle revoked mid-session ends the open session at the next check, and no other is let in', async () => {
  const client = appClientOf();
  assert.deepEqual([...(await client.unsafe('SELECT 1 AS one'))], [{ one: 1 }]);
  const revoked = Date.now();
  await revoke();
  // One check is 200 ms here: within it, the deadline, and a margin for a slow machine.
  const took = await endedAfter(client, revoked);
  assert.ok(took < 600, `${took} ms`);
  await assert.rejects(client.unsafe('SELECT 1'));
  await client.end();
  const another = appClientOf();
  await assert.rejects(another.unsafe('SELECT 1'), 'nor is a new one opened');
  await another.end();
  assert.equal(refusals.at(-1)?.status, 401);
});

test('a person whose grant ends loses their open sessions at the next check', async () => {
  const client = appClientOf();
  assert.deepEqual([...(await client.unsafe('SELECT 1 AS one'))], [{ one: 1 }]);
  const lost = Date.now();
  await amend(world, 'grants', sql`principal = ${ADA}`, { role: 'none' });
  const took = await endedAfter(client, lost);
  assert.ok(took < 600, `${took} ms`);
  await client.end();
  assert.equal((await refusal()).status, 403);
});

test('sessions opened at different times end together, within one check of the revocation', async () => {
  const first = appClientOf();
  await first.unsafe('SELECT 1');
  await sleep(100);
  const second = appClientOf();
  await second.unsafe('SELECT 1');
  const revoked = Date.now();
  await revoke();
  const [a, b] = await Promise.all([endedAfter(first, revoked), endedAfter(second, revoked)]);
  assert.ok(Math.max(a, b) < 600, `${a} ms and ${b} ms`);
  await Promise.all([first.end(), second.end()]);
});

test('a group of sessions is checked once an interval, however many it holds: one peek, never one per session', async () => {
  const clients = Array.from({ length: 10 }, () => appClientOf());
  for (const client of clients) await client.unsafe('SELECT 1');
  // Two and a half intervals, counted from now: two checks, or three, for all ten.
  const [, calls] = await cost(() => sleep(500));
  assert.ok(calls.every((call) => call === 'peek'), calls.join());
  assert.ok(calls.length >= 1 && calls.length <= 3, `${calls.length} checks`);
  await Promise.all(clients.map((client) => client.end()));
});

test('a check the vault never answers is a no, by its deadline: the sessions do not outlive a stalled vault', async () => {
  const client = appClientOf();
  await client.unsafe('SELECT 1');
  current.stall = true;
  const stalled = Date.now();
  // A check every 200 ms, each with 200 ms to answer: within both and a margin.
  const took = await endedAfter(client, stalled);
  assert.ok(took < 700, `${took} ms`);
  await client.end();
});

test("a check still out when the group's last session leaves arms nothing when it answers yes: the group is gone with its sessions", async () => {
  // A check every 2 s, its bound 3 s from the last yes: the session leaves while the second check hangs, a second before the bound.
  current.proxy = proxyOf({ recheckSeconds: 2 });
  const client = appClientOf();
  await client.unsafe('SELECT 1');
  current.stall = true;
  while (current.stalled.length === 0) await sleep(20);
  await client.end();
  await sleep(200);
  const armed: unknown[] = [];
  const setTimeoutOf = globalThis.setTimeout;
  globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
    if (new Error().stack?.includes('credential-proxy')) armed.push(args[1]);
    return setTimeoutOf(...args);
  }) as typeof setTimeout;
  try {
    for (const answer of current.stalled) answer(true);
    await sleep(50);
  } finally {
    globalThis.setTimeout = setTimeoutOf;
  }
  assert.deepEqual(armed, [], 'a timer armed for a group no session holds');
});

test("a check's no ends the group as it comes, not at the bound its last yes left it", async () => {
  // A check every 500 ms, the bound 500 ms past it: a no left to the bound would leave the session open half a second more.
  current.proxy = proxyOf({ recheckSeconds: 0.5 });
  const client = appClientOf();
  await client.unsafe('SELECT 1');
  await revoke();
  const ended = await endedAfter(client, 0);
  assert.ok(current.noes.length > 0, 'a check said no');
  assert.ok(ended - current.noes[0]! < 150, `${ended - current.noes[0]!} ms after the no`);
  await client.end();
});

test("a check asks for the tunnel's key, not only its environment: a URL deleted mid-session ends the session", async () => {
  const client = appClientOf();
  await client.unsafe('SELECT 1');
  const deleted = Date.now();
  await amend(world, 'secrets', sql`key = 'DATABASE_URL'`, { archivedAt: new Date() });
  const took = await endedAfter(client, deleted);
  assert.ok(took < 600, `${took} ms`);
  await client.end();
});

test('a tunnel reaches only the hosts it names, and a private database only with insecureUpstreams', async () => {
  current.proxy = proxyOf({ tunnels: { db: postgres('DATABASE_URL', { hosts: ['db.acme.example'] }) } });
  assert.equal((await refusal()).status, 403, 'loopback is not db.acme.example');
  current.proxy = proxyOf({ insecureUpstreams: false });
  assert.equal((await refusal()).status, 403, 'loopback, without insecureUpstreams');
  for (const key of Object.keys(URLS).filter((key) => key.startsWith('LOOPBACK_'))) {
    current.proxy = proxyOf({ tunnels: { db: postgres(key) }, insecureUpstreams: false });
    assert.equal((await refusal()).status, 403, URLS[key]);
  }
  // A name, which may resolve to a private address, only when the tunnel's hosts list it: the value's writer picks it, not the deployment.
  current.proxy = proxyOf({ tunnels: { db: postgres('NAMED_URL') }, insecureUpstreams: false });
  assert.match((await refusal()).message, /names its host by name, which the tunnel db dials only when its hosts list it/);
  current.proxy = proxyOf({ tunnels: { db: postgres('NAMED_URL', { hosts: ['db.acme.example'] }) }, insecureUpstreams: false });
  assert.ok(await admitted(), 'a listed name is dialled');
  // Its fully qualified spelling is the same host.
  current.proxy = proxyOf({ tunnels: { db: postgres('FQDN_URL', { hosts: ['db.acme.example'] }) }, insecureUpstreams: false });
  assert.ok(await admitted());
  // An address needs no list.
  current.proxy = proxyOf({ tunnels: { db: postgres('ADDRESS_URL') }, insecureUpstreams: false });
  assert.ok(await admitted());
  // A value that is no Postgres URL: said, never shown.
  current.proxy = proxyOf({ tunnels: { db: postgres('NOT_A_URL') } });
  const wrong = await refusal();
  assert.deepEqual([wrong.status, wrong.message.includes('mysql')], [409, false]);
});

test('a tunnel through a network binding reaches the private host it names, plaintext, without insecureUpstreams', async () => {
  current.proxy = proxyOf({ tunnels: { db: postgres('REPLICA_URL', { hosts: [REPLICA], connect: network }) }, insecureUpstreams: false });
  const client = appClientOf();
  try {
    assert.deepEqual([...(await client.unsafe('SELECT current_user AS who'))], [{ who: 'coffre_runtime' }]);
  } finally {
    await client.end();
  }
  assert.deepEqual(dialled, [`${REPLICA}:5432`]);
  // TLS asked for, which the binding does not carry: refused before any dial, and said.
  current.proxy = proxyOf({ tunnels: { db: postgres('REPLICA_TLS_URL', { hosts: [REPLICA], connect: network }) }, insecureUpstreams: false });
  const tls = await refusal();
  assert.equal(tls.status, 409);
  assert.match(tls.message, /asks for TLS, which the tunnel db's network binding does not carry: sslmode=disable/);
  // A host the tunnel does not name, and the same private host without the binding: refused.
  current.proxy = proxyOf({ tunnels: { db: postgres('OTHER_PRIVATE_URL', { hosts: [REPLICA], connect: network }) }, insecureUpstreams: false });
  assert.equal((await refusal()).status, 403);
  current.proxy = proxyOf({ tunnels: { db: postgres('REPLICA_URL') }, insecureUpstreams: false });
  assert.equal((await refusal()).status, 403);
  assert.deepEqual(dialled, [`${REPLICA}:5432`], 'no other dial through the binding');
});

test("a tunnel's path and its caller: a tunnel the deployment names, a handle as the bearer, and a plain request told it is a WebSocket", async () => {
  path = '/use/market/prod/nope';
  assert.equal((await refusal()).status, 404);
  path = '/use/market/prod/db/more';
  assert.equal((await refusal()).status, 404);
  path = '/use/market/prod/db';
  headers = async () => ({});
  assert.equal((await refusal()).status, 401);
  headers = async () => ({ authorization: `Bearer ${generateToken('handle')}` });
  const [unknown, calls] = await cost(() => refusal());
  assert.equal(unknown.status, 401);
  assert.deepEqual(calls, [], "a token that is no handle's is refused on its row, before the vault");
  const plain = await app.request('/use/market/prod/db', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(plain.status, 426);
});

/** The deploy session's upgrade: its token, and a proof of `GET` on the tunnel's https URL under its gate's nonce. */
async function asDeploy(): Promise<Record<string, string>> {
  const nonce = await held(DEPLOY).nonce();
  const proof = await createProof(deploy.key, { method: 'GET', url: `${PUBLIC_URL}${path}`, token: deploy.token, nonce });
  return { authorization: `DPoP ${deploy.token}`, dpop: proof };
}

test("a workload's tunnel: its gate takes the proof, the vault one use, the app asks no password, and a freeze ends it within a check", async () => {
  current.proxy = proxyOf({ recheckSeconds: 0.3 });
  headers = asDeploy;
  // No password: its signed upgrade authenticated it. The listener's driver sends one all the same if asked, so none is asked.
  const client = appClientOf('ignored');
  try {
    const [rows, calls, statements] = await cost(async () => [...(await client.unsafe('SELECT current_user AS who'))]);
    assert.deepEqual(rows, [{ who: 'coffre_runtime' }]);
    assert.deepEqual(calls, ['use', 'peek']);
    assert.equal(statements, 1, "the session's row, read to route it");
    assert.deepEqual(gated, [DEPLOY], 'its gate, once');
    const frozen = Date.now();
    await amend(world, 'credentials', sql`token_hash = ${tokenOf(deploy.token)}`, { frozenAt: new Date() });
    // Checked every two thirds of 300 ms, a third to answer: within the bound and a margin.
    const took = await endedAfter(client, frozen);
    assert.ok(took < 700, `${took} ms`);
  } finally {
    await client.end();
  }
  const refused = await refusal();
  assert.equal(refused.status, 403);
});

test("a workload's tunnel: a proof replayed is refused at its gate, before the vault; a narrowed session reaches only what it names", async () => {
  const signed = await asDeploy();
  headers = async () => signed;
  assert.ok(await admitted());
  const [replayed, calls] = await cost(() => refusal());
  assert.equal(replayed.status, 401);
  assert.deepEqual(calls, []);
  headers = asDeploy;
  await amend(world, 'credentials', sql`token_hash = ${tokenOf(deploy.token)}`, { constraints: JSON.stringify({ credentials: ['stripe'] }) });
  // The vault's memory of the session's rows, two seconds of it, goes first: a proxied use answers from it, as any does.
  world.memory.reads.clear();
  const narrowed = await refusal();
  assert.equal(narrowed.status, 403);
  assert.match(narrowed.message, /narrowed session/);
});

test("a workload's tunnels are grouped by session: a freeze of one session ends its tunnels, not another session's", async () => {
  current.proxy = proxyOf({ recheckSeconds: 0.3 });
  const other = { token: generateToken('workload'), key: await generateProofKey() };
  await write(world, ...rows('credentials', session(other.token, deployBinding, { jkt: await thumbprint(other.key.jwk), scope: ON_PROD, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000) })));
  const as = (who: { token: string; key: ProofKey }) => async () => {
    const nonce = await held(DEPLOY).nonce();
    return { authorization: `DPoP ${who.token}`, dpop: await createProof(who.key, { method: 'GET', url: `${PUBLIC_URL}${path}`, token: who.token, nonce }) };
  };
  headers = as(deploy);
  const frozen = appClientOf('ignored');
  await frozen.unsafe('SELECT 1');
  headers = as(other);
  const kept = appClientOf('ignored');
  try {
    await kept.unsafe('SELECT 1');
    const at = Date.now();
    await amend(world, 'credentials', sql`token_hash = ${tokenOf(deploy.token)}`, { frozenAt: new Date() });
    const took = await endedAfter(frozen, at);
    assert.ok(took < 700, `${took} ms`);
    // Past several checks of the other session's group: it still runs.
    await sleep(600);
    assert.deepEqual([...(await kept.unsafe('SELECT 1 AS one'))], [{ one: 1 }]);
  } finally {
    await Promise.all([frozen.end(), kept.end()]);
  }
});

// --- 0.14.7's wire cases, on 0.16's tunnel ---

test('LISTEN and NOTIFY across two tunnelled connections', async () => {
  const listening = await rawSession();
  let notifying: RawSession | undefined;
  try {
    notifying = await rawSession();
    await listening.query('LISTEN coffre_tunnel');
    await notifying.query("SELECT pg_notify('coffre_tunnel', 'through the tunnel')");
    // NotificationResponse: the notifier's pid, the channel, the payload.
    const heard = await listening.until('A');
    const [channel, payload] = heard.body.subarray(4).toString().split('\0');
    assert.deepEqual([channel, payload], ['coffre_tunnel', 'through the tunnel']);
  } finally {
    listening.close();
    notifying?.close();
  }
});

test('COPY both ways, on the wire as psql sends it', async () => {
  // As the database's owner, who may make the temporary table to copy into: the app's login may not.
  const owner = APP_URL.replace('coffre_runtime:local-runtime-only', 'coffre_owner:local-dev-only');
  await write(world, ...rows('secrets', value(world, secret(prod, 'OWNER_URL'), `${owner}?sslmode=disable`)));
  current.proxy = proxyOf({ tunnels: { db: postgres('OWNER_URL') } });
  const raw = await rawSession();
  try {
    await raw.query('CREATE TEMP TABLE carried (n int)');
    // COPY FROM STDIN: CopyInResponse, then the rows as CopyData, CopyDone.
    assert.equal(await raw.send('Q', cstring('COPY carried FROM STDIN')), 'G');
    await raw.write(message('d', Buffer.from('4\n5\n6\n')));
    await raw.write(message('c', Buffer.alloc(0)));
    await raw.until('Z');
    assert.equal(await raw.copyOut('COPY (SELECT sum(n) FROM carried) TO STDOUT'), '15\n');
  } finally {
    raw.close();
  }
});

test('a password message longer than a handle is refused before it is read, and the vault is not asked again', async () => {
  const [, calls] = await cost(async () => {
    const socket = tcp({ host: '127.0.0.1', port });
    // Reset by the tunnel, with what it had not read: the reset is the close.
    socket.on('error', () => undefined);
    const closed = new Promise((resolve) => socket.once('close', () => resolve('closed')));
    await once(socket, 'connect');
    socket.write(startup());
    await once(socket, 'data');
    const head = Buffer.alloc(5);
    head.write('p', 0);
    head.writeInt32BE(0x7fffffff, 1);
    socket.write(head);
    socket.write(Buffer.alloc(64 * 1024));
    // Read whole, it would wait on 2 GiB until the startup's 30 s deadline.
    assert.equal(await Promise.race([closed, sleep(2_000)]), 'closed', 'closed at once');
  });
  assert.deepEqual(calls, ['use'], 'no peek: the login never began');
});

test('a startup asks for encryption once each, and no more', async () => {
  const raw = tcp({ host: '127.0.0.1', port });
  await once(raw, 'connect');
  const ssl = Buffer.alloc(8);
  ssl.writeInt32BE(8, 0);
  ssl.writeInt32BE(80877103, 4);
  let answered = '';
  raw.on('data', (chunk: Buffer) => (answered += chunk.toString('latin1')));
  raw.write(Buffer.concat(Array.from({ length: 1000 }, () => ssl)));
  await once(raw, 'close');
  assert.ok(answered.startsWith('NN') && !answered.startsWith('NNN'), JSON.stringify(answered.slice(0, 4)));
});

test('a database URL is read as it is dialled: loopback in any numeric form is loopback, a name in lower case', () => {
  for (const host of ['127.1', '2130706433', '0x7f000001', '127.0.0.1']) assert.equal(database(`postgres://u:p@${host}:5432/d`).host, '127.0.0.1', host);
  assert.equal(database('postgres://u:p@[::1]:5432/d').host, '::1');
  assert.equal(database('postgres://u:p@DB.Acme.Example/d').host, 'db.acme.example');
});

test('SASLprep maps as Postgres does, and falls back to the password as it is', () => {
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

/** A database of the test's own on loopback, which the tunnel `db` dials from now: `answer` gets each connection, and what it sent. */
async function fakeDatabase(answer: (socket: Socket, chunk: Buffer, stage: number) => number, query = '?sslmode=disable'): Promise<{ sockets: Socket[]; close(): void }> {
  const sockets: Socket[] = [];
  const fake = createServer((socket) => {
    sockets.push(socket);
    let stage = 0;
    socket.on('error', () => undefined);
    socket.on('data', (chunk: Buffer) => void (stage = answer(socket, chunk, stage)));
  });
  fake.listen(0, '127.0.0.1');
  await once(fake, 'listening');
  await write(world, ...rows('secrets', value(world, secret(prod, 'FAKE_URL'), `postgres://u:p@127.0.0.1:${(fake.address() as AddressInfo).port}/d${query}`)));
  current.proxy = proxyOf({ tunnels: { db: postgres('FAKE_URL') } });
  return {
    sockets,
    close: () => {
      for (const socket of sockets) socket.destroy();
      fake.close();
    },
  };
}

/** A database that asks for SCRAM, and answers the client's first message with `iterations`; `then`, what it says to the client's last. */
const scramFake = (iterations: number, then?: (socket: Socket) => void) => (socket: Socket, chunk: Buffer, stage: number) => {
  if (stage === 0) socket.write(message('R', Buffer.concat([Buffer.from([0, 0, 0, 10]), cstring('SCRAM-SHA-256'), Buffer.from([0])])));
  else if (stage === 1) {
    const nonce = /r=([^,]+)/.exec(chunk.toString('latin1'))![1]!;
    socket.write(message('R', Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from(`r=${nonce}server,s=${Buffer.from('salt').toString('base64')},i=${iterations}`)])));
  } else if (stage === 2) then?.(socket);
  return stage + 1;
};

test('a database that ends SCRAM without its signature is no database the URL names: refused', async () => {
  // It takes the proof, then says AuthenticationOk with no server-final message.
  const fake = await fakeDatabase(scramFake(4096, (socket) => socket.write(Buffer.concat([message('R', Buffer.from([0, 0, 0, 0])), message('Z', Buffer.from('I'))]))));
  const client = appClientOf();
  try {
    // Let in, the query would go to a database that never answers it: bounded, so a login let through fails rather than hangs.
    await assert.rejects(Promise.race([client.unsafe('SELECT 1'), sleep(3_000)]), /without proving it knows the password/);
  } finally {
    // The fake first: a query it holds would keep the client's end waiting.
    fake.close();
    await client.end();
  }
});

test('a database that asks for more SCRAM iterations than any needs is refused before the work begins', async (t) => {
  // One past the tunnel's most (100,000): computed, it costs milliseconds, so a broken limit fails here, and never hangs.
  let proved = false;
  const derived: number[] = [];
  const deriveBits = crypto.subtle.deriveBits;
  t.mock.method(crypto.subtle, 'deriveBits', (algorithm: Pbkdf2Params, key: CryptoKey, length: number) => {
    derived.push(algorithm.iterations);
    return deriveBits.call(crypto.subtle, algorithm, key, length);
  });
  const fake = await fakeDatabase(scramFake(100_001, () => void (proved = true)));
  const client = appClientOf();
  try {
    await assert.rejects(Promise.race([client.unsafe('SELECT 1'), sleep(3_000).then(() => assert.fail('neither refused nor logged in within 3 s'))]), /SCRAM iterations/);
    assert.deepEqual(derived, [], 'the tunnel ran PBKDF2 before refusing');
    assert.equal(proved, false, 'the tunnel sent the database its proof: it did the work');
  } finally {
    // The fake first: a query it holds would keep the client's end waiting.
    fake.close();
    await client.end();
  }
});

test('a connection the app drops while the database has not answered leaves no socket open to it', async () => {
  // A database that reads what it is sent and never answers: the tunnel waits on its answer to SSLRequest.
  const silent = await fakeDatabase((socket, _, stage) => stage, '');
  try {
    const raw = tcp({ host: '127.0.0.1', port });
    await once(raw, 'connect');
    raw.write(startup());
    await once(raw, 'data');
    raw.write(message('p', cstring(handle)));
    for (let waited = 0; silent.sockets.length === 0 && waited < 2000; waited += 20) await sleep(20);
    assert.equal(silent.sockets.length, 1, 'the tunnel reached the database');
    const closed = once(silent.sockets[0]!, 'close');
    raw.destroy();
    assert.notEqual(await Promise.race([closed, sleep(2_000)]), undefined, "the database's socket closed with the app's");
  } finally {
    silent.close();
  }
});

test('a cancel request through a network binding reaches the database, though its connector dials after the socket opens', async () => {
  // A VPC Network binding as Cloudflare's is: open at once, its connector dialing the database only later; closed
  // before that, it sends nothing (W150, measured live).
  const late: Network = {
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
        socket = tcp({ host: '127.0.0.1', port: Number(new URL(APP_URL).port) });
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
  current.proxy = proxyOf({ tunnels: { db: postgres('REPLICA_URL', { hosts: [REPLICA], connect: late }) }, insecureUpstreams: false });
  const client = appClientOf();
  try {
    const { state } = await client.unsafe('SELECT 1');
    const sleeping = client.unsafe('SELECT pg_sleep(30)').execute();
    await sleep(200);
    const cancel = tcp({ host: '127.0.0.1', port });
    await once(cancel, 'connect');
    cancel.write(cancelRequest(state!));
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
  const unused: Network = { connect: () => Promise.reject(new Error('unused')) };
  assert.throws(tunnel({ connect: unused }), /names the hosts it reaches there/);
  assert.throws(tunnel({ hosts: [], connect: unused }), /names the hosts it reaches there/);
  // Private hosts, with a binding and without insecureUpstreams; never without it.
  assert.doesNotThrow(tunnel({ hosts: ['10.0.1.5'], connect: unused }));
  assert.throws(tunnel({ hosts: ['10.0.1.5'] }), /names a private host/);
  for (const host of ['localhost.', 'LocalHost', '127.1', '::ffff:10.0.1.5', '[fd00::5]']) assert.throws(tunnel({ hosts: [host] }), /names a private host/, host);
});

test('a dial through a network binding still under way when the app leaves is given up: the socket that comes after is closed', async () => {
  // A binding that answers only when told, with a socket that says when it is closed.
  let answer!: (socket: WorkersSocket) => void;
  let asked!: () => void;
  const dialling = new Promise<void>((resolve) => (asked = resolve));
  const pending: Network = {
    connect: () => {
      asked();
      return new Promise<WorkersSocket>((done) => (answer = done));
    },
  };
  current.proxy = proxyOf({ tunnels: { db: postgres('REPLICA_URL', { hosts: [REPLICA], connect: pending }) }, insecureUpstreams: false });
  const raw = tcp({ host: '127.0.0.1', port });
  await once(raw, 'connect');
  raw.write(startup());
  await once(raw, 'data');
  raw.write(message('p', cstring(handle)));
  await dialling;
  raw.destroy();
  await sleep(200);
  let closed = false;
  answer({ readable: new ReadableStream(), writable: new WritableStream(), opened: Promise.resolve(), closed: new Promise(() => undefined), close: async () => void (closed = true), startTls: () => { throw new Error('unused'); } });
  for (let waited = 0; !closed && waited < 2000; waited += 20) await sleep(20);
  assert.ok(closed, 'the late socket was closed');
});

type RawSession = Awaited<ReturnType<typeof rawSession>>;

/** How long a raw session waits for the tunnel's next message before it fails: a regression fails its test, never hangs the file. */
const RAW_READ_MS = 5_000;

/** A raw session on the listener, as psql's wire is: the simple query protocol, COPY included. */
async function rawSession() {
  const socket = tcp({ host: '127.0.0.1', port });
  await once(socket, 'connect');
  let buffered = Buffer.alloc(0);
  /** Why no more will come: the connection ended or failed. */
  let gone: Error | undefined;
  const waiting: (() => void)[] = [];
  const wakeAll = () => waiting.splice(0).forEach((wake) => wake());
  socket.on('data', (chunk: Buffer) => {
    buffered = Buffer.concat([buffered, chunk]);
    wakeAll();
  });
  socket.on('error', (error) => void (gone ??= error));
  socket.on('close', () => {
    gone ??= new Error('the tunnel closed the connection');
    wakeAll();
  });
  const next = async (): Promise<{ type: string; body: Buffer }> => {
    const deadline = Date.now() + RAW_READ_MS;
    while (buffered.length < 5 || buffered.length < 1 + buffered.readInt32BE(1)) {
      if (gone !== undefined) throw gone;
      const left = deadline - Date.now();
      if (left <= 0) throw new Error(`no message from the tunnel within ${RAW_READ_MS} ms`);
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, left);
        waiting.push(() => (clearTimeout(timer), resolve()));
      });
    }
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
  try {
    await write(startup());
    await until('R');
    await write(message('p', cstring(handle)));
    await until('Z');
  } catch (error) {
    socket.destroy();
    throw error;
  }
  return {
    write,
    until,
    async query(text: string) {
      await write(message('Q', cstring(text)));
      await until('Z');
    },
    /** A message sent; the type of the first answer that is no notice or parameter. */
    async send(type: string, body: Buffer) {
      await write(message(type, body));
      for (let got = await next(); ; got = await next()) if (!['N', 'S'].includes(got.type)) return got.type;
    },
    async copyOut(text: string) {
      await write(message('Q', cstring(text)));
      let out = '';
      for (let got = await next(); got.type !== 'Z'; got = await next()) {
        if (got.type === 'E') throw new Error(got.body.toString());
        if (got.type === 'd') out += got.body.toString();
      }
      return out;
    },
    close: () => socket.destroy(),
  };
}

// --- the wire, as psql writes it ---

const cstring = (text: string) => Buffer.concat([Buffer.from(text), Buffer.from([0])]);

function message(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.write(type, 0);
  head.writeInt32BE(body.length + 4, 1);
  return Buffer.concat([head, body]);
}

/** A StartupMessage, protocol 3.0, as user `app`. */
function startup(): Buffer {
  const body = Buffer.concat([Buffer.from([0, 3, 0, 0]), cstring('user'), cstring('app'), Buffer.from([0])]);
  const length = Buffer.alloc(4);
  length.writeInt32BE(body.length + 4);
  return Buffer.concat([length, body]);
}

/** A CancelRequest, as psql sends one, with the key a session was given. */
function cancelRequest({ pid, secret }: { pid: number; secret: number }): Buffer {
  const packet = Buffer.alloc(16);
  packet.writeInt32BE(16, 0);
  packet.writeInt32BE(80877102, 4);
  packet.writeUInt32BE(pid >>> 0, 8);
  packet.writeUInt32BE(secret >>> 0, 12);
  return packet;
}
