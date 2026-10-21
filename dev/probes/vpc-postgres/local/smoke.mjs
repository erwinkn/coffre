#!/usr/bin/env node
// `pnpm smoke`: runs the probe under `wrangler dev` against a Postgres 17 of
// its own in Docker (127.0.0.1:56145, SCRAM, TLS on then off), and checks the
// gate, both routes, a hold, and the failures it must report by stage; then
// runs the wire code from Node against two hostile fake servers. It removes
// its container however it ends.
import { spawn, execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { probe } from '../src/pg.ts';

const here = new URL('.', import.meta.url).pathname;
const container = `vpc-probe-smoke-${process.pid}`;
const password = 'local-smoke-password-not-a-secret';
const key = 'local-smoke-probe-key-0123456789abcdef';
const base = 'http://127.0.0.1:8145';

const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
// Over TCP: the entrypoint's init server listens on its Unix socket only, so a TCP answer is the real server.
const sql = (statement) => docker('exec', '-e', 'PGPASSWORD=owner', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-tAc', statement);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let wrangler;
const seen = [];
// Interrupted, it still stops wrangler and removes the container.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    cleanUp();
    process.exit(1);
  });
}
async function get(path, headers = { authorization: `Bearer ${key}` }, method = 'GET') {
  const response = await fetch(`${base}${path}`, { method, headers });
  const text = await response.text();
  seen.push(text);
  return { status: response.status, text, json: text.trim() ? JSON.parse(text) : null };
}

const int32 = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeInt32BE(value);
  return bytes;
};
const frame = (type, body) => Buffer.concat([Buffer.from(type), int32(body.length + 4), body]);

/** The probe, from Node, against a fake server that answers SSLRequest with N and then does `misbehave` after StartupMessage. */
async function hostile(misbehave) {
  const server = net.createServer((socket) => {
    socket.on('error', () => {});
    socket.once('data', () => {
      socket.write('N');
      socket.once('data', () => misbehave(socket));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const dial = (address) => {
    const [host, port] = address.split(':');
    const socket = net.connect(Number(port), host);
    return { ...Duplex.toWeb(socket), opened: once(socket, 'connect'), close: async () => void socket.destroy() };
  };
  try {
    return await probe(dial, { host: '127.0.0.1', port: String(server.address().port), database: 'x', user: 'x', password }, 0);
  } finally {
    server.close();
  }
}

async function check(name, run) {
  await run();
  console.log(`ok - ${name}`);
}

try {
  docker('run', '-d', '--rm', '--name', container, '-p', '127.0.0.1:56145:5432',
    '-e', 'POSTGRES_PASSWORD=owner', '-e', 'POSTGRES_HOST_AUTH_METHOD=scram-sha-256',
    'postgres:17');
  for (let i = 0; ; i++) {
    try {
      sql('select 1');
      break;
    } catch (error) {
      if (i > 60) throw error;
      await wait(500);
    }
  }
  sql(`create role debug_ro login password '${password}'`);
  // TLS on through ALTER SYSTEM, not the command line, so a later reload can turn it off.
  sql("alter system set ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'");
  sql("alter system set ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'");
  sql('alter system set ssl = on');
  sql('select pg_reload_conf()');

  wrangler = spawn('pnpm', ['exec', 'wrangler', 'dev', '-c', `${here}wrangler.jsonc`, '--ip', '127.0.0.1', '--port', '8145'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  let log = '';
  wrangler.stdout.on('data', (chunk) => (log += chunk));
  wrangler.stderr.on('data', (chunk) => (log += chunk));
  for (let i = 0; ; i++) {
    try {
      await fetch(`${base}/`);
      break;
    } catch (error) {
      if (i > 120) throw new Error(`wrangler dev did not start:\n${log}`);
      await wait(500);
    }
  }

  await check('the gate answers an empty 404 to everything without the key, and to unknown routes with it', async () => {
    for (const [path, headers, method] of [
      ['/worker', {}],
      ['/do', { authorization: 'Bearer wrong' }],
      ['/do', { authorization: key }],
      ['/do', { authorization: `Bearer ${key}x` }],
      ['/', {}],
      ['/other', {}],
      ['/worker', {}, 'POST'],
      // With the key, an unknown path or method looks the same.
      ['/other', undefined],
      ['/worker', undefined, 'POST'],
    ]) {
      const response = await get(path, headers, method);
      assert.equal(response.status, 404, `${method ?? 'GET'} ${path}`);
      assert.equal(response.text, '');
    }
  });

  await check('hold past 600 s, or not whole seconds, is refused', async () => {
    for (const hold of ['601', '1.5', '-1', 'x']) assert.equal((await get(`/do?hold=${hold}`)).status, 400);
  });

  for (const route of ['worker', 'do']) {
    await check(`/${route}: TLS on, the probe redials in plaintext, logs in with SCRAM and queries`, async () => {
      const { json } = await get(`/${route}`);
      assert.equal(json.ok, true, JSON.stringify(json));
      assert.equal(json.route, route);
      assert.equal(json.sslRequest, 'S');
      assert.equal(json.redialedPlaintext, true);
      assert.deepEqual(json.authOffered, ['SCRAM-SHA-256']);
      assert.equal(json.loginOk, true);
      assert.equal(json.select1, '1');
      assert.equal(json.session.current_user, 'debug_ro');
      assert.equal(json.session.ssl, 'f');
      assert.match(json.serverVersion, /^17/);
    });
  }

  await check('/do?hold=25: the socket survives an idle hold, with heartbeats before the JSON', async () => {
    const { text, json } = await get('/do?hold=25');
    assert.ok(text.startsWith(' '), 'a heartbeat byte came first');
    assert.equal(json.ok, true, JSON.stringify(json));
    assert.equal(json.afterHold.seconds, 25);
    assert.equal(json.afterHold.select1, '1');
  });

  await check('a connection that dies during a hold is reported at the hold stage', async () => {
    const pending = get('/do?hold=4');
    await wait(2000);
    sql("select pg_terminate_backend(pid) from pg_stat_activity where application_name = 'vpc-postgres-probe'");
    const { json } = await pending;
    assert.equal(json.ok, false);
    assert.equal(json.stage, 'hold', JSON.stringify(json));
  });

  sql('alter system set ssl = off');
  sql('select pg_reload_conf()');
  await check('TLS off: the server answers N and the probe stays on its first socket', async () => {
    const { json } = await get('/worker');
    assert.equal(json.ok, true, JSON.stringify(json));
    assert.equal(json.sslRequest, 'N');
    assert.equal(json.redialedPlaintext, undefined);
  });

  sql("alter role debug_ro password 'not-the-configured-one'");
  await check('a wrong password fails at the auth stage with the server error', async () => {
    const { json } = await get('/do');
    assert.equal(json.ok, false);
    assert.equal(json.stage, 'auth');
    assert.match(json.error, /28P01/);
  });
  sql(`alter role debug_ro password '${password}'`);

  docker('exec', container, 'sh', '-c', "sed -i 's/scram-sha-256$/password/' /var/lib/postgresql/data/pg_hba.conf");
  sql('select pg_reload_conf()');
  await check('a server that asks for a cleartext password gets none', async () => {
    const { json } = await get('/worker');
    assert.equal(json.ok, false);
    assert.equal(json.stage, 'auth');
    assert.deepEqual(json.authOffered, ['cleartext password']);
  });

  docker('stop', container);
  await check('nothing listening fails at the dial or SSLRequest stage', async () => {
    const { json } = await get('/worker');
    assert.equal(json.ok, false);
    assert.ok(['dial', 'ssl-request'].includes(json.stage), JSON.stringify(json));
  });

  await check('no response ever held the password', async () => {
    for (const text of seen) assert.ok(!text.includes(password));
  });

  await check('an ErrorResponse without a terminator fails at once, not in a loop', async () => {
    const report = await hostile((socket) => socket.write(frame('E', Buffer.from('SFATAL'))));
    assert.equal(report.stage, 'auth', JSON.stringify(report));
    assert.ok(report.totalMs < 5000, JSON.stringify(report));
  });

  await check('a server that never stops sending messages hits the stage deadline', async () => {
    // A SCRAM login that verifies, then ParameterStatus every 100 ms and never ReadyForQuery.
    const report = await hostile((socket) => {
      socket.write(frame('R', Buffer.concat([int32(10), Buffer.from('SCRAM-SHA-256\0\0')])));
      socket.once('data', (initial) => {
        // SASLInitialResponse: 'p', length, the mechanism's C string, the response's length, then client-first.
        const clientFirstBare = initial.subarray(initial.indexOf(0, 5) + 5).toString().slice('n,,'.length);
        const salt = randomBytes(16);
        const serverFirst = `r=${clientFirstBare.slice('n=,r='.length)}server,s=${salt.toString('base64')},i=4096`;
        socket.write(frame('R', Buffer.concat([int32(11), Buffer.from(serverFirst)])));
        socket.once('data', (final) => {
          const withoutProof = final.subarray(5).toString().split(',p=')[0];
          const serverKey = createHmac('sha256', pbkdf2Sync(password, salt, 4096, 32, 'sha256')).update('Server Key').digest();
          const signature = createHmac('sha256', serverKey).update(`${clientFirstBare},${serverFirst},${withoutProof}`).digest('base64');
          socket.write(frame('R', Buffer.concat([int32(12), Buffer.from(`v=${signature}`)])));
          socket.write(frame('R', int32(0)));
          const timer = setInterval(() => socket.write(frame('S', Buffer.from('spam\0spam\0'))), 100);
          socket.on('close', () => clearInterval(timer));
        });
      });
    });
    assert.equal(report.stage, 'auth', JSON.stringify(report));
    assert.match(report.error, /no answer within 15 s/);
  });
} finally {
  cleanUp();
}

function cleanUp() {
  try {
    if (wrangler) process.kill(-wrangler.pid);
  } catch {}
  try {
    docker('rm', '-f', container);
  } catch {}
}
