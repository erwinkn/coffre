#!/usr/bin/env node
// `pnpm smoke`: runs the probe under `wrangler dev` against a Postgres 17 of
// its own in Docker (127.0.0.1:56145, SCRAM, TLS on then off), and checks the
// gate, both routes, a hold, and the failures it must report by stage. It
// removes its container however it ends.
import { spawn, execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';

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
async function get(path, headers = { authorization: `Bearer ${key}` }, method = 'GET') {
  const response = await fetch(`${base}${path}`, { method, headers });
  const text = await response.text();
  seen.push(text);
  return { status: response.status, text, json: text.trim() ? JSON.parse(text) : null };
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

  await check('the gate answers an empty 404 to everything without the key', async () => {
    for (const [path, headers, method] of [
      ['/worker', {}],
      ['/do', { authorization: 'Bearer wrong' }],
      ['/do', { authorization: key }],
      ['/do', { authorization: `Bearer ${key}x` }],
      ['/', undefined],
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
} finally {
  if (wrangler) process.kill(-wrangler.pid);
  try {
    docker('rm', '-f', container);
  } catch {}
}
