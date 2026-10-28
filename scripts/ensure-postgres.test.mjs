import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { join, resolve } from 'node:path';
import test from 'node:test';

const script = resolve(import.meta.dirname, 'ensure-postgres.sh');

// route: where the fixture's `ip` sends the container's address: its own bridge,
// Cloudflare WARP's device, or a host without that bridge (Docker Desktop).
async function fixture(t, mode, callers = 1, route = 'bridge') {
    const dir = mkdtempSync(join(tmpdir(), 'coffre-postgres-bootstrap-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const project = 'fixture_' + dir.split('-').at(-1);
    t.after(() => rmSync(join(tmpdir(), `coffre-postgres-${process.getuid()}-${project}.lock`), { force: true }));
    mkdirSync(join(dir, 'probed'));
    mkdirSync(join(dir, 'scripts'));
    const portProbe = createServer();
    await new Promise((resolve) => portProbe.listen(0, '127.0.0.1', resolve));
    const port = portProbe.address().port;
    await new Promise((resolve) => portProbe.close(resolve));
    const localScript = join(dir, 'scripts/ensure-postgres.sh');
    writeFileSync(localScript, readFileSync(script, 'utf8'));
    writeFileSync(join(dir, 'scripts/postgres-port-available.mjs'), readFileSync(resolve(import.meta.dirname, 'postgres-port-available.mjs')));
    const state = JSON.stringify(dir);
    writeFileSync(join(dir, 'docker'), `#!${process.execPath}
import { appendFileSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
const dir = ${state};
const args = process.argv.slice(2);
const mode = ${JSON.stringify(mode)};
appendFileSync(dir + '/calls', JSON.stringify(args) + '\\n');
appendFileSync(dir + '/compose-files', (process.env.COMPOSE_FILE ?? '') + '\\n');
if (mode === 'stale' && args.includes('config')) { console.log('postgres:16.14'); process.exit(0); }
if (mode === 'stale' && args[0] === 'inspect') { console.log('postgres:16.14-alpine'); process.exit(0); }
if (args.includes('port')) {
    if (mode === 'healthy' || mode === 'stale' || mode === 'existing' || existsSync(dir + '/created')) console.log('0.0.0.0:${port}');
    // Before creation, allow the mocked internal probe to reach its barrier.
    else if (mode === 'cold') console.log('0.0.0.0:${port}');
    process.exit(0);
}
if (args.includes('exec')) {
    if (mode === 'healthy' || mode === 'stale') process.exit(0);
    if (mode === 'existing') {
        const n = existsSync(dir + '/probes') ? Number(readFileSync(dir + '/probes')) : 0;
        writeFileSync(dir + '/probes', String(n + 1));
        process.exit(n >= 2 ? 0 : 1);
    }
    if (mode === 'cold') {
        const mark = dir + '/probed/' + process.ppid;
        if (!existsSync(mark)) {
            writeFileSync(mark, '');
            const deadline = Date.now() + 5000;
            while (readdirSync(dir + '/probed').length < ${callers}) {
                if (Date.now() > deadline) throw new Error('cold-start test barrier timed out');
                await sleep(10);
            }
            process.exit(1);
        }
        process.exit(existsSync(dir + '/created') ? 0 : 1);
    }
    if (mode === 'bind') process.exit(existsSync(dir + '/created') ? 0 : 1);
    process.exit(1);
}
if (args.includes('ps')) {
    if (mode === 'existing' || mode === 'stale' || mode === 'healthy' || existsSync(dir + '/created')) console.log('fixture-postgres');
    process.exit(0);
}
if (args[0] === 'inspect' && args.some((arg) => arg.includes('NetworkSettings'))) {
    console.log('172.30.0.2 0123456789abcdef');
    process.exit(0);
}
if (args[0] === 'network') process.exit(0);
if (args.includes('down')) { writeFileSync(dir + '/down', ''); process.exit(0); }
if (args[0] === 'inspect') {
    console.log(mode === 'existing' || existsSync(dir + '/created') ? 'true' : 'false');
    process.exit(0);
}
if (args.includes('up')) {
    if (mode === 'fatal') {
        console.error('invalid mount configuration');
        process.exit(1);
    }
    if (mode === 'bind' && !existsSync(dir + '/contended')) {
        writeFileSync(dir + '/contended', '');
        console.error('failed to bind host port: address already in use');
        process.exit(1);
    }
    if (mode === 'existing') {
        writeFileSync(dir + '/recreated', '');
        process.exit(0);
    }
    try { writeFileSync(dir + '/created', '', { flag: 'wx' }); }
    catch {
        console.error('Conflict. The container name is already in use by container fixture-postgres');
        process.exit(1);
    }
    process.exit(0);
}
throw new Error('unexpected docker command: ' + args.join(' '));
`, { mode: 0o755 });
    writeFileSync(join(dir, 'ip'), `#!${process.execPath}
import { appendFileSync } from 'node:fs';
const args = process.argv.slice(2);
appendFileSync(${state} + '/ip-calls', JSON.stringify(args) + '\\n');
if (args.includes('route')) {
    const dev = ${JSON.stringify(route)} === 'warp' ? 'CloudflareWARP table 65743' : ${JSON.stringify(route)} === 'bridge' ? 'br-0123456789ab' : 'eth0';
    console.log('172.30.0.2 dev ' + dev + ' src 100.96.0.1 uid 1000');
    process.exit(0);
}
if (args.includes('link')) process.exit(${JSON.stringify(route)} === 'bridge' || ${JSON.stringify(route)} === 'warp' ? 0 : 1);
throw new Error('unexpected ip command: ' + args.join(' '));
`, { mode: 0o755 });
    const run = (asked = port, env = {}) => new Promise((resolve, reject) => {
        const child = spawn('/bin/bash', [localScript], {
            env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, COMPOSE_PROJECT_NAME: project, COFFRE_POSTGRES_PORT: String(asked), ...env },
            stdio: ['ignore', 'pipe', 'pipe'],
            detached: true,
        });
        // Terminate the whole owned group, including the lock holder, on a
        // failed probe. Killing only flock would leave its shell running.
        const deadline = setTimeout(() => {
            try { process.kill(-child.pid, 'SIGTERM'); }
            catch (error) { if (error.code !== 'ESRCH') throw error; }
        }, 15_000);
        deadline.unref();
        let output = '';
        child.stdout.on('data', (chunk) => { output += chunk; });
        child.stderr.on('data', (chunk) => { output += chunk; });
        child.once('error', (error) => { clearTimeout(deadline); reject(error); });
        child.once('close', (code) => { clearTimeout(deadline); resolve({ code, output }); });
    });
    return { dir, port, run, ipCalls: () => readFileSync(join(dir, 'ip-calls'), 'utf8').trim().split('\n').map(JSON.parse), calls: () => readFileSync(join(dir, 'calls'), 'utf8').trim().split('\n').map(JSON.parse) };
}

test('a healthy Postgres is reused without an up', async (t) => {
    const f = await fixture(t, 'healthy');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
    assert.ok(f.calls().every((args) => !args.includes('up')));
});

test('a healthy Postgres on compose\'s image is reused without a word', async (t) => {
    const f = await fixture(t, 'healthy');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
    assert.doesNotMatch(ran.output, /docker-compose\.yml names/);
});

test('a reused Postgres on another image than compose names is said so, and kept', async (t) => {
    const f = await fixture(t, 'stale');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
    assert.match(ran.output, /runs postgres:16\.14-alpine, but docker-compose\.yml names postgres:16\.14; it is reused as it is/);
    assert.ok(f.calls().every((args) => !args.includes('up')), 'a stale image is reported, never recreated');
});

test("a project's Postgres on another port than the one asked for is refused, not used", async (t) => {
    const f = await fixture(t, 'healthy');
    const ran = await f.run(f.port + 1);
    assert.equal(ran.code, 1);
    assert.match(ran.output, new RegExp(`publishes Postgres on :${f.port}, not :${f.port + 1}\\. Run that port as a project of its own`));
    assert.ok(f.calls().every((args) => !args.includes('up') && !args.includes('exec')));
});

test('a running but unready Postgres is awaited without recreation', async (t) => {
    const f = await fixture(t, 'existing');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
    assert.ok(f.calls().every((args) => !args.includes('up')), 'up could recreate another checkout\'s initializing container');
});

test('five callers observing a cold database all succeed with one serialized startup', async (t) => {
    const f = await fixture(t, 'cold', 5);
    const ran = await Promise.all(Array.from({ length: 5 }, () => f.run()));
    for (const result of ran) assert.equal(result.code, 0, result.output);
    const starts = f.calls().filter((args) => args.includes('up'));
    assert.equal(starts.length, 1);
    assert.ok(starts[0].includes('--no-recreate'));
});

test('an unrelated compose failure is reported immediately', async (t) => {
    const f = await fixture(t, 'fatal');
    const ran = await f.run();
    assert.equal(ran.code, 1);
    assert.match(ran.output, /invalid mount configuration/);
    assert.equal(f.calls().filter((args) => args.includes('up')).length, 1);
});

test('a transient bind conflict is retried without replacing the container', async (t) => {
    const f = await fixture(t, 'bind');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
    assert.match(ran.output, /address already in use/);
    const starts = f.calls().filter((args) => args.includes('up'));
    assert.equal(starts.length, 2);
    assert.ok(starts.every((args) => args.includes('--no-recreate')));
});

test("a started Postgres whose address the host routes off the bridge is removed and refused", async (t) => {
    const f = await fixture(t, 'cold', 1, 'warp');
    const ran = await f.run();
    assert.equal(ran.code, 1);
    assert.match(ran.output, /routes 172\.30\.0\.2 through CloudflareWARP, not its bridge br-0123456789ab/);
    assert.match(ran.output, /COFFRE_POSTGRES_SUBNET=.*default-address-pools/s);
    const calls = f.calls();
    assert.ok(calls.some((args) => args.includes('down') && !args.includes('-v')), 'the container this script started is removed, its volume kept');
    assert.ok(calls.findIndex((args) => args.includes('down')) > calls.findIndex((args) => args.includes('up')));
});

test("a reused Postgres whose address the host routes off the bridge is refused and left running", async (t) => {
    const f = await fixture(t, 'healthy', 1, 'warp');
    const ran = await f.run();
    assert.equal(ran.code, 1);
    assert.match(ran.output, /through CloudflareWARP/);
    assert.match(ran.output, /already running, so it is left alone/);
    assert.ok(f.calls().every((args) => !args.includes('up') && !args.includes('down') && !args.includes('stop')));
});

test("a Postgres routed through its own bridge passes, after one route lookup", async (t) => {
    const f = await fixture(t, 'healthy');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
    assert.deepEqual(f.ipCalls().filter((args) => args.includes('route')), [['-o', 'route', 'get', '172.30.0.2']]);
});

test("a host without the container's bridge (Docker Desktop) is not held to the route", async (t) => {
    const f = await fixture(t, 'healthy', 1, 'none');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
});

test("COFFRE_POSTGRES_SUBNET adds the subnet file to compose's files", async (t) => {
    const f = await fixture(t, 'healthy');
    const ran = await f.run(f.port, { COFFRE_POSTGRES_SUBNET: '10.77.0.0/24', COMPOSE_FILE: '' });
    assert.equal(ran.code, 0, ran.output);
    const files = readFileSync(join(f.dir, 'compose-files'), 'utf8').trim().split('\n');
    assert.ok(files.every((value) => value === 'docker-compose.yml:docker-compose.subnet.yml'), files.join());
    const plain = await fixture(t, 'healthy');
    assert.equal((await plain.run(plain.port, { COMPOSE_FILE: '' })).code, 0);
    assert.ok(readFileSync(join(plain.dir, 'compose-files'), 'utf8').trim().split('\n').every((value) => value === ''), 'no subnet asked, compose files untouched');
});
