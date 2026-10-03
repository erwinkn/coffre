import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { join, resolve } from 'node:path';
import test from 'node:test';

const script = resolve(import.meta.dirname, 'ensure-postgres.sh');

async function fixture(t, mode, callers = 1) {
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
    writeFileSync(localScript, readFileSync(script, 'utf8').replaceAll('55432', String(port)));
    writeFileSync(join(dir, 'scripts/postgres-port-available.mjs'), readFileSync(resolve(import.meta.dirname, 'postgres-port-available.mjs')));
    const state = JSON.stringify(dir);
    writeFileSync(join(dir, 'docker'), `#!${process.execPath}
import { appendFileSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
const dir = ${state};
const args = process.argv.slice(2);
const mode = ${JSON.stringify(mode)};
appendFileSync(dir + '/calls', JSON.stringify(args) + '\\n');
if (args.includes('port')) {
    if (mode === 'healthy' || mode === 'existing' || existsSync(dir + '/created')) console.log('0.0.0.0:${port}');
    // Before creation, allow the mocked internal probe to reach its barrier.
    else if (mode === 'cold') console.log('0.0.0.0:${port}');
    process.exit(0);
}
if (args.includes('exec')) {
    if (mode === 'healthy') process.exit(0);
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
    if (mode === 'existing' || existsSync(dir + '/created')) console.log('fixture-postgres');
    process.exit(0);
}
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
    const run = () => new Promise((resolve, reject) => {
        const child = spawn('/bin/bash', [localScript], {
            env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, COMPOSE_PROJECT_NAME: project },
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
    return { dir, run, calls: () => readFileSync(join(dir, 'calls'), 'utf8').trim().split('\n').map(JSON.parse) };
}

test('a healthy Postgres is reused without an up', async (t) => {
    const f = await fixture(t, 'healthy');
    const ran = await f.run();
    assert.equal(ran.code, 0, ran.output);
    assert.ok(f.calls().every((args) => !args.includes('up')));
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
