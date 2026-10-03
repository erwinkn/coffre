import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const script = resolve(import.meta.dirname, 'reserve-postgres-port.sh');

function run(t, reserved, ci = 'true') {
    const dir = mkdtempSync(join(tmpdir(), 'coffre-postgres-port-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    writeFileSync(join(dir, 'sudo'), '#!/bin/sh\nexec "$@"\n', { mode: 0o755 });
    writeFileSync(join(dir, 'sysctl'), `#!${process.execPath}
import { writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
if (args[0] === '-n') console.log(${JSON.stringify(reserved)});
else if (args[0] === '-w') writeFileSync(${JSON.stringify(join(dir, 'written'))}, args[1]);
else throw new Error('unexpected sysctl command');
`, { mode: 0o755 });
    const ran = spawnSync('/bin/bash', [script], {
        env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, GITHUB_ACTIONS: ci },
        encoding: 'utf8', timeout: 10_000,
    });
    const written = join(dir, 'written');
    return { ...ran, reservation: existsSync(written) ? readFileSync(written, 'utf8') : null };
}

test('CI reserves only the Postgres port and preserves other applications\' reservations', (t) => {
    for (const [before, after] of [['', '55432'], ['6000-6010,7000', '6000-6010,7000,55432']]) {
        const ran = run(t, before);
        assert.equal(ran.status, 0, ran.stderr);
        assert.equal(ran.reservation, `net.ipv4.ip_local_reserved_ports=${after}`);
    }
});

test('an existing reservation, including a containing range, is left alone', (t) => {
    for (const before of ['55432', '5000,55430-55435,65000']) {
        const ran = run(t, before);
        assert.equal(ran.status, 0, ran.stderr);
        assert.equal(ran.reservation, null);
    }
});

test('the reservation script refuses to change a developer host outside CI', (t) => {
    const ran = run(t, '', '');
    assert.equal(ran.status, 1);
    assert.equal(ran.reservation, null);
    assert.match(ran.stderr, /only for GitHub Actions runners/);
});
