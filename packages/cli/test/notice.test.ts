import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { DAY_MS, dailyNotice, noticeFor, type Checked } from '../src/notice.ts';

const ORIGIN = 'https://coffre.example';
const behind = { version: '0.1.12', migrations: { applied: 1, known: ['0000_baseline', '0001_remove_syncs'] } };
const current = { ...behind, migrations: { ...behind.migrations, applied: 2 } };

function memory(initial: Checked = {}) {
  let checked = initial;
  return { read: () => checked, write: (next: Checked) => (checked = next), get: () => checked };
}

test('a database behind its code is said in one line, with what to run', () => {
  assert.equal(
    noticeFor(ORIGIN, behind),
    'https://coffre.example runs coffre 0.1.12, and 1 database migration is pending (0001_remove_syncs): run `coffre migrate`',
  );
});

test('nothing is said when the database is current, or to anyone but an owner', () => {
  assert.equal(noticeFor(ORIGIN, current), null);
  assert.equal(noticeFor(ORIGIN, null), null);
});

test('the notice is asked for at most once a day per instance', async () => {
  const checked = memory();
  let asked = 0;
  const me = async () => {
    asked++;
    return { instance: behind };
  };
  const now = Date.parse('2026-10-04T08:00:00Z');
  assert.match((await dailyNotice(ORIGIN, now, checked, me))!, /run `coffre migrate`/);
  assert.equal(await dailyNotice(ORIGIN, now + DAY_MS - 1, checked, me), null, 'not again within the day');
  assert.equal(asked, 1, 'and without asking');
  assert.match((await dailyNotice(ORIGIN, now + DAY_MS, checked, me))!, /pending/, 'a day later, again');
  assert.equal(await dailyNotice('https://other.example', now, checked, async () => ({ instance: current })), null);
  assert.deepEqual(Object.keys(checked.get()).sort(), ['https://coffre.example', 'https://other.example']);
});

test('an instance that cannot be asked says nothing, and is asked again next time', async () => {
  const checked = memory();
  assert.equal(await dailyNotice(ORIGIN, 0, checked, async () => Promise.reject(new Error('offline'))), null);
  assert.deepEqual(checked.get(), {});
});

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

/** `coffre projects`, signed in to `origin` as a person, with `home` kept between runs. */
function projects(origin: string, home: string): Promise<{ code: number | null; stderr: string }> {
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'projects'], {
    env: { PATH: process.env.PATH, HOME: home },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  return new Promise((resolve) => child.on('close', (code) => resolve({ code, stderr })));
}

test('a command run by an owner says so on stderr, once a day; and nothing once the database is current', async () => {
  let instance = behind;
  const server = createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    if (request.url === '/api/me') response.end(JSON.stringify({ principal: { type: 'user', id: 'admin@acme.example' }, instance }));
    else response.end(JSON.stringify({ projects: [] }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const home = mkdtempSync(join(tmpdir(), 'coffre-notice-'));
  try {
    mkdirSync(join(home, '.coffre'), { mode: 0o700 });
    writeFileSync(
      join(home, '.coffre', 'credentials.json'),
      JSON.stringify({ version: 2, current: origin, instances: { [origin]: { mode: 'signin', token: 'session', obtainedAt: '2026-10-04T08:00:00Z' } } }),
      { mode: 0o600 },
    );
    const first = await projects(origin, home);
    assert.equal(first.code, 0, first.stderr);
    assert.match(first.stderr, /1 database migration is pending \(0001_remove_syncs\): run `coffre migrate`/);
    assert.equal((await projects(origin, home)).stderr, '', 'once a day');

    instance = current;
    rmSync(join(home, '.coffre', 'checked.json'));
    assert.equal((await projects(origin, home)).stderr, '', 'nothing pending, nothing said');
  } finally {
    server.close();
    rmSync(home, { recursive: true, force: true });
  }
});
