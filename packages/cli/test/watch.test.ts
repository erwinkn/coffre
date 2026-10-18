import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';

import { interval, replaceFile, watch } from '../src/watch.ts';
import { signedInWithToken } from './fakes.ts';

function scratch(t: TestContext): string {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-watch-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('replaceFile writes a file only you can read, whole, and leaves one that already says exactly that', (t) => {
  const dir = scratch(t);
  const file = join(dir, '.env');
  assert.equal(replaceFile(file, 'A=1\n'), true);
  assert.equal(readFileSync(file, 'utf8'), 'A=1\n');
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(replaceFile(file, 'A=1\n'), false);
  assert.equal(replaceFile(file, 'A=2\n'), true);
  assert.equal(readFileSync(file, 'utf8'), 'A=2\n');
  // A file others could read is replaced, though it says the same.
  chmodSync(file, 0o644);
  assert.equal(replaceFile(file, 'A=2\n'), true);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(dir), ['.env'], 'nothing left beside it');
  assert.throws(() => replaceFile(join(dir, 'nowhere', '.env'), 'A=1\n'), /ENOENT/);
  assert.deepEqual(readdirSync(dir), ['.env']);
});

test('--interval takes seconds, minutes or hours, from five seconds to a day', () => {
  assert.deepEqual(['60', '60s', '5m', '1h', '24h'].map(interval), [60_000, 60_000, 300_000, 3_600_000, 86_400_000]);
  // Past 2^31 - 1 ms, Node would fire at once: 600h would poll without pause.
  for (const wrong of ['4s', '0', '1d', '-5', '1.5m', '', 'm', '25h', '600h', '86401']) assert.throws(() => interval(wrong), /--interval takes a duration from 5s to 24h/);
});

/**
 * A watch over scripted versions, until they run out: what it read, wrote,
 * ran and said, and how long it waited. Each read is of the version last
 * asked, unless `readAs` says what the next reads saw instead.
 */
async function rounds(t: TestContext, versions: (string | Error)[], onChange: string | null = null, readAs: string[] = []) {
  const dir = scratch(t);
  const file = join(dir, '.env');
  const hooks = join(dir, 'hooks');
  const seen = { reads: 0, waits: [] as number[], said: [] as string[] };
  const stop = new Error('stop');
  let asked = '';
  const ran = watch({
    version: async () => {
      const next = versions.shift()!;
      if (next instanceof Error) throw next;
      return (asked = next);
    },
    read: async () => ({ text: `VERSION=${++seen.reads}\n`, version: readAs.shift() ?? asked }),
    file,
    intervalMs: 60_000,
    onChange: onChange?.replace('$HOOKS', hooks) ?? null,
    say: (line) => seen.said.push(line),
    wait: async (ms) => {
      seen.waits.push(ms);
      if (versions.length === 0) throw stop;
    },
  });
  await assert.rejects(ran, stop);
  return { ...seen, path: file, file: readFileSync(file, 'utf8'), hooks: existsSync(hooks) ? readFileSync(hooks, 'utf8') : '' };
}

test('a watch reads once a version is new, runs the hook after each new file, and waits its interval', async (t) => {
  const watched = await rounds(t, ['a', 'a', 'b', 'b', 'c'], 'echo ran >> "$HOOKS"');
  assert.equal(watched.reads, 3);
  assert.equal(watched.file, 'VERSION=3\n');
  assert.equal(watched.hooks, 'ran\nran\nran\n');
  assert.deepEqual(watched.waits, Array(5).fill(60_000));
});

test('a watch remembers the version of what it read: a change undone after the read is read again', async (t) => {
  // Asked A, KEY archived; it is unarchived before the read, which sees B; archived again, the version is A once more.
  const watched = await rounds(t, ['A', 'A', 'A'], null, ['B']);
  assert.equal(watched.reads, 2, 'A again is not what was read');
  assert.equal(watched.file, 'VERSION=2\n');
});

test('a failed round keeps the file, says why, and waits twice as long each time, up to 15 minutes', async (t) => {
  const down = new Error('coffre.test is unreachable');
  const watched = await rounds(t, ['a', down, down, down, down, down, 'a', 'b'], 'exit 3');
  assert.equal(watched.reads, 2, 'the version it had before the failures is not read again');
  assert.equal(watched.file, 'VERSION=2\n');
  assert.deepEqual(watched.waits.map((ms) => ms / 60_000), [1, 2, 4, 8, 15, 15, 1, 1]);
  assert.deepEqual(watched.said, [
    `wrote ${watched.path}`,
    '--on-change exited with 3',
    ...[2, 4, 8, 15, 15].map((minutes) => `coffre.test is unreachable; ${watched.path} keeps what it had, and coffre asks again in ${minutes}m`),
    `wrote ${watched.path}`,
    '--on-change exited with 3',
  ]);
});

test('a first round that fails ends the watch, as an export would: there is no file to keep', async () => {
  const refused = new Error('forbidden: you need secret.read on market/prod');
  await assert.rejects(
    watch({ version: async () => { throw refused; }, read: async () => assert.fail('nothing is read'), file: '/nowhere/.env', intervalMs: 60_000, onChange: null, say: () => assert.fail('nothing to say') }),
    refused,
  );
});

test('coffre export --watch writes the file, then runs the hook; --output-file alone writes it once; each says what it left out', async (t) => {
  const dir = scratch(t);
  const asked: string[] = [];
  const server = createServer((request, response) => {
    asked.push(`${request.method} ${request.url}`);
    const body = request.url === '/api/projects/market/prod/version' ? { version: 'v1' } : { operationId: 'op', values: { B: 'two', A: 'one' }, sensitive: ['PRIVATE'], version: 'v1' };
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  signedInWithToken(dir, origin, 'coffre_svc_' + 'x'.repeat(40));
  const coffre = (args: string[]) =>
    spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'export', 'market/prod', ...args], {
      cwd: dir,
      env: { ...process.env, HOME: dir, USERPROFILE: dir },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

  const exporting = coffre(['--output-file', 'once.env']);
  let said = '';
  exporting.stderr.setEncoding('utf8').on('data', (data: string) => (said += data));
  const [code] = await once(exporting, 'close');
  assert.equal(code, 0);
  assert.match(said, /^coffre: left out, sensitive, which nobody is handed: PRIVATE /);
  assert.equal(readFileSync(join(dir, 'once.env'), 'utf8'), 'A=one\nB=two\n');
  assert.equal(statSync(join(dir, 'once.env')).mode & 0o777, 0o600);
  assert.deepEqual(asked.splice(0), ['POST /api/reveals']);

  const watching = coffre(['--output-file', '.env', '--watch', '--on-change', 'echo ran > hooked']);
  t.after(() => watching.kill());
  let stderr = '';
  watching.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  for (let waited = 0; !existsSync(join(dir, 'hooked')); waited += 50) {
    assert.ok(waited < 10_000, `the hook ran: ${stderr}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(readFileSync(join(dir, '.env'), 'utf8'), 'A=one\nB=two\n');
  assert.equal(statSync(join(dir, '.env')).mode & 0o777, 0o600);
  assert.deepEqual(asked, ['GET /api/projects/market/prod/version', 'POST /api/reveals']);
  assert.match(stderr, /^coffre: keeping \.env current with market\/prod; each read is in the audit log under your name, and asking whether to read is not\ncoffre: left out, sensitive, which nobody is handed: PRIVATE .*\ncoffre: wrote \.env\n/);
  assert.ok(!stderr.includes('one') && !stderr.includes('two'));
});

test('coffre export says which flags go together before it asks anything', async (t) => {
  const dir = scratch(t);
  const refusals: [string[], RegExp][] = [
    [['--watch'], /--watch keeps a file current: name it, --output-file <file>/],
    [['--interval', '5m'], /--interval and --on-change are for --watch/],
    [['--on-change', 'true', '--output-file', '.env'], /--interval and --on-change are for --watch/],
    [['--output-file', '.env', '--watch', '--interval', '1s'], /--interval takes a duration from 5s to 24h/],
  ];
  for (const [args, message] of refusals) {
    const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'export', 'market/prod', ...args], {
      cwd: dir,
      env: { ...process.env, HOME: dir, USERPROFILE: dir },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
    const [code] = await once(child, 'close');
    assert.equal(code, 1, args.join(' '));
    assert.match(stderr, message);
  }
});

test("coffre export --watch refuses a CI run's saved credential, which lasts five minutes, before it asks anything", async (t) => {
  const dir = scratch(t);
  const origin = 'http://127.0.0.1:9';
  mkdirSync(join(dir, '.coffre'), { mode: 0o700 });
  const session = { mode: 'signin', kind: 'run', token: 'coffre_run_' + 'x'.repeat(40), expiresAt: new Date(Date.now() + 300_000).toISOString(), obtainedAt: new Date().toISOString() };
  writeFileSync(join(dir, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: origin, instances: { [origin]: session } }), { mode: 0o600 });
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'export', 'market/prod', '--output-file', '.env', '--watch'], {
    cwd: dir,
    env: { ...process.env, HOME: dir, USERPROFILE: dir },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  assert.equal(code, 1);
  assert.match(stderr, /--watch outlives a CI run's credential, which lasts five minutes/);
  assert.ok(!existsSync(join(dir, '.env')));
});
