import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { formatDotenv, formatShellExports, parseDotenv } from '@coffre/core/dotenv';

import { githubEnvironment, githubMasks } from '../src/github-env.ts';

const awkward = {
  EMPTY: '',
  PEM: '-----BEGIN KEY-----\nline one\r\nline two\n-----END KEY-----\n',
  QUOTES: '"single\' and double" = %25 %0A $HOME `echo no`',
  FRAMING: 'coffre_delimiter\nEOF\nEND\nVALUE=wrong\nOTHER<<delimiter\n',
  COMMAND: 'before\n::error::not a command\n%0A::stop-commands::not-a-command',
  CR: 'last character is CR\r',
};

/** Read the runner's heredoc grammar. Windows ReadLine strips CRLF; Linux
 * strips LF only. Keep the exact substring between the framing newlines.
 * https://github.com/actions/runner/blob/main/src/Runner.Worker/FileCommandManager.cs
 */
function readEnvironment(text: string, newline = '\n'): Record<string, string> {
  let offset = 0;
  const line = () => {
    const start = offset;
    const end = text.indexOf('\n', start);
    assert.ok(end !== -1, 'unterminated environment record');
    offset = end + 1;
    return { start, text: text.slice(start, newline === '\r\n' && text[end - 1] === '\r' ? end - 1 : end) };
  };
  const values: Record<string, string> = {};
  while (offset < text.length) {
    const header = line().text;
    const [key, delimiter] = header.split('<<');
    assert.ok(key && delimiter, 'expected a heredoc header');
    const start = offset;
    let next = line();
    while (next.text !== delimiter) next = line();
    values[key] = text.slice(start, next.start - newline.length);
  }
  return values;
}

test('GitHub environment records preserve every byte, with distinct safe delimiters and either host newline', () => {
  for (const newline of ['\n', '\r\n']) {
    const text = githubEnvironment(Object.entries(awkward), undefined, newline);
    assert.deepEqual(readEnvironment(text, newline), awkward);
    const delimiters = [...text.matchAll(/^\w+<<(coffre_[\w-]+)/gm)].map((match) => match[1]);
    assert.equal(new Set(delimiters).size, Object.keys(awkward).length);
    for (const delimiter of delimiters) for (const value of Object.values(awkward)) assert.ok(!value.includes(delimiter));
  }
  const choices = ['coffre_delimiter', 'EOF', 'fresh'];
  const text = githubEnvironment([['FRAMING', awkward.FRAMING]], () => choices.shift()!);
  assert.ok(text.startsWith('FRAMING<<fresh\n'));
  assert.deepEqual(readEnvironment(text), { FRAMING: awkward.FRAMING });
});

test('GitHub masks escape percent, CR and LF, and mask each nonempty line as well as the whole value', () => {
  assert.equal(githubMasks([['K', 'a%0A\r\nb\nc\r']]), '::add-mask::a%250A%0D%0Ab%0Ac%0D\n::add-mask::a%250A\n::add-mask::b\n::add-mask::c\n');
  assert.equal(githubMasks([['EMPTY', '']]), '');
  const commands = githubMasks(Object.entries(awkward)).trimEnd().split('\n');
  assert.ok(commands.every((line) => line.startsWith('::add-mask::')));
});

test('GitHub refuses invalid entries and keys the runner cannot set', () => {
  for (const key of ['NOT-A-NAME', 'NODE_OPTIONS']) {
    assert.throws(() => githubEnvironment([[key, 'private']]), /valid variable name|cannot be set/);
  }
  assert.throws(() => githubEnvironment([['K', 'a\0b']]), /NUL/);
  assert.deepEqual(readEnvironment(githubEnvironment([['GITHUB_TOKEN', 'a literal bearer']])), { GITHUB_TOKEN: 'a literal bearer' });
});

test('existing dotenv round-trips multiline and command-shaped values; shell export executes none of them', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-export-shell-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const marker = join(dir, 'injected');
  const values = { ...awkward, INJECTION: `$(touch ${marker})\n'; touch ${marker}; #\n\`touch ${marker}\``, QUOTED_INJECTION: `'$(touch ${marker})` };
  const entries = Object.entries(values);
  const parsed = parseDotenv(formatDotenv(entries));
  assert.deepEqual(parsed.problems, []);
  assert.deepEqual(Object.fromEntries(parsed.entries.map(({ key, value }) => [key, value])), values);
  const code = `process.stdout.write(JSON.stringify(Object.fromEntries(${JSON.stringify(Object.keys(values))}.map(key => [key, process.env[key]]))))`;
  const result = execFileSync('sh', ['-c', `${formatShellExports(entries)}\nexec "$1" -e '${code}'`, 'coffre-export-test', process.execPath], { encoding: 'utf8' });
  assert.deepEqual(JSON.parse(result), values);
  assert.equal(existsSync(marker), false, 'the shell executed secret text');
});

const TOKEN = `coffre_cli_${'s'.repeat(43)}`;

async function fixture(t: test.TestContext, values: Record<string, string> = awkward) {
  const directory = mkdtempSync(join(tmpdir(), 'coffre-export-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const envFile = join(directory, 'github-env');
  writeFileSync(envFile, 'EXISTING<<initial\nkept\ninitial\n');
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/api/reveals');
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ values }));
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  return {
    envFile,
    requests: () => requests,
    async run(format: string, path: string | null = envFile) {
      const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_') && key !== 'GITHUB_ENV'));
      Object.assign(env, { COFFRE_STATE_DIR: directory });
      if (path !== null) env.GITHUB_ENV = path;
      // As the Action runs it: the token on stdin, never in an argument or a variable.
      const session = ['--url', `http://127.0.0.1:${address.port}`, '--token-file', '-'];
      const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, ...session, 'export', 'market/prod', '--format', format], { env, stdio: ['pipe', 'pipe', 'pipe'], timeout: 10_000 });
      // A run that stops before reading stdin closes it: not this test's failure.
      child.stdin.on('error', () => {});
      child.stdin.end(`${TOKEN}\n`);
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8').on('data', (data: string) => stdout += data);
      child.stderr.setEncoding('utf8').on('data', (data: string) => stderr += data);
      const [code] = await once(child, 'close');
      return { code, stdout, stderr };
    },
  };
}

test('CLI GitHub export appends to the environment file and prints only all its masks', async (t) => {
  const setup = await fixture(t);
  const run = await setup.run('github');
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout, githubMasks(Object.entries(awkward).sort(([a], [b]) => a.localeCompare(b))));
  assert.equal(run.stderr, '');
  assert.deepEqual(readEnvironment(readFileSync(setup.envFile, 'utf8')), { EXISTING: 'kept', ...awkward });
  assert.equal(setup.requests(), 1);
});

test('CLI refuses GitHub export without GITHUB_ENV before it reads a secret', async (t) => {
  const setup = await fixture(t);
  for (const path of [null, '']) {
    const run = await setup.run('github', path);
    assert.equal(run.code, 1);
    assert.match(run.stderr, /requires GITHUB_ENV/);
    assert.equal(run.stdout, '');
  }
  assert.equal(setup.requests(), 0);
});

test('CLI masks before a write failure and never appends a partial invalid batch', async (t) => {
  const setup = await fixture(t);
  const run = await setup.run('github', `${setup.envFile}/missing`);
  assert.equal(run.code, 1);
  assert.equal(run.stdout, githubMasks(Object.entries(awkward).sort(([a], [b]) => a.localeCompare(b))));
  assert.ok(!run.stderr.includes(awkward.PEM));
  const invalid = await fixture(t, { GOOD: 'private', NODE_OPTIONS: 'bad' });
  const before = readFileSync(invalid.envFile, 'utf8');
  const refused = await invalid.run('github');
  assert.equal(refused.code, 1);
  assert.equal(readFileSync(invalid.envFile, 'utf8'), before);
  assert.ok(refused.stdout.startsWith('::add-mask::private\n'));
});

test('CLI JSON, dotenv and shell exports preserve awkward values', async (t) => {
  const setup = await fixture(t);
  for (const format of ['json', 'dotenv', 'shell']) {
    const run = await setup.run(format);
    assert.equal(run.code, 0, run.stderr);
    if (format === 'json') assert.deepEqual(JSON.parse(run.stdout), awkward);
    else if (format === 'dotenv') assert.deepEqual(Object.fromEntries(parseDotenv(run.stdout).entries.map(({ key, value }) => [key, value])), awkward);
    else assert.equal(run.stdout, formatShellExports(Object.entries(awkward).sort(([a], [b]) => a.localeCompare(b))));
  }
});
