// `coffre grant` against an instance that refuses it: a member never
// admitted is told how to admit them, by the server's reason, never its words.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { signedInWithToken } from './fakes.ts';

const TOKEN = `coffre_cli_${'s'.repeat(43)}`;

/** `coffre grant <args>` against a coffre answering every call with `status` and `body`; the calls it was sent. */
async function grant(t: test.TestContext, status: number, body: unknown, args: string[]) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-grant-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const calls: string[] = [];
  const server = createServer((req, res) => {
    req.resume().on('end', () => {
      calls.push(`${req.method} ${req.url}`);
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    });
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  signedInWithToken(home, `http://127.0.0.1:${address.port}`, TOKEN);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'grant', ...args], {
    env: { ...env, HOME: home }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000,
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  return { code, stdout, stderr, calls };
}

test("a grant to someone never admitted, 0.16's 404 `not_a_member`, says to admit them first", async (t) => {
  const refused = { error: 'not_found', message: 'token:deploy: no such member', reason: 'not_a_member' };
  const service = await grant(t, 404, refused, ['market', 'deploy', '--service', '--role', 'viewer']);
  assert.deepEqual([service.code, service.stdout, service.calls], [1, '', ['PATCH /api/access/token%3Adeploy']]);
  assert.equal(service.stderr, 'coffre: token:deploy: no such member: admit them first, `coffre admit service:deploy`\n');
  const person = await grant(t, 404, { ...refused, message: 'user:ada@acme.example: no such member' }, ['market', 'ada@acme.example', '--env', 'prod', '--role', 'viewer']);
  assert.equal(person.stderr, 'coffre: user:ada@acme.example: no such member: admit them first, `coffre admit ada@acme.example`\n');
});

test('any other refusal of a grant says no more than the server did', async (t) => {
  // Another 404, without the reason: no hint, whatever its words.
  const other = await grant(t, 404, { error: 'not_found', message: 'no such member' }, ['market', 'deploy', '--service', '--role', 'viewer']);
  assert.equal(other.stderr, 'coffre: not found: no such member\n');
  // 0.14's 409 is no longer 0.16's answer: it is said as any conflict.
  const old = await grant(t, 409, { error: 'conflict', message: 'not registered', reason: 'principal_not_registered' }, ['market', 'deploy', '--service', '--role', 'viewer']);
  assert.equal(old.stderr, 'coffre: request failed with status 409: not registered\n');
});
