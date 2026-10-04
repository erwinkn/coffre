import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { github, signin } from '@coffre/core/identity';
import { migrateDatabase } from '@coffre/db/migrate';

import { answer } from './start-fixture.ts';
import { serveWith, type Server } from '../src/node-server.ts';
import { testVault } from './api-fixture.ts';

const scratch = mkdtempSync(join(tmpdir(), 'coffre-node-server-'));
const database = `file:${join(scratch, 'coffre.db')}`;
const statics = join(scratch, 'client');
mkdirSync(join(statics, '_coffre', 'assets'), { recursive: true });
writeFileSync(join(statics, '_coffre', 'assets', 'main-abc123.js'), 'console.log(1)');
writeFileSync(join(statics, 'outside.txt'), 'not under _coffre');

/** Pages that answer in two chunks, with two cookies, and say what URL they saw. */
const ui = {
  fetch: async (request: Request) =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(`<p>${request.url}</p>`));
          controller.enqueue(new TextEncoder().encode('<p>second</p>'));
          controller.close();
        },
      }),
      { headers: [['content-type', 'text/html'], ['set-cookie', 'a=1; Path=/'], ['set-cookie', 'b=2; Path=/']] },
    ),
};

let server: Server;

test.before(async () => {
  await migrateDatabase(database);
  server = await serveWith(
    {
      publicUrl: 'http://127.0.0.1:3089',
      database,
      vault: testVault(['admin@acme.example']),
      auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }),
      auditChainKey: Buffer.alloc(32, 1).toString('base64'),
    },
    { port: 0, schedule: false },
    (request, runtime, sourceIp) => answer(request, runtime, ui, sourceIp),
    statics,
  );
});

test.after(async () => {
  await server?.close();
  rmSync(scratch, { recursive: true, force: true });
});

/** A raw request, so the path and Host header go out exactly as written. */
function raw(path: string, headers: Record<string, string> = {}, method = 'GET') {
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>(
    (resolve, reject) => {
      const req = request(server.url, { path, method, headers }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      });
      req.on('error', reject);
      req.end();
    },
  );
}

test('health answers, with the security headers', async () => {
  const response = await raw('/livez');
  assert.equal(response.status, 200);
  assert.equal(response.body, '{"ok":true}');
  assert.equal(response.headers['x-frame-options'], 'DENY');
});

test('pages stream through, on the public URL whatever Host says, with every cookie', async () => {
  const response = await raw('/projects?x=1', { host: 'evil.example' });
  assert.equal(response.status, 200);
  assert.equal(response.body, '<p>http://127.0.0.1:3089/projects?x=1</p><p>second</p>');
  assert.deepEqual(response.headers['set-cookie'], ['a=1; Path=/', 'b=2; Path=/']);
  assert.match(String(response.headers['content-security-policy']), /script-src 'self' 'nonce-/);

  const head = await raw('/projects', {}, 'HEAD');
  assert.equal(head.status, 200);
  assert.equal(head.body, '');
});

test('the UI\'s files are served from _coffre/, and nothing beside them', async () => {
  const asset = await raw('/_coffre/assets/main-abc123.js');
  assert.equal(asset.status, 200);
  assert.equal(asset.body, 'console.log(1)');
  assert.equal(asset.headers['cache-control'], 'public, max-age=31536000, immutable');
  assert.equal(asset.headers['content-type'], 'text/javascript; charset=utf-8');

  // Not a file: the pages answer, as for any other path.
  for (const path of ['/_coffre/%2e%2e/outside.txt', '/_coffre/assets/missing.js', '/_coffre/assets/']) {
    const response = await raw(path);
    assert.doesNotMatch(response.body, /not under _coffre|console\.log/, path);
    assert.equal(response.headers['cache-control'] === 'public, max-age=31536000, immutable', false, path);
  }
});

test('the API answers as the API, and refuses without a credential', async () => {
  const response = await raw('/api/me');
  assert.equal(response.status, 401);
  assert.equal(JSON.parse(response.body).error, 'unauthenticated');
});


test('a request target cannot replace the public origin or satisfy its Origin check', async () => {
  for (const path of ['//evil.example/auth/signout', '/\\evil.example/auth/signout', 'https://evil.example/auth/signout']) {
    const response = await raw(path, { origin: 'https://evil.example' }, 'POST');
    assert.equal(response.status, 400, path);
    assert.equal(response.body, 'Invalid request target', path);
  }
  const crossOrigin = await raw('/auth/signout', { origin: 'https://evil.example' }, 'POST');
  assert.equal(crossOrigin.status, 403);
  const sameOrigin = await raw('/auth/signout', { origin: 'http://127.0.0.1:3089' }, 'POST');
  assert.equal(sameOrigin.status, 303);
});
