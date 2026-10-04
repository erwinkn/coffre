import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError, createClient } from '../src/index.ts';

function recording(reply: () => Response = () => Response.json({ ok: true })) {
  const requests: { method: string; url: string; headers: Headers; body: string }[] = [];
  const client = createClient({
    url: 'https://coffre.acme.example/',
    headers: () => ({ authorization: 'Bearer t' }),
    transport: async (request) => {
      requests.push({
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: await request.text(),
      });
      return reply();
    },
  });
  return { client, requests };
}

test('a path becomes one named segment per level', async () => {
  const { client, requests } = recording();
  await client.secrets.history('market/prod/DATABASE_URL');
  await client.secrets.list('market/prod');
  assert.deepEqual(
    requests.map((request) => `${request.method} ${request.url}`),
    [
      'GET https://coffre.acme.example/api/secrets/market/prod/DATABASE_URL/versions',
      'GET https://coffre.acme.example/api/secrets/market/prod',
    ],
  );
  assert.equal(requests[0].headers.get('authorization'), 'Bearer t');
});

test('a GET sends its input as the query, anything else as a JSON body', async () => {
  const { client, requests } = recording();
  await client.audit.list({ path: 'market/prod', limit: 20 });
  await client.secrets.set('market/prod', { A: '1', OLD: null });
  assert.equal(requests[0].url, 'https://coffre.acme.example/api/audit?path=market%2Fprod&limit=20');
  assert.equal(requests[0].body, '');
  assert.equal(requests[1].method, 'PATCH');
  assert.equal(requests[1].headers.get('content-type'), 'application/json');
  assert.deepEqual(JSON.parse(requests[1].body), { A: '1', OLD: null });
});

test('reveal is a POST that names the path in the body', async () => {
  const { client, requests } = recording();
  await client.secrets.reveal('market/prod/DATABASE_URL');
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].url, 'https://coffre.acme.example/api/reveals');
  assert.deepEqual(JSON.parse(requests[0].body), { path: 'market/prod/DATABASE_URL' });
});

test('member ids are encoded as one segment', async () => {
  const { client, requests } = recording();
  await client.access.set('user:ada@acme.example', { market: 'developer' });
  assert.equal(requests[0].url, 'https://coffre.acme.example/api/access/user%3Aada%40acme.example');
});

test('an error answer throws a CoffreError with its code and message', async () => {
  const { client } = recording(() =>
    Response.json({ error: 'forbidden', message: 'you need secret.write on market/prod' }, { status: 403 }),
  );
  await assert.rejects(client.secrets.set('market/prod', { A: '1' }), (error) => {
    assert.ok(error instanceof CoffreError);
    assert.equal(error.status, 403);
    assert.equal(error.code, 'forbidden');
    assert.equal(error.message, 'you need secret.write on market/prod');
    return true;
  });
});

test('an error that is not JSON still throws with its status', async () => {
  const { client } = recording(() => new Response('<html>', { status: 502 }));
  await assert.rejects(client.me(), { name: 'CoffreError', status: 502, code: 'http_error' });
});
