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

test("a binding's removal under way (a 202) is asked again, the same request, until it is done (W331)", async () => {
  const answers = [
    Response.json({ removing: { left: 300 } }, { status: 202 }),
    Response.json({ removing: { left: 72 } }, { status: 202 }),
    Response.json({ binding: { id: 'b2' }, replaced: ['b1'] }),
  ];
  const told: number[] = [];
  const requests: { method: string; url: string; type: string | null; body: string }[] = [];
  const client = createClient({
    url: 'https://coffre.acme.example',
    onRemoving: (left) => told.push(left),
    transport: async (request) => {
      requests.push({ method: request.method, url: request.url, type: request.headers.get('content-type'), body: await request.text() });
      return answers.shift()!;
    },
  });
  const input = { profile: 'github', issuer: null, claims: { repository_id: '1' }, label: null, replaces: ['b1'] } as never;
  assert.deepEqual(await client.bindings.create('token:api', input), { binding: { id: 'b2', removing: null }, replaced: ['b1'] });
  assert.equal(requests.length, 3);
  assert.deepEqual(new Set(requests.map((request) => JSON.stringify(request))).size, 1, 'each the same request');
  assert.equal(requests[0].type, 'application/json');
  assert.deepEqual(told, [300, 72]);
});

test("a server older than 0.16 says nothing of a binding's removal: its views read as none under way (review r10)", async () => {
  const view = { id: 'b1', profile: 'github', issuer: 'https://token.actions.githubusercontent.com', claims: {}, scope: null, label: null, createdAt: '2026-11-01T00:00:00.000Z', createdBy: 'ada@acme.example', lastUsedAt: null };
  const { client } = recording(() => Response.json({ bindings: [view] }));
  const [listed] = (await client.bindings.list('token:api')).bindings;
  assert.equal(listed!.removing, null);
});

test('a removal under way that asking again does not move on throws, rather than asking for ever (W331)', async () => {
  // As a request made from inside another one does, once that request has spent its calls: no further along.
  let asked = 0;
  const client = createClient({
    url: 'https://coffre.acme.example',
    transport: async () => {
      asked += 1;
      return Response.json({ removing: { left: 500 } }, { status: 202 });
    },
  });
  await assert.rejects(client.bindings.remove('token:api', 'b1'), { name: 'CoffreError', status: 202, code: 'removal_under_way' });
  assert.equal(asked, 2);
  // One that made no call, though what is left falls (credentials ending on their own): no further along either.
  let falling = 400;
  const idle = createClient({
    url: 'https://coffre.acme.example',
    transport: async () => Response.json({ removing: { left: (falling -= 1), progressed: false } }, { status: 202 }),
  });
  await assert.rejects(idle.bindings.remove('token:api', 'b1'), { name: 'CoffreError', status: 202, code: 'removal_under_way' });
  assert.equal(falling, 399, 'asked once');
  // Any other 202 is an answer like any.
  const { client: plain } = recording(() => Response.json({ queued: true }, { status: 202 }));
  assert.deepEqual(await plain.me(), { queued: true });
});

test('an error that is not JSON still throws with its status', async () => {
  const { client } = recording(() => new Response('<html>', { status: 502 }));
  await assert.rejects(client.me(), { name: 'CoffreError', status: 502, code: 'http_error' });
});

test('a success whose body is cut off throws `unreadable` with its status, never a null output', async () => {
  // The status line and the first bytes arrived; then the connection dropped.
  const cut = () =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"passkeys":[{"id":'));
          controller.error(new TypeError('terminated'));
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  const { client } = recording(cut);
  await assert.rejects(client.passkeys.list('user:ada'), { name: 'CoffreError', status: 200, code: 'unreadable', method: 'GET' });
  await assert.rejects(client.passkeys.reset('user:ada'), { name: 'CoffreError', status: 200, code: 'unreadable', method: 'DELETE' });
  // A whole JSON body still reads, `null` included.
  const { client: whole } = recording(() => Response.json(null));
  assert.equal(await whole.call('GET /me', {}), null);
});

test("a server older than 0.15 has no route for 0.15's log: it keeps 0.14's alone", async () => {
  const { client } = recording(() => Response.json({ error: 'not_found', message: 'no such route' }, { status: 404 }));
  assert.deepEqual(await client.audit.verifyTrees(), { kept: false });
  // Any other refusal is one.
  const { client: refused } = recording(() => Response.json({ error: 'forbidden', message: 'no' }, { status: 403 }));
  await assert.rejects(refused.audit.verifyTrees(), { name: 'CoffreError', status: 403 });
});
