// `coffre freeze` and `coffre unfreeze`: each one request, the target as the
// person typed it, `service:<name>` as people name a service account.
import test from 'node:test';
import assert from 'node:assert/strict';

import { createClient } from '@coffre/client';

import { freeze, unfreeze } from '../src/freeze.ts';
import { UsageError } from '../src/manage.ts';

type Call = { method: string; path: string; body: unknown };

function fixture(answer: (call: Call) => unknown) {
  const calls: Call[] = [];
  const api = createClient({
    url: 'https://coffre.test',
    transport: async (request) => {
      const url = new URL(request.url);
      const text = await request.text();
      const call = { method: request.method, path: url.pathname.slice('/api'.length), body: text === '' ? undefined : JSON.parse(text) };
      calls.push(call);
      return Response.json(answer(call));
    },
  });
  const written = { out: '', err: '' };
  const io = { out: { write: (text: string) => (written.out += text) }, err: { write: (text: string) => (written.err += text), isTTY: false } };
  return { connect: () => api, calls, written, io };
}

test('freeze alone lists what is frozen, the instance first, a service account by its service: name', async () => {
  const listed = fixture(() => ({ freezes: [
    { target: 'instance', service: null, frozenAt: '2026-11-14T09:00:00.000Z' },
    { target: 'token:api-prod', service: 'token:api-prod', frozenAt: '2026-11-14T09:12:03.000Z' },
  ] }));
  await freeze(listed.connect, [], listed.io);
  assert.deepEqual(listed.calls, [{ method: 'GET', path: '/freezes', body: undefined }]);
  assert.equal(listed.written.out, 'instance  frozen since 2026-11-14T09:00:00.000Z\nservice:api-prod  frozen since 2026-11-14T09:12:03.000Z\n');

  const none = fixture(() => ({ freezes: [] }));
  await freeze(none.connect, [], none.io);
  assert.equal(none.written.out, 'Nothing is frozen\n');
});

test('freeze <target> --reason sends both, in one request, and says how to lift it', async () => {
  const { connect, calls, written, io } = fixture(() => ({ target: 'token:api-prod', frozenAt: '2026-11-14T09:12:03.000Z' }));
  await freeze(connect, ['service:api-prod', '--reason', 'leaked key'], io);
  assert.deepEqual(calls, [{ method: 'POST', path: '/freezes', body: { target: 'service:api-prod', reason: 'leaked key' } }]);
  assert.equal(written.out, 'froze service:api-prod: every use under it is refused from its next request, until `coffre unfreeze service:api-prod`\n');
});

test('freeze takes a reason with a target, and only then; nothing is sent otherwise', async () => {
  const { connect, calls, io } = fixture(() => assert.fail('nothing is sent'));
  await assert.rejects(freeze(connect, ['instance'], io), UsageError);
  await assert.rejects(freeze(connect, ['instance', '--reason', '  '], io), UsageError);
  await assert.rejects(freeze(connect, ['--reason', 'why'], io), UsageError);
  assert.deepEqual(calls, []);
});

test('unfreeze <target> lifts it, the target one path segment however it is spelled', async () => {
  const { connect, calls, written, io } = fixture(() => ({ target: 'binding:00000000-0000-4000-8000-000000000001', frozenAt: null }));
  await unfreeze(connect, ['binding:00000000-0000-4000-8000-000000000001'], io);
  assert.deepEqual(calls, [{ method: 'DELETE', path: '/freezes/binding%3A00000000-0000-4000-8000-000000000001', body: undefined }]);
  assert.equal(written.out, 'unfroze binding:00000000-0000-4000-8000-000000000001\n');
});
