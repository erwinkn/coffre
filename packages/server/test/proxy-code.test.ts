// Code's proxy items as the Proxy tab reads them (docs/design/proxy-ui.md, section 6): each
// in the shape of a UI definition, and, where code's allow list matches otherwise than the
// tab's, saying how (`allowAs`), which the tab's preview follows.
import test from 'node:test';
import assert from 'node:assert/strict';

import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { proxyCodeOf } from '../src/proxy-code.ts';

const itemsOf = (credentials: Parameters<typeof credentialProxy>[0]['credentials']) => {
  const items = proxyCodeOf([credentialProxy({ credentials })])?.items ?? [];
  return Object.fromEntries(items.map((item) => [item.definition.name, item]));
};

test("a code route's allow list says how it matches: as code, as before 0.16, or with no method at all", () => {
  const inject = header('authorization', 'Bearer {KEY}');
  const items = itemsOf({
    open: { upstream: 'https://api.example.com', inject },
    modern: { upstream: 'https://api.example.com', inject, allow: [{ methods: ['GET'], path: '/files/' }] },
    legacy: { upstream: 'https://api.example.com', inject, methods: ['GET'], paths: ['/files/*'] },
    none: { upstream: 'https://api.example.com', inject, methods: [] },
    pathless: { upstream: 'https://api.example.com', inject, methods: ['post', 'PROPFIND'], paths: [] },
  });
  assert.equal(items.open?.allowAs, null);
  assert.deepEqual(items.modern?.allowAs, { from: 'code', methods: null });
  assert.deepEqual(items.legacy?.allowAs, { from: 'legacy', methods: ['GET'] });
  // `methods: []` took no method before 0.16; the tab's `methods: []` is any, so the item says so apart.
  assert.deepEqual(items.none?.allowAs, { from: 'legacy', methods: [] });
  assert.deepEqual(items.none?.definition.kind === 'route' && items.none.definition.allow, [{ methods: [], path: '/' }]);
  // `paths: []` leaves no allow entry, so its methods, which still answer first (405), live in `allowAs` alone.
  assert.deepEqual(items.pathless?.definition.kind === 'route' && items.pathless.definition.allow, []);
  assert.deepEqual(items.pathless?.allowAs, { from: 'legacy', methods: ['POST', 'PROPFIND'] });
});
