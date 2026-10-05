import test from 'node:test';
import assert from 'node:assert/strict';

import { createMemoryHistory, createRootRoute, createRoute, createRouter } from '@tanstack/react-router';

import { parseSearch, stringifySearch, stringsOf } from '../src/lib/search.ts';

// The router's search keeps every value a string (`lib/search.ts`), so the
// consent page reads an MCP client's parameters as sent: its validateSearch
// is `stringsOf` (options.ts, which loads pages, so not from Node).

test('every value is read as the URL has it, and written back the same', () => {
  const sent = '?state=1e5&code=0123&detail=1&flag=true&empty=&scope=browse+write';
  const search = parseSearch(sent);
  assert.deepEqual(search, { state: '1e5', code: '0123', detail: '1', flag: 'true', empty: '', scope: 'browse write' });
  assert.equal(stringifySearch(search), sent);
  assert.equal(stringifySearch({ tab: undefined }), '');
});

test('a sign-in redirect carries where to resume, and gives it back whole', () => {
  const next = 'https://coffre.test/oauth/authorize?client_id=c&state=1e5&redirect_uri=http%3A%2F%2F127.0.0.1%3A33419%2Fcallback';
  assert.deepEqual(parseSearch(stringifySearch({ next })), { next });
});

test("the consent page takes the client's parameters as strings, whatever they look like", () => {
  const search = parseSearch('?client_id=c&state=1e5&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  assert.deepEqual(stringsOf(search), {
    client_id: 'c', state: '1e5', response_type: 'code', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  });
  assert.deepEqual(stringsOf({ state: '1e5', page: 2, open: true }), { state: '1e5' });
});

test('a router with them keeps state=1e5 as 1e5, through its search and the URL it builds', async () => {
  const root = createRootRoute();
  const authorize = createRoute({ getParentRoute: () => root, path: '/oauth/authorize', validateSearch: stringsOf });
  const href = '/oauth/authorize?client_id=c&state=1e5&scope=browse+write';
  const router = createRouter({
    routeTree: root.addChildren([authorize]),
    history: createMemoryHistory({ initialEntries: [href] }),
    parseSearch,
    stringifySearch,
  });
  await router.load();
  assert.deepEqual(router.state.location.search, { client_id: 'c', state: '1e5', scope: 'browse write' });
  assert.equal(router.buildLocation({ to: '/oauth/authorize', search: true }).href, href);
});
