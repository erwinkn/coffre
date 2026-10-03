import test from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { QueryObserver, type QueryClient } from '@tanstack/react-query';

import {
  affects,
  createQueryClient,
  FRESH_MS,
  keys,
  loadDirectory,
  loadProject,
  loadShell,
  queries,
  refresh,
} from '../src/lib/queries.ts';

const market = {
  slug: 'market',
  name: 'Market',
  archivedAt: null,
  permissions: ['grant.manage'],
  environments: [{ slug: 'dev', name: 'Dev', accessible: true, details: { archivedAt: null, secretCount: 1 } }],
  secretCount: 1,
};

const me = {
  principal: { type: 'user', id: 'ada@acme.example' },
  registered: true,
  tampered: false,
  instanceRole: 'owner',
  isRootAdmin: false,
  canReadAudit: true,
  environments: [],
};

/** A client that answers every read and counts the calls, by route. */
function fakeClient() {
  const calls: string[] = [];
  const answer = <T>(route: string, value: T) => async () => {
    calls.push(route);
    return value;
  };
  const client = {
    auth: answer('GET /auth', { mode: 'signin', signin: null, access: null }),
    me: answer('GET /me', me),
    projects: { list: answer('GET /projects', { projects: [market] }) },
    members: {
      list: async (path?: string) => {
        calls.push(path === undefined ? 'GET /members' : `GET /members?path=${path}`);
        return { members: [], removed: [] };
      },
    },
    secrets: { list: answer('GET /secrets/market/dev', { keys: [], permissions: [] }) },
  } as unknown as CoffreClient;
  return { client, calls };
}

/** Each loader a navigation runs, as the router runs them: the root's, then the page's. */
const navigate = {
  projects: (queryClient: QueryClient, client: CoffreClient) =>
    Promise.all([loadShell(queryClient, client), queryClient.fetchQuery(queries.projects(client))]),
  project: (queryClient: QueryClient, client: CoffreClient) =>
    Promise.all([loadShell(queryClient, client), loadProject(queryClient, client, 'market')]),
  users: (queryClient: QueryClient, client: CoffreClient) =>
    Promise.all([loadShell(queryClient, client), loadDirectory(queryClient, client)]),
};

/** A query a mounted component is reading, which an invalidation refetches at once. */
function onScreen(queryClient: QueryClient, options: Parameters<QueryClient['fetchQuery']>[0]) {
  const observer = new QueryObserver(queryClient, options as never);
  const stop = observer.subscribe(() => {});
  return stop;
}

test('a page asks the API once for what the shell already read', async () => {
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  await navigate.projects(queryClient, client);
  assert.deepEqual(calls.sort(), ['GET /auth', 'GET /me', 'GET /projects']);
});

test('a second navigation within the fresh window makes no API call', async () => {
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  await navigate.projects(queryClient, client);
  await navigate.project(queryClient, client);
  const settled = calls.length;

  await navigate.projects(queryClient, client);
  await navigate.project(queryClient, client);
  assert.equal(calls.length, settled);
});

test('past the fresh window, a navigation reads again', async (t) => {
  t.mock.timers.enable({ apis: ['Date'] });
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  await navigate.projects(queryClient, client);
  calls.length = 0;

  t.mock.timers.tick(FRESH_MS + 1);
  await navigate.projects(queryClient, client);
  assert.deepEqual(calls.sort(), ['GET /auth', 'GET /me', 'GET /projects']);
});

test('the audit log and its verification are read on every visit', () => {
  const { client } = fakeClient();
  assert.equal(queries.auditEntries(client, {}).staleTime, 0);
  assert.equal(queries.auditChain(client).staleTime, 0);
});

test('every change marks the audit log and its verification stale', async () => {
  const queryClient = createQueryClient();
  queryClient.setQueryData([...keys.audit, 'chain'], { integrity: 'intact' });
  queryClient.setQueryData([...keys.audit, 'entries', {}], { ok: true, entries: [] });
  await refresh(queryClient, affects.sessions());
  assert.equal(queryClient.getQueryState([...keys.audit, 'chain'])?.isInvalidated, true);
  assert.equal(queryClient.getQueryState([...keys.audit, 'entries', {}])?.isInvalidated, true);
});

test('a secret change refetches the environment and the counts, and nothing else', async () => {
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  const place = { project: 'market', environment: 'dev' };
  await navigate.project(queryClient, client);
  await Promise.all([
    queryClient.fetchQuery(queries.secrets(client, place)),
  ]);
  const stops = [
    onScreen(queryClient, queries.secrets(client, place)),
    onScreen(queryClient, queries.projects(client)),
    onScreen(queryClient, queries.me(client)),
    onScreen(queryClient, queries.grants(client, 'market')),
  ];
  calls.length = 0;

  await refresh(queryClient, affects.secrets(place));
  assert.deepEqual(calls.sort(), ['GET /projects', 'GET /secrets/market/dev']);
  for (const stop of stops) stop();
});

test('an access change refetches the project’s grants and what you can see, not its secrets', async () => {
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  const place = { project: 'market', environment: 'dev' };
  await navigate.project(queryClient, client);
  await queryClient.fetchQuery(queries.secrets(client, place));
  const stops = [
    onScreen(queryClient, queries.grants(client, 'market')),
    onScreen(queryClient, queries.projects(client)),
    onScreen(queryClient, queries.me(client)),
    onScreen(queryClient, queries.secrets(client, place)),
  ];
  calls.length = 0;

  await refresh(queryClient, affects.access('market', 'user:dev@acme.example'));
  assert.deepEqual(calls.sort(), ['GET /me', 'GET /members?path=market', 'GET /projects']);
  for (const stop of stops) stop();
});

test('a change refetches what is off screen on its next use, not before', async () => {
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  await navigate.users(queryClient, client);
  calls.length = 0;

  // Removing someone from another page: the directory is not on screen.
  await refresh(queryClient, affects.removal('user:dev@acme.example'));
  assert.deepEqual(calls, []);

  await navigate.users(queryClient, client);
  assert.deepEqual(calls, ['GET /members']);
  assert.ok(queryClient.getQueryState([...keys.directory, { owner: true }])?.isInvalidated === false);
});

test('nobody but an owner is asked for the directory', async () => {
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  const answer = await queryClient.fetchQuery(queries.directory(client, false));
  assert.equal(answer.ok, false);
  assert.deepEqual(calls, []);
});
