import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError, type CoffreClient } from '@coffre/client';
import { QueryObserver, type QueryClient } from '@tanstack/react-query';

import {
  affects,
  createQueryClient,
  FRESH_MS,
  keys,
  loadAccess,
  loadDirectory,
  loadEnvironment,
  loadPrincipal,
  loadProject,
  loadShell,
  loadSignIn,
  queries,
  refresh,
  shellOf,
  tabOpens,
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
  instanceRole: 'admin',
  scope: { projects: 'all', environments: 'all' },
  runsInstance: true,
  setsUpServices: true,
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

test('a tab opens from what its page read, however old, and refreshes it behind the page', async (t) => {
  t.mock.timers.enable({ apis: ['Date'] });
  const calls: string[] = [];
  let offline = false;
  // Every read answers at once, until the network stops answering at all.
  const answer = <T>(route: string, value: T) => () => {
    calls.push(route);
    return offline ? new Promise<T>(() => {}) : Promise.resolve(value);
  };
  const access = { member: 'token:ci-deploy', principalType: 'service', principalId: 'ci-deploy', status: 'active', instanceRole: 'member', scope: null, managed: true, grants: [] };
  const client = {
    auth: answer('GET /auth', { mode: 'signin', signin: null, access: null }),
    me: answer('GET /me', me),
    projects: { list: answer('GET /projects', { projects: [market] }) },
    members: { get: answer('GET /members/token:ci-deploy', {}), access: answer('GET /members/token:ci-deploy/access', access) },
  } as unknown as CoffreClient;
  const queryClient = createQueryClient();
  await loadPrincipal(queryClient, client, 'service', 'ci-deploy');
  calls.length = 0;

  t.mock.timers.tick(FRESH_MS + 1);
  offline = true;
  const [shell, held] = await Promise.all([
    loadShell(queryClient, client, 'cached'),
    loadAccess(queryClient, client, 'token:ci-deploy', 'cached'),
  ]);
  assert.equal(shell.capabilities.canReadAudit, true);
  assert.deepEqual(held, { ok: true, ...access });
  // Asked again all the same, behind the page.
  assert.deepEqual(calls.sort(), ['GET /auth', 'GET /me', 'GET /members/token:ci-deploy/access', 'GET /projects']);
});

test('a tab sends nobody away on a stale no: a service account added back opens on its sign-in', async () => {
  let status = 'removed';
  const client = {
    auth: async () => ({ mode: 'signin', signin: { providers: [] }, access: null }),
    me: async () => me,
    projects: { list: async () => ({ projects: [market] }) },
    members: {
      access: async () => ({ member: 'token:ci-deploy', principalType: 'service', principalId: 'ci-deploy', status, instanceRole: 'member', scope: null, managed: true, grants: [] }),
    },
    tokens: { list: async () => ({ tokens: [] }) },
  } as unknown as CoffreClient;
  const queryClient = createQueryClient();
  const shows = async (freshness: 'fresh' | 'cached') => (await loadSignIn(queryClient, client, 'token:ci-deploy', freshness)) !== null;
  assert.equal(await tabOpens(shows), false, 'removed: nothing to issue');

  // Added back here: the change marks what was read of it stale, and the cache still says removed.
  status = 'active';
  await refresh(queryClient, affects.admission('token:ci-deploy'));
  assert.equal(await tabOpens(shows), true);
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

  // The projects too: they list the grants on every project, which removal ends.
  await navigate.users(queryClient, client);
  assert.deepEqual(calls, ['GET /projects', 'GET /members']);
  assert.ok(queryClient.getQueryState([...keys.directory, { owner: true }])?.isInvalidated === false);
});

test('nobody but an owner is asked for the directory', async () => {
  const { client, calls } = fakeClient();
  const queryClient = createQueryClient();
  const answer = await queryClient.fetchQuery(queries.directory(client, false));
  assert.equal(answer.ok, false);
  assert.deepEqual(calls, []);
});


test('the directory keeps which Owners the deployment names, for the tag and the lock', async () => {
  const client = {
    members: {
      list: async () => ({
        members: [
          { principalType: 'user', principalId: 'root@acme.example', instanceRole: 'owner', scope: null, declared: true, grants: [] },
        ],
        removed: [],
      }),
    },
  } as unknown as CoffreClient;
  const result = await queries.directory(client, true).queryFn!({} as never);
  assert.ok(result.ok);
  assert.equal(result.principals[0]?.declared, true);
});

/**
 * The environment page's reads, each held until the test answers it: the
 * order they are asked in, and how many are asked before the secrets answer.
 */
function environmentClient({ accessible, secrets, archivedAt = null }: { accessible: boolean; secrets: () => Promise<unknown>; archivedAt?: string | null }) {
  const calls: string[] = [];
  const asked = (route: string, value: () => Promise<unknown>) => () => {
    calls.push(route);
    return value();
  };
  const dev = { ...market.environments[0]!, accessible, details: accessible ? market.environments[0]!.details : null };
  const client = {
    projects: { list: asked('GET /projects', async () => ({ projects: [{ ...market, archivedAt, environments: [dev] }] })) },
    secrets: { list: asked('GET /secrets/market/dev', secrets) },
    references: { list: asked('GET /references', async () => ({ references: [] })) },
    environments: { missing: asked('GET /missing', async () => ({ missing: [], dismissed: [] })) },
  } as unknown as CoffreClient;
  return { client, calls };
}

test('an environment you read is read in one round trip: its secrets, references and missing keys at once', async () => {
  let answer!: (value: unknown) => void;
  const { client, calls } = environmentClient({
    accessible: true,
    secrets: () => new Promise((resolve) => (answer = resolve)),
  });
  const queryClient = createQueryClient();
  await queryClient.fetchQuery(queries.projects(client));
  calls.length = 0;

  const loaded = loadEnvironment(queryClient, client, { project: 'market', environment: 'dev' });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(calls.sort(), ['GET /missing', 'GET /references', 'GET /secrets/market/dev'], 'all three before the secrets answer');
  answer({ keys: [], permissions: [], rotateAfterDays: null });
  assert.equal((await loaded).ok, true);
});

test('an environment the project tree does not open to you asks its secrets alone, so a refusal is logged once', async () => {
  const { client, calls } = environmentClient({
    accessible: false,
    secrets: async () => {
      throw new CoffreError(403, 'forbidden', 'no grant covers market/dev');
    },
  });
  const queryClient = createQueryClient();
  const loaded = await loadEnvironment(queryClient, client, { project: 'market', environment: 'dev' });
  assert.equal(loaded.ok, false);
  assert.deepEqual(calls, ['GET /projects', 'GET /secrets/market/dev']);
});

test('an environment of an archived project asks its secrets alone, though you read it', async () => {
  const { client, calls } = environmentClient({
    accessible: true,
    archivedAt: '2026-10-01T00:00:00.000Z',
    secrets: async () => {
      throw new CoffreError(404, 'not_found', 'unknown project or environment');
    },
  });
  const queryClient = createQueryClient();
  const loaded = await loadEnvironment(queryClient, client, { project: 'market', environment: 'dev' });
  assert.equal(loaded.ok, false);
  assert.deepEqual(calls, ['GET /projects', 'GET /secrets/market/dev']);
});
