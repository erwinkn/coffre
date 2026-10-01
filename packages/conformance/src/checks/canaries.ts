// A value leaves coffre through a reveal and nowhere else: not in any
// answer to a GET, whoever asks, not in a page, and not in what it stores or
// prints. Every value set is a random canary, so finding one is a leak.
import { existsSync, readFileSync } from 'node:fs';

import type { Params, RouteInput, RouteKey } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import { BULK, DEV, PROD, PROJECT, SERVICE, type Canaries, type People } from './people.ts';

type GetKey = Extract<RouteKey, `GET ${string}`>;

/**
 * Each GET route, with what to ask it. Typed over every GET in the API, so
 * a route added to the server fails the typecheck here until it is scanned.
 */
type Calls = { [K in GetKey]: { params: Params<K>; input?: RouteInput<K> }[] };

function calls(people: People): Calls {
  const members = [people.admin, people.reader, people.leaver, people.bulk].map((person) => person.member);
  const places = [DEV, PROD, BULK].map((path) => {
    const [project, environment] = path.split('/') as [string, string];
    return { project, environment };
  });
  return {
    'GET /me': [{ params: {} }],
    'GET /projects': [{ params: {} }],
    'GET /secrets/:project/:environment': places.map((params) => ({ params })),
    'GET /secrets/:project/:environment/:key/versions': [
      { params: { ...places[0]!, key: 'API_KEY' } },
      { params: { ...places[1]!, key: 'API_KEY' } },
    ],
    'GET /members': [{ params: {} }, { params: {}, input: { path: DEV } }],
    'GET /members/:member': [...members, SERVICE].map((member) => ({ params: { member } })),
    'GET /members/:member/tokens': [{ params: { member: SERVICE } }],
    'GET /sessions': [{ params: {} }],
    'GET /identities': [{ params: {} }],
    'GET /device-logins/:code': [{ params: { code: 'BCDF-GHJK' } }],
    'GET /syncs/providers': [{ params: {} }],
    'GET /syncs/:project/:environment': places.map((params) => ({ params })),
    'GET /audit': [{ params: {}, input: { limit: 500 } }],
    'GET /audit/verification': [{ params: {} }],
    'GET /audit/vault': [{ params: {}, input: { limit: 200 } }],
  };
}

function pages(people: People): string[] {
  const users = [people.admin, people.reader, people.leaver, people.bulk];
  return [
    '/',
    '/login',
    '/unregistered',
    '/account',
    '/access',
    '/audit',
    '/settings',
    '/auth/device',
    '/projects',
    `/projects/${PROJECT}`,
    ...[DEV, PROD, BULK].map((path) => `/projects/${path}`),
    '/users',
    ...users.map((person) => `/users/${encodeURIComponent(person.email)}`),
    '/tokens',
    `/tokens/${SERVICE.slice('token:'.length)}`,
  ];
}

export async function canaryScan(deployment: Deployment, people: People, canaries: Canaries): Promise<string> {
  const values = Object.values(canaries);
  const leaks: string[] = [];
  const look = (where: string, text: string) => {
    const found = values.filter((value) => text.includes(value));
    if (found.length > 0) leaks.push(`${where}: ${found.length} value${found.length === 1 ? '' : 's'}`);
  };

  const token = (value: string) => (url: string) => fetch(url, { headers: { authorization: `Bearer ${value}` } });
  const browsers = {
    'the root admin': people.admin.browser,
    'the reader': people.reader.browser,
    'the bulk reader': people.bulk.browser,
    'the leaver, removed': people.leaver.browser,
    'the stranger': people.stranger.browser,
  };
  const callers: [string, (url: string) => Promise<Response>][] = [
    ['no one', (url) => fetch(url, { redirect: 'manual' })],
    ...Object.entries(browsers).map(([name, browser]): [string, (url: string) => Promise<Response>] => [name, (url) => browser.fetch(url)]),
    ["the leaver's CLI, removed", token(people.leaver.cliToken)],
    ['the service, removed', token(people.service.token)],
  ];

  let answers = 0;
  const routes = Object.entries(calls(people)) as [GetKey, { params: Record<string, string>; input?: object }[]][];
  for (const [key, asks] of routes) {
    for (const { params, input } of asks) {
      const url = address(deployment.origin, key, params, input);
      for (const [name, fetchAs] of callers) {
        look(`${key} as ${name}`, await (await fetchAs(url)).text());
        answers++;
      }
    }
  }
  const paths = pages(people);
  for (const path of paths) {
    for (const [name, fetchAs] of callers.slice(0, 1 + Object.keys(browsers).length)) {
      look(`the page ${path} as ${name}`, await (await fetchAs(`${deployment.origin}${path}`)).text());
      answers++;
    }
  }

  const stored: string[] = [];
  if (deployment.databaseFile === null) {
    await using(deployment.database(), async (sql) => {
      const tables = await sql.query<{ name: string }>(
        `SELECT table_name AS name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`,
      );
      for (const { name } of tables) {
        const rows = await sql.query<{ row: string }>(`SELECT t::text AS row FROM "${name}" t`);
        look(`the database's ${name} table`, rows.map((row) => row.row).join('\n'));
      }
      stored.push(`${tables.length} tables`);
    });
  } else {
    look("the database's file", files(deployment.databaseFile));
    stored.push('the database file');
  }
  const store = deployment.vaultStore();
  if (store !== null) {
    look("the vault's store", files(store));
    stored.push("the vault's store");
  }
  look("the processes' output", deployment.output());
  stored.push("the processes' output");

  expect(leaks.length === 0, 'a value was found outside a reveal', leaks);
  return `${answers} answers from ${routes.length} GET routes and ${paths.length} pages as ${callers.length} callers, and ${stored.join(', ')}: no value`;
}

function address(origin: string, key: GetKey, params: Record<string, string>, input: object | undefined): string {
  const path = key.slice('GET '.length).replace(/:(\w+)/g, (_, name: string) => encodeURIComponent(params[name]!));
  const url = new URL(`${origin}/api${path}`);
  for (const [name, value] of Object.entries(input ?? {})) url.searchParams.set(name, String(value));
  return url.href;
}

/** A SQLite file and its write-ahead log, as bytes: what anyone with the disk would read. */
function files(path: string): string {
  return [path, `${path}-wal`]
    .filter((file) => existsSync(file))
    .map((file) => readFileSync(file).toString('latin1'))
    .join('\n');
}
