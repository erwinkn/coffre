// A value leaves coffre through a reveal and nowhere else: not in any
// answer to a GET, whoever asks, not in a page, and not in what it stores or
// prints. Every value set is a random canary, so finding one is a leak.
import { existsSync, readFileSync } from 'node:fs';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import { getCalls, getUrls } from '@coffre/client/routes';
import { scanTables, tables } from './storage.ts';
import { canary, BULK, DEV, PROD, PROJECT, SERVICE, type Canaries, type People } from './people.ts';

function calls(people: People) {
  const places = [DEV, PROD, BULK].map((path) => {
    const [project, environment] = path.split('/') as [string, string];
    return { project, environment };
  });
  return getCalls({
    places,
    secrets: places.slice(0, 2).map((place) => ({ ...place, key: 'API_KEY' })),
    members: [...[people.admin, people.reader, people.leaver, people.bulk].map((person) => person.member), SERVICE],
    services: [SERVICE],
  });
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
  const look = (where: string, content: string | Uint8Array) => {
    const bytes = Buffer.from(content);
    const found = values.filter((value) => bytes.includes(value));
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

  // These GETs are independent. Keep every route/caller pair, with a small
  // number in flight so latency does not add up across all answers.
  const reads: { where: string; url: string; fetchAs: (url: string) => Promise<Response> }[] = [];
  const routes = calls(people);
  for (const { key, url } of getUrls(deployment.origin, routes)) {
    for (const [name, fetchAs] of callers) reads.push({ where: `${key} as ${name}`, url, fetchAs });
  }
  const paths = pages(people);
  for (const path of paths) {
    for (const [name, fetchAs] of callers.slice(0, 1 + Object.keys(browsers).length)) {
      reads.push({ where: `the page ${path} as ${name}`, url: `${deployment.origin}${path}`, fetchAs });
    }
  }
  let next = 0;
  const workers = await Promise.allSettled(Array.from({ length: 4 }, async () => {
    while (next < reads.length) {
      const { where, url, fetchAs } = reads[next++]!;
      look(where, await (await fetchAs(url)).text());
    }
  }));
  // Drain in-flight reads even on an error: none may overlap the next check.
  for (const worker of workers) if (worker.status === 'rejected') throw worker.reason;
  const answers = reads.length;

  const stored: string[] = [];
  await using(deployment.database(), async (sql) => {
    const names = await tables(sql);
    // Prove the reader sees bytes before trusting an absence of plaintext.
    const control = canary();
    await sql.exec(`CREATE TABLE conformance_canary_probe (value ${sql.engine === 'postgres' ? 'bytea' : 'BLOB'})`);
    try {
      await sql.query(`INSERT INTO conformance_canary_probe VALUES (${sql.engine === 'postgres' ? '$1' : '?'})`, [Buffer.from(control)]);
      let found = false;
      await scanTables(sql, ['conformance_canary_probe'], (_, bytes) => { found ||= Buffer.from(bytes).includes(control); });
      expect(found, 'the database scanner missed its planted binary canary');
    } finally {
      await sql.exec('DROP TABLE conformance_canary_probe');
    }
    await scanTables(sql, names, look);
    stored.push(`${names.length} tables, with a binary positive control`);
  });
  if (deployment.databaseFile !== null) {
    look("the database's file", files(deployment.databaseFile));
    stored.push('the database file and WAL');
  }
  look("the processes' output", deployment.output());
  stored.push("the processes' output");

  expect(leaks.length === 0, 'a value was found outside a reveal', leaks);
  return `${answers} answers from ${Object.keys(routes).length} GET routes and ${paths.length} pages as ${callers.length} callers, and ${stored.join(', ')}: no value`;
}

/** A SQLite file and its write-ahead log, as bytes: what anyone with the disk would read. */
function files(path: string): Buffer {
  expect(existsSync(path), `the store file could not be found: ${path}`);
  return Buffer.concat([path, `${path}-wal`]
    .filter((file) => existsSync(file))
    .map((file) => readFileSync(file)));
}
