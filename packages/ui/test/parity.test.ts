import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createClient, type CoffreClient } from '@coffre/client';
import { everyRoute } from '@coffre/client/routes';

import { UI_PARITY, type ClientCall } from '../src/parity.ts';

const SRC = fileURLToPath(new URL('../src/', import.meta.url));

/** Every source file of the pages, as text. */
function sources(dir = SRC): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? sources(join(dir, entry.name))
      : /\.tsx?$/.test(entry.name)
        ? [readFileSync(join(dir, entry.name), 'utf8')]
        : [],
  );
}

/** A route's pattern as a path: `/members/:member` matches `/members/user%3Aada`. */
function matches(route: string, method: string, path: string): boolean {
  const [routeMethod, pattern] = route.split(' ') as [string, string];
  const shape = new RegExp(`^${pattern.replace(/:[a-z]+/g, '[^/]+')}$`);
  return routeMethod === method && shape.test(path);
}

/**
 * The requests one client call sends, made with stand-in arguments: a path
 * that is a project, an environment and a key at once, an id, a body.
 */
async function requestsOf(call: ClientCall): Promise<string[]> {
  const sent: string[] = [];
  const client = createClient({
    url: 'https://coffre.test',
    transport: async (request) => {
      // The API lives under /api; a route names what follows.
      sent.push(`${request.method} ${new URL(request.url).pathname.replace(/^\/api(?=\/)/, '')}`);
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const [namespace, method] = call.split('.') as [keyof CoffreClient, string | undefined];
  const target = (method === undefined ? client[namespace] : (client[namespace] as Record<string, unknown>)[method]) as (
    ...args: unknown[]
  ) => Promise<unknown>;
  // What the call makes of the answer does not matter here, only what it asked.
  await target('acme/prod/KEY', 'id', {}).catch(() => undefined);
  return sent;
}

test('every route of the API is done somewhere in the pages, or says why not', async () => {
  const routes = everyRoute('https://coffre.test').map(({ key }) => key).sort();
  assert.deepEqual(Object.keys(UI_PARITY).sort(), routes, 'UI_PARITY lists each route once, and only routes');

  const code = sources().join('\n');
  for (const [route, reach] of Object.entries(UI_PARITY)) {
    if ('not' in reach) {
      assert.ok(reach.not.length > 20, `${route} says why no page does it`);
      continue;
    }
    if ('inFlight' in reach) {
      assert.match(reach.inFlight, /#\d+|thr_\w+|W\d+/, `${route} names the pull request or thread bringing its page`);
      continue;
    }
    assert.ok(reach.ui.length > 0, `${route} names where it is done`);
    for (const { does, in: file, call } of reach.ui) {
      assert.ok(existsSync(join(SRC, file)), `${route}: ${does}: no src/${file}`);
      // `coffre.secrets.history(`, or split over lines as formatting leaves it.
      const called = new RegExp(`\\.${call.split('.').join('\\s*\\.')}\\(`);
      assert.ok(called.test(code), `${route}: ${does}: the pages never call ${call}`);
      const sent = await requestsOf(call);
      assert.ok(
        sent.some((request) => matches(route, ...(request.split(' ') as [string, string]))),
        `${route}: ${call} sends ${sent.join(', ') || 'nothing'}`,
      );
    }
  }
});
