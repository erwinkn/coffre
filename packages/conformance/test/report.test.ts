import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';

import { Browser } from '../src/browser.ts';
import { Report } from '../src/report.ts';

/** A server that answers as wrangler dev's proxy does when its connection to the Worker drops: a 500 in plain text. */
async function dropping(t: test.TestContext): Promise<string> {
  const server = createServer((_request, response) => {
    response.writeHead(500, { 'content-type': 'text/plain' });
    response.end('Error: Network connection lost.\n    at async Object.fetch (entry.worker.js:5318:22)');
  });
  await new Promise<void>((listening) => server.listen(0, '127.0.0.1', listening));
  t.after(() => new Promise((closed) => server.close(closed)));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

test('a failed check prints the bodies of the 5xx answers it met, and what the processes wrote meanwhile, whole', async (t) => {
  const origin = await dropping(t);
  const printed: string[] = [];
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'error', (text: string) => printed.push(text));
  let written = 'before the check\n';
  const report = new Report({
    mark: () => {
      const at = written.length;
      return () => written.slice(at);
    },
  });
  await report.check('grant', {}, async () => {
    written += [
      '[wrangler:info] GET /projects 200 OK (12ms)',
      '\x1b[2m[wrangler:info]\x1b[22m GET /projects 307 Temporary Redirect (3ms)',
      '[wrangler:info] PATCH /api/access/service%3Aci 403 Forbidden (5ms)',
      '✘ [ERROR] Error inside ProxyWorker (the affected request failed; the dev server continues): PATCH /api/access/service%3Aci (failed after 1 attempt): Network connection lost.',
      '[wrangler:info] PATCH /api/access/service%3Aci 500 Internal Server Error (7ms)',
    ].join('\n');
    await new Browser(origin).client().access.set('service:ci', { 'conformance/dev': 'viewer' });
    return 'granted';
  });
  assert.deepEqual(report.failed, ['grant']);
  const shown = printed.join('\n');
  assert.match(shown, /request failed with status 500/);
  // The body the client error dropped.
  assert.match(shown, /PATCH \/api\/access\/service%3Aci 500: Error: Network connection lost\./);
  // What wrangler said meanwhile, but for the requests answered below 500.
  assert.match(shown, /Error inside ProxyWorker .* Network connection lost\./);
  assert.match(shown, /PATCH \/api\/access\/service%3Aci 500 Internal Server Error/);
  assert.match(shown, /but for 3 requests answered below 500/);
  assert.doesNotMatch(shown, /GET \/projects|403 Forbidden|before the check/);
});

test('a check that passes prints none of it, and the next failure only its own', async (t) => {
  const origin = await dropping(t);
  const printed: string[] = [];
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'error', (text: string) => printed.push(text));
  const report = new Report();
  await report.check('first', {}, async () => {
    await new Browser(origin).fetch('/first');
    return 'a 500 met, and passed';
  });
  assert.deepEqual(printed, []);
  await report.check('second', {}, async () => {
    await new Browser(origin).fetch('/second');
    throw new Error('failed');
  });
  const shown = printed.join('\n');
  assert.match(shown, /GET \/second 500/);
  assert.doesNotMatch(shown, /\/first/);
  // No mark, no output.
  assert.doesNotMatch(shown, /The processes' output/);
});
