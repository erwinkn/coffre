import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type RequestListener } from 'node:http';
import type { AddressInfo } from 'node:net';

import { Browser } from '../src/browser.ts';
import { Report } from '../src/report.ts';

async function serving(t: test.TestContext, listener: RequestListener): Promise<string> {
  const server = createServer(listener);
  await new Promise<void>((listening) => server.listen(0, '127.0.0.1', listening));
  t.after(() => {
    server.closeAllConnections();
    return new Promise((closed) => server.close(closed));
  });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/** A server that answers as wrangler dev's proxy does when its connection to the Worker drops: a 500 in plain text. */
function dropping(t: test.TestContext): Promise<string> {
  return serving(t, (_request, response) => {
    response.writeHead(500, { 'content-type': 'text/plain' });
    response.end('Error: Network connection lost.\n    at async Object.fetch (entry.worker.js:5318:22)');
  });
}

/** Miniflare's own line for a request, coloured as it prints it to a terminal. */
function styled(method: string, path: string, status: number, text: string): string {
  const colour = status < 300 ? 32 : status < 400 ? 34 : status < 500 ? 33 : 31;
  return `\x1b[2m[wrangler:info]\x1b[22m \x1b[0m\x1b[1m${method}\x1b[22m ${path} \x1b[${colour}m\x1b[1m${status}\x1b[22m ${text} \x1b[39m\x1b[90m(4ms)\x1b[39m\x1b[0m`;
}

function printing(t: test.TestContext): string[] {
  const printed: string[] = [];
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'error', (text: string) => printed.push(text));
  return printed;
}

test('a failed check prints the bodies of the 5xx answers it met, and what the processes wrote meanwhile, whole', async (t) => {
  const origin = await dropping(t);
  const printed = printing(t);
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
      styled('GET', '/projects', 307, 'Temporary Redirect'),
      styled('GET', '/activity', 200, 'OK'),
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
  assert.match(shown, /but for 4 requests answered below 500/);
  assert.doesNotMatch(shown, /\/projects|\/activity|403 Forbidden|before the check/);
});

test('a check that passes prints none of it, and the next failure only its own', async (t) => {
  const origin = await dropping(t);
  const printed = printing(t);
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

test("a request a check left running is that check's, even when it ends in the next", async (t) => {
  let answer!: () => void;
  let arrived!: () => void;
  const waiting = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  const origin = await serving(t, (request, response) => {
    const send = () => {
      response.writeHead(500, { 'content-type': 'text/plain' });
      response.end(`failed ${request.url}`);
    };
    if (request.url !== '/slow') return send();
    answer = send;
    arrived();
  });
  const printed = printing(t);
  const report = new Report();
  let slow!: Promise<Response>;
  await report.check('first', {}, async () => {
    // As a page load whose other request failed first: `Promise.all` gives up on this one.
    slow = new Browser(origin).fetch('/slow');
    return 'left /slow running';
  });
  await report.check('second', {}, async () => {
    await waiting;
    answer();
    await slow;
    await new Browser(origin).fetch('/second');
    throw new Error('failed');
  });
  const shown = printed.join('\n');
  assert.match(shown, /GET \/second 500: failed \/second/);
  assert.doesNotMatch(shown, /\/slow/);
});

test("a 5xx body that streams on, or is huge, holds up nothing: a failure shows its start, and why it stops", async (t) => {
  const origin = await serving(t, (request, response) => {
    response.writeHead(500, { 'content-type': 'text/plain' });
    if (request.url === '/endless') response.write('Error: still going');
    else response.end('x'.repeat(4 * 1024 * 1024));
  });
  const printed = printing(t);
  const report = new Report();
  await report.check('streams', {}, async () => {
    const browser = new Browser(origin);
    const started = Date.now();
    const endless = await browser.fetch('/endless');
    assert.equal(endless.status, 500);
    assert.ok(Date.now() - started < 5000, 'the request returned without waiting on its body');
    await endless.body?.cancel();
    const huge = await browser.fetch('/huge');
    assert.equal((await huge.text()).length, 4 * 1024 * 1024, 'the caller still reads the whole body');
    throw new Error('failed');
  });
  const shown = printed.join('\n');
  assert.match(shown, /GET \/endless 500: Error: still going… \(the rest unread: the body was still coming after 1000 ms\)/);
  assert.match(shown, /GET \/huge 500: x{2000}… \(cut at 2000 characters\)/);
});
