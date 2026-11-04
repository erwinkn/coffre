import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type RequestListener } from 'node:http';
import type { AddressInfo } from 'node:net';

import { Unreachable } from '@coffre/client';

import { bearer, Browser } from '../src/browser.ts';
import { Report } from '../src/report.ts';

async function serving(t: test.TestContext, listener: RequestListener): Promise<string> {
  return (await stoppable(t, listener)).origin;
}

/** A server, and its stopping, as the harness stops the processes: every connection closed. */
async function stoppable(t: test.TestContext, listener: RequestListener): Promise<{ origin: string; stop: () => Promise<void> }> {
  const server = createServer(listener);
  await new Promise<void>((listening) => server.listen(0, '127.0.0.1', listening));
  let stopped: Promise<void> | undefined;
  const stop = () => {
    server.closeAllConnections();
    return (stopped ??= new Promise((closed) => server.close(() => closed())));
  };
  t.after(stop);
  return { origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, stop };
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
      // srvx's, as the Node example's server logs a request.
      '\x1b[90m[9:31:22 AM]\x1b[39m \x1b[1mGET\x1b[22m \x1b[34mhttp://127.0.0.1:3290/livez\x1b[39m [\x1b[32m200\x1b[39m] \x1b[90m(0.68ms)\x1b[39m',
      '\x1b[90m[9:31:23 AM]\x1b[39m \x1b[1mPOST\x1b[22m \x1b[34mhttp://127.0.0.1:3290/api/reveals\x1b[39m [\x1b[31m500\x1b[39m] \x1b[90m(3.10ms)\x1b[39m',
      '[wrangler:info] PATCH /api/access/service%3Aci 403 Forbidden (5ms)',
      '✘ [ERROR] Error inside ProxyWorker (the affected request failed; the dev server continues): PATCH /api/access/service%3Aci (failed after 1 attempt): Network connection lost.',
      '[wrangler:info] PATCH /api/access/service%3Aci 500 Internal Server Error (7ms)',
    ].join('\n');
    await new Browser(origin).client().access.set('service:ci', { 'conformance/dev': 'viewer' });
    return 'granted';
  });
  assert.deepEqual(report.failed, ['grant']);
  const shown = `${printed.join('\n')}\n${await report.afterwards('')}`;
  assert.match(shown, /request failed with status 500/);
  // The body the client error dropped.
  assert.match(shown, /PATCH \/api\/access\/service%3Aci 500: Error: Network connection lost\./);
  // What wrangler said meanwhile, but for the requests answered below 500.
  assert.match(shown, /Error inside ProxyWorker .* Network connection lost\./);
  assert.match(shown, /PATCH \/api\/access\/service%3Aci 500 Internal Server Error/);
  assert.match(shown, /\/api\/reveals.*500/);
  assert.match(shown, /during this check, but for 5 requests answered below 500/);
  assert.doesNotMatch(shown, /\/projects|\/activity|\/livez|403 Forbidden|before the check/);
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
  assert.equal(await report.afterwards('output'), undefined, 'a run with no failure ends with nothing more');
  await report.check('second', {}, async () => {
    await new Browser(origin).fetch('/second');
    throw new Error('failed');
  });
  // No mark, no output during the check.
  assert.doesNotMatch(printed.join('\n'), /The processes' output/);
  const shown = (await report.afterwards(''))!;
  assert.match(shown, /second:\n  GET \/second 500/);
  assert.doesNotMatch(shown, /\/first/);
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
  const shown = (await report.afterwards(''))!;
  assert.match(shown, /GET \/second 500: failed \/second/);
  assert.doesNotMatch(shown, /\/slow/);
});

test('a 5xx body is shown whole, however large, cancelled or not, and one that streams on until its server stops shows what came, and why it stops', async (t) => {
  const { origin, stop } = await stoppable(t, (request, response) => {
    response.writeHead(500, { 'content-type': 'text/plain' });
    if (request.url === '/endless') response.write('Error: still going');
    else if (request.url === '/cancelled') response.end('Error: unread');
    else response.end('x'.repeat(4 * 1024 * 1024));
  });
  printing(t);
  const report = new Report();
  await report.check('streams', {}, async () => {
    const browser = new Browser(origin);
    const endless = await browser.fetch('/endless');
    assert.equal(endless.status, 500, 'the request returned without waiting on its body');
    // As the headers check drops each body: the cancel returns once the body has come.
    await (await browser.fetch('/cancelled')).body?.cancel();
    const huge = await browser.fetch('/huge');
    assert.equal((await huge.text()).length, 4 * 1024 * 1024, 'the caller still reads the whole body');
    throw new Error('failed');
  });
  await stop();
  const shown = (await report.afterwards(''))!;
  assert.match(shown, /GET \/endless 500: Error: still going… \(the rest unread: TypeError: terminated\)/);
  assert.match(shown, /GET \/cancelled 500: Error: unread/);
  assert.ok(shown.includes(`GET /huge 500: ${'x'.repeat(4 * 1024 * 1024)}`), 'the huge body whole');
});

test('a request made with `fetch` itself, as the health and readiness checks make theirs, is kept too', async (t) => {
  const origin = await dropping(t);
  const printed = printing(t);
  const report = new Report();
  await report.check('health', {}, async () => {
    const live = await fetch(`${origin}/livez`);
    throw new Error(`/livez answered ${live.status}`);
  });
  assert.match(printed.join('\n'), /\/livez answered 500/);
  assert.match((await report.afterwards(''))!, /GET \/livez 500: Error: Network connection lost\./);
});

test('the run ends with every request a failed check left running, once it has ended: its answer, its error, or its server stopping', async (t) => {
  const { origin, stop } = await stoppable(t, (request, response) => {
    if (request.url === '/dropped') return request.socket.destroy();
    if (request.url === '/hung') return;
    // A page's other call, whose 500 comes after the first has failed it.
    setTimeout(() => {
      response.writeHead(500, { 'content-type': 'text/plain' });
      response.write('Error: late');
      setTimeout(() => response.end(' and slow'), 200);
    }, 200);
  });
  printing(t);
  const report = new Report();
  await report.check('page load', {}, async () => {
    const browser = new Browser(origin);
    await Promise.all([browser.fetch('/late'), browser.fetch('/dropped'), browser.fetch('/hung')]);
    return 'loaded';
  });
  const ending = report.afterwards('');
  const settled = await Promise.race([ending.then(() => true), new Promise((resolve) => setTimeout(resolve, 1000, false))]);
  assert.equal(settled, false, 'the end waits on /hung, which nothing has ended');
  await stop();
  const shown = (await ending)!;
  assert.match(shown, /GET \/late 500: Error: late and slow/);
  assert.match(shown, /GET \/dropped no answer: could not reach http:\/\/127\.0\.0\.1:\d+: /);
  assert.match(shown, /GET \/hung no answer: could not reach http:\/\/127\.0\.0\.1:\d+: /);
});

test("a bearer client still says why it could not reach the instance", async (t) => {
  const server = createServer();
  await new Promise<void>((listening) => server.listen(0, '127.0.0.1', listening));
  const closed = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  await new Promise((done) => server.close(done));
  printing(t);
  const report = new Report();
  let thrown: unknown;
  await report.check('reach', {}, async () => {
    thrown = await bearer(closed, 'token').me().catch((error: unknown) => error);
    throw thrown;
  });
  assert.ok(thrown instanceof Unreachable, String(thrown));
  assert.match(thrown.message, /could not reach http:\/\/127\.0\.0\.1:\d+: .*ECONNREFUSED/);
});

test("the run ends with the processes' whole output, filtered: a line written after a failed check's output was printed is there, however much came after", async (t) => {
  const printed = printing(t);
  let written = 'before the check\n';
  const report = new Report({
    mark: () => {
      const at = written.length;
      return () => written.slice(at);
    },
  });
  await report.check('grant', {}, async () => {
    throw new Error('request failed with status 500');
  });
  const late = '✘ [ERROR] Error inside ProxyWorker (the affected request failed; the dev server continues): PATCH /api/access/service%3Aci (failed after 1 attempt): Network connection lost.';
  // Wrangler's line, after the check's own output; then more checks, passing, and their requests.
  written += `${late}\n${'[wrangler:info] GET /projects 200 OK (3ms)\n'.repeat(1000)}`;
  await report.check('later', {}, async () => {
    written += 'a later check\n';
    return 'passed';
  });
  assert.doesNotMatch(printed.join('\n'), /Error inside ProxyWorker/);
  const afterwards = (await report.afterwards(written))!;
  assert.ok(afterwards.includes(late));
  assert.match(afterwards, /The processes' output, but for 1000 requests answered below 500/);
  assert.match(afterwards, /before the check/);
  assert.match(afterwards, /a later check/);
  assert.doesNotMatch(afterwards, /GET \/projects|The answers of 500/);
});
