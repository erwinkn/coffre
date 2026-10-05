import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { Chrome, findChrome } from '../src/chrome.ts';

const chrome = findChrome();

test("a page's heading, its cards' titles, its text, and what its scripts throw, as Chrome reports them", { skip: chrome === null && 'no Chrome or Chromium here' }, async () => {
  const pages: Record<string, string> = {
    '/fine':
      '<!doctype html><title>t</title><h1> Projects </h1>' +
      '<section><h2 class="card-title"> Sign in with OIDC </h2></section><section><h2 class="card-title">Bearer tokens</h2></section>' +
      '<script>document.title = document.cookie</script>',
    // What a signed-in page did under wrangler's keep_names: a helper only the bundle had.
    '/broken': '<!doctype html><h1>Projects</h1><script>const f = __name(() => {}, "f")</script>',
    // A failed load is an error too: the icon the browser asks for is here.
    '/favicon.ico': '',
  };
  const server = createServer((request, response) => {
    const page = pages[request.url ?? ''];
    response.writeHead(page === undefined ? 404 : 200, { 'content-type': 'text/html' }).end(page ?? '');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const browser = await Chrome.open(chrome!);
  try {
    assert.deepEqual(await browser.load(`${origin}/fine`, [['session', 's3cret']], 200), {
      heading: 'Projects',
      cards: ['Sign in with OIDC', 'Bearer tokens'],
      text: 'Projects\nSign in with OIDC\nBearer tokens',
      errors: [],
    });
    const broken = await browser.load(`${origin}/broken`, [], 200);
    assert.equal(broken.heading, 'Projects');
    assert.equal(broken.errors.length, 1);
    assert.match(broken.errors[0]!, /^ReferenceError: __name is not defined \(http:\/\/127\.0\.0\.1:\d+\/broken:1\)$/);
  } finally {
    await browser.close();
    server.close();
  }
});
