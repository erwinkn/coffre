import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { Chrome, findChrome } from '../src/chrome.ts';

const chrome = findChrome();

// Chrome fails a call it does not answer (chrome.ts); a test that still stalls, on a loaded host, fails here rather than hang the run.
test("a page's heading, its cards' titles, its text and address, and what its scripts throw, as Chrome reports them", { skip: chrome === null && 'no Chrome or Chromium here', timeout: 180_000 }, async () => {
  const pages: Record<string, string> = {
    // Read once, the notice is taken out of the address, as coffre's pages do.
    '/fine':
      '<!doctype html><title>t</title><h1> Projects </h1>' +
      '<section><h2 class="card-title"> Sign in with OIDC </h2></section><section><h2 class="card-title">Bearer tokens</h2></section>' +
      '<script>history.replaceState(null, "", location.pathname)</script>',
    // What a signed-in page did under wrangler's keep_names: a helper only the bundle had.
    '/broken': '<!doctype html><h1>Projects</h1><script>const f = __name(() => {}, "f")</script>',
    // A button that opens a confirmation, as a person would next.
    '/remove':
      '<!doctype html><h1>Projects</h1><button id="remove">Remove</button>' +
      '<script>remove.onclick = () => document.body.insertAdjacentHTML("beforeend", "<div role=alertdialog>Removing revokes 2 grants</div>")</script>',
    // A failed load is an error too: the icon the browser asks for is here.
    '/favicon.ico': '',
  };
  const server = createServer((request, response) => {
    const page = pages[new URL(request.url ?? '/', 'http://x').pathname];
    response.writeHead(page === undefined ? 404 : 200, { 'content-type': 'text/html' }).end(page ?? '');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const browser = await Chrome.open(chrome!);
  try {
    assert.deepEqual(await browser.load(`${origin}/fine?linked=github`, [['session', 's3cret']], 200), {
      heading: 'Projects',
      cards: ['Sign in with OIDC', 'Bearer tokens'],
      text: 'Projects\nSign in with OIDC\nBearer tokens',
      href: `${origin}/fine`,
      dialog: null,
      errors: [],
    });
    const removing = await browser.load(`${origin}/remove`, [], 200, 'document.getElementById("remove").click()');
    assert.equal(removing.dialog, 'Removing revokes 2 grants', 'the dialog a step opened is read');
    const broken = await browser.load(`${origin}/broken`, [], 200);
    assert.equal(broken.heading, 'Projects');
    assert.equal(broken.errors.length, 1);
    assert.match(broken.errors[0]!, /^ReferenceError: __name is not defined \(http:\/\/127\.0\.0\.1:\d+\/broken:1\)$/);
  } finally {
    await browser.close();
    server.close();
  }
});
