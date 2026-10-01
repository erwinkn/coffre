import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, type RequestListener } from 'node:http';
import { fileURLToPath } from 'node:url';
import { unstable_dev } from 'wrangler';

import { requestJson, type JsonRequest } from '../../src/sync/http.ts';

async function local(handler: RequestListener) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address !== null && typeof address !== 'string');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); }),
  };
}

for (const runtime of ['Node', 'Workers']) {
  test(`${runtime}: sync redirects refuse the target without forwarding credentials or values`, async (t) => {
    let received = 0;
    const sink = await local((_req, res) => {
      received++;
      res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
    });
    t.after(sink.close);
    let status = 307;
    const upstream = await local((_req, res) => {
      res.writeHead(status, { location: `${sink.origin}/secret-path?token=secret-query` }).end();
    });
    t.after(upstream.close);
    let send = (request: JsonRequest) => requestJson({ token: 'project-token' }, request);
    if (runtime === 'Workers') {
      const worker = await unstable_dev(fileURLToPath(new URL('./http-worker.ts', import.meta.url)), {
        local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0,
        compatibilityDate: '2026-08-01', persist: false, logLevel: 'error',
        experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
      });
      t.after(worker.stop);
      send = async (request) => {
        const response = await worker.fetch('/', { method: 'POST', body: JSON.stringify(request) });
        const body = await response.json() as { error: string };
        if (!response.ok) throw new Error(body.error);
        return body as never;
      };
    }
    for (status of [301, 302, 303, 307, 308]) {
      await assert.rejects(send({
        method: 'POST', url: `${upstream.origin}/graphql`,
        headers: { 'Project-Access-Token': 'project-token', Authorization: 'Bearer account-token' },
        body: { variables: { DATABASE_URL: 'private-value' } },
      }), { message: `Refused redirect to ${new URL(sink.origin).host} (HTTP ${status})` });
      assert.equal(received, 0, 'no request reaches the redirect target');
    }
  });
}
