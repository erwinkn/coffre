// A database too small for coffre's pools stops a Node process whenever it is
// first reached, not only at start: one down at start and too small once back
// stops it then, rather than leaving it up and failing each request (W364,
// review r2). scripts/test-setup.sh runs it beside a cluster that lets in 15
// connections (`COFFRE_TEST_SETUP_SMALL_CLUSTER`); elsewhere it is skipped.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mock, test } from 'node:test';

import { createCoffre, github, signin } from '../src/node.ts';
import { closedPort, proxy } from './db/proxy.ts';

const SMALL_CLUSTER = process.env.COFFRE_TEST_SETUP_SMALL_CLUSTER;
const ORIGIN = 'https://secrets.acme.example';

test(
  'a database down at start and too small once back stops the process when a readiness probe reaches it',
  { skip: SMALL_CLUSTER === undefined ? 'needs COFFRE_TEST_SETUP_SMALL_CLUSTER (scripts/test-setup.sh)' : false },
  async () => {
    const port = await closedPort();
    const url = new URL(`${SMALL_CLUSTER!}/postgres`);
    url.host = `127.0.0.1:${port}`;
    let stopped: (code: number | undefined) => void = () => {};
    const exited = new Promise<number | undefined>((resolve) => (stopped = resolve));
    const exit = mock.method(process, 'exit', ((code?: number) => stopped(code)) as typeof process.exit);
    const said = mock.method(console, 'error', () => {});
    try {
      const node = createCoffre({
        publicUrl: ORIGIN,
        database: url.href,
        vault: { call: async () => assert.fail('the vault was called') },
        auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
        auditChainKey: randomBytes(32).toString('base64'),
      });
      const readyz = async () => {
        const request = new Request(`${ORIGIN}/readyz`);
        return node.request(request).coffre.route(request);
      };
      assert.equal((await readyz()).status, 503);
      // The first attempt failed on the closed port, and stopped nothing.
      await new Promise((resolve) => setTimeout(resolve, 200));
      assert.equal(exit.mock.callCount(), 0);
      const back = await proxy(port, SMALL_CLUSTER!);
      try {
        assert.equal((await readyz()).status, 503);
        const code = await Promise.race([exited, new Promise((resolve) => setTimeout(() => resolve('still up'), 10_000))]);
        assert.equal(code, 1);
        assert.ok(said.mock.calls.some((call) => /max_connections/.test(String(call.arguments[0]))), 'the process said what it needs');
      } finally {
        await back.close();
      }
    } finally {
      exit.mock.restore();
      said.mock.restore();
    }
  },
);
