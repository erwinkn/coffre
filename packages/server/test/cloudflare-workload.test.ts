// The Cloudflare binding (docs/design/workload-access.md, section 9.2), in
// workerd, as two Workers of an account run it: coffre's
// (test/workers/workload-coffre-worker.ts), which exports `CoffreWorkload`,
// and an app's (test/workers/workload-caller-worker.ts), which binds it
// several times, each binding's props its own. Props are the caller's
// proof: a binding without props naming a service, or naming one with no
// cloudflare binding, gets nothing. Postgres only, as coffre's Worker
// reaches its database over Hyperdrive.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createTestHarness, type TestHarness } from 'wrangler';

import { propsService } from '../src/cloudflare-workload.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { deps, useMcp } from './mcp-fixture.ts';

const skip = TEST_ENGINE !== 'postgres' ? "coffre's Worker reaches its database over Hyperdrive, Postgres" : false;
const COFFRE = 'coffre-workload-test';

let dir: string;
let harness: TestHarness | undefined;

useMcp(async () => {});

/** The two Workers, once the suite's instance exists: coffre's is given its keys. */
async function boot(): Promise<TestHarness> {
  if (harness !== undefined) return harness;
  dir = mkdtempSync(join(tmpdir(), 'coffre-workload-'));
  const worker = (name: string) => fileURLToPath(new URL(`./workers/${name}`, import.meta.url));
  const binding = (name: string, props?: Record<string, unknown>) => ({ binding: name, service: COFFRE, entrypoint: 'CoffreWorkload', ...(props === undefined ? {} : { props }) });
  writeFileSync(
    join(dir, 'coffre.json'),
    JSON.stringify({
      name: COFFRE,
      main: worker('workload-coffre-worker.ts'),
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { APP_KEY: deps.chainKey.toString('base64'), VAULT_KEY: (deps.vault as unknown as { kek: Buffer }).kek.toString('base64'), UPSTREAM: 'http://127.0.0.1:9' },
      hyperdrive: [
        { binding: 'HYPERDRIVE', id: 'coffre-app', localConnectionString: TEST_RUNTIME_DATABASE_URL },
        { binding: 'VAULT_HYPERDRIVE', id: 'coffre-vault', localConnectionString: TEST_VAULT_DATABASE_URL },
      ],
      services: [{ binding: 'VAULT', service: COFFRE, entrypoint: 'Vault' }],
    }),
  );
  writeFileSync(
    join(dir, 'caller.json'),
    JSON.stringify({
      name: 'coffre-workload-caller',
      main: worker('workload-caller-worker.ts'),
      compatibility_date: '2026-08-06',
      services: [
        binding('COFFRE', { service: 'edge-api' }),
        binding('UNBOUND', { service: 'ghost' }),
        binding('NO_PROPS'),
        binding('EXTRA', { service: 'edge-api', place: 'market/prod' }),
        binding('NUMBER', { service: 42 }),
      ],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  harness = createTestHarness({ root: dir, workers: [{ configPath: join(dir, 'caller.json') }, { configPath: join(dir, 'coffre.json') }] });
  await harness.listen();
  return harness;
}

after(async () => {
  await harness?.close();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
});

/** What the caller's call through `binding` returned, or threw. */
async function call(binding: string, op: string, more: Record<string, string> = {}): Promise<{ status?: number; body?: string; answer?: unknown; threw?: string }> {
  const answered = await (await boot()).fetch(`/?${new URLSearchParams({ binding, op, ...more })}`);
  assert.equal(answered.status, 200, await answered.clone().text());
  return (await answered.json()) as { status?: number; body?: string; answer?: unknown; threw?: string };
}

test('props name a service, exactly: `edge-api` or `token:edge-api`, and no other field', () => {
  assert.equal(propsService({ service: 'edge-api' }), 'token:edge-api');
  assert.equal(propsService({ service: 'token:edge-api' }), 'token:edge-api');
  for (const props of [undefined, null, 'edge-api', ['edge-api'], {}, { service: 42 }, { service: '' }, { service: 'Edge-API' }, { service: 'edge api' }, { service: 'user:ada@acme.example' }, { service: 'token:' }, { service: 'edge-api', place: 'market/prod' }, { Service: 'edge-api' }]) {
    assert.equal(propsService(props), null, JSON.stringify(props));
  }
});

test('a binding without props naming a service gets nothing, through fetch or any RPC method', { skip, timeout: 180_000 }, async () => {
  for (const binding of ['NO_PROPS', 'EXTRA', 'NUMBER']) {
    const fetched = await call(binding, 'fetch');
    assert.equal(fetched.status, 401, `${binding}: ${fetched.body}`);
    assert.equal((JSON.parse(fetched.body!) as { reason: string }).reason, 'props');
    for (const op of ['sign', 'verify', 'presign']) {
      const answered = await call(binding, op);
      assert.equal(answered.answer, undefined, `${binding} ${op} got ${JSON.stringify(answered.answer)}`);
      assert.match(answered.threw ?? '', /without props naming its service/, `${binding} ${op}`);
    }
  }
});

test("a binding reaches the proxy's paths only, never the API, sign-in or the pages", { skip, timeout: 180_000 }, async () => {
  for (const path of ['/api/members', '/auth/login', '/', '/useless', '/mcp']) {
    const answered = await call('COFFRE', 'fetch', { path });
    assert.equal(answered.status, 404, `${path}: ${answered.body}`);
  }
});

test('a binding whose props name a service with no cloudflare binding gets nothing', { skip, timeout: 180_000 }, async () => {
  const fetched = await call('UNBOUND', 'fetch');
  assert.ok(fetched.status! >= 400, `${fetched.status}: ${fetched.body}`);
  for (const op of ['sign', 'verify', 'presign']) {
    const answered = await call('UNBOUND', op);
    assert.equal(answered.answer, undefined, `${op} got ${JSON.stringify(answered.answer)}`);
    assert.ok(answered.threw !== undefined, op);
  }
});

test('an RPC call names its place as <project>/<environment>, or none', { skip, timeout: 180_000 }, async () => {
  for (const place of ['market', 'market/prod/extra', '/prod']) {
    const answered = await call('COFFRE', 'sign', { place });
    assert.match(answered.threw ?? '', /place names an environment/, place);
  }
});

test("props naming a service reach the proxy's route, on the call's own database", { skip, timeout: 180_000 }, async () => {
  const fetched = await call('COFFRE', 'fetch');
  assert.equal(fetched.status, 501, fetched.body ?? '');
  assert.equal((JSON.parse(fetched.body!) as { reason: string }).reason, 'unbuilt');
});
