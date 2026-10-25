import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { clash, environmentPaths } from '../src/environments.ts';
import { signedInWithToken } from './fakes.ts';
import { inTerminal, ptySkip } from './pty.ts';

const TOKEN = `coffre_cli_${'s'.repeat(43)}`;

test('environments are named as <project>/<environment>, each once', () => {
  assert.deepEqual(environmentPaths(['deploy/prod', 'auth/prod']), ['deploy/prod', 'auth/prod']);
  assert.throws(() => environmentPaths([]), /name an environment/);
  assert.throws(() => environmentPaths(['deploy/prod/KEY']), /expected <project>\/<environment>, not "deploy\/prod\/KEY"/);
  assert.throws(() => environmentPaths(['deploy/prod', 'deploy/prod']), /deploy\/prod is named twice/);
});

test('a clash names each key and both environments that define it, by the pair', () => {
  assert.equal(clash([['deploy/prod', ['A', 'B']], ['auth/prod', ['C']]]), null);
  assert.equal(
    clash([['deploy/prod', ['A', 'TOKEN', 'URL']], ['auth/prod', ['URL', 'TOKEN']], ['www/prod', ['A']]]),
    'deploy/prod and auth/prod both define TOKEN and URL; deploy/prod and www/prod both define A',
  );
});

type Listed = {
  key: string;
  version: number | null;
  archived?: boolean;
  reference?: { state: string; source?: string; version?: number | null; createdBy?: string };
  updatedAt?: string | null;
  updatedBy?: string | null;
  parent?: { from: string; state: 'inherited' | 'overridden' | 'removed'; changed: boolean; reset: boolean; held: boolean } | null;
};
type Environment = {
  values: Record<string, string>;
  listed?: Listed[];
  refused?: number;
  /** The reasons its reads answer 409 `conflict` with, one apiece, before it reads as asked. */
  conflicts?: string[];
  /** The instance's threshold, 365 if not given; `'unsaid'` for an instance before it, which leaves it out. */
  rotateAfterDays?: number | null | 'unsaid';
  /** Read whole, whatever keys it is asked for, as an instance before 0.12. */
  whole?: boolean;
};

/** A coffre holding these environments, which keeps every request it is sent. */
async function instance(t: test.TestContext, environments: Record<string, Environment>) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const requests: string[] = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    const listing = /^\/api\/secrets\/([^/]+)\/([^/]+)$/.exec(req.url ?? '');
    const asked = listing === null ? (JSON.parse(body || '{}') as { path?: string; keys?: string[] }) : {};
    const path = listing === null ? asked.path : `${listing[1]}/${listing[2]}`;
    requests.push(`${listing === null ? 'reveal' : 'list'} ${path}${asked.keys === undefined ? '' : `: ${asked.keys.join(' ')}`}`);
    const environment = path === undefined ? undefined : environments[path.split('/').slice(0, 2).join('/')];
    if (environment === undefined) return send(404, { error: 'not_found', message: 'unknown project or environment' });
    if (environment.refused !== undefined) return send(environment.refused, { error: 'forbidden', message: 'you do not have permission to do that' });
    if (listing !== null) {
      const keys = environment.listed ?? Object.keys(environment.values).map((key) => ({ key, version: 1 }));
      return send(200, {
        permissions: ['secret.read'],
        keys: keys.map((key) => ({ archived: false, reference: null, folder: null, updatedAt: null, updatedBy: null, ...key })),
        ...(environment.rotateAfterDays === 'unsaid' ? {} : { rotateAfterDays: environment.rotateAfterDays === undefined ? 365 : environment.rotateAfterDays }),
      });
    }
    const conflict = environment.conflicts?.shift();
    if (conflict !== undefined) return send(409, { error: 'conflict', message: 'the access policy changed while this was answered: try again', reason: conflict });
    const { keys } = asked;
    send(200, { operationId: 'op', values: keys === undefined || environment.whole ? environment.values : Object.fromEntries(Object.entries(environment.values).filter(([key]) => keys.includes(key))) });
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  signedInWithToken(home, `http://127.0.0.1:${address.port}`, TOKEN);

  const environment = () => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_') && key !== 'GITHUB_ENV'));
    return Object.assign(env, { COFFRE_STATE_DIR: home, HOME: home });
  };

  return {
    requests,
    environment,
    /** `extra` is set over the caller's environment; a key given as undefined is unset in it. */
    async coffre(args: string[], extra: Record<string, string | undefined> = {}) {
      const env: Record<string, string | undefined> = Object.assign(environment(), extra);
      const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
      child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
      const [code] = await once(child, 'close');
      return { code, stdout, stderr };
    },
  };
}

/** A command that prints the variables named, as run hands them to it. */
const printing = (...keys: string[]) => [process.execPath, '-e', `process.stdout.write(JSON.stringify(Object.fromEntries(${JSON.stringify(keys)}.map((k) => [k, process.env[k] ?? null]))))`];

test('run of several environments injects their union, each read once, after each is listed', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { CLOUDFLARE_API_TOKEN: 'cf-secret', DATABASE_URL: 'postgres://x' } },
    'auth/prod': { values: { GITHUB_CLIENT_SECRET: 'gh-secret' } },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('CLOUDFLARE_API_TOKEN', 'DATABASE_URL', 'GITHUB_CLIENT_SECRET')]);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { CLOUDFLARE_API_TOKEN: 'cf-secret', DATABASE_URL: 'postgres://x', GITHUB_CLIENT_SECRET: 'gh-secret' });
  assert.deepEqual(coffre.requests, ['list deploy/prod', 'list auth/prod', 'reveal deploy/prod', 'reveal auth/prod']);
});

test('run overwrites a variable the shell sets, unless --keep-existing keeps it, empty ones too, and says which by name', async (t) => {
  const coffre = await instance(t, { 'deploy/prod': { values: { STRIPE_KEY: 'coffre-stripe-value', EMPTY_HERE: 'coffre-empty-value', FRESH: 'coffre-fresh-value' } } });
  // The caller's own environment may set any of these.
  const unset = { STRIPE_KEY: undefined, EMPTY_HERE: undefined, FRESH: undefined };
  const shell = { ...unset, STRIPE_KEY: 'sk_test_x', EMPTY_HERE: '' };
  const show = printing('STRIPE_KEY', 'EMPTY_HERE', 'FRESH');

  const overwriting = await coffre.coffre(['run', 'deploy/prod', '--', ...show], shell);
  assert.equal(overwriting.code, 0, overwriting.stderr);
  assert.deepEqual(JSON.parse(overwriting.stdout), { STRIPE_KEY: 'coffre-stripe-value', EMPTY_HERE: 'coffre-empty-value', FRESH: 'coffre-fresh-value' });
  assert.equal(overwriting.stderr, '');

  for (const args of [['run', '--keep-existing', 'deploy/prod', '--', ...show], ['run', 'deploy/prod', '--keep-existing', '--', ...show]]) {
    const keeping = await coffre.coffre(args, shell);
    assert.equal(keeping.code, 0, keeping.stderr);
    assert.deepEqual(JSON.parse(keeping.stdout), { STRIPE_KEY: 'sk_test_x', EMPTY_HERE: '', FRESH: 'coffre-fresh-value' });
    assert.equal(keeping.stderr, "coffre: kept the value already set in your environment for EMPTY_HERE, STRIPE_KEY, not coffre's\n");
    assert.ok(!keeping.stderr.includes('sk_test_x') && !keeping.stderr.includes('coffre-stripe-value'), 'a value was printed');
  }

  // Nothing set in the shell, nothing kept, nothing said.
  const untouched = await coffre.coffre(['run', '--keep-existing', 'deploy/prod', '--', ...show], unset);
  assert.equal(untouched.code, 0, untouched.stderr);
  assert.deepEqual(JSON.parse(untouched.stdout), { STRIPE_KEY: 'coffre-stripe-value', EMPTY_HERE: 'coffre-empty-value', FRESH: 'coffre-fresh-value' });
  assert.equal(untouched.stderr, '');
});

test('--keep-existing across several environments keeps the union\'s shell-set keys, and a clash still stops run', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { TOKEN: 'deploy-token-value', URL: 'deploy-url-value' } },
    'auth/prod': { values: { SECRET: 'auth-secret-value' } },
    'www/prod': { values: { TOKEN: 'www-token-value' } },
  });
  const unset = { TOKEN: undefined, URL: undefined, SECRET: undefined };
  const merged = await coffre.coffre(['run', '--keep-existing', 'deploy/prod', 'auth/prod', '--', ...printing('TOKEN', 'URL', 'SECRET')], { ...unset, TOKEN: 'mine' });
  assert.equal(merged.code, 0, merged.stderr);
  assert.deepEqual(JSON.parse(merged.stdout), { TOKEN: 'mine', URL: 'deploy-url-value', SECRET: 'auth-secret-value' });

  // The shell's TOKEN settles nothing between two environments that both define it.
  const clashing = await coffre.coffre(['run', '--keep-existing', 'deploy/prod', 'www/prod', '--', ...printing('TOKEN')], { ...unset, TOKEN: 'mine' });
  assert.equal(clashing.code, 1);
  assert.equal(clashing.stdout, '', 'the command ran');
  assert.equal(clashing.stderr, 'coffre: deploy/prod and www/prod both define TOKEN: a key comes from one environment only. Nothing was read\n');
});

test('run of one environment reads it as it always did, without listing it first', async (t) => {
  const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 'one' } } });
  const run = await coffre.coffre(['run', 'deploy/prod', '--', ...printing('TOKEN')]);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { TOKEN: 'one' });
  assert.deepEqual(coffre.requests, ['reveal deploy/prod']);
});

test('a key two environments define stops run before any value is read, naming it and both, not its values', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { API_URL: 'deploy-url-value', TOKEN: 'deploy-token-value', ONLY_HERE: 'x' } },
    'auth/prod': { values: { API_URL: 'auth-url-value', TOKEN: 'auth-token-value' } },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('API_URL')]);
  assert.equal(run.code, 1);
  assert.equal(run.stdout, '', 'the command ran');
  assert.equal(run.stderr, 'coffre: deploy/prod and auth/prod both define API_URL and TOKEN: a key comes from one environment only. Nothing was read\n');
  assert.deepEqual(coffre.requests, ['list deploy/prod', 'list auth/prod']);
});

test('archived keys and keys without a value clash with nothing, as run reads neither', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { TOKEN: 'deploy' }, listed: [{ key: 'TOKEN', version: 1 }, { key: 'OLD', version: 3, archived: true }, { key: 'EMPTY', version: null }] },
    'auth/prod': { values: { OLD: 'auth', EMPTY: 'auth' } },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('TOKEN', 'OLD', 'EMPTY')]);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { TOKEN: 'deploy', OLD: 'auth', EMPTY: 'auth' });
});

test('an environment refused, unknown or holding a reference that cannot be read stops run before any value is read', async (t) => {
  const cases: [Record<string, Environment>, string][] = [
    [{ 'auth/prod': { values: {}, refused: 403 } }, 'coffre: auth/prod: you do not have permission to do that. Nothing was read\n'],
    [{}, 'coffre: auth/prod: unknown project or environment. Nothing was read\n'],
    [
      { 'auth/prod': { values: {}, listed: [{ key: 'SHARED', version: null, reference: { state: 'source_archived' } }] } },
      'coffre: auth/prod/SHARED is a reference that cannot be read (source archived): `coffre references auth/prod` says more. Nothing was read\n',
    ],
  ];
  for (const [auth, said] of cases) {
    const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 'deploy-token-value' } }, ...auth });
    const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('TOKEN')]);
    assert.equal(run.code, 1);
    assert.equal(run.stdout, '', 'the command ran');
    assert.equal(run.stderr, said);
    assert.deepEqual(coffre.requests, ['list deploy/prod', 'list auth/prod'], 'a value was read');
  }
});

test('a key that came to clash between listing and reading still stops run, its values unused', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { TOKEN: 'deploy-token-value' } },
    'auth/prod': { values: { TOKEN: 'auth-token-value' }, listed: [] },
  });
  const run = await coffre.coffre(['run', 'deploy/prod', 'auth/prod', '--', ...printing('TOKEN')]);
  assert.equal(run.code, 1);
  assert.equal(run.stdout, '', 'the command ran');
  assert.equal(run.stderr, 'coffre: deploy/prod and auth/prod both define TOKEN, as read just now. No value was used, and the reads are in the audit log\n');
});

test('run and export refuse an environment named twice, or a secret in place of one, before any request', async (t) => {
  const coffre = await instance(t, {});
  for (const args of [['run', 'deploy/prod', 'deploy/prod', '--', 'true'], ['export', 'deploy/prod/TOKEN']]) {
    const run = await coffre.coffre(args);
    assert.equal(run.code, 2);
    assert.match(run.stderr, /^coffre: (deploy\/prod is named twice|expected <project>\/<environment>, not "deploy\/prod\/TOKEN")\n/);
  }
  assert.deepEqual(coffre.requests, []);
});

test('export of several environments prints their union, and refuses a clash as run does', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { B: 'deploy', A: 'deploy' } },
    'auth/prod': { values: { C: 'auth' } },
    'www/prod': { values: { A: 'www-value' } },
  });
  const union = await coffre.coffre(['export', 'deploy/prod', 'auth/prod', '--format', 'json']);
  assert.equal(union.code, 0, union.stderr);
  assert.equal(union.stdout, `${JSON.stringify({ A: 'deploy', B: 'deploy', C: 'auth' }, null, 2)}\n`);
  const clashing = await coffre.coffre(['export', '--format', 'dotenv', 'deploy/prod', 'www/prod']);
  assert.equal(clashing.code, 1);
  assert.equal(clashing.stdout, '');
  assert.equal(clashing.stderr, 'coffre: deploy/prod and www/prod both define A: a key comes from one environment only. Nothing was read\n');
});

test('export --keys lists first and reads only the keys it names, by name or prefix; an environment it names none of is not read', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { DATABASE_URL: 'db', STRIPE_KEY: 'sk', STRIPE_WEBHOOK: 'wh', SHARED: 'deploy', OTHER: 'x' } },
    'auth/prod': { values: { GITHUB_CLIENT_SECRET: 'gh', SHARED: 'auth' } },
    'www/prod': { values: { UNRELATED: 'y' } },
  });
  // SHARED, which two of them define, is no clash: it is not read.
  const run = await coffre.coffre(['export', 'deploy/prod', 'auth/prod', 'www/prod', '--keys', 'DATABASE_URL\nSTRIPE_*', '--keys=GITHUB_CLIENT_SECRET STRIPE_*', '--format', 'json']);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout, `${JSON.stringify({ DATABASE_URL: 'db', GITHUB_CLIENT_SECRET: 'gh', STRIPE_KEY: 'sk', STRIPE_WEBHOOK: 'wh' }, null, 2)}\n`);
  assert.equal(run.stderr, '');
  assert.deepEqual(coffre.requests, [
    'list deploy/prod', 'list auth/prod', 'list www/prod',
    'reveal deploy/prod: DATABASE_URL STRIPE_KEY STRIPE_WEBHOOK', 'reveal auth/prod: GITHUB_CLIENT_SECRET',
  ]);
  // Of one environment too: listed, then those keys only.
  coffre.requests.length = 0;
  const one = await coffre.coffre(['export', 'deploy/prod', '--keys', 'STRIPE_KEY', '--format', 'dotenv']);
  assert.equal(one.code, 0, one.stderr);
  assert.equal(one.stdout, 'STRIPE_KEY=sk\n');
  assert.deepEqual(coffre.requests, ['list deploy/prod', 'reveal deploy/prod: STRIPE_KEY']);
});

test('export --keys stops before anything is read on a name none of the environments holds, or a prefix that starts none of their keys', async (t) => {
  const coffre = await instance(t, {
    'deploy/prod': { values: { DATABASE_URL: 'db' }, listed: [{ key: 'DATABASE_URL', version: 1 }, { key: 'OLD_KEY', version: 2, archived: true }, { key: 'EMPTY', version: null }] },
    'auth/prod': { values: { TOKEN: 't' } },
  });
  const cases: [string, string][] = [
    ['DATABASE_URL DATABSE_URL', 'coffre: deploy/prod and auth/prod hold no key that --keys names as DATABSE_URL. Nothing was read\n'],
    ['DATABASE_URL STRIPE_*', 'coffre: deploy/prod and auth/prod hold no key that --keys names as STRIPE_*. Nothing was read\n'],
    // Archived, or without a value, a key is not one to export.
    ['TOKEN OLD_KEY EMPTY', 'coffre: deploy/prod and auth/prod hold no key that --keys names as OLD_KEY and EMPTY. Nothing was read\n'],
  ];
  for (const [keys, said] of cases) {
    coffre.requests.length = 0;
    const run = await coffre.coffre(['export', 'deploy/prod', 'auth/prod', '--keys', keys]);
    assert.equal(run.code, 1);
    assert.equal(run.stdout, '');
    assert.equal(run.stderr, said);
    assert.deepEqual(coffre.requests, ['list deploy/prod', 'list auth/prod'], keys);
  }
  coffre.requests.length = 0;
  const one = await coffre.coffre(['export', 'deploy/prod', '--keys', 'TOKEN']);
  assert.equal(one.stderr, 'coffre: deploy/prod holds no key that --keys names as TOKEN. Nothing was read\n');
  // A key two of them define clashes once named, as without --keys.
  const clashing = await instance(t, { 'deploy/prod': { values: { TOKEN: 'a' } }, 'auth/prod': { values: { TOKEN: 'b' } } });
  const named = await clashing.coffre(['export', 'deploy/prod', 'auth/prod', '--keys', 'TOK*']);
  assert.equal(named.stderr, 'coffre: deploy/prod and auth/prod both define TOKEN: a key comes from one environment only. Nothing was read\n');
  assert.deepEqual(clashing.requests, ['list deploy/prod', 'list auth/prod']);
});

test("export --keys says a parent's key the caller cannot read is inherited, not missing, and says a named key a workload only uses was left out", async (t) => {
  const fork = await instance(t, {
    'market/prod-eu': { values: {}, listed: [{ key: 'EU_REGION', version: 1 }, { key: 'STRIPE_KEY', version: null, parent: { from: 'prod', state: 'inherited', changed: false, reset: false, held: true } }] },
  });
  const hidden = await fork.coffre(['export', 'market/prod-eu', '--keys', 'EU_REGION STRIPE_*']);
  assert.equal(hidden.code, 1);
  assert.equal(hidden.stderr, 'coffre: market/prod-eu inherits STRIPE_KEY from market/prod, which you cannot read. Nothing was read\n');
  assert.deepEqual(fork.requests, ['list market/prod-eu']);

  const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const server = createServer((req, res) => {
    const send = (value: unknown) => res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    if (req.method === 'GET') return send({ keys: ['TOKEN', 'SIGNER'].map((key) => ({ key, version: 1, archived: false, reference: null })) });
    send({ operationId: 'op', values: { TOKEN: 't' }, sensitive: [], useOnly: ['SIGNER'], version: 'v' });
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  signedInWithToken(home, `http://127.0.0.1:${(server.address() as { port: number }).port}`, TOKEN);
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'export', 'deploy/prod', '--keys', 'TOKEN SIGNER', '--format', 'json'], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  assert.equal(code, 0, stderr);
  assert.deepEqual(JSON.parse(stdout), { TOKEN: 't' });
  assert.equal(stderr, "coffre: left out, which this workload only uses through coffre: SIGNER (its binding's reads do not list them)\n");
});

test('export --keys refuses every key, a malformed name and --watch before any request', async (t) => {
  const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 't' } } });
  const cases: [string[], RegExp, number][] = [
    [['--keys', '*'], /^coffre: --keys names keys, or the keys a prefix starts, STRIPE_\*, never all of them: `coffre run <project>\/<environment> -- <command>` hands every key to one process\n/, 2],
    [['--keys', ''], /^coffre: --keys names the keys to export/, 2],
    [['--keys', ' \n'], /^coffre: --keys names the keys to export/, 2],
    [['--keys', 'STRIPE_*_KEY'], /^coffre: --keys takes key names, or a prefix and \*, as STRIPE_\*, not "STRIPE_\*_KEY"\n/, 2],
    [['--keys', '1KEY'], /not "1KEY"/, 2],
    [['--keys', 'A-B'], /not "A-B"/, 2],
    [['--keys', `K${'E'.repeat(128)}`], /--keys takes key names/, 2],
    [['--keys', 'TOKEN', '--output-file', 'x', '--watch'], /^coffre: --watch keeps every key of its environments current: leave --keys out\n$/, 1],
  ];
  for (const [flags, said, code] of cases) {
    const run = await coffre.coffre(['export', 'deploy/prod', ...flags]);
    assert.equal(run.code, code, flags.join(' '));
    assert.match(run.stderr, said);
  }
  assert.deepEqual(coffre.requests, []);
});

test('export --keys from an instance before 0.12, which reads every key, exports only those named and says so', async (t) => {
  const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 't', OTHER: 'o' }, whole: true } });
  const run = await coffre.coffre(['export', 'deploy/prod', '--keys', 'TOKEN', '--format', 'json']);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { TOKEN: 't' });
  assert.equal(run.stderr, 'coffre: deploy/prod was read whole, as an instance before 0.12 reads it: only the keys --keys names are exported, and the audit log has every one\n');
});

test('export --keys stops on a key gone between listing and reading, its values unused', async (t) => {
  const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 't' }, listed: [{ key: 'TOKEN', version: 1 }, { key: 'GONE', version: 1 }] } });
  const run = await coffre.coffre(['export', 'deploy/prod', '--keys', 'TOKEN GONE', '--format', 'json']);
  assert.equal(run.code, 1);
  assert.equal(run.stdout, '');
  assert.equal(run.stderr, 'coffre: deploy/prod no longer holds GONE, as read just now. No value was used, and the read is in the audit log\n');
});

test('run, export and get read again, once, when the access policy changed under their read', async (t) => {
  const reads: [string[], (stdout: string) => void][] = [
    [['run', 'deploy/prod', '--', ...printing('TOKEN')], (stdout) => assert.deepEqual(JSON.parse(stdout), { TOKEN: 'deploy-token-value' })],
    [['export', 'deploy/prod', '--format', 'json'], (stdout) => assert.deepEqual(JSON.parse(stdout), { TOKEN: 'deploy-token-value' })],
    [['get', 'deploy/prod/TOKEN'], (stdout) => assert.equal(stdout, 'deploy-token-value')],
  ];
  for (const [args, check] of reads) {
    const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 'deploy-token-value' }, conflicts: ['policy_changed'] } });
    const read = await coffre.coffre(args);
    assert.equal(read.code, 0, read.stderr);
    check(read.stdout);
    assert.equal(read.stderr, '');
    assert.deepEqual(coffre.requests, [`reveal ${args[1]}`, `reveal ${args[1]}`], args[0]);
  }
});

test('--verbose says the read the policy changed under, that it asks again, and the read again', async (t) => {
  const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 'deploy-token-value' }, conflicts: ['policy_changed'] } });
  const read = await coffre.coffre(['--verbose', 'get', 'deploy/prod/TOKEN']);
  assert.equal(read.code, 0, read.stderr);
  assert.equal(read.stdout, 'deploy-token-value');
  assert.deepEqual(read.stderr.replace(/: (\d+) in \d+(\.\d)? m?s/g, ': $1 in t').split('\n'), [
    'coffre: POST /api/reveals: 409 in t',
    'coffre: the access policy changed while POST /api/reveals was answered: asking again in 300 ms',
    'coffre: POST /api/reveals: 200 in t',
    '',
  ]);
});

test('a read the policy changed under twice ends as a refusal does, and another conflict is not asked again', async (t) => {
  for (const [conflicts, reads] of [[['policy_changed', 'policy_changed'], 2], [['stale'], 1]] as const) {
    for (const args of [['export', 'deploy/prod'], ['get', 'deploy/prod/TOKEN']]) {
      const coffre = await instance(t, { 'deploy/prod': { values: { TOKEN: 'deploy-token-value' }, conflicts: [...conflicts] } });
      const read = await coffre.coffre(args);
      assert.equal(read.code, 1);
      assert.equal(read.stdout, '');
      assert.equal(read.stderr, 'coffre: request failed with status 409: the access policy changed while this was answered: try again\n');
      assert.deepEqual(coffre.requests, Array(reads).fill(`reveal ${args[1]}`), `${args[0]}, ${conflicts.join(' ')}`);
    }
  }
});

test("list of a fork says where each key stands to its parent's: inherited, overridden, removed", async (t) => {
  const today = new Date(Date.now() - 3_600_000).toISOString();
  const coffre = await instance(t, {
    'market/prod-eu': {
      values: {},
      rotateAfterDays: null,
      listed: [
        { key: 'DATABASE_URL', version: 1, updatedAt: today, updatedBy: 'cy@acme.example', parent: { from: 'prod', state: 'overridden', changed: true, reset: false, held: true } },
        { key: 'EU_REGION', version: 1, updatedAt: today, updatedBy: 'cy@acme.example' },
        { key: 'SENTRY_DSN', version: null, parent: { from: 'prod', state: 'removed', changed: false, reset: false, held: true } },
        { key: 'STALE_DSN', version: null, parent: { from: 'prod', state: 'removed', changed: false, reset: false, held: false } },
        { key: 'STRIPE_KEY', version: 2, updatedAt: today, updatedBy: 'ada@acme.example', parent: { from: 'prod', state: 'inherited', changed: false, reset: true, held: true } },
      ],
    },
  });
  const listed = await coffre.coffre(['list', 'market/prod-eu']);
  assert.equal(listed.code, 0, listed.stderr);
  assert.equal(listed.stdout, [
    'DATABASE_URL\tv1\tcy@acme.example\ttoday  (overrides prod; prod changed since)',
    'EU_REGION\tv1\tcy@acme.example\ttoday',
    'SENTRY_DSN\tv-\t-\t-  (removed here: not inherited from prod)',
    'STALE_DSN\tv-\t-\t-  (removed here: prod dropped it too)',
    'STRIPE_KEY\tv2\tada@acme.example\ttoday  (from prod; its own reset, and kept)',
    '',
  ].join('\n'));
});

test("list says how old each value is, a reference's its source's, flags those past the instance's rotateAfterDays, and lists only them", async (t) => {
  // An hour into each day, so that no day boundary falls between here and the CLI's clock.
  const ago = (days: number) => new Date(Date.now() - days * 86_400_000 - 3_600_000).toISOString();
  const coffre = await instance(t, {
    'deploy/prod': {
      values: {},
      rotateAfterDays: 90,
      listed: [
        { key: 'FRESH', version: 2, updatedAt: ago(0), updatedBy: 'ada@acme.example' },
        { key: 'OLD', version: 1, updatedAt: ago(91), updatedBy: 'bo@acme.example' },
        { key: 'SHARED', version: null, updatedAt: ago(400), reference: { state: 'live', source: 'auth/prod/SHARED', version: 4, createdBy: 'user:ada@acme.example' } },
        { key: 'GONE', version: 3, updatedAt: ago(500), updatedBy: 'bo@acme.example', archived: true },
        { key: 'EMPTY', version: null },
      ],
    },
    'www/prod': { values: {}, rotateAfterDays: null, listed: [{ key: 'OLD', version: 1, updatedAt: ago(1000), updatedBy: 'bo@acme.example' }] },
    'old/prod': { values: {}, rotateAfterDays: 'unsaid', listed: [{ key: 'OLD', version: 1, updatedAt: ago(1000), updatedBy: 'bo@acme.example' }] },
  });

  const all = await coffre.coffre(['list', 'deploy/prod']);
  assert.equal(all.code, 0, all.stderr);
  assert.equal(all.stdout, [
    'FRESH\tv2\tada@acme.example\ttoday',
    'OLD\tv1\tbo@acme.example\t91 days ago  (unchanged over 90 days: rotate it)',
    'SHARED\t→ auth/prod/SHARED\tv4\tada@acme.example\t400 days ago  (unchanged over 90 days: rotate it)',
    'GONE\tv3\tbo@acme.example\t500 days ago  (archived)',
    'EMPTY\tv-\t-\t-',
    '',
  ].join('\n'));

  const stale = await coffre.coffre(['list', 'deploy/prod', '--stale', '--json']);
  assert.equal(stale.code, 0, stale.stderr);
  assert.deepEqual((JSON.parse(stale.stdout) as Listed[]).map(({ key, updatedAt }) => [key, updatedAt !== null]), [['OLD', true], ['SHARED', true]]);
  const older = await coffre.coffre(['list', 'deploy/prod', '--older-than', '365d']);
  assert.equal(older.stdout.split('\n').filter(Boolean).map((line) => line.split('\t')[0]).join(' '), 'SHARED');

  // An instance that flags nothing has nothing for --stale, and says how else to ask; no flag on any line.
  const off = await coffre.coffre(['list', 'www/prod', '--stale']);
  assert.notEqual(off.code, 0);
  assert.match(off.stderr, /flags no value for rotation.*--older-than 90d/);
  assert.equal((await coffre.coffre(['list', 'www/prod'])).stdout, 'OLD\tv1\tbo@acme.example\t1000 days ago\n');

  // An instance before rotation ages says nothing of them: --stale would list nothing, so it refuses, and saying why.
  const old = await coffre.coffre(['list', 'old/prod', '--stale', '--json']);
  assert.notEqual(old.code, 0);
  assert.equal(old.stdout, '');
  assert.match(old.stderr, /older than rotation ages \(coffre 0\.6\).*upgrade it, or name an age, --older-than 90d/);
  assert.equal((await coffre.coffre(['list', 'old/prod'])).stdout, 'OLD\tv1\tbo@acme.example\t1000 days ago\n');
  assert.equal((await coffre.coffre(['list', 'old/prod', '--older-than', '90d'])).stdout, 'OLD\tv1\tbo@acme.example\t1000 days ago\n');

  for (const [args, message] of [[['--older-than', '3m'], /--older-than takes days, as 90d, not "3m"/], [['--stale', '--older-than', '9d'], /--stale or --older-than, not both/]] as const) {
    const refused = await coffre.coffre(['list', 'deploy/prod', ...args]);
    assert.notEqual(refused.code, 0);
    assert.match(refused.stderr, message);
  }
});

test('get piped writes the value byte for byte: no newline of its own, and the newlines it holds kept', async (t) => {
  const values = { PLAIN: 'k'.repeat(64), ENDS: 'ends with a newline\n', INSIDE: '-----BEGIN KEY-----\nline\r\nline\n-----END KEY-----', EMPTY: '', UNICODE: 'é→✓' };
  const coffre = await instance(t, { 'app/prod': { values } });
  for (const [key, value] of Object.entries(values)) {
    const get = await coffre.coffre(['get', `app/prod/${key}`]);
    assert.equal(get.code, 0, get.stderr);
    assert.equal(Buffer.from(get.stdout).toString('hex'), Buffer.from(value).toString('hex'), key);
  }
});

test('get in a terminal ends its line, so the prompt comes back on one of its own', { skip: ptySkip }, async (t) => {
  const coffre = await instance(t, { 'app/prod': { values: { PLAIN: 'visible-value' } } });
  const { output, code } = await inTerminal(['get', 'app/prod/PLAIN'], coffre.environment(), async () => {});
  assert.equal(code, 0, output);
  // The terminal turns the newline into CR LF.
  assert.equal(output, 'visible-value\r\n');
});

test("a terminal's Ctrl-C reaches a run's command, and the run waits for it; a SIGTERM to the run is passed on to its command", async (t) => {
  const { environment } = await instance(t, { 'market/dev': { values: { API_KEY: 'k' } } });
  const run = (script: string) =>
    spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'run', 'market/dev', '--', process.execPath, '-e', script], { env: environment(), stdio: ['ignore', 'pipe', 'ignore'] });
  // The command says when its handler is set, the run's set before it started: then the signal goes.
  const started = async (child: ReturnType<typeof run>) => {
    let said = '';
    for await (const chunk of child.stdout!) if ((said += String(chunk)).includes('ready')) return;
    assert.fail('the command never said it was ready');
  };
  // Its command answers SIGINT itself, as a psql at its prompt does: the run, sent it too by the terminal, keeps its listeners and waits.
  const interrupted = run("process.on('SIGINT', () => {}); console.log('ready'); setTimeout(() => process.exit(7), 1000)");
  await started(interrupted);
  interrupted.kill('SIGINT');
  assert.deepEqual(await once(interrupted, 'exit'), [7, null]);
  // A SIGTERM sent to the run alone ends its command, which the run does not leave behind.
  const terminated = run("process.on('SIGTERM', () => process.exit(9)); console.log('ready'); setTimeout(() => {}, 20000)");
  await started(terminated);
  terminated.kill('SIGTERM');
  assert.deepEqual(await once(terminated, 'exit'), [9, null]);
});

test("a person's export --keys, on an instance with the credential proxy, is refused before a handle is made or a key listed", async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const pat = `coffre_pat_${'p'.repeat(43)}`;
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    if (req.url === '/use') return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ proxy: 'coffre', credentials: [] }));
    res.writeHead(500).end();
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  signedInWithToken(home, `http://127.0.0.1:${port}`, pat);
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'export', 'market/dev', '--keys', 'DATABASE_URL'], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  assert.equal(code, 1);
  assert.equal(stderr, "coffre: --keys picks values, and a person's export here gets placeholders, which the credential proxy plans for whole environments: leave --keys out\n");
  assert.deepEqual(requests, ['GET /use']);
});

test("a person's run, on an instance with the credential proxy, gets placeholders: one handle, the plan's variables, and what it leaves out, said", async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const pat = `coffre_pat_${'p'.repeat(43)}`;
  const handle = `coffre_use_${'h'.repeat(43)}`;
  const requests: string[] = [];
  const labels: string[] = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    if (req.url === '/api/handles') labels.push((JSON.parse(body) as { label: string }).label);
    requests.push(`${req.method} ${req.url} ${req.headers.authorization === `Bearer ${handle}` ? 'handle' : req.headers.authorization === `Bearer ${pat}` ? 'token' : 'none'}`);
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    if (req.url === '/use') return send(200, { proxy: 'coffre', credentials: ['schumann'] });
    if (req.url === '/api/handles') return send(200, { id: 'h1', token: handle, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), scope: { 'market/dev': 'viewer' } });
    if (req.method === 'DELETE' && req.url === '/api/handles/h1') return send(200, { revoked: true });
    if (req.url === '/use/market/dev') {
      const at = `http://${req.headers.host}/use/market/dev/schumann`;
      // A placeholder shaped as its client checks it, a JWT here, is no value given as it is.
      return send(200, { environment: 'market/dev', env: { SCHUMANN_API_KEY: handle, WEBHOOK_SECRET: 'whsec_local', DFNS_AUTH_TOKEN: `e30.e30.${handle}` }, credentials: { schumann: at }, left: ['DATABASE_URL'] });
    }
    send(404, { error: 'not_found', message: `no route for ${req.url}` });
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  signedInWithToken(home, `http://127.0.0.1:${port}`, pat);
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'run', 'market/dev', '--', ...printing('SCHUMANN_API_KEY', 'SCHUMANN_BASE_URL', 'WEBHOOK_SECRET', 'DATABASE_URL', 'COFFRE_HANDLE', 'COFFRE_CREDENTIALS')], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  assert.equal(code, 0, stderr);
  const at = `http://127.0.0.1:${port}/use/market/dev/schumann`;
  // No base URL: the app's own config points at the proxy's stable URL, `/use/schumann`.
  assert.deepEqual(JSON.parse(stdout), {
    SCHUMANN_API_KEY: handle,
    SCHUMANN_BASE_URL: null,
    WEBHOOK_SECRET: 'whsec_local',
    DATABASE_URL: null,
    COFFRE_HANDLE: handle,
    COFFRE_CREDENTIALS: JSON.stringify({ schumann: at }),
  });
  assert.match(stderr, /placeholders for market\/dev: schumann/);
  assert.match(stderr, /values as they are, which you may read: WEBHOOK_SECRET$/m);
  assert.match(stderr, /left out, neither proxied nor yours to read: DATABASE_URL/);
  // Never a read of values: the proxy's question, one handle made with the token, the plan asked with the handle; and
  // once the command ended, the handle revoked, so that nothing the run started holds it after.
  assert.deepEqual(requests, ['GET /use token', 'POST /api/handles token', 'GET /use/market/dev handle', 'DELETE /api/handles/h1 token']);
  assert.match(labels[0]!, /^coffre run on .+: market\/dev$/);
});

test("a person's run carries each tunnel's connections to coffre, with the handle, on a listener of its own", async (t) => {
  const { WebSocketServer } = await import('ws');
  const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const pat = `coffre_pat_${'p'.repeat(43)}`;
  const handle = `coffre_use_${'t'.repeat(43)}`;
  const server = createServer(async (req, res) => {
    for await (const _ of req);
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    if (req.url === '/use') return send(200, { proxy: 'coffre', credentials: [] });
    if (req.url === '/api/handles') return send(200, { id: 'h1', token: handle, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), scope: {} });
    if (req.url === '/use/market/dev') return send(200, { environment: 'market/dev', env: {}, credentials: {}, tunnels: { db: { key: 'DATABASE_URL', url: `ws://${req.headers.host}/use/market/dev/db` } }, left: [] });
    send(404, { error: 'not_found', message: req.url });
  });
  // coffre's end of the tunnel: the handle checked, each byte echoed back with what it saw.
  const sockets = new WebSocketServer({ noServer: true });
  const asked: string[] = [];
  server.on('upgrade', (req, socket, head) => {
    asked.push(`${req.url} ${req.headers.authorization}`);
    sockets.handleUpgrade(req, socket, head, (ws) => ws.on('message', (data: Buffer) => ws.send(Buffer.concat([Buffer.from('echo:'), data]))));
  });
  t.after(() => new Promise<void>((resolve) => (sockets.close(), server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  signedInWithToken(home, `http://127.0.0.1:${port}`, pat);
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
  // The app: connects to DATABASE_URL's host and port, sends a byte string, prints the URL and what came back.
  const app = `const u = new URL(process.env.DATABASE_URL); const s = require('node:net').connect(Number(u.port), u.hostname, () => s.write('ping')); s.on('data', (d) => { console.log(JSON.stringify({ url: process.env.DATABASE_URL, got: String(d) })); s.destroy(); });`;
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'run', 'market/dev', '--', process.execPath, '-e', app], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  assert.equal(code, 0, stderr);
  const { url, got } = JSON.parse(stdout) as { url: string; got: string };
  assert.match(url, new RegExp(`^postgres://app:${handle}@127\\.0\\.0\\.1:\\d+/app\\?sslmode=disable$`));
  assert.equal(got, 'echo:ping');
  assert.deepEqual(asked, [`/use/market/dev/db Bearer ${handle}`]);
  assert.match(stderr, /DATABASE_URL through a tunnel to its database/);
});

test('a tunnel whose coffre never answers the upgrade gives up on it, closing the app connection', async () => {
  const { listen } = await import('../src/tunnels.ts');
  // A coffre that takes the connection and never answers it.
  const held: import('node:net').Socket[] = [];
  const silent = (await import('node:net')).createServer((socket) => held.push(socket));
  silent.listen(0, '127.0.0.1');
  await once(silent, 'listening');
  try {
    const { port } = silent.address() as { port: number };
    const tunnel = await listen({ key: 'DATABASE_URL', url: `ws://127.0.0.1:${port}/use/market/dev/db` }, `coffre_use_${'h'.repeat(43)}`, { handshakeMs: 1000 });
    const url = new URL(tunnel.url);
    const app = (await import('node:net')).connect(Number(url.port), url.hostname);
    await once(app, 'connect');
    app.write(Buffer.from([0, 0, 0, 8, 4, 210, 22, 47]));
    const started = Date.now();
    await once(app, 'close');
    // The listener waits its handshake's time (70 s unless told), past the time coffre has to answer with its own refusal.
    assert.ok(Date.now() - started < 5_000);
    tunnel.close();
  } finally {
    for (const socket of held) socket.destroy();
    silent.close();
  }
});

for (const raced of [false, true]) {
  test(`a person's run makes their own value of each key a recipe made, in their personal config, once${raced ? ': a run that lost the race reads the winner' : ''}`, async (t) => {
    const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
    t.after(() => rmSync(home, { recursive: true, force: true }));
    const pat = `coffre_pat_${'p'.repeat(43)}`;
    const handle = `coffre_use_${'h'.repeat(43)}`;
    const requests: string[] = [];
    const written: Record<string, { value: string; generated: { recipe: string }; replaces: string }>[] = [];
    // What the person's personal config holds: the winner's, when another run wrote first.
    let mine: string | null = null;
    const server = createServer(async (req, res) => {
      let body = '';
      for await (const chunk of req) body += String(chunk);
      const url = decodeURIComponent(req.url ?? '');
      requests.push(`${req.method} ${url}`);
      const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
      if (url === '/use') return send(200, { proxy: 'coffre', credentials: [] });
      if (url === '/api/handles') return send(200, { id: 'h1', token: handle, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), scope: { 'market/local': 'viewer' } });
      if (req.method === 'DELETE' && url === '/api/handles/h1') return send(200, { revoked: true });
      if (url === '/use/market/local') {
        return mine === null
          ? send(200, { environment: 'market/local', env: { REGION: 'eu' }, credentials: {}, left: ['SEAL_KEY', 'TYPED'], generate: { SEAL_KEY: { recipe: 'bytes:32:hex', replaces: 'v-local-1' } } })
          : send(200, { environment: 'market/local@me', env: { REGION: 'eu', SEAL_KEY: mine }, credentials: {}, left: ['TYPED'], generate: {} });
      }
      if (req.method === 'PATCH' && url === '/api/secrets/market/local@me') {
        written.push(JSON.parse(body) as (typeof written)[number]);
        if (raced) {
          mine = 'the-other-runs-value';
          return send(409, { error: 'conflict', reason: 'stale', message: 'SEAL_KEY changed since it was listed: it was written, rolled back or regenerated meanwhile. Nothing was written' });
        }
        mine = written[0]!.SEAL_KEY!.value;
        return send(200, { operationId: 'op', keys: { SEAL_KEY: { version: 1 } } });
      }
      send(404, { error: 'not_found', message: `no route for ${url}` });
    });
    t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as { port: number };
    signedInWithToken(home, `http://127.0.0.1:${port}`, pat);
    const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
    const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'run', 'market/local', '--', ...printing('SEAL_KEY', 'REGION')], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
    child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
    const [code] = await once(child, 'close');
    assert.equal(code, 0, stderr);
    // Made here by the recipe, sent with it and the version it replaces, never shown.
    assert.equal(written.length, 1);
    const { value, generated, replaces } = written[0]!.SEAL_KEY!;
    assert.match(value, /^[0-9a-f]{64}$/);
    assert.deepEqual([generated, replaces], [{ recipe: 'bytes:32:hex' }, 'v-local-1']);
    assert.ok(!stderr.includes(value));
    assert.deepEqual(JSON.parse(stdout), { SEAL_KEY: raced ? 'the-other-runs-value' : value, REGION: 'eu' });
    assert.equal(/made your own SEAL_KEY in market\/local@me/.test(stderr), !raced);
    assert.deepEqual(requests, ['GET /use', 'POST /api/handles', 'GET /use/market/local', 'PATCH /api/secrets/market/local@me', 'GET /use/market/local', 'DELETE /api/handles/h1']);
  });
}

test("a person's run says why their own value could not be made, rather than retry what never will", async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-run-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const pat = `coffre_pat_${'p'.repeat(43)}`;
  const handle = `coffre_use_${'h'.repeat(43)}`;
  let patches = 0;
  const server = createServer(async (req, res) => {
    for await (const chunk of req) void chunk;
    const url = decodeURIComponent(req.url ?? '');
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    if (url === '/use') return send(200, { proxy: 'coffre', credentials: [] });
    if (url === '/api/handles') return send(200, { id: 'h1', token: handle, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), scope: {} });
    if (url === '/use/market/deep') return send(200, { environment: 'market/deep', env: {}, credentials: {}, left: ['SEAL_KEY'], generate: { SEAL_KEY: { recipe: 'bytes:32', replaces: 'v1' } } });
    if (req.method === 'PATCH') {
      patches += 1;
      return send(409, { error: 'conflict', message: 'market/deep already inherits from 3 environments: it takes no personal config' });
    }
    send(404, { error: 'not_found', message: `no route for ${url}` });
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  signedInWithToken(home, `http://127.0.0.1:${port}`, pat);
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'run', 'market/deep', '--', 'true'], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  assert.equal(code, 1);
  assert.equal(patches, 1);
  assert.match(stderr, /market\/deep@me: market\/deep already inherits from 3 environments: it takes no personal config/);
});
