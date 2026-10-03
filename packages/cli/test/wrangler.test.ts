// What setup relies on in wrangler, held against the real one, at the
// version the Workers template pins: its token, its login's link and
// listener, and a deploy's secrets on stdin and custom-domain route, in a
// dry run. Nothing reaches Cloudflare: the login is answered with the wrong
// state, which wrangler refuses before it asks Cloudflare for a token.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { cloudflareToken, deploymentWrangler, said, stopWranglers } from '../src/cloudflare.ts';
import { editWorker } from '../src/deployment.ts';
import { templateDir } from '../src/init.ts';
import { Steps } from '../src/steps.ts';
import { cancelTerminals, fakeTerminal, realWrangler } from './fakes.ts';

// Whatever a failed test leaves waiting, a prompt, a wrangler on its port, goes: this file's process always ends.
after(() => {
  cancelTerminals();
  stopWranglers();
});

/** The real wrangler starts in a second or two, and bundles in a few more: a test that takes a minute has failed. */
const LIMIT = { timeout: 60_000 };

/** A Workers deployment whose wrangler is the real one, with a home of its own, so that no login of yours is read or written. */
function deployment(t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-wrangler-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  cpSync(templateDir('workers'), dir, { recursive: true, filter: (path) => !path.includes('node_modules') });
  mkdirSync(join(dir, 'node_modules', '.bin'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', '.bin', 'wrangler'), `#!/bin/sh\nexec '${process.execPath}' '${realWrangler()}' "$@"\n`);
  chmodSync(join(dir, 'node_modules', '.bin', 'wrangler'), 0o755);
  mkdirSync(join(dir, 'empty'));
  writeFileSync(join(dir, 'stub.js'), 'export default { fetch: () => new Response("ok") };\n');
  return dir;
}

/** The environment wrangler runs in, here: a home in the deployment, no CI, no token unless given. */
function isolated(dir: string, extra: NodeJS.ProcessEnv = {}): () => void {
  const saved = { ...process.env };
  for (const name of ['CI', 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_API_BASE_URL', 'NODE_OPTIONS']) delete process.env[name];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, '.config'), ...extra });
  return () => {
    for (const name of Object.keys(process.env)) if (!(name in saved)) delete process.env[name];
    Object.assign(process.env, saved);
  };
}

test('with CLOUDFLARE_API_TOKEN, the token is wrangler\'s answer, and no login runs', LIMIT, async (t) => {
  const dir = deployment(t);
  const restore = isolated(dir, { CLOUDFLARE_API_TOKEN: 'cf-api-token-for-a-machine-without-a-browser' });
  try {
    const terminal = fakeTerminal();
    const steps = new Steps(terminal.out, ['Sign in to Cloudflare'], () => terminal.keys, String);
    let token = '';
    await steps.run(0, async (step) => ((token = await cloudflareToken(deploymentWrangler(dir), step, () => assert.fail('a login'))), 'Signed in'));
    steps.end();
    assert.equal(token, 'cf-api-token-for-a-machine-without-a-browser');
  } finally {
    restore();
  }
});

/** Whether nothing listens on `port` on localhost, as wrangler's login needs. */
function free(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createServer().once('error', () => resolve(false));
    probe.listen(port, 'localhost', () => probe.close(() => resolve(true)));
  });
}

/** Whether something accepts connections on localhost at `port`. */
function listening(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect(port, 'localhost', () => {
      socket.destroy();
      resolve(true);
    }).on('error', () => resolve(false));
  });
}

test("wrangler's login prints the link setup reads, and its listener takes the address pasted back", LIMIT, async (t) => {
  if (!(await free(8976))) return t.skip('something listens on localhost:8976, where wrangler logs in');
  const dir = deployment(t);
  const restore = isolated(dir);
  const terminal = fakeTerminal();
  const steps = new Steps(terminal.out, ['Sign in to Cloudflare'], () => terminal.keys, String);
  try {
    const links: string[] = [];
    const signing = steps.run(0, async (step) => (await cloudflareToken(deploymentWrangler(dir), step, (_label, address) => links.push(address)), 'Signed in'));
    signing.catch(() => {});
    const refused = assert.rejects(signing);
    for (let tries = 0; links.length === 0; tries += 1) {
      assert.ok(tries < 600, 'no link from wrangler login');
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const link = new URL(links[0]!);
    assert.equal(link.origin, 'https://dash.cloudflare.com');
    assert.equal(link.searchParams.get('redirect_uri'), 'http://localhost:8976/oauth/callback');
    // wrangler prints its link before it listens: the test pastes once it does (setup itself would try again for a while).
    for (let tries = 0; !(await listening(8976)); tries += 1) {
      assert.ok(tries < 200, 'wrangler never listened on localhost:8976');
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    // The browser's way back, but for another login: wrangler hears it, refuses it, and stops, asking Cloudflare nothing.
    terminal.keys.write('http://127.0.0.1:8976/oauth/callback?code=not-a-code&state=another-login\r');
    await refused;
    await assert.rejects(signing, (error: Error) => {
      assert.match(error.message, /Cloudflare sign-in failed: .*doesn't match the one sent/);
      assert.ok(!error.message.includes('\x1b'), 'no colour codes in what setup shows');
      return true;
    });
  } finally {
    steps.end();
    restore();
  }
});

test('a dry run of the real wrangler reads the secrets on stdin, shows only their names, and holds the route to a custom domain\'s rules', LIMIT, async (t) => {
  const dir = deployment(t);
  const restore = isolated(dir);
  try {
    const wrangler = deploymentWrangler(dir);
    // The app's wrangler.jsonc as setup fills it in.
    editWorker(dir, 'app/wrangler.jsonc', [
      { path: ['name'], value: 'coffre-try' },
      { path: ['account_id'], value: 'acc-acme', after: 'name' },
      { path: ['services', 0, 'service'], value: 'coffre-try-vault' },
      { path: ['vars', 'PUBLIC_URL'], value: 'https://coffre-try.acme.test' },
      { path: ['vars', 'GITHUB_CLIENT_ID'], value: 'Iv23liabcdef' },
      { path: ['hyperdrive', 0, 'id'], value: '0123456789abcdef0123456789abcdef' },
      { path: ['routes'], value: [{ pattern: 'coffre-try.acme.test', custom_domain: true }], after: 'workers_dev' },
    ]);
    const secrets = { APP_KEY: 'app-key-value-never-shown', GITHUB_CLIENT_SECRET: 'client-secret-value-never-shown' };
    const dry = (config: string) =>
      wrangler(['deploy', 'stub.js', '--assets', 'empty', '--dry-run', '-c', config, '--secrets-file', '/dev/stdin'], { input: JSON.stringify(secrets) });

    const run = await dry('app/wrangler.jsonc');
    assert.equal(run.code, 0, said(run));
    const output = run.stdout + run.stderr;
    assert.match(output, /env\.APP_KEY \("\(hidden\)"\)/);
    assert.match(output, /env\.GITHUB_CLIENT_SECRET \("\(hidden\)"\)/);
    assert.match(output, /env\.HYPERDRIVE \(0123456789abcdef0123456789abcdef\)/);
    assert.match(output, /env\.VAULT \(coffre-try-vault\)/);
    for (const value of Object.values(secrets)) assert.ok(!output.includes(value), 'a secret in what wrangler printed');

    // The same with a path in the route: the rules hold in a dry run, so the run above passed them.
    editWorker(dir, 'app/wrangler.jsonc', [{ path: ['routes', 0, 'pattern'], value: 'coffre-try.acme.test/x' }]);
    const refused = await dry('app/wrangler.jsonc');
    assert.equal(refused.code, 1);
    assert.match(said(refused), /Paths are not allowed in Custom Domains/);
  } finally {
    restore();
  }
});
