// `coffre setup` doing Cloudflare too, end to end, in a terminal: against a
// disposable cluster, and stand-ins for Cloudflare's API, GitHub, wrangler
// and a browser. A first run whose app deploy fails, the run that resumes
// it, one that finds everything done, a second deployment beside the first
// on one account, a third on the first's database server, and one that
// stops before changing a database in use.
// Every deploy is also the real wrangler's, in a dry run, on the same files
// and the same stdin.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import pg from 'pg';

import { editWorker, readWorker } from '../src/deployment.ts';
import { templateDir } from '../src/init.ts';
import { asSuperuser, CLUSTER, connects, database, emptyCluster, needsCluster, OTHER_CLUSTER } from './cluster.ts';
import { fakeCloudflare, fakeGitHub, fakeOpener, fakeVite, fakeWrangler, realWrangler, submitManifest } from './fakes.ts';
import { ENTER_ALT, inTerminal, ptySkip, screens, type Session, typingUrl, visible } from './pty.ts';

const skip = needsCluster.skip || ptySkip;
const TOKEN = `cf-oauth-${'t'.repeat(40)}`;
const ADDRESS = 'secrets.acme.test';

let dir: string;
let cloudflare: Awaited<ReturnType<typeof fakeCloudflare>>;
let github: Awaited<ReturnType<typeof fakeGitHub>>;
let live: ReturnType<typeof createServer>;
let env: NodeJS.ProcessEnv;
/** The database owner's URL setup is given, typed at its prompt. */
let url: string;

before(async () => {
  if (skip) return;
  await emptyCluster();
  if (OTHER_CLUSTER !== undefined) await emptyCluster(OTHER_CLUSTER);
  dir = mkdtempSync(join(tmpdir(), 'coffre-workers-'));
  cloudflare = await fakeCloudflare(TOKEN);
  github = await fakeGitHub();
  // coffre, deployed: what answers at its address.
  live = createServer((request, response) => response.writeHead(request.url === '/livez' ? 200 : 404).end('{"ok":true}'));
  await new Promise<void>((resolve) => live.listen(0, '127.0.0.1', resolve));
  const at = `http://127.0.0.1:${(live.address() as { port: number }).port}`;
  // Its addresses, which no resolver knows, reach it through a fetch that knows.
  writeFileSync(
    join(dir, 'network.mjs'),
    `const real = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  return real(url.hostname.endsWith('.acme.test') ? ${JSON.stringify(at)} + url.pathname : input, init);
};\n`,
  );
  const deployment = join(dir, 'deployment');
  cpSync(templateDir('workers'), deployment, { recursive: true, filter: (path) => !path.includes('node_modules') });
  // GitHub, as for GitHub Enterprise Server: at the addresses the app's vars give.
  editWorker(deployment, 'app/wrangler.jsonc', [
    { path: ['vars', 'GITHUB_URL'], value: github.github.web },
    { path: ['vars', 'GITHUB_API_URL'], value: github.github.api },
  ]);
  fakeWrangler(deployment, join(dir, 'wrangler'), TOKEN, realWrangler());
  fakeVite(deployment);
  fakeOpener(join(dir, 'bin'));
  url = await database('setup_workers', 'owner');
  env = {
    PATH: `${join(dir, 'bin')}:${process.env.PATH}`,
    HOME: dir,
    CLOUDFLARE_API_BASE_URL: cloudflare.url,
    NODE_OPTIONS: `--import=${join(dir, 'network.mjs')}`,
  };
});

after(async () => {
  if (skip) return;
  cloudflare.close();
  github.close();
  live.close();
  rmSync(dir, { recursive: true, force: true });
  await emptyCluster();
  if (OTHER_CLUSTER !== undefined) await emptyCluster(OTHER_CLUSTER);
});

/** Whether each of the first deployment's Hyperdrive configs still logs in. */
async function firstConnects(): Promise<boolean[]> {
  const configs = cloudflare.state.configs.get('acc-acme')!.filter(({ name }) => name === 'coffre' || name === 'coffre-vault');
  return Promise.all(configs.map(({ origin }) => connects(`postgresql://${origin.user}:${origin.password}@${origin.host}:${origin.port}/${origin.database}`)));
}

/** A copy of the template beside the first deployment, its GitHub the fake one, its wrangler the fake one. */
function another(name: string): string {
  const where = join(dir, name);
  cpSync(templateDir('workers'), where, { recursive: true, filter: (path) => !path.includes('node_modules') });
  editWorker(where, 'app/wrangler.jsonc', [
    { path: ['vars', 'GITHUB_URL'], value: github.github.web },
    { path: ['vars', 'GITHUB_API_URL'], value: github.github.api },
  ]);
  fakeWrangler(where, join(dir, 'wrangler'), TOKEN, realWrangler());
  fakeVite(where);
  return where;
}

const deployment = () => join(dir, 'deployment');

function setup(play: (terminal: Session) => Promise<void>, where = deployment(), databaseUrl = url) {
  return inTerminal(['setup'], env, typingUrl(databaseUrl, play), { columns: 160, rows: 48 }, where);
}

/** What the real wrangler said, in its dry run of a Worker's last deploy. */
const dryRun = (name: string) => readFileSync(join(dir, 'wrangler', `dry-${name}`), 'utf8');

type Call = { args: string[]; stdin: string; account: string | null };
function calls(): Call[] {
  const path = join(dir, 'wrangler', 'calls.jsonl');
  const all = existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').map((line) => JSON.parse(line) as Call) : [];
  rmSync(path, { force: true });
  return all;
}

// Each test's calls are its own: none left by one that failed before it read them.
beforeEach(() => {
  if (!skip) rmSync(join(dir, 'wrangler', 'calls.jsonl'), { force: true });
});

/** The addresses starting with `prefix` the browser was asked to open. */
function openedAll(prefix: string): string[] {
  const path = join(dir, 'bin', 'opened');
  return existsSync(path) ? readFileSync(path, 'utf8').split('\n').filter((line) => line.startsWith(prefix)) : [];
}

/** The address the browser was asked to open after the first `seen` starting with `prefix`, once it has been. */
async function opened(prefix: string, seen = 0): Promise<string> {
  for (let tries = 0; ; tries += 1) {
    const found = openedAll(prefix)[seen];
    if (found !== undefined) return found;
    if (tries === 200) throw new Error(`never opened ${prefix}…`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/** Yes to Cloudflare; the address and the root admins as they are offered, once signed in. */
async function answer(terminal: Session, address = ''): Promise<void> {
  await terminal.waitFor('Set Cloudflare up too?');
  terminal.send('\r');
  await terminal.waitFor("coffre's address");
  terminal.send(`${address}\r`);
  await terminal.waitFor('Root admins');
  terminal.send('\r');
}

/** Every secret this deployment has, none of which may reach the main screen, nor wrangler's arguments. */
const secrets = new Set<string>();

function assertKept(output: string, wrangler: Call[]): void {
  const { main } = screens(output);
  for (const secret of secrets) {
    assert.ok(!main.includes(secret), `a secret on the main screen: ${secret.slice(0, 6)}…`);
    for (const call of wrangler) assert.ok(!call.args.join(' ').includes(secret), "a secret in wrangler's arguments");
  }
}

/** What each screen showed, to read: escape codes out, lines ending as written. */
const mainText = (output: string) => visible(screens(output).main).replace(/\r\n/g, '\n');
const alternateText = (output: string) => visible(screens(output).alternate).replace(/\r\n/g, '\n');
const keysIn = (output: string) => [...new Set(alternateText(output).match(/[A-Za-z0-9+/]{43}=/g))];

test('a first run: signed in, Hyperdrive, the GitHub App and the files done; the keys shown, then the app deploy fails', { skip }, async () => {
  writeFileSync(join(dir, 'wrangler', 'fail-coffre'), '');
  secrets.add(new URL(url).password).add(TOKEN);
  const { output, code } = await setup(async (terminal) => {
    await terminal.waitFor('Set Cloudflare up too?');
    terminal.send('\r');
    // No browser reaches this machine: the address it failed at, pasted back.
    await terminal.waitFor('https://dash.cloudflare.com/oauth2/auth');
    const login = JSON.parse(readFileSync(join(dir, 'wrangler', 'login'), 'utf8')) as { port: number; state: string };
    terminal.send(`http://localhost:${login.port}/oauth/callback?code=cf-c0de&state=${login.state}\r`);
    await terminal.waitFor('Which Cloudflare account?');
    terminal.send('\r');
    await terminal.waitFor("coffre's address");
    terminal.send('secrets.other.test\r');
    await terminal.waitFor('not under a domain of this account: acme.test');
    terminal.send(`\x15${ADDRESS}\r`);
    await terminal.waitFor('Root admins');
    terminal.send('\r');
    // A browser on this machine: setup's page, GitHub's, and back.
    await terminal.waitFor("GitHub: create coffre's app");
    const page = await opened('http://127.0.0.1:');
    await fetch(await submitManifest(await (await fetch(page)).text()));
    await terminal.waitFor('reveal all');
    terminal.send('R');
    await terminal.waitFor('Vault key');
    terminal.send('q');
    await terminal.waitFor('Have you saved all three values?');
    terminal.send('y');
    await terminal.waitFor('Deploy the app');
  });
  const text = mainText(output);
  assert.equal(code, 1, text);
  assert.match(text, /✓ Signed in to Cloudflare as ops@acme\.test, account Acme/);
  assert.match(text, /✓ coffre's address {2}secrets\.acme\.test/);
  assert.match(text, /✓ Root admins {2}ops@acme\.test/);
  assert.match(text, /✓ Created coffre_runtime and coffre_vault_runtime/);
  assert.match(text, /✓ Hyperdrive configs coffre and coffre-vault, caching off\n\s+coffre\s+made, for coffre_runtime\n\s+coffre-vault\s+made, for coffre_vault_runtime/);
  assert.match(text, /✓ Made coffre's GitHub App, coffre-secrets-acme-test/);
  assert.match(
    text,
    /✓ Filled in app\/wrangler\.jsonc and vault\/wrangler\.jsonc\n\s+app\s+the account, Hyperdrive, GitHub's client ID, the address and its custom domain\n\s+vault\s+the account, Hyperdrive, the root admins and the vault ID\n/,
  );
  assert.match(text, /✓ Deployed the vault, coffre-vault, with its key/);
  assert.match(text, /✗ Deploy the app\n\s+wrangler could not deploy app\/dist\/server\/wrangler\.json/);
  assert.equal(text.split('\n').filter((line) => line.includes('✗')).at(-1), '  ✗ Deploy the app', 'its failure, said once, and nothing after');
  assert.match(alternateText(output), /Next, setup gives them to Cloudflare, which never shows them again/);
  assert.ok(!alternateText(output).includes('database URL'), 'the URLs live in Hyperdrive');

  // Hyperdrive has each login, with a password that works, and caching off.
  const configs = cloudflare.state.configs.get('acc-acme')!;
  assert.deepEqual(configs.map(({ name, origin, caching }) => [name, origin.user, caching.disabled]), [
    ['coffre', 'coffre_runtime', true],
    ['coffre-vault', 'coffre_vault_runtime', true],
  ]);
  for (const { origin } of configs) {
    secrets.add(origin.password);
    assert.ok(await connects(`postgresql://${origin.user}:${origin.password}@${origin.host}:${origin.port}/${origin.database}`));
  }
  // The keys shown are the ones the vault got, on stdin; the app's never went.
  const [appKey, vaultKey] = keysIn(output);
  const vaultId = /vault-\d{4}-\d{2}-\d{2}-[a-z2-7]{6}/.exec(alternateText(output))![0];
  secrets.add(appKey!).add(vaultKey!);
  const wrangler = calls();
  const deploys = wrangler.filter(({ args }) => args[0] === 'deploy');
  assert.deepEqual(deploys.map(({ args }) => args), [
    ['deploy', '-c', 'vault/wrangler.jsonc', '--secrets-file', '/dev/stdin'],
    ['deploy', '-c', 'app/dist/server/wrangler.json', '--secrets-file', '/dev/stdin'],
  ]);
  assert.deepEqual(JSON.parse(deploys[0]!.stdin), { VAULT_KEY: vaultKey });
  // The real wrangler read the same files, and the key from its stdin, which it named and never showed.
  assert.match(dryRun('coffre-vault'), /env\.VAULT_KEY \("\(hidden\)"\)/);
  assert.match(dryRun('coffre-vault'), new RegExp(`env\\.VAULT_HYPERDRIVE \\(${configs[1]!.id}\\)`));
  assert.ok(!dryRun('coffre-vault').includes(vaultKey!));
  const sent = JSON.parse(deploys[1]!.stdin) as { APP_KEY: string; GITHUB_CLIENT_SECRET: string };
  assert.equal(sent.APP_KEY, appKey);
  secrets.add(sent.GITHUB_CLIENT_SECRET);
  assertKept(output, wrangler);
  assert.ok(!output.includes('cf-c0de'), 'the pasted address');

  // Both files, filled in.
  const app = readWorker(deployment(), 'app/wrangler.jsonc');
  const vault = readWorker(deployment(), 'vault/wrangler.jsonc');
  assert.deepEqual([app.accountId, app.hyperdrive, app.route, app.vars.PUBLIC_URL], ['acc-acme', configs[0]!.id, ADDRESS, `https://${ADDRESS}`]);
  assert.match(app.vars.GITHUB_CLIENT_ID!, /^Iv23li/);
  assert.deepEqual([vault.accountId, vault.hyperdrive, vault.vars.ROOT_ADMINS, vault.vars.VAULT_KEY_ID], ['acc-acme', configs[1]!.id, 'ops@acme.test', vaultId]);
  assert.deepEqual(github.state.manifests.map((manifest) => manifest.callback_urls), [[`https://${ADDRESS}/auth/callback/github`]]);
});

test('the run after: the vault keeps its key; the app gets a new one, and a new client secret for the same GitHub App', { skip }, async () => {
  unlinkSync(join(dir, 'wrangler', 'fail-coffre'));
  const clientSecret = 'f'.repeat(40);
  secrets.add(clientSecret);
  const { output, code } = await setup(async (terminal) => {
    await answer(terminal);
    await terminal.waitFor('Paste the new client secret, hidden as you paste it');
    terminal.send(`${clientSecret}\r`);
    await terminal.waitFor('reveal all');
    terminal.send('R');
    await terminal.waitFor('Signs the app');
    terminal.send('q');
    await terminal.waitFor('Have you saved the value?');
    terminal.send('y');
    await terminal.waitFor('coffre is at');
  });
  const text = mainText(output);
  assert.equal(code, 0, text);
  assert.match(text, /✓ Kept coffre_runtime and coffre_vault_runtime, with their passwords/);
  assert.match(text, /coffre\s+kept\n\s+coffre-vault\s+kept/);
  assert.match(text, /✓ Took a new client secret for coffre's GitHub App/);
  assert.match(text, /✓ Deployed the vault, coffre-vault\n/);
  assert.match(text, /✓ Deployed the app, coffre, with its key and GitHub's secret/);
  assert.match(text, /✓ coffre answers at https:\/\/secrets\.acme\.test/);
  assert.match(text, /Sign in\s+https:\/\/secrets\.acme\.test, with GitHub, as ops@acme\.test/);
  const alternate = alternateText(output);
  assert.match(alternate, /App key/);
  assert.ok(!alternate.includes('Vault key'), 'the vault has its own');
  assert.match(alternate, /in place of the one an earlier run showed, which never reached Cloudflare/);
  const [appKey] = keysIn(output);
  secrets.add(appKey!);
  const wrangler = calls();
  const deploys = wrangler.filter(({ args }) => args[0] === 'deploy');
  assert.deepEqual(deploys.map(({ args }) => args.length), [3, 5]);
  assert.deepEqual(JSON.parse(deploys[1]!.stdin), { APP_KEY: appKey, GITHUB_CLIENT_SECRET: clientSecret });
  assert.match(dryRun('coffre'), /env\.APP_KEY \("\(hidden\)"\)[\s\S]*env\.GITHUB_CLIENT_SECRET \("\(hidden\)"\)/);
  assert.match(dryRun('coffre'), /env\.VAULT \(coffre-vault\)/);
  for (const value of [appKey!, clientSecret]) assert.ok(!dryRun('coffre').includes(value));
  assert.equal(cloudflare.state.configs.get('acc-acme')!.length, 2);
  assert.equal(github.state.manifests.length, 1, 'no second app');
  assertKept(output, wrangler);
});

test('a run with everything done: nothing made, nothing shown, both deployed again as they are', { skip }, async () => {
  const before = cloudflare.state.configs.get('acc-acme')!.map(({ origin }) => origin.password);
  const { output, code } = await setup((terminal) => answer(terminal));
  const text = mainText(output);
  assert.equal(code, 0, text);
  assert.ok(!output.includes(ENTER_ALT), 'no screen: nothing new to save');
  assert.match(text, /✓ Kept coffre's GitHub App, client ID Iv23li/);
  assert.match(text, /✓ app\/ and vault\/wrangler\.jsonc, as they were/);
  assert.match(text, /✓ coffre answers at/);
  const wrangler = calls();
  assert.deepEqual(wrangler.filter(({ args }) => args[0] === 'deploy').map(({ args }) => args), [
    ['deploy', '-c', 'vault/wrangler.jsonc'],
    ['deploy', '-c', 'app/dist/server/wrangler.json'],
  ]);
  assert.deepEqual(cloudflare.state.configs.get('acc-acme')!.map(({ origin }) => origin.password), before);
  assertKept(output, wrangler);
});

test("a second deployment on the same account: it takes names of its own, and the first's Workers and Hyperdrive configs stay as they were, byte for byte", { skip: skip || (OTHER_CLUSTER === undefined && 'needs a second cluster') }, async () => {
  const first = () =>
    JSON.stringify({
      configs: cloudflare.state.configs.get('acc-acme')!.filter(({ name }) => name === 'coffre' || name === 'coffre-vault'),
      workers: ['coffre', 'coffre-vault'].map((name) => {
        const { secrets: names, bindings } = cloudflare.state.scripts.get(`acc-acme/${name}`)!;
        return [name, [...names], bindings];
      }),
      files: ['app', 'vault'].map((component) => readFileSync(join(deployment(), component, 'wrangler.jsonc'), 'utf8')),
    });
  const before = first();
  assert.deepEqual(await firstConnects(), [true, true]);
  // Its database on a server of its own, as two deployments' must be: a login is the server's.
  await asSuperuser('postgres', (client) => client.query('CREATE DATABASE setup_workers_two'), OTHER_CLUSTER);
  const second = another('second');
  const pages = openedAll('http://127.0.0.1:').length;
  const { output, code } = await setup(
    async (terminal) => {
      await terminal.waitFor('Set Cloudflare up too?');
      terminal.send('\r');
      await terminal.waitFor('Which Cloudflare account?');
      terminal.send('\r');
      await terminal.waitFor("coffre's address");
      terminal.send('coffre-try.acme.test\r');
      await terminal.waitFor("This deployment's name");
      // The first's name, refused; then the one offered, from the address.
      terminal.send('\x15coffre\r');
      await terminal.waitFor("another deployment's too");
      terminal.send('\x15coffre-try\r');
      await terminal.waitFor('Root admins');
      terminal.send('\r');
      await terminal.waitFor("GitHub: create coffre's app");
      await fetch(await submitManifest(await (await fetch(await opened('http://127.0.0.1:', pages))).text()));
      await terminal.waitFor('reveal all');
      terminal.send('q');
      await terminal.waitFor('Have you saved all three values?');
      terminal.send('y');
      // Both deploys, each with the real wrangler's dry run, which bundles: slow on a loaded host.
      await terminal.waitFor('coffre is at', 60_000);
    },
    second,
    `${OTHER_CLUSTER}/setup_workers_two`,
  );
  const text = mainText(output);
  assert.equal(code, 0, text);
  assert.match(
    text,
    /On this account, the Worker coffre, the Hyperdrive config coffre, the Worker coffre-vault and the Hyperdrive config coffre-vault\s+are\s+another\s+deployment's\.\s+Setup leaves them as they are\./,
  );
  assert.match(text, /✓ This deployment's name {2}coffre-try/);
  assert.match(text, /✓ Hyperdrive configs coffre-try and coffre-try-vault, caching off/);
  assert.match(text, /✓ Deployed the app, coffre-try, with its key and GitHub's secret/);
  assert.match(text, /✓ coffre answers at https:\/\/coffre-try\.acme\.test/);

  assert.equal(first(), before, "the first deployment's Workers, Hyperdrive configs and files");
  assert.deepEqual(await firstConnects(), [true, true], "the first deployment's logins");
  const configs = cloudflare.state.configs.get('acc-acme')!.filter(({ name }) => name.startsWith('coffre-try'));
  assert.deepEqual(configs.map(({ name, origin }) => [name, origin.database]), [
    ['coffre-try', 'setup_workers_two'],
    ['coffre-try-vault', 'setup_workers_two'],
  ]);
  const app = readWorker(second, 'app/wrangler.jsonc');
  const vault = readWorker(second, 'vault/wrangler.jsonc');
  assert.deepEqual([app.name, app.hyperdrive, vault.name, vault.hyperdrive], ['coffre-try', configs[0]!.id, 'coffre-try-vault', configs[1]!.id]);
  assert.match(readFileSync(join(second, 'app', 'wrangler.jsonc'), 'utf8'), /"services": \[\{ "binding": "VAULT", "service": "coffre-try-vault" \}\]/);
  assert.deepEqual(cloudflare.state.scripts.get('acc-acme/coffre-try')!.bindings, [
    { type: 'hyperdrive', name: 'HYPERDRIVE', id: configs[0]!.id },
    ...Object.entries(app.vars).map(([name, value]) => ({ type: 'plain_text', name, text: value })),
    { type: 'service', name: 'VAULT', service: 'coffre-try-vault' },
  ]);
  assert.match(dryRun('coffre-try'), /env\.VAULT \(coffre-try-vault\)/);
  calls();
});

test("a deployment on another's database server: setup stops before giving their shared login a new password", { skip }, async () => {
  const before = cloudflare.state.configs.get('acc-acme')!.length;
  const third = another('third');
  await asSuperuser('postgres', (client) => client.query('CREATE DATABASE setup_workers_three'));
  const { output, code } = await setup(
    async (terminal) => {
      await terminal.waitFor('Set Cloudflare up too?');
      terminal.send('\r');
      await terminal.waitFor('Which Cloudflare account?');
      terminal.send('\r');
      await terminal.waitFor("coffre's address");
      terminal.send('coffre-three.acme.test\r');
      await terminal.waitFor("This deployment's name");
      terminal.send('\r');
      await terminal.waitFor('Root admins');
      terminal.send('\r');
    },
    third,
    `${CLUSTER}/setup_workers_three`,
  );
  const text = mainText(output);
  assert.equal(code, 1, text);
  assert.match(text, /✗ Make the two logins\n\s+coffre_runtime is also the login of the Hyperdrive config coffre, another deployment's, on this database server/);
  assert.deepEqual(await firstConnects(), [true, true], "the first deployment's logins keep their passwords");
  assert.equal(cloudflare.state.configs.get('acc-acme')!.length, before);
  assert.deepEqual(calls().filter(({ args }) => args[0] === 'deploy'), []);
});

test('a Worker without its key over a database in use: setup stops before changing anything', { skip }, async () => {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
      VALUES (0, 'vault', 'vault:probe', 0, 'system:vault', 'key.check', 'allow', '{}', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))`);
  } finally {
    await client.end();
  }
  cloudflare.state.scripts.get('acc-acme/coffre-vault')!.secrets.delete('VAULT_KEY');
  const files = ['app', 'vault'].map((component) => readFileSync(join(deployment(), component, 'wrangler.jsonc'), 'utf8'));
  const { output, code } = await setup((terminal) => answer(terminal));
  const text = mainText(output);
  assert.equal(code, 1, text);
  assert.match(text, /✗ Connect to 127\.0\.0\.1\/setup_workers\n\s+The vault Worker coffre-vault has no VAULT_KEY, but the database already holds data/);
  assert.ok(!output.includes(ENTER_ALT));
  assert.deepEqual(calls().filter(({ args }) => args[0] === 'deploy'), []);
  assert.deepEqual(['app', 'vault'].map((component) => readFileSync(join(deployment(), component, 'wrangler.jsonc'), 'utf8')), files);
});
