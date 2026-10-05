// `coffre setup` on Workers for an address whose DNS is not on the
// Cloudflare account, end to end, in a terminal, against a disposable
// cluster and stand-ins for Cloudflare's API, GitHub, wrangler and a
// browser. With domains on the account: served through the one chosen,
// the records shown, the wait stopped with Ctrl-C, then a run after the
// DNS change that picks up there. With none: the domain added and its
// nameservers shown, or the workers.dev address. Every deploy is also the
// real wrangler's, in a dry run, on the same files.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { parse } from 'jsonc-parser';

import { editWorker } from '../src/deployment.ts';
import { templateDir } from '../src/init.ts';
import { asSuperuser, CLUSTER, database, emptyCluster, needsCluster } from './cluster.ts';
import { fakeCloudflare, fakeGitHub, fakeOpener, fakeVite, fakeWrangler, realWrangler, submitManifest } from './fakes.ts';
import { inTerminal, ptySkip, screens, type Session, visible } from './pty.ts';

const skip = needsCluster.skip || ptySkip;
const TOKEN = `cf-api-${'t'.repeat(40)}`;
const ADDRESS = 'secrets.example.org';
const DOWN = '\x1b[B';

let dir: string;
let cloudflare: Awaited<ReturnType<typeof fakeCloudflare>>;
let github: Awaited<ReturnType<typeof fakeGitHub>>;
let live: ReturnType<typeof createServer>;
let env: NodeJS.ProcessEnv;

before(async () => {
  if (skip) return;
  await emptyCluster();
  dir = mkdtempSync(join(tmpdir(), 'coffre-domain-'));
  cloudflare = await fakeCloudflare(TOKEN);
  // Two domains, each with Cloudflare for SaaS on, neither the address's.
  cloudflare.state.zones['acc-acme'] = [
    { id: 'zone-1', name: 'acme.test', status: 'active' },
    { id: 'zone-2', name: 'acme.dev', status: 'active' },
  ];
  cloudflare.state.saas.add('zone-1').add('zone-2');
  github = await fakeGitHub();
  live = createServer((request, response) => response.writeHead(request.url === '/livez' ? 200 : 404).end('{"ok":true}'));
  await new Promise<void>((resolve) => live.listen(0, '127.0.0.1', resolve));
  const at = `http://127.0.0.1:${(live.address() as { port: number }).port}`;
  // coffre's addresses, which no resolver knows, reach it through a fetch that knows.
  writeFileSync(
    join(dir, 'network.mjs'),
    `const real = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  return real(/\\.(example\\.org|workers\\.dev)$/.test(url.hostname) ? ${JSON.stringify(at)} + url.pathname : input, init);
};\n`,
  );
  fakeOpener(join(dir, 'bin'));
  env = {
    PATH: `${join(dir, 'bin')}:${process.env.PATH}`,
    HOME: dir,
    COFFRE_SETUP_DATABASE_URL: await database('setup_domain', 'superuser'),
    CLOUDFLARE_API_BASE_URL: cloudflare.url,
    NODE_OPTIONS: `--import=${join(dir, 'network.mjs')}`,
  };
  // Signed in already, as with CLOUDFLARE_API_TOKEN: wrangler gives its token.
  deployment('first');
  writeFileSync(join(dir, 'wrangler', 'token'), TOKEN);
});

after(async () => {
  if (skip) return;
  cloudflare.close();
  github.close();
  live.close();
  rmSync(dir, { recursive: true, force: true });
  await emptyCluster();
});

/** A copy of the template, its GitHub the fake one, its wrangler and Vite fakes. */
function deployment(name: string): string {
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

function setup(where: string, play: (terminal: Session) => Promise<void>, more: NodeJS.ProcessEnv = {}) {
  return inTerminal(['setup'], { ...env, ...more }, play, { columns: 160, rows: 48 }, join(dir, where));
}

const mainText = (output: string) => visible(screens(output).main).replace(/\r\n/g, '\n');
const app = (where: string) => parse(readFileSync(join(dir, where, 'app', 'wrangler.jsonc'), 'utf8')) as Record<string, unknown> & { vars: Record<string, string> };

/** Yes to Cloudflare, on the account chosen, `down` the list, or the one the deployment records (null), at `address`. */
async function start(terminal: Session, address: string, down: number | null = 0): Promise<void> {
  await terminal.waitFor('Set Cloudflare up too?');
  terminal.send('\r');
  if (down !== null) {
    await terminal.waitFor('Which Cloudflare account?');
    terminal.send(`${DOWN.repeat(down)}\r`);
  }
  await terminal.waitFor("coffre's address");
  terminal.send(`\x15${address}\r`);
}

/** GitHub's app made in the browser, then the keys saved. */
async function githubAndKeys(terminal: Session, pages: number): Promise<void> {
  await terminal.waitFor("GitHub: create coffre's app");
  const page = await opened('http://127.0.0.1:', pages);
  await fetch(await submitManifest(await (await fetch(page)).text()));
  await terminal.waitFor('reveal all');
  terminal.send('q');
  await terminal.waitFor('Have you saved all three values?');
  terminal.send('y');
}

function openedAll(prefix: string): string[] {
  try {
    return readFileSync(join(dir, 'bin', 'opened'), 'utf8').split('\n').filter((line) => line.startsWith(prefix));
  } catch {
    return [];
  }
}

async function opened(prefix: string, seen: number): Promise<string> {
  for (let tries = 0; ; tries += 1) {
    const found = openedAll(prefix)[seen];
    if (found !== undefined) return found;
    if (tries === 400) throw new Error(`never opened ${prefix}…`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

test('DNS elsewhere, two domains on the account: setup asks which, serves the address through it, shows the records, and waits; Ctrl-C there', { skip }, async () => {
  const { output, code } = await setup('first', async (terminal) => {
    await start(terminal, ADDRESS);
    await terminal.waitFor('Root admins');
    terminal.send('\r');
    await terminal.waitFor(`Which of your domains serves ${ADDRESS}?`);
    terminal.send(`${DOWN}\r`);
    await githubAndKeys(terminal, 0);
    // Deployed, both Workers, each with the real wrangler's dry run: slow on a loaded host.
    await terminal.waitFor('Wait for the DNS records', 60_000);
    terminal.send('\x03');
  });
  const text = mainText(output);
  assert.equal(code, 130, text);
  assert.match(text, /secrets\.example\.org's DNS isn't on this Cloudflare account\.\s+Setup serves it through one of your domains, with Cloudflare for SaaS/);
  assert.match(text, /✓ secrets\.example\.org is a custom hostname of acme\.dev\n\s+fallback origin {2}coffre-fallback\.acme\.dev, made\n\s+custom hostname {2}secrets\.example\.org, made/);
  const hostname = cloudflare.state.hostnames.get('zone-2')![0]!;
  // Shown once made, before the certificate's records are known; then again at the wait, with them.
  const shown = [...text.matchAll(/Add these records where secrets\.example\.org's DNS is:\n((?:\s{4}(?:CNAME|TXT) .*\n)+)/g)].map((match) => match[1]!.trim().split(/\n\s*/));
  assert.deepEqual(shown, [
    [
      `CNAME  ${ADDRESS}                      →  coffre-fallback.acme.dev`,
      `TXT    _cf-custom-hostname.${ADDRESS}  "${hostname.ownership_verification.value}"`,
    ],
    [
      `CNAME  ${ADDRESS}                      →  coffre-fallback.acme.dev`,
      `TXT    _cf-custom-hostname.${ADDRESS}  "${hostname.ownership_verification.value}"`,
      ...hostname.ssl.validation_records!.map(({ txt_value }) => `TXT    _acme-challenge.${ADDRESS}      "${txt_value}"`),
    ],
  ]);
  assert.match(text, /You can stop it with Ctrl-C, and run setup again once the records are in: it picks up here/);
  assert.equal(cloudflare.state.fallback.get('zone-2')!.origin, 'coffre-fallback.acme.dev');
  assert.equal(cloudflare.state.hostnames.get('zone-1')?.length ?? 0, 0, 'nothing on the other domain');
  // The app's route on the zone, by its id; no custom domain, no workers.dev.
  const config = app('first');
  assert.deepEqual([config.vars.PUBLIC_URL, config.workers_dev, config.routes], [`https://${ADDRESS}`, false, [{ pattern: `${ADDRESS}/*`, zone_id: 'zone-2' }]]);
  assert.match(text, /app\s+the account, Hyperdrive, GitHub's client ID, the address and its route through acme\.dev/);
  assert.match(readFileSync(join(dir, 'wrangler', 'dry-coffre'), 'utf8'), /--dry-run: exiting now/);
});

test('the run after the DNS change: nothing asked about the domain, the custom hostname kept, done once Cloudflare has seen the records', { skip }, async () => {
  for (const name of [ADDRESS, `_cf-custom-hostname.${ADDRESS}`, `_acme-challenge.${ADDRESS}`]) cloudflare.state.published.add(name);
  const { output, code } = await setup('first', async (terminal) => {
    await start(terminal, ADDRESS, null);
    await terminal.waitFor('Root admins');
    terminal.send('\r');
    await terminal.waitFor('coffre is at', 60_000);
  });
  const text = mainText(output);
  assert.equal(code, 0, text);
  assert.ok(!text.includes('Which of your domains'), text);
  assert.ok(!text.includes('Add these records'), 'none left to add');
  assert.match(text, /✓ secrets\.example\.org is a custom hostname of acme\.dev\n\s+fallback origin {2}coffre-fallback\.acme\.dev, kept\n\s+custom hostname {2}secrets\.example\.org, kept/);
  assert.match(text, /✓ Cloudflare has seen secrets\.example\.org's records, and its certificate is out/);
  assert.match(text, /✓ coffre answers at https:\/\/secrets\.example\.org/);
  assert.equal(cloudflare.state.hostnames.get('zone-2')!.length, 1);
});

test('no domain on the account: setup explains both ways; adding the domain shows its nameservers, and stops until they move', { skip }, async () => {
  deployment('home');
  cloudflare.state.subdomains['acc-home'] = 'home';
  const choose = (terminal: Session) => async () => {
    await start(terminal, ADDRESS, 1);
    await terminal.waitFor('How should coffre be reached?');
    terminal.send('\r');
    await terminal.waitFor('The domain to add');
    terminal.send('\r');
  };
  // A login that may not add one, as wrangler's: where to, instead.
  cloudflare.state.denied.add('zone');
  let run = await setup('home', (terminal) => choose(terminal)());
  assert.equal(run.code, 1, mainText(run.output));
  assert.match(mainText(run.output), /This Cloudflare login may not add a domain\. Add example\.org on Cloudflare's dashboard/);
  cloudflare.state.denied.clear();

  run = await setup('home', (terminal) => choose(terminal)());
  let text = mainText(run.output);
  assert.equal(run.code, 0, text);
  assert.match(text, /secrets\.example\.org's DNS isn't on this Cloudflare account\./);
  assert.match(text, /Either\s+add\s+example\.org\s+to\s+Cloudflare,\s+which\s+then\s+serves\s+its\s+DNS[\s\S]*or\s+use\s+the\s+Worker's\s+workers\.dev\s+address\s+for\s+now/);
  assert.match(text, /Add example\.org to this Cloudflare account\n\s+At its workers\.dev address for now, coffre\.home\.workers\.dev/);
  assert.match(text, /→ example\.org is on this Cloudflare account now\. At your registrar, set its nameservers to:\n\s+ada\.ns\.cloudflare\.com\n\s+bob\.ns\.cloudflare\.com/);
  assert.deepEqual(cloudflare.state.zones['acc-home']!.map(({ name, status }) => [name, status]), [['example.org', 'pending']]);

  // Run again before the nameservers moved: the same, and nothing asked.
  run = await setup('home', (terminal) => start(terminal, ADDRESS, 1));
  text = mainText(run.output);
  assert.equal(run.code, 0, text);
  assert.match(text, /→ example\.org is on Cloudflare, waiting for its nameservers\. At your registrar, set its nameservers to:/);
  assert.ok(!text.includes('How should coffre be reached?'));
  assert.equal(cloudflare.state.zones['acc-home']!.length, 1);
});

test("no domain on the account: the Worker's workers.dev address, for now; deployed there", { skip }, async () => {
  deployment('dev');
  await asSuperuser('postgres', (client) => client.query('CREATE DATABASE setup_domain_two'));
  const more = { COFFRE_SETUP_DATABASE_URL: `${CLUSTER}/setup_domain_two` };
  const choose = async (terminal: Session) => {
    await start(terminal, 'secrets.other.org', 1);
    await terminal.waitFor('How should coffre be reached?');
    terminal.send(`${DOWN}\r`);
  };
  // No workers.dev subdomain on the account yet: where to choose one.
  delete cloudflare.state.subdomains['acc-home'];
  let run = await setup('dev', choose, more);
  assert.equal(run.code, 1, mainText(run.output));
  assert.match(mainText(run.output), /This account has no workers\.dev subdomain yet: choose one on Cloudflare's dashboard/);

  cloudflare.state.subdomains['acc-home'] = 'home';
  const pages = openedAll('http://127.0.0.1:').length;
  run = await setup(
    'dev',
    async (terminal) => {
      await choose(terminal);
      await terminal.waitFor('Root admins');
      terminal.send('\r');
      await githubAndKeys(terminal, pages);
      await terminal.waitFor('coffre is at', 60_000);
    },
    more,
  );
  const text = mainText(run.output);
  assert.equal(run.code, 0, text);
  assert.match(text, /✓ coffre answers at https:\/\/coffre\.home\.workers\.dev/);
  const config = app('dev');
  assert.deepEqual([config.vars.PUBLIC_URL, config.workers_dev, config.routes], ['https://coffre.home.workers.dev', true, []]);
  assert.deepEqual(github.state.manifests.at(-1)!.callback_urls, ['https://coffre.home.workers.dev/auth/callback/github']);
});
