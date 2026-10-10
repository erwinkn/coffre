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

import { migrateDatabase } from '@coffre/db/migrate';
import { parse } from 'jsonc-parser';

import { editWorker } from '../src/deployment.ts';
import { templateDir } from '../src/init.ts';
import { asSuperuser, CLUSTER, database, emptyCluster, needsCluster, OTHER_CLUSTER, SMALL_CLUSTER } from './cluster.ts';
import { fakeCloudflare, fakeGitHub, fakeOpener, fakeVite, fakeWrangler, realWrangler, submitManifest } from './fakes.ts';
import { answering, inTerminal, ptySkip, screens, type Session, typingUrl, visible } from './pty.ts';

const skip = needsCluster.skip || ptySkip;
const TOKEN = `cf-oauth-${'t'.repeat(40)}`;
/** A token made on the dashboard, which may do what wrangler's login may not. */
const API_TOKEN = `cf-dashboard-${'d'.repeat(40)}`;
const ADDRESS = 'secrets.example.org';
const DOWN = '\x1b[B';

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
  dir = mkdtempSync(join(tmpdir(), 'coffre-domain-'));
  cloudflare = await fakeCloudflare(TOKEN);
  // Two domains, each with Cloudflare for SaaS on, neither the address's.
  cloudflare.state.zones['acc-acme'] = [
    { id: 'zone-1', name: 'acme.test', status: 'active' },
    { id: 'zone-2', name: 'acme.dev', status: 'active' },
  ];
  cloudflare.state.saas.add('zone-1').add('zone-2');
  cloudflare.state.apiTokens.add(API_TOKEN);
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
  url = await database('setup_domain', 'superuser');
  env = {
    PATH: `${join(dir, 'bin')}:${process.env.PATH}`,
    HOME: dir,
    CLOUDFLARE_API_BASE_URL: cloudflare.url,
    NODE_OPTIONS: `--import=${join(dir, 'network.mjs')}`,
  };
  // Signed in already: wrangler gives its login's token.
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

function setup(where: string, play: (terminal: Session) => Promise<void>, databaseUrl = url) {
  return inTerminal(['setup'], env, typingUrl(databaseUrl, play), { columns: 160, rows: 48 }, join(dir, where));
}

/** Each wrangler deploy since the last read: the token in its environment, if setup gave it one. */
function deploys(): { config: string; apiToken: string | null }[] {
  const path = join(dir, 'wrangler', 'calls.jsonl');
  let lines: string[] = [];
  try {
    lines = readFileSync(path, 'utf8').trim().split('\n');
  } catch {
    return [];
  }
  rmSync(path, { force: true });
  return lines
    .map((line) => JSON.parse(line) as { args: string[]; apiToken: string | null })
    .filter(({ args }) => args[0] === 'deploy')
    .map(({ args, apiToken }) => ({ config: args[2]!, apiToken }));
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

test("DNS elsewhere, two domains on the account, wrangler's login refused: setup asks for a token, asks which domain, serves the address through it, shows the records, and waits; Ctrl-C there", { skip }, async () => {
  // wrangler's login, as Cloudflare may answer it: no custom hostnames, no DNS records.
  cloudflare.state.denied.add('ssl').add('dns');
  const { output, code } = await setup('first', async (terminal) => {
    await start(terminal, ADDRESS);
    await terminal.waitFor('Root admins');
    terminal.send('\r');
    // Not a token, then one Cloudflare refuses, then the one made on the dashboard.
    await terminal.waitFor('Paste a Cloudflare API token, hidden as you paste it');
    terminal.send('short\r');
    await terminal.waitFor('that is not a Cloudflare API token');
    terminal.send(`cf-wrong-${'w'.repeat(40)}\r`);
    await terminal.waitFor('Cloudflare refused that token as well');
    await terminal.waitFor('Paste a Cloudflare API token');
    terminal.send(`${API_TOKEN}\r`);
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
  assert.match(
    text,
    /Cloudflare refused this login the custom hostnames of\s+acme\.test\s+and\s+acme\.dev:\s+wrangler's\s+login\s+may\s+not\s+manage\s+them,\s+and\s+has\s+no\s+scope\s+for\s+DNS\s+records/,
  );
  assert.ok(!output.includes(API_TOKEN), 'the token, never shown');
  // Both Workers deployed under the token given; never wrangler's login.
  assert.deepEqual(deploys(), [
    { config: 'vault/wrangler.jsonc', apiToken: API_TOKEN },
    { config: 'app/dist/server/wrangler.json', apiToken: API_TOKEN },
  ]);
  assert.match(text, /✓ secrets\.example\.org is a custom hostname of acme\.dev\n\s+fallback origin {2}coffre-fallback\.acme\.dev, made\n\s+custom hostname {2}secrets\.example\.org, made/);
  const hostname = cloudflare.state.hostnames.get('zone-2')![0]!;
  // Shown whole once made, the certificate's records with the rest; then again at the wait.
  const all = [
    `CNAME  ${ADDRESS}                      →  coffre-fallback.acme.dev`,
    `TXT    _cf-custom-hostname.${ADDRESS}  "${hostname.ownership_verification.value}"`,
    ...hostname.ssl.validation_records!.map(({ txt_value }) => `TXT    _acme-challenge.${ADDRESS}      "${txt_value}"`),
  ];
  const shown = [...text.matchAll(/Add these records where secrets\.example\.org's DNS is:\n((?:\s{4}(?:CNAME|TXT) .*\n)+)/g)].map((match) => match[1]!.trim().split(/\n\s*/));
  assert.deepEqual(shown, [all, all]);
  assert.match(text, /You can stop it with Ctrl-C, and run setup again once the records are in: it picks up here/);
  assert.equal(cloudflare.state.fallback.get('zone-2')!.origin, 'coffre-fallback.acme.dev');
  assert.equal(cloudflare.state.hostnames.get('zone-1')?.length ?? 0, 0, 'nothing on the other domain');
  // The app's route on the zone, by its id; no custom domain, no workers.dev.
  const config = app('first');
  assert.deepEqual([config.vars.PUBLIC_URL, config.workers_dev, config.routes], [`https://${ADDRESS}`, false, [{ pattern: `${ADDRESS}/*`, zone_id: 'zone-2' }]]);
  assert.match(text, /app\s+the account, Hyperdrive, GitHub's client ID, the address and its route through acme\.dev/);
  assert.match(readFileSync(join(dir, 'wrangler', 'dry-coffre'), 'utf8'), /--dry-run: exiting now/);
});

test("the run after the DNS change: no token asked, as wrangler's login is enough now; nothing asked about the domain, the custom hostname kept, done once Cloudflare has seen the records", { skip }, async () => {
  // The fallback origin is there: nothing left needs DNS, which wrangler's login still may not.
  cloudflare.state.denied.delete('ssl');
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
  assert.ok(!text.includes('Paste a Cloudflare API token'), 'no token asked');
  assert.deepEqual(deploys().map(({ apiToken }) => apiToken), [null, null], "wrangler's login, as it is");
  assert.ok(!text.includes('Add these records'), 'none left to add');
  assert.match(text, /✓ secrets\.example\.org is a custom hostname of acme\.dev\n\s+fallback origin {2}coffre-fallback\.acme\.dev, kept\n\s+custom hostname {2}secrets\.example\.org, kept/);
  assert.match(text, /✓ Cloudflare has seen secrets\.example\.org's records, and its certificate is out/);
  assert.match(text, /✓ coffre answers at https:\/\/secrets\.example\.org/);
  assert.equal(cloudflare.state.hostnames.get('zone-2')!.length, 1);
});

/**
 * Setup on `databaseUrl` for a new deployment at `address`, on the account
 * `down` the list, every question answered as it comes, until it refuses
 * with `refusal`: what it showed, its exit, and what it wrote to Cloudflare.
 * `meanwhile` changes the database while setup waits on its first question.
 */
async function refused(where: string, databaseUrl: string, address: string, down: number, refusal: string, meanwhile?: () => Promise<unknown>) {
  // Nothing denied: as setup once did, it would make the custom hostname, or add the domain, then refuse.
  cloudflare.state.denied.clear();
  deployment(where);
  const before = cloudflare.state.requests.length;
  const answers = {
    'Set Cloudflare up too?': '\r',
    'Which Cloudflare account?': `${DOWN.repeat(down)}\r`,
    "coffre's address": `\x15${address}\r`,
    "This deployment's name": '\r',
    'Root admins': '\r',
    'Which of your domains serves': '\r',
    'How should coffre be reached?': '\r',
    'The domain to add': '\r',
  };
  const { output, code } = await setup(
    where,
    async (terminal) => {
      if (meanwhile !== undefined) {
        await terminal.waitFor('Set Cloudflare up too?');
        await meanwhile();
        terminal.send('\r');
      }
      await answering(terminal, answers, [refusal, 'set its nameservers to']);
    },
    databaseUrl,
  );
  const requests = cloudflare.state.requests.slice(before);
  return { text: mainText(output), code, requests, writes: requests.filter(({ method }) => method !== 'GET').map(({ method, path }) => `${method} ${path}`) };
}

/** What the cluster keeps for each of coffre's logins' passwords. */
const verifiers = (cluster = CLUSTER) =>
  asSuperuser('postgres', async (client) => (await client.query("SELECT rolname, rolpassword FROM pg_authid WHERE rolname LIKE 'coffre_%' ORDER BY rolname")).rows, cluster);

/** A database on the cluster that holds data: coffre's log has an entry, as far as setup can tell. */
async function inUse(name: string): Promise<string> {
  await asSuperuser('postgres', (client) => client.query(`CREATE DATABASE ${name}`));
  await asSuperuser(name, (client) => client.query('CREATE TABLE audit_log (seq bigint); INSERT INTO audit_log VALUES (0)'));
  return `${CLUSTER}/${name}`;
}

test("DNS elsewhere, Workers without their keys over a database in use: setup refuses before it makes a fallback origin, DNS record or custom hostname", { skip }, async () => {
  const { text, code, writes } = await refused('used', await inUse('setup_domain_used'), 'used.example.org', 0, 'already holds data');
  assert.deepEqual(writes, [], 'nothing written to Cloudflare');
  assert.equal(code, 1, text);
  assert.match(text, /✗ The app Worker coffre-used has no APP_KEY, but the database already holds data/);
  assert.ok(!text.includes('Root admins'), 'refused before the questions left');
  assert.equal(cloudflare.state.hostnames.get('zone-1')?.length ?? 0, 0);
});

test("DNS elsewhere, an administrator who can't create roles: setup refuses before Cloudflare's questions, and asks Cloudflare nothing", { skip }, async () => {
  await asSuperuser('postgres', async (client) => {
    await client.query('CREATE DATABASE setup_domain_weak');
    await client.query("CREATE ROLE setup_owner LOGIN PASSWORD 'owner-only-p4ss'");
  });
  const weak = new URL(`${CLUSTER}/setup_domain_weak`);
  weak.username = 'setup_owner';
  weak.password = 'owner-only-p4ss';
  try {
    const { text, code, requests } = await refused('weak', weak.href, 'weak.example.org', 0, 'cannot create roles');
    assert.deepEqual(requests, [], 'nothing asked of Cloudflare, nor written');
    assert.equal(code, 1, text);
    assert.match(text, /✗ Check setup_owner can create roles\n\s+setup_owner cannot create roles/);
    assert.ok(!text.includes('Set Cloudflare up too?'), text);
  } finally {
    await asSuperuser('postgres', async (client) => {
      await client.query('DROP DATABASE setup_domain_weak WITH (FORCE)');
      await client.query('DROP ROLE setup_owner');
    });
  }
});

test("DNS elsewhere, on the server of another deployment, whose login this one would take: setup refuses before it makes a fallback origin, DNS record or custom hostname, and neither login was changed, as it says", { skip }, async () => {
  await asSuperuser('postgres', (client) => client.query('CREATE DATABASE setup_domain_shared'));
  const held = await verifiers();
  const { text, code, writes } = await refused('shared', `${CLUSTER}/setup_domain_shared`, 'shared.example.org', 0, 'is also the login of');
  assert.deepEqual(writes, [], 'nothing written to Cloudflare');
  assert.equal(code, 1, text);
  assert.match(text, /✗ coffre_runtime is also the login of the Hyperdrive config coffre, another deployment's, on this database server/);
  assert.match(text, /Neither\s+login\s+was\s+changed\./);
  assert.deepEqual(await verifiers(), held, "the first deployment's logins keep their passwords");
});

// On a server of their own: the first deployment's logins are on the cluster's.
const otherSkip = skip || (OTHER_CLUSTER === undefined && 'needs the other cluster');

test('a database that comes to hold data while setup asks its questions: setup refuses before it makes a key for it', { skip: otherSkip }, async () => {
  // Set up before, without Cloudflare: its logins made, migrated, holding no data yet.
  await asSuperuser('postgres', async (client) => {
    await client.query('CREATE DATABASE setup_domain_late_used');
    await client.query("CREATE ROLE coffre_runtime LOGIN PASSWORD 'late-app'");
    await client.query("CREATE ROLE coffre_vault_runtime LOGIN PASSWORD 'late-vault'");
  }, OTHER_CLUSTER);
  await migrateDatabase(`${OTHER_CLUSTER}/setup_domain_late_used`);
  const held = await verifiers(OTHER_CLUSTER);
  try {
    const { text, code, writes } = await refused('late-used', `${OTHER_CLUSTER}/setup_domain_late_used`, 'late-used.acme.test', 0, 'already holds data', () =>
      // Its first entry, written while setup waits.
      asSuperuser('setup_domain_late_used', (client) =>
        client.query(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
          VALUES (0, 'vault', 'vault:probe', 0, 'system:vault', 'key.check', 'allow', '{}', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))`),
      OTHER_CLUSTER),
    );
    assert.equal(code, 1, text);
    assert.match(text, /✗ Make the two logins\n\s+The app Worker coffre-late-used has no APP_KEY, but the database already holds data/);
    assert.deepEqual(writes, [], 'no Hyperdrive config, and no Worker deployed with a new key');
    assert.deepEqual(deploys(), []);
    assert.deepEqual(await verifiers(OTHER_CLUSTER), held, 'the logins keep their passwords');
  } finally {
    await emptyCluster(OTHER_CLUSTER);
  }
});

test("another deployment's logins made on this server while setup asks its questions: setup refuses before it gives them new passwords", { skip: otherSkip }, async () => {
  const other = new URL(OTHER_CLUSTER!);
  // That deployment's Hyperdrive config, on this server, its logins not made yet when setup reads them.
  cloudflare.state.configs.get('acc-acme')!.push({
    id: 'hd-elsewhere',
    name: 'elsewhere',
    origin: { host: other.hostname, port: Number(other.port), database: 'elsewhere', user: 'coffre_runtime', password: 'elsewhere-app' },
    caching: { disabled: true },
    origin_connection_limit: 20,
  });
  await asSuperuser('postgres', (client) => client.query('CREATE DATABASE setup_domain_late_shared'), OTHER_CLUSTER);
  let held: unknown[] = [];
  try {
    const { text, code, writes } = await refused('late-shared', `${OTHER_CLUSTER}/setup_domain_late_shared`, 'late-shared.acme.test', 0, 'is also the login of', async () => {
      await asSuperuser('postgres', async (client) => {
        await client.query("CREATE ROLE coffre_runtime LOGIN PASSWORD 'elsewhere-app'");
        await client.query("CREATE ROLE coffre_vault_runtime LOGIN PASSWORD 'elsewhere-vault'");
      }, OTHER_CLUSTER);
      held = await verifiers(OTHER_CLUSTER);
    });
    assert.equal(code, 1, text);
    assert.match(text, /✗ Make the two logins\n\s+coffre_runtime is also the login of the Hyperdrive config elsewhere, another deployment's, on this database server/);
    assert.equal(held.length, 2);
    assert.deepEqual(await verifiers(OTHER_CLUSTER), held, "the other deployment's logins keep their passwords");
    assert.deepEqual(writes, [], 'no Hyperdrive config made');
    assert.deepEqual(deploys(), []);
  } finally {
    cloudflare.state.configs.set('acc-acme', cloudflare.state.configs.get('acc-acme')!.filter(({ id }) => id !== 'hd-elsewhere'));
    await emptyCluster(OTHER_CLUSTER);
  }
});

test("no domain on the account, Workers without their keys over a database in use: setup refuses before the domain is added", { skip }, async () => {
  const zones = cloudflare.state.zones['acc-home']?.length ?? 0;
  const { text, code, writes } = await refused('home-used', await inUse('setup_domain_home_used'), 'secrets.used.test', 1, 'already holds data');
  assert.deepEqual(writes, [], 'nothing written to Cloudflare');
  assert.equal(code, 1, text);
  assert.match(text, /✗ The app Worker coffre has no APP_KEY, but the database already holds data/);
  assert.ok(!text.includes('How should coffre be reached?'), 'refused before the choice');
  assert.equal(cloudflare.state.zones['acc-home']?.length ?? 0, zones);
});

test("no domain on the account: setup explains both ways; adding the domain, refused to wrangler's login, under a token; its nameservers shown, and setup stops until they move", { skip }, async () => {
  deployment('home');
  cloudflare.state.subdomains['acc-home'] = 'home';
  cloudflare.state.denied.add('zone');
  let run = await setup('home', async (terminal) => {
    await start(terminal, ADDRESS, 1);
    await terminal.waitFor('How should coffre be reached?');
    terminal.send('\r');
    await terminal.waitFor('The domain to add');
    terminal.send('\r');
    await terminal.waitFor('Cloudflare API token');
    terminal.send(`cf-wrong-${'w'.repeat(40)}\r`);
    await terminal.waitFor('Cloudflare refused that token as well');
    await terminal.waitFor('Cloudflare API token');
    terminal.send(`${API_TOKEN}\r`);
  });
  let text = mainText(run.output);
  assert.equal(run.code, 0, text);
  assert.match(text, /secrets\.example\.org's DNS isn't on this Cloudflare account\./);
  assert.match(text, /Either\s+add\s+example\.org\s+to\s+Cloudflare,\s+which\s+then\s+serves\s+its\s+DNS[\s\S]*or\s+use\s+the\s+Worker's\s+workers\.dev\s+address\s+for\s+now/);
  assert.match(text, /Add example\.org to this Cloudflare account\n\s+At its workers\.dev address for now, coffre\.home\.workers\.dev/);
  assert.match(text, /Cloudflare refused this login adding example\.org:\s+wrangler's\s+login\s+may\s+not\.[\s\S]*Zone:\s+Zone\s+Edit,\s+for\s+all\s+zones\s+of\s+the\s+account/);
  assert.match(text, /→ example\.org is on this Cloudflare account now\. At your registrar, set its nameservers to:\n\s+ada\.ns\.cloudflare\.com\n\s+bob\.ns\.cloudflare\.com/);
  assert.ok(!run.output.includes(API_TOKEN), 'the token, never shown');
  assert.deepEqual(cloudflare.state.zones['acc-home']!.map(({ name, status }) => [name, status]), [['example.org', 'pending']]);
  cloudflare.state.denied.delete('zone');

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
  const second = `${CLUSTER}/setup_domain_two`;
  const choose = async (terminal: Session) => {
    await start(terminal, 'secrets.other.org', 1);
    await terminal.waitFor('How should coffre be reached?');
    terminal.send(`${DOWN}\r`);
  };
  // No workers.dev subdomain on the account yet: where to choose one.
  delete cloudflare.state.subdomains['acc-home'];
  let run = await setup('dev', choose, second);
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
    second,
  );
  const text = mainText(run.output);
  assert.equal(run.code, 0, text);
  assert.match(text, /✓ coffre answers at https:\/\/coffre\.home\.workers\.dev/);
  const config = app('dev');
  assert.deepEqual([config.vars.PUBLIC_URL, config.workers_dev, config.routes], ['https://coffre.home.workers.dev', true, []]);
  assert.deepEqual(github.state.manifests.at(-1)!.callback_urls, ['https://coffre.home.workers.dev/auth/callback/github']);
});

/**
 * Setup on a database too small for both Hyperdrive configs, `answers` given
 * to whatever Cloudflare questions it asks first: what it showed, its exit,
 * and what it asked of Cloudflare.
 */
async function tooSmall(where: string, answers: Record<string, string>) {
  await emptyCluster(SMALL_CLUSTER);
  await asSuperuser('postgres', (client) => client.query('CREATE DATABASE setup_domain_small'), SMALL_CLUSTER);
  deployment(where);
  const before = cloudflare.state.requests.length;
  try {
    // Until the refusal; or, as setup once did, a domain added and its nameservers shown, or the run over.
    const { output, code } = await setup(where, (terminal) => answering(terminal, answers, ['raise max_connections', 'set its nameservers to']), `${SMALL_CLUSTER}/setup_domain_small`);
    return { text: mainText(output), code, requests: cloudflare.state.requests.slice(before) };
  } finally {
    await emptyCluster(SMALL_CLUSTER);
  }
}

const smallSkip = skip || (SMALL_CLUSTER === undefined && 'needs the small cluster: scripts/test-setup.sh');
const REFUSED = /✗ Check 127\.0\.0\.1\/setup_domain_small has room for Hyperdrive\n\s+the database's max_connections is 15, 3 of them reserved/;

test("DNS elsewhere, on a database too small for both Hyperdrive configs: setup stops before Cloudflare's questions, with no fallback origin, DNS record or custom hostname made", { skip: smallSkip }, async () => {
  cloudflare.state.denied.clear();
  const { text, code, requests } = await tooSmall('small-saas', {
    'Set Cloudflare up too?': '\r',
    'Which Cloudflare account?': '\r',
    "coffre's address": '\x15small.example.org\r',
    "This deployment's name": '\r',
    'Root admins': '\r',
    'Which of your domains serves': '\r',
  });
  assert.deepEqual(requests.filter(({ method }) => method !== 'GET').map(({ method, path }) => `${method} ${path}`), [], 'nothing written to Cloudflare');
  assert.equal(code, 1, text);
  assert.match(text, REFUSED);
  assert.ok(!text.includes('Set Cloudflare up too?'), text);
  assert.deepEqual(requests, [], 'nor anything read');
});

test("no domain on the account, on a database too small for both Hyperdrive configs: setup stops before Cloudflare's questions, the domain not added", { skip: smallSkip }, async () => {
  cloudflare.state.denied.clear();
  const { text, code, requests } = await tooSmall('small-home', {
    'Set Cloudflare up too?': '\r',
    'Which Cloudflare account?': `${DOWN}\r`,
    "coffre's address": '\x15secrets.small.test\r',
    'How should coffre be reached?': '\r',
    'The domain to add': '\r',
  });
  assert.deepEqual(requests.filter(({ method }) => method !== 'GET').map(({ method, path }) => `${method} ${path}`), [], 'nothing written to Cloudflare');
  assert.equal(code, 1, text);
  assert.match(text, REFUSED);
  assert.ok(!text.includes('Set Cloudflare up too?'), text);
  assert.deepEqual(requests, [], 'nor anything read');
});
