// Deploys on every push, as `coffre setup` sets them up, against stand-ins
// for Cloudflare's API, GitHub's and gh: the deploy's Cloudflare token, made
// through the API or on the dashboard's form and checked, and the
// repository's three secrets, which the stand-in for GitHub opens as GitHub
// does. No value reaches a line setup shows.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { globSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CloudflareApi, type Zone } from '../src/cloudflare.ts';
import { deployOnPush, gitRemote, githubTokenForm, type Pushes, repositoryOf, tokenForm, tokenName, WORKFLOW } from '../src/deploy-on-push.ts';
import { templateDir } from '../src/init.ts';
import type { Step } from '../src/steps.ts';
import { fakeCloudflare, fakeGh, fakeGitHub } from './fakes.ts';

/** wrangler's login, which may not make API tokens. */
const OAUTH = `cf-oauth-${'o'.repeat(40)}`;
/** A token that may, as one with API Tokens Edit. */
const MAKER = `cf-maker-${'m'.repeat(40)}`;
const GH = `gho_${'g'.repeat(36)}`;
const PAT = `github_pat_${'p'.repeat(40)}`;
const OWNER = new URL('postgresql://owner:s3cret-owner-password@db.acme.test:5432/coffre?sslmode=verify-full');
const REPOSITORY = 'acme/secrets';
const ZONE: Zone = { id: 'zone-1', name: 'acme.test', status: 'active' };
const ACCOUNT = { id: 'acc-acme', name: 'Acme' };
const DEPLOY = ['workers_scripts', 'account_settings', 'workers_kv_storage', 'hyperdrive'];

let dir: string;
let cloudflare: Awaited<ReturnType<typeof fakeCloudflare>>;
let github: Awaited<ReturnType<typeof fakeGitHub>>;
const path = process.env.PATH;
const base = process.env.CLOUDFLARE_API_BASE_URL;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'coffre-pushes-'));
  cloudflare = await fakeCloudflare(OAUTH);
  github = await fakeGitHub();
  process.env.CLOUDFLARE_API_BASE_URL = cloudflare.url;
  // No gh here but the stand-in: never the real one, nor its login.
  process.env.PATH = `${join(dir, 'bin')}:${path}`;
});

after(() => {
  process.env.PATH = path;
  if (base === undefined) delete process.env.CLOUDFLARE_API_BASE_URL;
  else process.env.CLOUDFLARE_API_BASE_URL = base;
  cloudflare.close();
  github.close();
  rmSync(dir, { recursive: true, force: true });
});

/** gh signed in to `host`, or, with none, to another GitHub altogether. */
function gh(host: string | null): void {
  fakeGh(join(dir, 'bin'), host ?? 'github.example.org', GH);
}

/** A step that answers as scripted: each choice, then each line pasted until one is taken. What it is shown, it keeps. */
function scripted(script: { choose?: number[]; paste?: string[] }) {
  const said = { notes: [] as string[], asides: [] as string[], links: [] as string[], refusals: [] as string[], questions: [] as string[] };
  const step: Step = {
    note: (text) => void said.notes.push(text),
    under: () => {},
    ask: async () => false,
    choose: async (question) => {
      said.questions.push(question);
      const choice = script.choose?.shift();
      if (choice === undefined) throw new Error(`asked, unscripted: ${question}`);
      return choice;
    },
    paste: async (prompt, accept) => {
      for (;;) {
        const text = script.paste?.shift();
        if (text === undefined) throw new Error(`nothing left to paste at: ${prompt}`);
        const refusal = await accept(text);
        if (refusal === null) return text;
        said.refusals.push(refusal);
      }
    },
  };
  return { step, said, say: { aside: (text: string) => void said.asides.push(text), link: (label: string, address: string) => void said.links.push(`${label} ${address}`) } };
}

function context(where: string, overrides: Partial<Pushes> = {}): Pushes {
  return {
    dir: where,
    repository: REPOSITORY,
    github: github.github,
    api: new CloudflareApi(OAUTH),
    account: ACCOUNT,
    zone: ZONE,
    owner: OWNER,
    rotate: false,
    secrets: [],
    ...overrides,
  };
}

/** No value anywhere on what setup showed. */
function assertShown(shown: unknown, values: string[]): void {
  const text = JSON.stringify(shown);
  for (const value of values) assert.ok(!text.includes(value), `a secret shown: ${value.slice(0, 8)}…`);
}

const opened = () => github.state.secrets.get(REPOSITORY) ?? new Map<string, string>();

test("a remote's repository, on the deployment's GitHub only", () => {
  const com = { web: 'https://github.com', api: 'https://api.github.com' };
  for (const remote of ['https://github.com/acme/secrets.git', 'https://github.com/acme/secrets', 'git@github.com:acme/secrets.git', 'ssh://git@github.com/acme/secrets.git', 'https://token@github.com/acme/secrets/']) {
    assert.equal(repositoryOf(remote, com), 'acme/secrets', remote);
  }
  for (const remote of ['https://gitlab.com/acme/secrets.git', 'git@gitlab.com:acme/secrets.git', 'https://github.com/acme', 'https://github.com/acme/secrets/tree/main', '/srv/git/secrets.git', '']) {
    assert.equal(repositoryOf(remote, com), null, remote);
  }
  // GitHub Enterprise Server, as the app's vars name it.
  assert.equal(repositoryOf('git@git.acme.test:ops/secrets.git', { web: 'https://git.acme.test', api: 'https://git.acme.test/api/v3' }), 'ops/secrets');
});

test("a directory's remote: origin, or its only one; none without git", (t) => {
  // As git has it here, with no one's own configuration: no address rewritten.
  const config = { GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM: process.env.GIT_CONFIG_NOSYSTEM };
  Object.assign(process.env, { GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' });
  t.after(() => {
    for (const [name, value] of Object.entries(config)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
  const repo = join(dir, 'repo');
  mkdirSync(repo);
  assert.equal(gitRemote(repo), null);
  execFileSync('git', ['init', '-q', repo]);
  assert.equal(gitRemote(repo), null);
  execFileSync('git', ['-C', repo, 'remote', 'add', 'upstream', 'git@github.com:acme/upstream.git']);
  assert.equal(gitRemote(repo), 'git@github.com:acme/upstream.git');
  execFileSync('git', ['-C', repo, 'remote', 'add', 'origin', 'https://github.com/acme/secrets.git']);
  assert.equal(gitRemote(repo), 'https://github.com/acme/secrets.git');
});

test("the forms setup fills in: the dashboard's for the deploy's token, GitHub's for a day's token on the repository's secrets", () => {
  const form = new URL(tokenForm(tokenName(REPOSITORY), ZONE));
  assert.equal(form.origin + form.pathname, 'https://dash.cloudflare.com/profile/api-tokens');
  assert.deepEqual(JSON.parse(form.searchParams.get('permissionGroupKeys')!), [
    { key: 'workers_scripts', type: 'edit' },
    { key: 'account_settings', type: 'read' },
    { key: 'workers_kv_storage', type: 'edit' },
    { key: 'hyperdrive', type: 'read' },
    { key: 'workers_routes', type: 'edit' },
  ]);
  assert.deepEqual([form.searchParams.get('accountId'), form.searchParams.get('zoneId'), form.searchParams.get('name')], ['*', 'all', 'coffre deploys: acme/secrets']);
  assert.ok(!JSON.parse(new URL(tokenForm('x', null)).searchParams.get('permissionGroupKeys')!).some(({ key }: { key: string }) => key === 'workers_routes'));

  const pat = new URL(githubTokenForm({ web: 'https://github.com', api: 'https://api.github.com' }, REPOSITORY));
  assert.equal(pat.href.split('?')[0], 'https://github.com/settings/personal-access-tokens/new');
  assert.deepEqual(
    [pat.searchParams.get('target_name'), pat.searchParams.get('expires_in'), pat.searchParams.get('secrets'), pat.searchParams.get('name')],
    ['acme', '1', 'write', 'coffre setup: acme/secrets'],
  );
});

test("wrangler's login may not make tokens: the dashboard's form, a token short of a permission refused, then the three secrets sealed to the repository", async () => {
  gh(null);
  const where = join(dir, 'made-by-hand');
  mkdirSync(where);
  const partial = `cf-partial-${'a'.repeat(30)}`;
  const full = `cf-full-${'b'.repeat(30)}`;
  cloudflare.state.scoped.set(partial, new Set(['workers_scripts', 'account_settings', 'workers_kv_storage', 'workers_routes:zone-1']));
  cloudflare.state.scoped.set(full, new Set([...DEPLOY, 'workers_routes:zone-1']));
  const wrong = `github_pat_${'w'.repeat(40)}`;
  github.state.tokens.set(wrong, new Set(['acme/other']));
  github.state.tokens.set(PAT, new Set([REPOSITORY]));
  const { step, said, say } = scripted({ choose: [0], paste: [wrong, PAT, 'short', partial, full] });
  const shared = context(where);
  const done = await deployOnPush(shared, step, say);

  assert.deepEqual(said.questions, ["Set acme/secrets's Actions secrets now, with a GitHub token?"]);
  assert.match(said.links[0]!, /^Make it at http:\/\/127\.0\.0\.1:\d+\/settings\/personal-access-tokens\/new\?/);
  assert.match(said.asides[0]!, /Under Repository access, choose Only select repositories, then acme\/secrets/);
  assert.equal(said.refusals[0], "that token may not set acme/secrets's secrets: it needs Secrets: Read and write, on acme/secrets");
  assert.match(
    said.asides[1]!,
    /^Cloudflare refused this login making an API token: wrangler's login may not\. Make one for the deploys, named coffre deploys: acme\/secrets, with exactly Account, Acme: Workers Scripts Edit, Account Settings Read, Workers KV Storage Edit and Hyperdrive Read; and Zone, acme\.test: Workers Routes Edit\./,
  );
  assert.equal(said.links[1], `Make it at ${tokenForm(tokenName(REPOSITORY), ZONE)}`);
  assert.deepEqual(said.refusals.slice(1), ['that is not a Cloudflare API token: copy it whole', 'that token lacks Hyperdrive Read, which the deploy needs']);

  // What GitHub Actions sees: each value, opened with the repository's key.
  assert.deepEqual(Object.fromEntries(opened()), { CLOUDFLARE_API_TOKEN: full, CLOUDFLARE_ACCOUNT_ID: 'acc-acme', DATABASE_OWNER_URL: OWNER.href });
  assert.equal(cloudflare.state.tokens.length, 0, 'none made through the API');
  assert.deepEqual(done, {
    text: 'acme/secrets deploys on every push to main, signed in to GitHub with the token given',
    details: [
      "CLOUDFLARE_API_TOKEN   the token you made, for the account's Workers, and acme.test's routes",
      'CLOUDFLARE_ACCOUNT_ID  set, Acme',
      'DATABASE_OWNER_URL     set, the URL setup was given',
      'Wrote .github/workflows/deploy.yml: commit it, with pnpm-lock.yaml, and push',
    ],
  });
  // A deployment from before init wrote the workflow has the template's now.
  assert.equal(readFileSync(join(where, WORKFLOW), 'utf8'), readFileSync(join(templateDir('workers'), WORKFLOW), 'utf8'));
  for (const value of [PAT, wrong, partial, full]) assert.ok(shared.secrets.includes(value), 'each value, to take out of any error');
  assertShown([done, said], [PAT, wrong, partial, full, OWNER.password]);
});

test("a login that may make tokens: the deploy's permissions exactly, on the account and the zone's routes; signed in with gh's login", async () => {
  github.state.secrets.delete(REPOSITORY);
  github.state.tokens.set(GH, new Set([REPOSITORY]));
  gh('127.0.0.1');
  cloudflare.state.apiTokens.add(MAKER);
  cloudflare.state.tokenMakers.add(MAKER);
  const where = join(dir, 'made-by-api');
  mkdirSync(join(where, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(where, WORKFLOW), '# the deployment\'s own\n');
  const { step, said, say } = scripted({});
  const done = await deployOnPush(context(where, { api: new CloudflareApi(MAKER) }), step, say);

  assert.equal(cloudflare.state.tokens.length, 1);
  const [made] = cloudflare.state.tokens;
  assert.equal(made!.name, 'coffre deploys: acme/secrets');
  assert.deepEqual(made!.policies, [
    { effect: 'allow', resources: { 'com.cloudflare.api.account.acc-acme': '*' }, permission_groups: [{ id: 'pg-scripts' }, { id: 'pg-settings' }, { id: 'pg-kv' }, { id: 'pg-hyperdrive' }] },
    { effect: 'allow', resources: { 'com.cloudflare.api.account.zone.zone-1': '*' }, permission_groups: [{ id: 'pg-routes' }] },
  ]);
  assert.equal(opened().get('CLOUDFLARE_API_TOKEN'), made!.value);
  assert.equal(done!.text, "acme/secrets deploys on every push to main, signed in to GitHub with gh's login");
  assert.equal(done!.details[0], "CLOUDFLARE_API_TOKEN   a new token, coffre deploys: acme/secrets, for the account's Workers, and acme.test's routes");
  assert.equal(done!.details.length, 3, 'the workflow was there already');
  assert.equal(readFileSync(join(where, WORKFLOW), 'utf8'), "# the deployment's own\n", 'and left as it is');
  assert.deepEqual(said.questions, []);
  assertShown([done, said], [made!.value, GH, OWNER.password]);
});

test('run again: the token kept; asked to rotate, a new one, and the one it replaces deleted', async () => {
  const where = join(dir, 'made-by-api');
  const before = opened().get('CLOUDFLARE_API_TOKEN');
  const kept = await deployOnPush(context(where, { api: new CloudflareApi(MAKER) }), scripted({}).step, scripted({}).say);
  assert.equal(kept!.details[0], 'CLOUDFLARE_API_TOKEN   kept: coffre setup --rotate-deploy-token makes a new one');
  assert.equal(opened().get('CLOUDFLARE_API_TOKEN'), before);
  assert.equal(cloudflare.state.tokens.length, 1);

  const rotated = await deployOnPush(context(where, { api: new CloudflareApi(MAKER), rotate: true }), scripted({}).step, scripted({}).say);
  assert.equal(cloudflare.state.tokens.length, 1, 'the old one deleted');
  const [now] = cloudflare.state.tokens;
  assert.notEqual(now!.value, before);
  assert.equal(opened().get('CLOUDFLARE_API_TOKEN'), now!.value);
  assert.ok(rotated!.details.includes('Deleted the token it replaces, coffre deploys: acme/secrets'));

  // Rotated under wrangler's login, the token made by hand: the one it replaces is the person's to delete.
  const full = `cf-full-${'c'.repeat(30)}`;
  cloudflare.state.scoped.set(full, new Set([...DEPLOY]));
  const { step, say } = scripted({ paste: [full] });
  const byHand = await deployOnPush(context(where, { rotate: true, zone: null }), step, say);
  assert.equal(opened().get('CLOUDFLARE_API_TOKEN'), full);
  assert.equal(byHand!.details[0], "CLOUDFLARE_API_TOKEN   the token you made, for the account's Workers");
  assert.ok(byHand!.details.includes('Delete the token it replaces on Cloudflare: https://dash.cloudflare.com/profile/api-tokens'));
  assert.equal(cloudflare.state.tokens.length, 1);
});

test('no GitHub token to give, and not now: nothing set, nothing made', async () => {
  gh(null);
  github.state.secrets.delete(REPOSITORY);
  const calls = github.state.calls.length;
  const tokens = cloudflare.state.tokens.length;
  const { step, say } = scripted({ choose: [1] });
  assert.equal(await deployOnPush(context(join(dir, 'made-by-api')), step, say), null);
  assert.equal(github.state.calls.length, calls);
  assert.equal(cloudflare.state.tokens.length, tokens);
  assert.equal(github.state.secrets.has(REPOSITORY), false);
});

test('the secrets are sealed by libsodium, here and nowhere else: no other module of coffre imports it', () => {
  const root = fileURLToPath(new URL('../../..', import.meta.url));
  const importers = globSync('packages/*/src/**/*.{ts,tsx}', { cwd: root }).filter((file) => /\b(from|import\(|require\()\s*['"]libsodium/.test(readFileSync(join(root, file), 'utf8')));
  assert.deepEqual(importers, ['packages/cli/src/deploy-on-push.ts']);
});
