// Deploys on every push, for `coffre setup` on Workers: the deployment's
// GitHub repository runs .github/workflows/deploy.yml, which `coffre init`
// writes, under three of the repository's Actions secrets. Setup makes the
// Cloudflare API token the workflow deploys with, scoped to what the deploy
// needs, and sets the three through GitHub's API, each sealed to the
// repository's public key with libsodium's sealed box, as GitHub's API
// takes them. It shows none of them, and writes none.
//
// wrangler's login may not make API tokens: setup tries, and when Cloudflare
// refuses, has the person make the token on a form it fills in, and checks
// the token before it takes it. GitHub's sign-in is gh's when it has one,
// else a fine-grained token made for this run, on a form filled in too.
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

import sodium from 'libsodium-wrappers';

import { type Account, CloudflareApi, denied, type TokenPolicy, type Zone } from './cloudflare.ts';
import type { GitHub } from './github-app.ts';
import { templateDir } from './init.ts';
import type { Step } from './steps.ts';
import { listed } from './tty.ts';

/** The workflow, where GitHub runs it from. */
export const WORKFLOW = '.github/workflows/deploy.yml';

/** The repository's Actions secrets the workflow reads. */
export const SECRETS = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'DATABASE_OWNER_URL'] as const;

/**
 * What the deploy does on Cloudflare, as `pnpm run deploy` does it: each
 * permission by its name on the dashboard, by its group's name in the API,
 * by its key in the dashboard's form, and a read that shows a token has it.
 * Workers Routes is the zone's coffre is served through; none on
 * workers.dev.
 */
const PERMISSIONS = [
  { label: 'Workers Scripts Edit', group: 'Workers Scripts Write', key: 'workers_scripts', type: 'edit', read: (account: string) => `/accounts/${account}/workers/scripts` },
  { label: 'Account Settings Read', group: 'Account Settings Read', key: 'account_settings', type: 'read', read: (account: string) => `/accounts/${account}` },
  { label: 'Workers KV Storage Edit', group: 'Workers KV Storage Write', key: 'workers_kv_storage', type: 'edit', read: (account: string) => `/accounts/${account}/storage/kv/namespaces` },
  { label: 'Hyperdrive Read', group: 'Hyperdrive Read', key: 'hyperdrive', type: 'read', read: (account: string) => `/accounts/${account}/hyperdrive/configs` },
] as const;
const ROUTES = { label: 'Workers Routes Edit', group: 'Workers Routes Write', key: 'workers_routes', type: 'edit', read: (zone: string) => `/zones/${zone}/workers/routes` } as const;

/** The token's name: which repository deploys with it. */
export const tokenName = (repository: string) => `coffre deploys: ${repository}`;

/** The permissions in words, as the dashboard names them, for the person making the token. */
export function permissionsNeeded(account: Account, zone: Zone | null): string {
  const routes = zone === null ? '' : `; and Zone, ${zone.name}: ${ROUTES.label}`;
  return `Account, ${account.name}: ${listed(PERMISSIONS.map(({ label }) => label), 'and')}${routes}`;
}

/** The token's policies, under the account and its zone, by the ids of the permission groups Cloudflare lists. */
export function deployPolicies(groups: readonly { id: string; name: string }[], account: string, zone: string | null): TokenPolicy[] {
  const id = (name: string) => {
    const group = groups.find((each) => each.name === name);
    if (group === undefined) throw new Error(`Cloudflare lists no permission named ${name}`);
    return { id: group.id };
  };
  return [
    { effect: 'allow', resources: { [`com.cloudflare.api.account.${account}`]: '*' }, permission_groups: PERMISSIONS.map(({ group }) => id(group)) },
    ...(zone === null ? [] : [{ effect: 'allow' as const, resources: { [`com.cloudflare.api.account.zone.${zone}`]: '*' as const }, permission_groups: [id(ROUTES.group)] }]),
  ];
}

/**
 * The dashboard's form for a new API token, its permissions filled in. The
 * form takes all accounts and all zones from an address, nothing narrower:
 * the person picks the account and the zone there.
 */
export function tokenForm(name: string, zone: Zone | null): string {
  const keys = [...PERMISSIONS, ...(zone === null ? [] : [ROUTES])].map(({ key, type }) => ({ key, type }));
  return `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=${encodeURIComponent(JSON.stringify(keys))}&accountId=*&zoneId=all&name=${encodeURIComponent(name)}`;
}

/** What a token may not do of what the deploy needs, by the dashboard's names: none when it may do it all. */
export async function missingPermissions(api: CloudflareApi, account: string, zone: string | null): Promise<string[]> {
  const checks = [...PERMISSIONS.map(({ label, read }) => ({ label, path: read(account) })), ...(zone === null ? [] : [{ label: ROUTES.label, path: ROUTES.read(zone) }])];
  const missing: string[] = [];
  for (const { label, path } of checks) if (!(await api.may(path))) missing.push(label);
  return missing;
}

// --- the repository ------------------------------------------------------------------

/**
 * A remote's repository, `owner/name`, when it is on `github`'s host: as
 * HTTPS, `https://github.com/acme/secrets.git`; as SSH,
 * `git@github.com:acme/secrets.git` or `ssh://git@github.com/acme/secrets`.
 */
export function repositoryOf(remote: string, github: GitHub): string | null {
  const host = new URL(github.web).hostname;
  const scp = /^(?:[^@/]+@)?([^:/]+):(?!\/)(.+)$/.exec(remote);
  let where: { hostname: string; path: string };
  if (scp !== null && !/^[a-z]+:\/\//i.test(remote)) where = { hostname: scp[1]!, path: scp[2]! };
  else {
    try {
      const url = new URL(remote);
      where = { hostname: url.hostname, path: url.pathname };
    } catch {
      return null;
    }
  }
  const parts = where.path.replace(/^\/+|\/+$/g, '').replace(/\.git$/, '').split('/');
  return where.hostname.toLowerCase() === host.toLowerCase() && parts.length === 2 && parts.every((part) => part !== '') ? parts.join('/') : null;
}

/** The address of the directory's remote: `origin`, or its only one. Null when it has none, or is no repository. */
export function gitRemote(dir: string): string | null {
  const git = (args: string[]) => spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  const remotes = git(['remote']);
  if (remotes.status !== 0) return null;
  const names = remotes.stdout.split('\n').filter((name) => name !== '');
  const name = names.includes('origin') ? 'origin' : names.length === 1 ? names[0]! : null;
  if (name === null) return null;
  const url = git(['remote', 'get-url', name]);
  return url.status === 0 ? url.stdout.trim() : null;
}

/** gh's token for a GitHub host, read from its stdout, never shown: null when gh is not here, or not signed in there. */
export function ghToken(hostname: string): Promise<string | null> {
  return new Promise((resolve) => {
    const child = spawn('gh', ['auth', 'token', '--hostname', hostname], { stdio: ['ignore', 'pipe', 'ignore'], env: { ...process.env, GH_PROMPT_DISABLED: '1' } });
    let out = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (out += chunk));
    child.on('error', () => resolve(null));
    child.on('close', (code) => resolve(code === 0 && out.trim() !== '' ? out.trim() : null));
  });
}

/** The form for a fine-grained GitHub token that may set the repository's secrets, and lasts a day: this run is all it is for. */
export function githubTokenForm(github: GitHub, repository: string): string {
  const params = new URLSearchParams({
    name: `coffre setup: ${repository}`.slice(0, 40),
    description: `coffre setup sets ${repository}'s Actions secrets for its deploys. Only this repository; it can expire.`,
    target_name: repository.split('/')[0]!,
    expires_in: '1',
    secrets: 'write',
  });
  return `${github.web}/settings/personal-access-tokens/new?${params}`;
}

export class GitHubError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** A repository's Actions secrets, through GitHub's API, under a token it never shows. */
export class GitHubRepository {
  readonly #github: GitHub;
  readonly #token: string;
  readonly name: string;

  constructor(github: GitHub, name: string, token: string) {
    this.#github = github;
    this.name = name;
    this.#token = token;
  }

  async #send(method: string, path: string, body?: unknown): Promise<Response> {
    const response = await fetch(`${this.#github.api}/repos/${this.name}/actions/secrets${path}`, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${this.#token}`,
        'user-agent': 'coffre-setup',
        'x-github-api-version': '2022-11-28',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      const { message } = (await response.json().catch(() => ({}))) as { message?: string };
      throw new GitHubError(`GitHub answered ${response.status} to ${method} ${this.name}'s secrets${message === undefined ? '' : `: ${message}`}`, response.status);
    }
    return response;
  }

  /** The key secrets are sealed to, and its id. Refused when the token may not read the repository's secrets: GitHub says 404 for a repository it hides. */
  async publicKey(): Promise<{ id: string; key: Uint8Array }> {
    const { key_id: id, key } = (await (await this.#send('GET', '/public-key')).json()) as { key_id: string; key: string };
    return { id, key: Buffer.from(key, 'base64') };
  }

  /** Whether the repository has a secret by this name. */
  async has(name: string): Promise<boolean> {
    try {
      await this.#send('GET', `/${name}`);
      return true;
    } catch (error) {
      if (error instanceof GitHubError && error.status === 404) return false;
      throw error;
    }
  }

  /** Set a secret, sealed to the repository's key: GitHub opens it, and nobody else. */
  async set(name: string, value: string, publicKey: { id: string; key: Uint8Array }): Promise<void> {
    await sodium.ready;
    const sealed = Buffer.from(sodium.crypto_box_seal(Buffer.from(value, 'utf8'), publicKey.key)).toString('base64');
    await this.#send('PUT', `/${name}`, { encrypted_value: sealed, key_id: publicKey.id });
  }
}

/** Whether GitHub refused a token for what it may do, or the repository it names. */
const refused = (error: unknown) => error instanceof GitHubError && [401, 403, 404].includes(error.status);

// --- the step -------------------------------------------------------------------------

export type Pushes = {
  dir: string;
  repository: string;
  github: GitHub;
  api: CloudflareApi;
  account: Account;
  /** The zone coffre is served through, whose routes the deploy sets; none on workers.dev. */
  zone: Zone | null;
  /** The database owner's URL, which setup was given: the workflow migrates with it. */
  owner: URL;
  /** A new Cloudflare token, even when the repository has one. */
  rotate: boolean;
  secrets: string[];
};

type Say = { aside: (text: string) => void; link: (label: string, address: string) => void };

/**
 * Set the repository's three secrets, with the workflow in place: null when
 * the person would rather not now, having no GitHub token to give.
 */
export async function deployOnPush(context: Pushes, step: Step, say: Say): Promise<{ text: string; details: string[] } | null> {
  const { repository, account, zone } = context;
  step.note(`GitHub: sign in, to set ${repository}'s secrets`);
  const github = await signIn(context, step, say);
  if (github === null) return null;
  const { repo, key, how } = github;

  let token: Made | null = null;
  if (context.rotate || !(await repo.has('CLOUDFLARE_API_TOKEN'))) {
    step.note('Cloudflare: an API token for the deploys');
    token = await deployToken(context, step, say);
  }
  step.note(`GitHub: set ${repository}'s secrets`);
  const values: [string, string][] = [
    ...(token === null ? [] : [['CLOUDFLARE_API_TOKEN', token.value] as [string, string]]),
    ['CLOUDFLARE_ACCOUNT_ID', account.id],
    ['DATABASE_OWNER_URL', context.owner.href],
  ];
  for (const [name, value] of values) await repo.set(name, value, key);
  const rotated = token !== null && context.rotate ? await retire(context, token) : [];

  // A deployment made before init wrote the workflow gets it now, to commit.
  const workflow = join(context.dir, WORKFLOW);
  const wrote = !existsSync(workflow);
  if (wrote) {
    mkdirSync(dirname(workflow), { recursive: true });
    copyFileSync(join(templateDir('workers'), WORKFLOW), workflow);
  }
  const width = Math.max(...SECRETS.map((name) => name.length)) + 2;
  const zoneNote = zone === null ? '' : `, and ${zone.name}'s routes`;
  return {
    text: `${repository} deploys on every push to main, ${how}`,
    details: [
      `${'CLOUDFLARE_API_TOKEN'.padEnd(width)}${token === null ? 'kept: coffre setup --rotate-deploy-token makes a new one' : `${token.made}, for the account's Workers${zoneNote}`}`,
      `${'CLOUDFLARE_ACCOUNT_ID'.padEnd(width)}set, ${account.name}`,
      `${'DATABASE_OWNER_URL'.padEnd(width)}set, the URL setup was given`,
      ...rotated,
      ...(wrote ? [`Wrote ${WORKFLOW}: commit it, with pnpm-lock.yaml, and push`] : []),
    ],
  };
}

/** GitHub, as gh signs in to it, else under a token made for this run; null when the person would rather not now. */
async function signIn(context: Pushes, step: Step, say: Say): Promise<{ repo: GitHubRepository; key: { id: string; key: Uint8Array }; how: string } | null> {
  const { github, repository, secrets } = context;
  const gh = await ghToken(new URL(github.web).hostname);
  if (gh !== null) {
    secrets.push(gh);
    const repo = new GitHubRepository(github, repository, gh);
    try {
      return { repo, key: await repo.publicKey(), how: "signed in to GitHub with gh's login" };
    } catch (error) {
      if (!refused(error)) throw error;
      say.aside(`gh's GitHub login may not set ${repository}'s secrets.`);
    }
  }
  const choice = await step.choose(`Set ${repository}'s Actions secrets now, with a GitHub token?`, [
    'Yes: I make a token for this run, on a form setup fills in',
    'Not now: setup says what to set',
  ]);
  if (choice !== 0) return null;
  say.aside(
    `A fine-grained token that may set ${repository}'s secrets, and lasts a day: the form has its permission, Secrets: Read and write. ` +
      `Under Repository access, choose Only select repositories, then ${repository}.`,
  );
  say.link('Make it at', githubTokenForm(github, repository));
  let found: { repo: GitHubRepository; key: { id: string; key: Uint8Array } } | null = null;
  await step.paste(
    'Paste the GitHub token, hidden as you paste it:',
    async (text) => {
      if (!/^\S{20,}$/.test(text)) return 'that is not a GitHub token: copy it whole';
      secrets.push(text);
      const repo = new GitHubRepository(github, repository, text);
      try {
        found = { repo, key: await repo.publicKey() };
        return null;
      } catch (error) {
        if (!refused(error)) throw error;
        return `that token may not set ${repository}'s secrets: it needs Secrets: Read and write, on ${repository}`;
      }
    },
    new AbortController().signal,
  );
  return { ...found!, how: 'signed in to GitHub with the token given' };
}

/** A deploy token, its id, and in a few words where it came from. */
type Made = { value: string; id: string | null; made: string };

/**
 * The deploy's Cloudflare token: made through the API, when this login may
 * make tokens; else made by the person on the dashboard's form, filled in,
 * and checked before it is taken.
 */
async function deployToken(context: Pushes, step: Step, say: Say): Promise<Made> {
  const { api, account, zone, repository, secrets } = context;
  const name = tokenName(repository);
  try {
    const made = await api.createToken(name, deployPolicies(await api.permissionGroups(), account.id, zone?.id ?? null));
    secrets.push(made.value);
    return { value: made.value, id: made.id, made: `a new token, ${name}` };
  } catch (error) {
    if (!denied(error)) throw error;
  }
  say.aside(
    `Cloudflare refused this login making an API token: wrangler's login may not. Make one for the deploys, named ${name}, with exactly ${permissionsNeeded(account, zone)}. ` +
      'The form has the permissions; choose the account and the zone there.',
  );
  say.link('Make it at', tokenForm(name, zone));
  let taken: Made | null = null;
  await step.paste(
    'Paste the Cloudflare token, hidden as you paste it:',
    async (text) => {
      if (!/^\S{20,}$/.test(text)) return 'that is not a Cloudflare API token: copy it whole';
      secrets.push(text);
      const given = new CloudflareApi(text);
      const missing = await missingPermissions(given, account.id, zone?.id ?? null);
      if (missing.length > 0) return `that token lacks ${listed(missing, 'and')}, which the deploy needs`;
      taken = { value: text, id: await given.tokenId(), made: 'the token you made' };
      return null;
    },
    new AbortController().signal,
  );
  return taken!;
}

/**
 * After a rotation, the tokens the new one replaces, by its name: deleted
 * when this login may, else left to delete on the dashboard. A token whose
 * id Cloudflare did not say could be among them, and none is deleted.
 */
async function retire(context: Pushes, token: Made): Promise<string[]> {
  const name = tokenName(context.repository);
  const byHand = ['Delete the token it replaces on Cloudflare: https://dash.cloudflare.com/profile/api-tokens'];
  if (token.id === null) return byHand;
  try {
    const old = (await context.api.tokens()).filter((each) => each.name === name && each.id !== token.id);
    for (const { id } of old) await context.api.deleteToken(id);
    return old.length === 0 ? [] : [`Deleted the token it replaces, ${name}`];
  } catch (error) {
    if (!denied(error)) throw error;
    return byHand;
  }
}
