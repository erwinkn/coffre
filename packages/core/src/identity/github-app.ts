/**
 * The deployment's own GitHub App, made once with `githubApp(…)` and passed
 * to each side that uses it (docs/github-app.md):
 *
 *   const app = githubApp({ appId, privateKey, clientId, clientSecret });
 *   signin({ providers: [github({ app })], workloads: { limits, github: app } })
 *
 * Sign-in uses its OAuth client, `clientId` and `clientSecret`, as it would
 * an OAuth app's (`github({ app })`). The forge side, `workloads.github`,
 * uses its ID and private key: it lists the repositories the app is
 * installed on, private ones too, where an owner trusts a workflow, and
 * resolves `owner/name` to the IDs a binding names, with Metadata:
 * read-only, so what it reaches there is the names and IDs of those
 * repositories. Either side may go without the other: `github({ clientId,
 * clientSecret })` signs in alone, and an app with no client lists alone.
 *
 * The app's private key lives with the app, the rest of the deployment's
 * configuration, not in the vault: it opens no secret, and the vault's
 * isolation is for the keys that do. It and the client secret stay in this
 * object's private fields, and no message, log line or answer carries them,
 * the JWTs it signs or the installation tokens they buy.
 *
 * The object lives as long as its configuration: the isolate's, on Workers,
 * or the process's. It keeps settled values only (AGENTS.md, "What an
 * isolate keeps"): the imported key, the app's name, and each
 * installation's token until shortly before it expires. Concurrent first
 * calls each import and ask for their own.
 */

import { MintUnavailable, type Minted, type Minter } from '../mint.ts';

export type GitHubAppOptions = {
  /** The app's ID, on its settings page ("App ID"): a number, not its client ID. */
  appId: string | number;
  /** A private key generated on its settings page: the PEM file, as downloaded. */
  privateKey: string;
  /** Its OAuth client, on the same page: for signing people in with it, `github({ app })`. Both, or neither. */
  clientId?: string;
  clientSecret?: string;
  /** https://github.com, or a GitHub Enterprise Server host: where people sign in. */
  webUrl?: string;
  /**
   * https://api.github.com, or `${host}/api/v3` on Enterprise Server. The
   * forge side takes github.com's only, or the dev IdP's on loopback: an
   * Enterprise Server's runs sign their tokens under another issuer than
   * the one its lookups bind to.
   */
  apiUrl?: string;
};

/**
 * What `tokens(…)` mints: installation tokens of one account the app is
 * installed on, for some of its repositories, with some of its permissions.
 */
export type InstallationTokenScope = {
  /** The account, by login: `acme`. */
  account: string;
  /** Its repositories, by name, at least one: a token for every repository the app reaches is never minted. */
  repositories: readonly string[];
  /** As GitHub names them, each within the app's own: `{ contents: 'write' }`. */
  permissions: Readonly<Record<string, 'read' | 'write'>>;
};

/** A repository, by the IDs a binding names: what `GET /workloads/lookup` answers. */
export type GitHubRepository = { github: string; repositoryId: string; ownerId: string; private: boolean };

/** What the app reaches: its name and where to install it, the accounts it is installed on, and their repositories. */
export type GitHubAppRepositories = {
  app: { name: string; installUrl: string };
  /** The accounts it is installed on, by login. */
  installations: string[];
  /** By name. */
  repositories: GitHubRepository[];
  /** More than one listing reaches: the others are typed by name. */
  truncated: boolean;
};

/** GitHub could not be asked, or refused the app: the message says which, for a person, and carries no credential. */
export class GitHubAppUnavailable extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'GitHubAppUnavailable';
  }
}

/** GitHub answers 100 per page at most. */
const PAGE = 100;
/** Requests one listing makes at most, tokens included: well under a Worker's subrequest limit. */
export const MAX_LISTING_REQUESTS = 40;
/** A token GitHub issues for an hour is used until this long before it ends, so that none expires mid-call. */
export const TOKEN_MARGIN_MS = 5 * 60 * 1000;
/** Each request, from DNS to the last byte. */
const DEADLINE_MS = 10_000;

type Installation = { id: number; account: string };
type Token = { token: string; expiresAt: number };

export class GitHubApp {
  readonly appId: string;
  readonly webUrl: string;
  readonly apiUrl: string;
  /** Its OAuth client's ID, which is no secret; null when it was given none. */
  readonly clientId: string | null;
  readonly #clientSecret: string | null;
  readonly #pkcs8: Uint8Array<ArrayBuffer>;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  #key: CryptoKey | null = null;
  #app: GitHubAppRepositories['app'] | null = null;
  readonly #tokens = new Map<number, Token>();

  constructor(
    options: { appId: string; apiUrl: string; webUrl?: string; pkcs8: Uint8Array<ArrayBuffer>; client?: { clientId: string; clientSecret: string } },
    io: { fetch?: typeof fetch; now?: () => number } = {},
  ) {
    this.appId = options.appId;
    this.webUrl = options.webUrl ?? 'https://github.com';
    this.apiUrl = options.apiUrl;
    this.clientId = options.client?.clientId ?? null;
    this.#clientSecret = options.client?.clientSecret ?? null;
    this.#pkcs8 = options.pkcs8;
    this.#fetch = io.fetch ?? ((input, init) => fetch(input, init));
    this.#now = io.now ?? Date.now;
  }

  /** Its OAuth client, for `github({ app })`; null when it was given none. */
  signinClient(): { clientId: string; clientSecret: string } | null {
    return this.clientId === null || this.#clientSecret === null ? null : { clientId: this.clientId, clientSecret: this.#clientSecret };
  }

  /**
   * A minter of this app's installation tokens, for the vault's `minted`:
   * each mint asks GitHub for a fresh one, an hour long, narrowed to
   * `scope`, and keeps nothing of it. Checked here, when the deployment
   * makes it, so a typo stops the vault from starting.
   */
  tokens(scope: InstallationTokenScope): Minter {
    const { account, repositories, permissions } = scope;
    const name = /^[A-Za-z0-9._-]{1,100}$/;
    if (!name.test(account)) throw new Error(`tokens(…).account must be a GitHub login; got "${account}"`);
    if (repositories.length === 0 || !repositories.every((each) => name.test(each))) {
      throw new Error('tokens(…).repositories must name at least one repository, each by its name alone');
    }
    const asked = Object.entries(permissions);
    if (asked.length === 0 || !asked.every(([key, level]) => /^[a-z_]{1,64}$/.test(key) && (level === 'read' || level === 'write'))) {
      throw new Error('tokens(…).permissions must name at least one permission, each read or write');
    }
    const fixed = { account, repositories: [...repositories].sort(), permissions: Object.fromEntries(asked.sort(([a], [b]) => a.localeCompare(b))) };
    return {
      provider: 'github-app',
      fields: ['token'],
      scope: { app: this.appId, ...fixed },
      mint: (signal) => this.#mint(fixed, signal),
    };
  }

  /** https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app, narrowed. */
  async #mint(scope: InstallationTokenScope, signal: AbortSignal): Promise<Minted> {
    try {
      const where = `${scope.account}/${scope.repositories[0]}`;
      const installation = record(await this.#call(`/repos/${where}/installation`, { method: 'GET', token: await this.#jwt(), missing: true, signal }));
      if (typeof installation.id !== 'number' || (installation.suspended_at !== null && installation.suspended_at !== undefined)) {
        throw new MintUnavailable(`the GitHub App is not installed on ${where}, or its installation is suspended`);
      }
      const answer = record(await this.#call(`/app/installations/${installation.id}/access_tokens`, {
        method: 'POST',
        token: await this.#jwt(),
        body: { repositories: scope.repositories, permissions: scope.permissions },
        signal,
      }));
      const expiresAt = typeof answer.expires_at === 'string' ? Date.parse(answer.expires_at) : NaN;
      if (typeof answer.token !== 'string' || !Number.isFinite(expiresAt)) throw new MintUnavailable('GitHub issued no installation token');
      const granted = Array.isArray(answer.repositories)
        ? { repositories: answer.repositories.flatMap((each) => (typeof record(each).name === 'string' ? [record(each).name] : [])) }
        : {};
      return { values: { token: answer.token }, expiresAt: new Date(expiresAt).toISOString(), granted: { permissions: answer.permissions ?? null, ...granted } };
    } catch (error) {
      if (error instanceof GitHubAppUnavailable) throw new MintUnavailable(error.message, { cause: error });
      throw error;
    }
  }

  /** Every repository of every account the app is installed on, as many as `MAX_LISTING_REQUESTS` reach. */
  async repositories(): Promise<GitHubAppRepositories> {
    // Every request the listing makes spends from it, tokens and retries included.
    const budget: Budget = { left: MAX_LISTING_REQUESTS };
    this.#app ??= await this.#appInfo(budget);
    const { installations, more } = await this.#installations(budget);
    let truncated = more;
    /** An installation's repositories, its first page paid from `own`, and the rest from what the listing has left. */
    const list = async (installation: Installation, own: Budget): Promise<GitHubRepository[]> => {
      const repositories: GitHubRepository[] = [];
      try {
        for (let page = 1; ; page++) {
          const body = record(await this.#asInstallation(installation.id, `/installation/repositories?per_page=${PAGE}&page=${page}`, { budget: own }));
          const items = Array.isArray(body.repositories) ? body.repositories : [];
          repositories.push(...items.flatMap((item) => repository(item) ?? []));
          const total = typeof body.total_count === 'number' ? body.total_count : 0;
          if (items.length < PAGE || page * PAGE >= total) return repositories;
        }
      } catch (error) {
        if (error !== SPENT) throw error;
        truncated = true;
        return repositories;
      }
    };
    // In waves, at once within each: every installation of a wave reserves what its first page can cost at
    // worst, a token and the page, or a kept token refused, a new one and the page again, so that each one
    // started finishes its first page. What a wave did not spend goes to the next.
    const listed: GitHubRepository[][] = [];
    for (let rest = installations; rest.length > 0; ) {
      const wave: { installation: Installation; own: Budget }[] = [];
      for (const installation of rest) {
        const worst = this.#kept(installation.id) === null ? 2 : 3;
        if (budget.left < worst) break;
        budget.left -= worst;
        wave.push({ installation, own: { left: worst, then: budget } });
      }
      if (wave.length === 0) {
        truncated = true;
        break;
      }
      rest = rest.slice(wave.length);
      listed.push(...(await Promise.all(wave.map(({ installation, own }) => list(installation, own)))));
      for (const { own } of wave) budget.left += own.left;
    }
    const byId = new Map(listed.flat().map((each) => [each.repositoryId, each]));
    return {
      app: this.#app,
      installations: installations.map(({ account }) => account),
      repositories: [...byId.values()].sort((a, b) => a.github.localeCompare(b.github)),
      truncated,
    };
  }

  /** `owner/name`'s IDs, when the app is installed on it; null when it is not, its installation is suspended, or GitHub knows no such repository. */
  async repository(fullName: string): Promise<GitHubRepository | null> {
    const { id, suspended_at: suspended } = record(await this.#asApp(`/repos/${fullName}/installation`, { missing: true }));
    if (typeof id !== 'number' || (suspended !== null && suspended !== undefined)) return null;
    return repository(await this.#asInstallation(id, `/repos/${fullName}`, { missing: true }));
  }

  async #appInfo(budget: Budget): Promise<GitHubAppRepositories['app']> {
    const app = record(await this.#asApp('/app', { budget }));
    if (typeof app.name !== 'string' || typeof app.html_url !== 'string') throw new GitHubAppUnavailable('GitHub answered /app without the app');
    return { name: app.name, installUrl: `${app.html_url}/installations/new` };
  }

  /** The installations not suspended, of the first page: `more` when there may be others. */
  async #installations(budget: Budget): Promise<{ installations: Installation[]; more: boolean }> {
    const answer = await this.#asApp(`/app/installations?per_page=${PAGE}`, { budget });
    const items = Array.isArray(answer) ? answer : [];
    const installations = items.flatMap((item): Installation[] => {
      const { id, account, suspended_at: suspended } = record(item);
      const login = record(account).login;
      return typeof id === 'number' && typeof login === 'string' && (suspended === null || suspended === undefined) ? [{ id, account: login }] : [];
    });
    return { installations: installations.sort((a, b) => a.account.localeCompare(b.account)), more: items.length >= PAGE };
  }

  async #asApp(path: string, options: { missing?: boolean; budget?: Budget } = {}): Promise<unknown> {
    return this.#call(path, { method: 'GET', token: await this.#jwt(), ...options });
  }

  /** As the installation, with its token; once more with a fresh one should GitHub refuse the one kept (the app was reinstalled, say). */
  async #asInstallation(id: number, path: string, options: { missing?: boolean; budget?: Budget } = {}): Promise<unknown> {
    const kept = this.#kept(id);
    const fresh = kept === null;
    const token = kept ?? (await this.#issueToken(id, options.budget));
    const answer = await this.#call(path, { method: 'GET', token, ...options, refused: !fresh });
    if (answer !== REFUSED) return answer;
    return this.#call(path, { method: 'GET', token: await this.#issueToken(id, options.budget), ...options });
  }

  /** The installation's token, while it has more than `TOKEN_MARGIN_MS` to live. */
  #kept(id: number): string | null {
    const kept = this.#tokens.get(id);
    return kept !== undefined && kept.expiresAt - TOKEN_MARGIN_MS > this.#now() ? kept.token : null;
  }

  /** https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app */
  async #issueToken(id: number, budget?: Budget): Promise<string> {
    this.#tokens.delete(id);
    const answer = record(await this.#call(`/app/installations/${id}/access_tokens`, { method: 'POST', token: await this.#jwt(), budget }));
    const expiresAt = typeof answer.expires_at === 'string' ? Date.parse(answer.expires_at) : NaN;
    if (typeof answer.token !== 'string' || !Number.isFinite(expiresAt)) throw new GitHubAppUnavailable('GitHub issued no installation token');
    this.#tokens.set(id, { token: answer.token, expiresAt });
    return answer.token;
  }

  /**
   * The app's JWT: RS256 over its ID, for nine minutes, issued a minute
   * back for a clock running ahead (GitHub refuses more than ten).
   * https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
   */
  async #jwt(): Promise<string> {
    const key = this.#key ?? (this.#key = await importKey(this.#pkcs8));
    const now = Math.floor(this.#now() / 1000);
    const input = `${base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: this.appId }))}`;
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(input));
    return `${input}.${base64url(new Uint8Array(signature))}`;
  }

  /**
   * One request, spent from `budget` when it has one, and thrown as
   * `SPENT` when none is left. A 404 is null where `missing` allows it; a
   * 401 is `REFUSED` where `refused` asks, for a token to be issued again;
   * any other answer than a 2xx says GitHub's status and the path, and a
   * redirect is never followed.
   */
  async #call(
    path: string,
    request: { method: 'GET' | 'POST'; token: string; body?: unknown; signal?: AbortSignal; missing?: boolean; refused?: boolean; budget?: Budget },
  ): Promise<unknown> {
    if (request.budget !== undefined && !spend(request.budget)) throw SPENT;
    let response: Response;
    try {
      response = await this.#fetch(`${this.apiUrl}${path}`, {
        method: request.method,
        redirect: 'manual',
        signal: request.signal === undefined ? AbortSignal.timeout(DEADLINE_MS) : AbortSignal.any([AbortSignal.timeout(DEADLINE_MS), request.signal]),
        headers: {
          accept: 'application/vnd.github+json',
          authorization: `Bearer ${request.token}`,
          'user-agent': 'coffre',
          'x-github-api-version': '2022-11-28',
          ...(request.body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(request.body === undefined ? {} : { body: JSON.stringify(request.body) }),
      });
    } catch (cause) {
      throw new GitHubAppUnavailable('GitHub could not be reached', { cause });
    }
    if (response.ok) {
      try {
        return await response.json();
      } catch {
        throw new GitHubAppUnavailable(`GitHub answered ${path.split('?')[0]} with no JSON`);
      }
    }
    await response.body?.cancel();
    if (response.status === 404 && request.missing === true) return null;
    if (response.status === 401 && request.refused === true) return REFUSED;
    if (response.status === 401) throw new GitHubAppUnavailable(`GitHub refused the app (401): check its app ID and private key`);
    throw new GitHubAppUnavailable(`GitHub answered ${path.split('?')[0]} with ${response.status}`);
  }
}

/** A kept token GitHub refused. */
const REFUSED = Symbol('refused');
/** A listing's requests, left to make: an installation's own reserve first, then the listing's. */
type Budget = { left: number; then?: Budget };

function spend(budget: Budget | undefined): boolean {
  for (let at = budget; at !== undefined; at = at.then) {
    if (at.left > 0) {
      at.left--;
      return true;
    }
  }
  return false;
}
/** None left: the listing stops there, and says it is partial. */
const SPENT = Symbol('spent');

/**
 * A private key's PEM as PKCS #8, which Web Crypto imports: GitHub's
 * download is PKCS #1 (`BEGIN RSA PRIVATE KEY`), wrapped here as an RSA
 * key's PKCS #8. Escaped newlines, as an environment variable sometimes
 * holds them, are newlines. Never says what the key was.
 */
export function pkcs8Of(pem: string): Uint8Array<ArrayBuffer> {
  const text = typeof pem === 'string' ? pem.replaceAll('\\n', '\n').trim() : '';
  const match = /^-----BEGIN (RSA )?PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1PRIVATE KEY-----$/.exec(text);
  if (match === null) {
    throw new Error('githubApp(…).privateKey must be the app\'s private key, the PEM file GitHub downloads (BEGIN RSA PRIVATE KEY)');
  }
  const der = new Uint8Array(Buffer.from(match[2]!.replace(/\s+/g, ''), 'base64'));
  if (match[1] === undefined) return der;
  // PrivateKeyInfo: version 0, rsaEncryption with no parameters, and the PKCS #1 key as an octet string.
  const algorithm = [0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const octets = [0x04, ...derLength(der.length)];
  const body = algorithm.length + octets.length + der.length;
  const out = new Uint8Array(new ArrayBuffer(1 + derLength(body).length + body));
  out.set([0x30, ...derLength(body), ...algorithm, ...octets]);
  out.set(der, out.length - der.length);
  return out;
}

function derLength(length: number): number[] {
  if (length < 0x80) return [length];
  const bytes: number[] = [];
  for (let rest = length; rest > 0; rest >>= 8) bytes.unshift(rest & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

async function importKey(pkcs8: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  } catch {
    throw new GitHubAppUnavailable('the GitHub App\'s private key is not an RSA private key');
  }
}

function base64url(value: string | Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/** A repository as GitHub's API answers it, by the IDs a binding names. */
function repository(value: unknown): GitHubRepository | null {
  const { id, full_name: name, owner, private: hidden } = record(value);
  const ownerId = record(owner).id;
  if (typeof name !== 'string' || !Number.isSafeInteger(id) || !Number.isSafeInteger(ownerId)) return null;
  return { github: name, repositoryId: String(id), ownerId: String(ownerId), private: hidden === true };
}
