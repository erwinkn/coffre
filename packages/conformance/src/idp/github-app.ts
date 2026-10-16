import { createPublicKey, generateKeyPair, randomBytes, type KeyObject } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { promisify } from 'node:util';

import { jwtVerify } from 'jose';

import { authorizationToken, sendJson, type Route } from './http.ts';

const API = '/github/api';
const DOCS = 'https://docs.github.com/rest';

export type FakeRepository = { id: number; name: string; private: boolean };
export type FakeInstallation = {
  id: number;
  account: { login: string; id: number; type: 'Organization' | 'User' };
  suspended: boolean;
  repositories: FakeRepository[];
};

/** acme's repositories, private ones among them, and a user's; one installation suspended. */
export function fakeInstallations(): FakeInstallation[] {
  return [
    {
      id: 1,
      account: { login: 'acme', id: 9919, type: 'Organization' },
      suspended: false,
      repositories: [
        { id: 41532, name: 'api', private: false },
        { id: 41533, name: 'web', private: false },
        { id: 41540, name: 'infra', private: true },
        { id: 41541, name: 'payments', private: true },
        { id: 41550, name: 'deploy-actions', private: true },
      ],
    },
    {
      id: 2,
      account: { login: 'octo-dev', id: 583231, type: 'User' },
      suspended: false,
      repositories: [{ id: 70001, name: 'dotfiles', private: true }],
    },
    {
      id: 3,
      account: { login: 'old-co', id: 77001, type: 'Organization' },
      suspended: true,
      repositories: [{ id: 80001, name: 'legacy', private: true }],
    },
  ];
}

/**
 * The deployment's GitHub App, as GitHub's REST API answers it, under
 * `/github/api` beside the fake GitHub's sign-in: the app's JWT, checked
 * against its public key as GitHub does, buys installation tokens, which
 * list each installation's repositories. What `@coffre/core`'s `GitHubApp`
 * runs against, through its real code paths.
 *
 * Its private key is GitHub's download, PKCS #1: `privateKey`, for the
 * deployment's configuration, made at `start()` unless given.
 */
export class FakeGitHubApp {
  readonly #origin: () => string;
  readonly appId = '1001';
  readonly name = 'Coffre (dev)';
  readonly slug = 'coffre-dev';
  /** The installations, by account; a test edits them as it likes. */
  installations: FakeInstallation[] = fakeInstallations();
  /** How long an installation token lives: an hour, as GitHub's. */
  tokenTtlMs = 60 * 60 * 1000;
  /** Installation tokens issued so far. */
  tokensIssued = 0;
  /** Every request answered 503 when set: GitHub down. */
  down = false;
  #privateKey: string | undefined;
  #publicKey: KeyObject | null = null;
  readonly #tokens = new Map<string, { installation: number; expiresAt: number }>();

  constructor(origin: () => string, privateKey?: string) {
    this.#origin = origin;
    this.#privateKey = privateKey;
  }

  /** The app's private key, PKCS #1 PEM, as GitHub downloads it. */
  get privateKey(): string {
    if (this.#privateKey === undefined) throw new Error('the fake GitHub App is not started');
    return this.#privateKey;
  }

  /** What a deployment's `workloads.githubApp` names to reach this one. */
  get options(): { appId: string; privateKey: string; apiUrl: string } {
    return { appId: this.appId, privateKey: this.privateKey, apiUrl: `${this.#origin()}${API}` };
  }

  async start(): Promise<void> {
    if (this.#privateKey === undefined) {
      const { privateKey } = await promisify(generateKeyPair)('rsa', { modulusLength: 2048 });
      this.#privateKey = privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
    }
    this.#publicKey = createPublicKey(this.#privateKey);
  }

  /** Every token issued dies now: as when the app is reinstalled. */
  revokeTokens(): void {
    this.#tokens.clear();
  }

  routes(): Route[] {
    const repo = '([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)';
    return [
      { method: 'GET', path: `${API}/app`, handler: async (req, res) => this.#asApp(req, res, () => this.#app()) },
      {
        method: 'GET',
        path: `${API}/app/installations`,
        handler: async (req, res, url) => this.#asApp(req, res, () => [200, this.#installations(url)]),
      },
      {
        method: 'POST',
        path: new RegExp(`^${API}/app/installations/[0-9]+/access_tokens$`),
        handler: async (req, res, url) => this.#asApp(req, res, () => this.#issue(Number(url.pathname.split('/').at(-2)))),
      },
      {
        method: 'GET',
        path: new RegExp(`^${API}/repos/${repo}/installation$`),
        handler: async (req, res, url) => this.#asApp(req, res, () => this.#installationOf(url.pathname.split('/').slice(-3, -1).join('/'))),
      },
      {
        method: 'GET',
        path: `${API}/installation/repositories`,
        handler: async (req, res, url) => this.#asInstallation(req, res, (installation) => [200, this.#page(installation, url)]),
      },
      {
        method: 'GET',
        path: new RegExp(`^${API}/repos/${repo}$`),
        handler: async (req, res, url) =>
          this.#asInstallation(req, res, (installation) => {
            const name = url.pathname.split('/').slice(-2).join('/');
            const found = installation.repositories.find((each) => `${installation.account.login}/${each.name}`.toLowerCase() === name.toLowerCase());
            return found === undefined ? notFound() : [200, this.#repository(installation, found)];
          }),
      },
    ];
  }

  #app(): Answer {
    return [200, { id: Number(this.appId), slug: this.slug, name: this.name, html_url: `${this.#origin()}/github/apps/${this.slug}`, permissions: { metadata: 'read' } }];
  }

  /** https://docs.github.com/en/rest/apps/apps#list-installations-for-the-authenticated-app */
  #installations(url: URL): unknown[] {
    const perPage = Math.min(Number(url.searchParams.get('per_page') ?? 30), 100);
    return this.installations.slice(0, perPage).map((installation) => ({
      id: installation.id,
      account: { login: installation.account.login, id: installation.account.id, type: installation.account.type },
      repository_selection: 'selected',
      app_id: Number(this.appId),
      suspended_at: installation.suspended ? '2026-01-01T00:00:00Z' : null,
    }));
  }

  /** https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app */
  #issue(id: number): Answer {
    const installation = this.installations.find((each) => each.id === id);
    if (installation === undefined) return notFound();
    if (installation.suspended) return [403, { message: 'This installation has been suspended', documentation_url: DOCS }];
    const token = `ghs_${randomBytes(18).toString('hex')}`;
    const expiresAt = Date.now() + this.tokenTtlMs;
    this.#tokens.set(token, { installation: id, expiresAt });
    this.tokensIssued++;
    return [201, { token, expires_at: new Date(expiresAt).toISOString().replace(/\.\d{3}Z$/, 'Z'), permissions: { metadata: 'read' }, repository_selection: 'selected' }];
  }

  /** https://docs.github.com/en/rest/apps/apps#get-a-repository-installation-for-the-authenticated-app */
  #installationOf(name: string): Answer {
    const installation = this.installations.find((each) =>
      each.repositories.some((repository) => `${each.account.login}/${repository.name}`.toLowerCase() === name.toLowerCase()),
    );
    if (installation === undefined) return notFound();
    return [200, { id: installation.id, account: { login: installation.account.login, id: installation.account.id }, suspended_at: installation.suspended ? '2026-01-01T00:00:00Z' : null }];
  }

  /** https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation */
  #page(installation: FakeInstallation, url: URL): unknown {
    const perPage = Math.min(Number(url.searchParams.get('per_page') ?? 30), 100);
    const page = Math.max(Number(url.searchParams.get('page') ?? 1), 1);
    return {
      total_count: installation.repositories.length,
      repository_selection: 'selected',
      repositories: installation.repositories.slice((page - 1) * perPage, page * perPage).map((each) => this.#repository(installation, each)),
    };
  }

  #repository(installation: FakeInstallation, repository: FakeRepository): unknown {
    const { login, id, type } = installation.account;
    return {
      id: repository.id,
      node_id: `R_dev${repository.id}`,
      name: repository.name,
      full_name: `${login}/${repository.name}`,
      private: repository.private,
      owner: { login, id, type },
      html_url: `https://github.com/${login}/${repository.name}`,
    };
  }

  /** As the app, by its JWT: RS256 under its key, issued by its ID, for ten minutes at most. */
  async #asApp(req: IncomingMessage, res: ServerResponse, answer: () => Answer): Promise<void> {
    if (this.down) return send(res, [503, { message: 'Service Unavailable' }]);
    const jwt = authorizationToken(req, ['bearer']);
    try {
      if (jwt === undefined || this.#publicKey === null) throw new Error('no JWT');
      const { payload } = await jwtVerify(jwt, this.#publicKey, { algorithms: ['RS256'], issuer: this.appId, clockTolerance: 60 });
      if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number' || payload.exp - payload.iat > 600) throw new Error('too long');
    } catch {
      return send(res, [401, { message: 'A JSON web token could not be decoded', documentation_url: DOCS }]);
    }
    send(res, answer());
  }

  /** As an installation, by a token it issued that lives still. */
  async #asInstallation(req: IncomingMessage, res: ServerResponse, answer: (installation: FakeInstallation) => Answer): Promise<void> {
    if (this.down) return send(res, [503, { message: 'Service Unavailable' }]);
    const token = this.#tokens.get(authorizationToken(req, ['bearer', 'token']) ?? '');
    const installation = this.installations.find((each) => each.id === token?.installation);
    if (token === undefined || token.expiresAt <= Date.now() || installation === undefined || installation.suspended) {
      return send(res, [401, { message: 'Bad credentials', documentation_url: DOCS }]);
    }
    send(res, answer(installation));
  }
}

type Answer = [number, unknown];

function notFound(): Answer {
  return [404, { message: 'Not Found', documentation_url: DOCS }];
}

function send(res: ServerResponse, [status, body]: Answer): void {
  sendJson(res, status, body, { 'x-github-api-version-selected': '2022-11-28' });
}
