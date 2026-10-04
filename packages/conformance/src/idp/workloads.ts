import { randomBytes } from 'node:crypto';

import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';

import { readParams, sendJson, type Route } from './http.ts';

/**
 * A CI platform's ID tokens, as GitHub Actions signs them for a run: an
 * issuer of its own under `/workloads`, with its discovery document and its
 * keys, one RS256 and one ES256, and tokens minted for whatever run a check
 * describes. What coffre's trust bindings and exchange are checked against,
 * through their real code paths: discovery, a key set fetched over HTTP, a
 * signature verified.
 *
 * `GET /workloads/actions` answers as a GitHub runner does a job with
 * `permissions: id-token: write`, to the bearer of `requestToken`. Locally,
 * `POST /workloads/token` mints one, for trying the CLI by hand:
 *
 *   COFFRE_ID_TOKEN=$(curl -s -X POST http://127.0.0.1:8081/workloads/token \
 *     -d aud=http://127.0.0.1:3000 | jq -r .token)
 */
export class WorkloadIssuer {
  readonly #origin: () => string;
  /** A job's ACTIONS_ID_TOKEN_REQUEST_TOKEN: the bearer `GET /workloads/actions` wants. */
  readonly requestToken = randomBytes(16).toString('hex');
  #keys: { alg: 'RS256' | 'ES256'; kid: string; privateKey: CryptoKey; jwk: JWK }[] = [];

  constructor(origin: () => string) {
    this.#origin = origin;
  }

  /** Where the tokens say they come from: `http://127.0.0.1:<port>/workloads`. */
  get issuer(): string {
    return `${this.#origin()}/workloads`;
  }

  get jwksUrl(): string {
    return `${this.issuer}/jwks`;
  }

  /** A job's ACTIONS_ID_TOKEN_REQUEST_URL, which already has a query, as GitHub's does. */
  get requestUrl(): string {
    return `${this.issuer}/actions?api-version=2.0`;
  }

  async start(): Promise<void> {
    this.#keys = await Promise.all(
      (['RS256', 'ES256'] as const).map(async (alg) => {
        const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
        const kid = `dev-workloads-${alg.toLowerCase()}`;
        return { alg, kid, privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg, use: 'sig' } };
      }),
    );
  }

  /**
   * A run's ID token: GitHub's claims for a push of `deploy.yml` to `main`
   * of `acme/api`, for `audience`, valid five minutes, unless `claims` says
   * otherwise.
   */
  async mint(audience: string, claims: Record<string, unknown> = {}, alg: 'RS256' | 'ES256' = 'RS256'): Promise<string> {
    const key = this.#keys.find((candidate) => candidate.alg === alg);
    if (key === undefined) throw new Error('the workload issuer is not started');
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ ...GITHUB_RUN, iss: this.issuer, aud: audience, iat: now, nbf: now - 5, exp: now + 300, jti: crypto.randomUUID(), ...claims })
      .setProtectedHeader({ alg: key.alg, kid: key.kid, typ: 'JWT' })
      .sign(key.privateKey);
  }

  routes(): Route[] {
    return [
      {
        method: 'GET',
        path: '/workloads/.well-known/openid-configuration',
        handler: async (_req, res) =>
          sendJson(res, 200, {
            issuer: this.issuer,
            jwks_uri: this.jwksUrl,
            subject_types_supported: ['public'],
            response_types_supported: ['id_token'],
            id_token_signing_alg_values_supported: ['RS256', 'ES256'],
            claims_supported: Object.keys(GITHUB_RUN),
          }),
      },
      { method: 'GET', path: '/workloads/jwks', handler: async (_req, res) => sendJson(res, 200, { keys: this.#keys.map((key) => key.jwk) }) },
      {
        method: 'GET',
        path: '/workloads/actions',
        handler: async (req, res, url) => {
          if (req.headers.authorization?.replace(/^bearer /i, '') !== this.requestToken) return sendJson(res, 401, { message: 'Bad credentials' });
          const audience = url.searchParams.get('audience');
          if (audience === null) return sendJson(res, 400, { message: 'no audience' });
          sendJson(res, 200, { count: 1, value: await this.mint(audience) });
        },
      },
      {
        method: 'POST',
        path: '/workloads/token',
        handler: async (req, res) => {
          const params = await readParams(req);
          const alg = params?.get('alg') === 'ES256' ? 'ES256' : 'RS256';
          sendJson(res, 200, { token: await this.mint(params?.get('aud') ?? 'http://127.0.0.1:3000', {}, alg) });
        },
      },
    ];
  }
}

/** A run of `deploy.yml`, pushed to `main` of `acme/api`, as GitHub's token says it. */
export const GITHUB_RUN = {
  sub: 'repo:acme/api:ref:refs/heads/main',
  repository: 'acme/api',
  repository_id: '41532',
  repository_owner: 'acme',
  repository_owner_id: '9919',
  workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  ref_type: 'branch',
  event_name: 'push',
  run_id: '7001',
  run_attempt: '1',
  sha: '3f2a9c1e7b6d5c4a3f2a9c1e7b6d5c4a3f2a9c1e',
  actor: 'ada',
} as const;
