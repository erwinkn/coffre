/**
 * A CI run signing in as a service, with the ID token its platform signs
 * for it (docs/design/oidc.md): `COFFRE_SERVICE=token:api-deploy` and no
 * `COFFRE_TOKEN`. The CLI takes the run's ID token, trades it at
 * `POST /api/auth/oidc` for a credential that lasts five minutes, and
 * keeps that credential in memory only: a self-hosted runner's disk
 * outlives the job. Each run of the CLI asks once; a token is spent once
 * used, so on GitHub each run asks the runner for a fresh one.
 */

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

export type WorkloadEnv = {
  COFFRE_ID_TOKEN?: string;
  COFFRE_ID_TOKEN_FILE?: string;
  ACTIONS_ID_TOKEN_REQUEST_URL?: string;
  ACTIONS_ID_TOKEN_REQUEST_TOKEN?: string;
};

/**
 * The run's ID token, for `audience`, this instance's URL: `COFFRE_ID_TOKEN`
 * (GitLab's `id_tokens`, or any issuer's), the file `COFFRE_ID_TOKEN_FILE`
 * names, or GitHub's runner, asked for a fresh one, when the job has
 * `permissions: id-token: write`.
 */
export async function idToken(
  env: WorkloadEnv,
  audience: string,
  io: { fetch: Fetch; readFile: (path: string) => Promise<string> },
): Promise<string> {
  const given = env.COFFRE_ID_TOKEN?.trim();
  if (given) return given;
  const file = env.COFFRE_ID_TOKEN_FILE?.trim();
  if (file) {
    const read = (await io.readFile(file).catch((error: unknown) => {
      throw new Error(`COFFRE_ID_TOKEN_FILE names ${file}, which could not be read: ${(error as Error).message}`);
    })).trim();
    if (read === '') throw new Error(`COFFRE_ID_TOKEN_FILE names ${file}, which is empty`);
    return read;
  }
  const [url, bearer] = [env.ACTIONS_ID_TOKEN_REQUEST_URL?.trim(), env.ACTIONS_ID_TOKEN_REQUEST_TOKEN?.trim()];
  if (url && bearer) {
    const request = new URL(url);
    request.searchParams.set('audience', audience);
    const response = await io.fetch(request.href, { headers: { authorization: `bearer ${bearer}`, accept: 'application/json' } });
    const body = (await response.json().catch(() => null)) as { value?: unknown } | null;
    if (!response.ok || typeof body?.value !== 'string') throw new Error(`GitHub did not give this job an ID token (status ${response.status})`);
    return body.value;
  }
  throw new Error(
    'COFFRE_SERVICE is set, but there is no ID token to sign in with: on GitHub Actions, give the job ' +
      '`permissions: id-token: write`; elsewhere, set COFFRE_ID_TOKEN (GitLab: an `id_tokens` entry whose aud is ' +
      `${audience}) or COFFRE_ID_TOKEN_FILE`,
  );
}

/** Trade an ID token for a credential of `service`, or throw saying why the instance refused. */
export async function exchange(origin: string, service: string, token: string, fetchImpl: Fetch): Promise<{ token: string; expiresAt: string }> {
  const response = await fetchImpl(`${origin}/api/auth/oidc`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ service, token }),
  });
  const body = (await response.json().catch(() => null)) as { token?: unknown; expiresAt?: unknown; reason?: unknown; message?: unknown } | null;
  if (response.ok && typeof body?.token === 'string' && typeof body.expiresAt === 'string') {
    return { token: body.token, expiresAt: body.expiresAt };
  }
  const why = typeof body?.message === 'string' ? body.message : `status ${response.status}`;
  const reason = typeof body?.reason === 'string' ? ` (${body.reason})` : '';
  throw new Error(`${origin} would not sign this run in as ${service}${reason}: ${why}`);
}
