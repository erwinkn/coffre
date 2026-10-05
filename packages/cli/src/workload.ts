/**
 * A CI run signing in as a service, with the ID token its platform signs
 * for it (docs/design/oidc.md), and no bearer token: `coffre --service
 * api-deploy …` for one command, or `coffre login <url> --service
 * api-deploy` for the commands after it. The CLI takes the run's ID token,
 * trades it at `POST /api/auth/oidc` for a credential that lasts five
 * minutes, and keeps that credential in memory, or, after a login, in the
 * session it saves, which lasts as long. A token is spent once used, so on
 * GitHub each exchange asks the runner for a fresh one.
 */

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

/** What GitHub's runner hands a job with `permissions: id-token: write`: where to ask for an ID token, and with what. */
export type Runner = {
  ACTIONS_ID_TOKEN_REQUEST_URL?: string;
  ACTIONS_ID_TOKEN_REQUEST_TOKEN?: string;
};

/**
 * The run's ID token, for `audience`, this instance's URL: the one
 * `coffre login --service <name> --id-token` asked for (GitLab's
 * `id_tokens`, or any issuer's), or GitHub's runner's, asked for a fresh
 * one, when the job has `permissions: id-token: write`.
 */
export async function idToken(given: string | undefined, runner: Runner, audience: string, fetchImpl: Fetch): Promise<string> {
  if (given) return given;
  const [url, bearer] = [runner.ACTIONS_ID_TOKEN_REQUEST_URL?.trim(), runner.ACTIONS_ID_TOKEN_REQUEST_TOKEN?.trim()];
  if (url && bearer) {
    const request = new URL(url);
    request.searchParams.set('audience', audience);
    const response = await fetchImpl(request.href, { headers: { authorization: `bearer ${bearer}`, accept: 'application/json' } });
    const body = (await response.json().catch(() => null)) as { value?: unknown } | null;
    if (!response.ok || typeof body?.value !== 'string') throw new Error(`GitHub did not give this job an ID token (status ${response.status})`);
    return body.value;
  }
  throw new Error(
    '--service signs in with the run\'s ID token, and there is none: on GitHub Actions, give the job ' +
      '`permissions: id-token: write`; elsewhere, pipe it to `coffre login <url> --service <name> --id-token` (GitLab: an `id_tokens` entry whose aud is ' +
      `${audience})`,
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
