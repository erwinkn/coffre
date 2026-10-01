import { fromBase64, toBase64 } from '../base64.ts';
import { optionalString, readFields, requiredString } from '../config.ts';
import { forEachLimited, isOk, requestJson, upstreamMessage, wholeCallCode, type JsonResponse } from '../http.ts';
import { sealedBox } from '../sealed-box.ts';
import { SyncProviderError, type SyncApplyResult, type SyncContext, type SyncProvider } from '../types.ts';

export type GitHubActionsConfig = { owner: string; repo: string; environment?: string };

const API = 'https://api.github.com';
const PAGE_SIZE = 100;
// https://docs.github.com/en/actions/reference/security/secrets#limits-for-secrets
const MAX_VALUE_BYTES = 48 * 1024;

/** Repository secrets, or an environment's, in GitHub Actions. */
export function githubActions(): SyncProvider<GitHubActionsConfig> {
  return provider;
}

const provider: SyncProvider<GitHubActionsConfig> = {
  id: 'github-actions',
  label: 'GitHub Actions',
  brand: 'github',
  fields: [
    { type: 'text', name: 'owner', label: 'Owner', placeholder: 'erwinkn' },
    { type: 'text', name: 'repo', label: 'Repository', placeholder: 'app' },
    {
      type: 'text',
      name: 'environment',
      label: 'Environment',
      placeholder: 'production',
      optional: true,
      hint: 'Leave empty to write repository secrets.',
    },
  ],
  credential: {
    placeholder: 'ops/sync/GITHUB_TOKEN',
    hint: 'Use a fine-grained token for this one repository, with Secrets: Read and write, or Environments: Read and write for an environment’s secrets. A classic token needs the repo scope.',
  },

  parseConfig(input) {
    const fields = readFields(input, 'GitHub Actions', ['owner', 'repo', 'environment']);
    return {
      owner: requiredString(fields, 'owner', {
        pattern: /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/,
        hint: 'must be a GitHub user or organization name',
        maxLength: 39,
      }),
      repo: requiredString(fields, 'repo', {
        pattern: /^[A-Za-z0-9._-]+$/,
        hint: 'must be a repository name, without the owner',
        maxLength: 100,
      }),
      environment: optionalString(fields, 'environment', { maxLength: 255 }),
    };
  },

  describe(config) {
    const repo = `${config.owner}/${config.repo}`;
    return config.environment ? `${repo} · environment ${config.environment}` : repo;
  },

  // https://docs.github.com/en/actions/reference/security/secrets#naming-your-secrets
  checkKey(key) {
    if (!/^[A-Za-z0-9_]+$/.test(key)) {
      return { ok: false, reason: 'GitHub secret names may only contain letters, digits and underscores' };
    }
    if (/^[0-9]/.test(key)) return { ok: false, reason: 'GitHub secret names cannot start with a digit' };
    if (/^GITHUB_/i.test(key)) return { ok: false, reason: 'GitHub reserves secret names starting with GITHUB_' };
    // Stricter than GitHub, on purpose: it upper-cases every name on save, so
    // "db_url" would come back from listKeys as "DB_URL" and look like a
    // different secret, and "db_url" plus "DB_URL" would overwrite each other.
    if (key !== key.toUpperCase()) {
      return { ok: false, reason: `GitHub stores secret names in upper case; name it ${key.toUpperCase()}` };
    }
    return { ok: true };
  },

  async listKeys(ctx, config) {
    const names: string[] = [];
    for (let page = 1; ; page++) {
      // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#list-repository-secrets
      // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#list-environment-secrets
      const response = await github(ctx, 'GET', `${secretsPath(config)}?per_page=${PAGE_SIZE}&page=${page}`);
      if (!isOk(response.status)) throw wholeCallError(response);

      const body = response.body as { total_count: number; secrets: { name: string }[] };
      names.push(...body.secrets.map((secret) => secret.name));
      if (body.secrets.length < PAGE_SIZE || names.length >= body.total_count) return names;
    }
  },

  async apply(ctx, config, plan) {
    const result: SyncApplyResult = { upserted: [], deleted: [], failed: [] };

    // Fetched even for a delete-only plan: it proves the repository (and
    // environment) exist, which is what lets a 404 on DELETE below mean
    // "already gone" rather than "wrong target".
    // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#get-a-repository-public-key
    // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#get-an-environment-public-key
    const keyResponse = await github(ctx, 'GET', `${secretsPath(config)}/public-key`);
    if (!isOk(keyResponse.status)) throw wholeCallError(keyResponse);
    const publicKey = keyResponse.body as { key_id: string; key: string };
    const recipient = fromBase64(publicKey.key);

    const encoder = new TextEncoder();
    const operations = [
      ...plan.upsert.map((variable) => ({ kind: 'upsert' as const, key: variable.key, value: variable.value })),
      ...plan.delete.map((key) => ({ kind: 'delete' as const, key, value: '' })),
    ];

    await forEachLimited(operations, async (operation) => {
      const path = `${secretsPath(config)}/${encodeURIComponent(operation.key)}`;

      if (operation.kind === 'delete') {
        // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#delete-a-repository-secret
        // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#delete-an-environment-secret
        const response = await github(ctx, 'DELETE', path);
        if (isOk(response.status) || response.status === 404) result.deleted.push(operation.key);
        else recordFailure(result, operation.key, 'delete', response);
        return;
      }

      const plaintext = encoder.encode(operation.value);
      if (plaintext.length > MAX_VALUE_BYTES) {
        result.failed.push({ key: operation.key, operation: 'upsert', message: 'GitHub limits secrets to 48 KB' });
        return;
      }
      // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#create-or-update-a-repository-secret
      // https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28#create-or-update-an-environment-secret
      const response = await github(ctx, 'PUT', path, {
        encrypted_value: toBase64(sealedBox(plaintext, recipient)),
        key_id: publicKey.key_id,
      });
      if (isOk(response.status)) result.upserted.push(operation.key);
      else recordFailure(result, operation.key, 'upsert', response);
    });

    return result;
  },
};

function secretsPath(config: GitHubActionsConfig): string {
  const repo = `${API}/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}`;
  // "The name must be URL encoded. For example, any slashes in the name must be
  // replaced with %2F." (environment secret endpoints)
  return config.environment
    ? `${repo}/environments/${encodeURIComponent(config.environment)}/secrets`
    : `${repo}/actions/secrets`;
}

// https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2022-11-28
function github(ctx: SyncContext, method: 'GET' | 'PUT' | 'DELETE', url: string, body?: unknown) {
  return requestJson(ctx, {
    method,
    url,
    body,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${ctx.token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      // GitHub rejects requests without one, and Workers do not send a default.
      'User-Agent': 'coffre-sync',
    },
    isRateLimited,
  });
}

// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#exceeding-the-rate-limit
// "you will receive a 403 or 429 response"; a 403 that is a rate limit carries
// retry-after or a zero x-ratelimit-remaining, a permission 403 carries neither.
function isRateLimited(response: { status: number; headers: Headers }): boolean {
  if (response.status === 429) return true;
  return (
    response.status === 403 &&
    (response.headers.has('retry-after') || response.headers.get('x-ratelimit-remaining') === '0')
  );
}

function message(response: JsonResponse): string {
  return `${upstreamMessage(response.body, (body) => body.message)} (HTTP ${response.status})`;
}

function wholeCallError(response: JsonResponse): SyncProviderError {
  const code = isRateLimited(response) ? 'rate_limited' : (wholeCallCode(response.status) ?? 'upstream');
  return new SyncProviderError(`GitHub: ${message(response)}`, code, response.status);
}

function recordFailure(
  result: SyncApplyResult,
  key: string,
  operation: 'upsert' | 'delete',
  response: JsonResponse,
): void {
  if (isRateLimited(response) || wholeCallCode(response.status) !== null) throw wholeCallError(response);
  result.failed.push({ key, operation, message: `GitHub rejected this secret: ${message(response)}` });
}
