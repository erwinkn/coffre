import { readFields, requiredString } from '../config.ts';
import { isOk, requestJson, upstreamMessage, wholeCallCode, type JsonResponse } from '../http.ts';
import { SyncProviderError, type SyncApplyResult, type SyncContext, type SyncProvider } from '../types.ts';

export type CloudflareWorkersConfig = {
  accountId: string;
  scriptName: string;
};

const API = 'https://api.cloudflare.com/client/v4';

// "You can upload up to 100 secrets per bulk request for a single version."
// https://developers.cloudflare.com/workers/configuration/secrets/
const BULK_LIMIT = 100;

type Envelope = {
  success?: boolean;
  errors?: { code?: number; message?: string }[];
  result?: unknown;
};

type SecretBody = { name: string; text: string; type: 'secret_text' };

/** A Worker's secrets on Cloudflare, deployed as a new version on every change. */
export function cloudflareWorkers(): SyncProvider<CloudflareWorkersConfig> {
  return provider;
}

const provider: SyncProvider<CloudflareWorkersConfig> = {
  id: 'cloudflare-workers',
  label: 'Cloudflare Workers',
  brand: 'cloudflare',
  fields: [
    { type: 'text', name: 'accountId', label: 'Account ID', placeholder: '32 hex characters' },
    { type: 'text', name: 'scriptName', label: 'Worker name', placeholder: 'api' },
  ],
  credential: {
    placeholder: 'ops/sync/CLOUDFLARE_API_TOKEN',
    hint: 'Use an API token with the Account › Workers Scripts › Edit permission. Each change deploys a new version of the Worker.',
  },

  parseConfig(input) {
    const fields = readFields(input, 'Cloudflare Workers', ['accountId', 'scriptName']);
    return {
      accountId: requiredString(fields, 'accountId', {
        pattern: /^[0-9a-f]{32}$/,
        hint: 'must be a Cloudflare account ID (32 lower-case hex characters)',
      }),
      // The pattern Cloudflare's OpenAPI schema gives for script names.
      scriptName: requiredString(fields, 'scriptName', {
        pattern: /^[a-z0-9_][a-z0-9-_]*$/,
        hint: 'must be a Worker name (lower-case letters, digits, "-" and "_")',
      }),
    };
  },

  describe(config) {
    return `Worker ${config.scriptName} · account ${config.accountId.slice(0, 8)}`;
  },

  checkKey(key) {
    // Workers expose secrets as env[name], so any non-empty name works;
    // a clash with another binding's name is Cloudflare's to report.
    if (key === '') return { ok: false, reason: 'Worker secret names cannot be empty' };
    return { ok: true };
  },

  async listKeys(ctx, config) {
    const secrets = await listSecrets(ctx, config);
    // secret_key bindings (Web Crypto keys) are not something coffre writes.
    return secrets.filter((secret) => secret.type === 'secret_text').map((secret) => secret.name);
  },

  async apply(ctx, config, plan) {
    const result: SyncApplyResult = { upserted: [], deleted: [], failed: [] };

    // Listing first turns deletes of absent secrets into no-ops, which the
    // merge patch below would otherwise have to guess the handling of.
    let present = new Set<string>();
    if (plan.delete.length > 0) {
      present = new Set((await listSecrets(ctx, config)).map((secret) => secret.name));
    }
    const changes: Change[] = [
      ...plan.upsert.map((variable): Change => ({
        key: variable.key,
        secret: { name: variable.key, text: variable.value, type: 'secret_text' },
      })),
      ...plan.delete.filter((key) => present.has(key)).map((key): Change => ({ key, secret: null })),
    ];
    result.deleted.push(...plan.delete.filter((key) => !present.has(key)));

    // Every secret edit creates a Worker version and deploys it immediately,
    // so the bulk endpoint matters: one version per 100 changes, not one per
    // key. Chunks run in order since each builds on the version before it.
    for (let start = 0; start < changes.length; start += BULK_LIMIT) {
      const chunk = changes.slice(start, start + BULK_LIMIT);
      const response = await bulkPatch(ctx, config, chunk);
      if (isOk(response.status)) {
        for (const change of chunk) record(result, change, null);
        continue;
      }
      throwIfWholeCall(response);
      // The bulk call is all-or-nothing, so one bad key (a value over the
      // size limit, a name taken by another binding) would sink the others.
      // Retrying one by one isolates it, at the cost of a version per key.
      // Serially: concurrent edits would race to build on the same version.
      for (const change of chunk) {
        const single = await writeOne(ctx, config, change);
        if (isOk(single.status) || (change.secret === null && single.status === 404)) {
          record(result, change, null);
          continue;
        }
        throwIfWholeCall(single);
        record(result, change, `Cloudflare rejected this secret: ${errorText(single)}`);
      }
    }

    return result;
  },
};

type Change = { key: string; secret: SecretBody | null };

function record(result: SyncApplyResult, change: Change, failure: string | null) {
  const operation = change.secret === null ? 'delete' : 'upsert';
  if (failure !== null) result.failed.push({ key: change.key, operation, message: failure });
  else if (operation === 'delete') result.deleted.push(change.key);
  else result.upserted.push(change.key);
}

function secretsUrl(config: CloudflareWorkersConfig, suffix: string): string {
  return `${API}/accounts/${config.accountId}/workers/scripts/${config.scriptName}/${suffix}`;
}

function headers(ctx: SyncContext) {
  return { Authorization: `Bearer ${ctx.token}` };
}

async function listSecrets(ctx: SyncContext, config: CloudflareWorkersConfig) {
  // "List the names of secrets bound to a Worker script." Not paginated.
  // https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/list/
  const response = await requestJson(ctx, {
    method: 'GET',
    url: secretsUrl(config, 'secrets'),
    headers: headers(ctx),
  });
  if (!isOk(response.status)) {
    throwIfWholeCall(response);
    throw cloudflareError(response, 'upstream');
  }
  const result = (response.body as Envelope | undefined)?.result;
  return (Array.isArray(result) ? result : []) as { name: string; type: string }[];
}

function bulkPatch(ctx: SyncContext, config: CloudflareWorkersConfig, chunk: Change[]) {
  // JSON Merge Patch: a secret object creates or updates, null deletes.
  // "This operation creates a single version with all changes included."
  // https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/bulk_update/
  return requestJson(ctx, {
    method: 'PATCH',
    url: secretsUrl(config, 'secrets-bulk'),
    headers: headers(ctx),
    body: { secrets: Object.fromEntries(chunk.map((change) => [change.key, change.secret])) },
  });
}

function writeOne(ctx: SyncContext, config: CloudflareWorkersConfig, change: Change) {
  if (change.secret !== null) {
    // https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/update/
    return requestJson(ctx, {
      method: 'PUT',
      url: secretsUrl(config, 'secrets'),
      headers: headers(ctx),
      body: change.secret,
    });
  }
  // url_encoded: "whether the secret name is URL encoded", so names with
  // "/" or "%" in them survive the path.
  // https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/delete/
  return requestJson(ctx, {
    method: 'DELETE',
    url: secretsUrl(config, `secrets/${encodeURIComponent(change.key)}?url_encoded=true`),
    headers: headers(ctx),
  });
}

function errorCodes(response: JsonResponse): number[] {
  const errors = (response.body as Envelope | undefined)?.errors;
  return Array.isArray(errors) ? errors.flatMap((error) => (typeof error.code === 'number' ? [error.code] : [])) : [];
}

function errorText(response: JsonResponse): string {
  const message = upstreamMessage(response.body, (body) =>
    Array.isArray(body.errors)
      ? (body.errors as Envelope['errors'])!.map((error) => error.message).filter(Boolean).join('; ')
      : undefined,
  );
  const codes = errorCodes(response);
  return `${message} (HTTP ${response.status}${codes.length ? `, code ${codes.join(', ')}` : ''})`;
}

function cloudflareError(response: JsonResponse, code: SyncProviderError['code']): SyncProviderError {
  return new SyncProviderError(`Cloudflare: ${errorText(response)}`, code, response.status);
}

// "Secret edit failed. You attempted to modify a secret, but the latest
// version of your Worker isn't currently deployed." Happens mid gradual
// rollout or after a `wrangler versions upload`; no key can succeed until
// someone deploys the latest version.
const LATEST_NOT_DEPLOYED = 10215;
// "Authentication error": Cloudflare's answer to a revoked, expired or
// unknown token, sent as a 403. It is also what a valid token without
// Workers Scripts Write gets, so the message keeps the upstream wording.
const AUTHENTICATION_ERROR = 10000;
// Malformed or unparseable Authorization headers.
const BAD_AUTH_HEADER = [6003, 6100, 6111];

function throwIfWholeCall(response: JsonResponse): void {
  const codes = errorCodes(response);
  if (codes.includes(LATEST_NOT_DEPLOYED)) throw cloudflareError(response, 'upstream');
  if (codes.includes(AUTHENTICATION_ERROR) || codes.some((code) => BAD_AUTH_HEADER.includes(code))) {
    throw cloudflareError(response, 'unauthorized');
  }
  const code = wholeCallCode(response.status);
  if (code !== null) throw cloudflareError(response, code);
}
