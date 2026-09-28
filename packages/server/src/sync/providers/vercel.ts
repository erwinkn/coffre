import { optionalString, readFields, requiredString } from '../config.ts';
import { forEachLimited, isOk, requestJson, upstreamMessage, wholeCallCode, type JsonResponse } from '../http.ts';
import {
  SyncConfigError,
  SyncProviderError,
  type SyncApplyResult,
  type SyncContext,
  type SyncProvider,
  type SyncProviderErrorCode,
} from '../types.ts';

export type VercelTarget = 'production' | 'preview' | 'development';

export type VercelConfig = {
  projectId: string;
  teamId?: string;
  targets: VercelTarget[];
  gitBranch?: string;
};

const API = 'https://api.vercel.com';
const TARGETS: readonly VercelTarget[] = ['production', 'preview', 'development'];

// https://vercel.com/docs/environment-variables/reserved-environment-variables
const RESERVED = new Set([
  'AWS_SECRET_KEY',
  'AWS_EXECUTION_ENV',
  'AWS_LAMBDA_LOG_GROUP_NAME',
  'AWS_LAMBDA_LOG_STREAM_NAME',
  'AWS_LAMBDA_FUNCTION_NAME',
  'AWS_LAMBDA_FUNCTION_MEMORY_SIZE',
  'AWS_LAMBDA_FUNCTION_VERSION',
  'NOW_REGION',
  'TZ',
  'LAMBDA_TASK_ROOT',
  'LAMBDA_RUNTIME_DIR',
]);

/** One environment variable record, as the list endpoint returns it. */
type EnvRecord = {
  id: string;
  key: string;
  type: string;
  target?: VercelTarget[] | VercelTarget;
  gitBranch?: string;
  customEnvironmentIds?: string[];
};

/** A record we want to exist: one key, one type, one set of targets. */
type Wanted = { type: 'sensitive' | 'encrypted'; target: VercelTarget[] };

export const vercel: SyncProvider<VercelConfig> = {
  kind: 'vercel',
  label: 'Vercel',

  parseConfig(input) {
    const fields = readFields(input, 'Vercel', ['projectId', 'teamId', 'targets', 'gitBranch']);
    const projectId = requiredString(fields, 'projectId', {
      pattern: /^[A-Za-z0-9._-]+$/,
      hint: 'must be a project ID (prj_…) or name',
      maxLength: 100,
    });
    const teamId = optionalString(fields, 'teamId', {
      pattern: /^team_[A-Za-z0-9]+$/,
      hint: 'must be a team ID (team_…), from the team settings page',
    });
    const gitBranch = optionalString(fields, 'gitBranch', { maxLength: 250 });

    const targets = fields.targets;
    if (!Array.isArray(targets) || targets.length === 0) {
      throw new SyncConfigError('"targets" must list at least one of "production", "preview", "development"');
    }
    for (const target of targets) {
      if (!TARGETS.includes(target)) {
        throw new SyncConfigError(`"targets" has unknown target ${JSON.stringify(target)}`);
      }
    }
    // A branch-specific variable only exists for previews, per the API: "If
    // defined, the git branch of the environment variable (must have
    // target=preview)".
    if (gitBranch !== undefined && (targets.length !== 1 || targets[0] !== 'preview')) {
      throw new SyncConfigError('"gitBranch" only applies to the "preview" target on its own');
    }

    return {
      projectId,
      teamId,
      targets: TARGETS.filter((target) => targets.includes(target)),
      gitBranch,
    };
  },

  describe(config) {
    const parts = [config.projectId, config.targets.join(' + ')];
    if (config.gitBranch) parts.push(`branch ${config.gitBranch}`);
    return parts.join(' · ');
  },

  checkKey(key) {
    if (key === '') return { ok: false, reason: 'Vercel variable names cannot be empty' };
    if (RESERVED.has(key)) return { ok: false, reason: `Vercel reserves ${key} for its function runtime` };
    return { ok: true };
  },

  async listKeys(ctx, config) {
    const records = await listRecords(ctx, config);
    return [...new Set(records.map((record) => record.key))];
  },

  async apply(ctx, config, plan) {
    const result: SyncApplyResult = { upserted: [], deleted: [], failed: [] };

    // One read up front: Vercel refuses a second record for a key whose
    // targets overlap an existing one, so every write below is planned
    // against what is already there.
    const byKey = new Map<string, EnvRecord[]>();
    for (const record of await listRecords(ctx, config)) {
      byKey.set(record.key, [...(byKey.get(record.key) ?? []), record]);
    }

    const wanted = wantedRecords(config.targets);
    const operations = [
      ...plan.upsert.map((variable) => ({ kind: 'upsert' as const, ...variable })),
      ...plan.delete.map((key) => ({ kind: 'delete' as const, key, value: '' })),
    ];

    await forEachLimited(operations, async (operation) => {
      const existing = byKey.get(operation.key) ?? [];
      const failure = await reconcile(
        ctx,
        config,
        operation.key,
        existing,
        operation.kind === 'upsert' ? { value: operation.value, wanted } : null,
      );
      if (failure !== null) result.failed.push({ key: operation.key, operation: operation.kind, message: failure });
      else if (operation.kind === 'upsert') result.upserted.push(operation.key);
      else result.deleted.push(operation.key);
    });

    return result;
  },
};

/**
 * Sensitive wherever Vercel allows it. It does not for Development: "You can
 * only create sensitive environment variables in the preview and production
 * environments." So production + development becomes two records.
 * https://vercel.com/docs/environment-variables/sensitive-environment-variables
 */
function wantedRecords(targets: VercelTarget[]): Wanted[] {
  const sensitive = targets.filter((target) => target !== 'development');
  const wanted: Wanted[] = [];
  if (sensitive.length > 0) wanted.push({ type: 'sensitive', target: sensitive });
  if (targets.includes('development')) wanted.push({ type: 'encrypted', target: ['development'] });
  return wanted;
}

/**
 * Brings one key's records in line with the plan, in an order that never
 * makes two records overlap: first free our targets from records we will not
 * reuse, then rewrite the ones we reuse, then create what is missing.
 * Returns an error message, or null on success.
 *
 * Targets outside ours belong to whoever set them. A record spanning
 * production and preview, when we own only production, is narrowed to
 * preview (keeping its value) rather than deleted.
 */
async function reconcile(
  ctx: SyncContext,
  config: VercelConfig,
  key: string,
  existing: EnvRecord[],
  upsert: { value: string; wanted: Wanted[] } | null,
): Promise<string | null> {
  const ours = new Set(config.targets);
  const reuse = new Map<EnvRecord, Wanted>();
  const missing: Wanted[] = [];

  for (const want of upsert?.wanted ?? []) {
    // Vercel cannot switch a record between sensitive and not in place ("remove
    // and re-add it"), so only a record of the same type, wholly inside our
    // targets, is reused.
    const match = existing.find(
      (record) =>
        !reuse.has(record) &&
        record.type === want.type &&
        !record.customEnvironmentIds?.length &&
        targetsOf(record).every((target) => ours.has(target)),
    );
    if (match) reuse.set(match, want);
    else missing.push(want);
  }

  for (const record of existing) {
    if (reuse.has(record)) continue;
    const kept = targetsOf(record).filter((target) => !ours.has(target));
    const response =
      kept.length > 0 || record.customEnvironmentIds?.length
        ? // https://vercel.com/docs/rest-api/projects/edit-an-environment-variable
          await vercelRequest(ctx, config, 'PATCH', `/v9/projects/${project(config)}/env/${encodeURIComponent(record.id)}`, {
            target: kept,
          })
        : // https://vercel.com/docs/rest-api/projects/remove-an-environment-variable
          await vercelRequest(ctx, config, 'DELETE', `/v9/projects/${project(config)}/env/${encodeURIComponent(record.id)}`);
    if (!isOk(response.status) && response.status !== 404) return keyFailure(response);
  }

  if (upsert === null) return null;

  for (const [record, want] of reuse) {
    // https://vercel.com/docs/rest-api/projects/edit-an-environment-variable
    const response = await vercelRequest(
      ctx,
      config,
      'PATCH',
      `/v9/projects/${project(config)}/env/${encodeURIComponent(record.id)}`,
      { value: upsert.value, target: want.target },
    );
    if (!isOk(response.status)) return keyFailure(response);
  }

  if (missing.length === 0) return null;

  // upsert=true is only a backstop for a record created between our read and
  // this write; the reconciliation above already made room.
  // https://vercel.com/docs/rest-api/projects/create-one-or-more-environment-variables
  const response = await vercelRequest(
    ctx,
    config,
    'POST',
    `/v10/projects/${project(config)}/env`,
    missing.map((want) => ({
      key,
      value: upsert.value,
      type: want.type,
      target: want.target,
      ...(config.gitBranch ? { gitBranch: config.gitBranch } : {}),
    })),
    { upsert: 'true' },
  );
  if (!isOk(response.status)) return keyFailure(response);

  // The batch endpoint answers 201 even when some entries failed.
  const failed = (response.body as { failed?: { error: { code?: string; message?: string } }[] }).failed ?? [];
  if (failed.length > 0) {
    const error = failed[0]!.error;
    return `Vercel rejected this variable: ${error.message ?? 'no error message'}${error.code ? ` (${error.code})` : ''}`;
  }
  return null;
}

/** The records for our targets (and branch), which are the only ones we touch. */
async function listRecords(ctx: SyncContext, config: VercelConfig): Promise<EnvRecord[]> {
  // https://vercel.com/docs/rest-api/projects/retrieve-the-environment-variables-of-a-project-by-id-or-name
  // The response is documented with a pagination object but no parameter to
  // request a further page; Vercel's own CLI reads it in one call, as we do.
  const response = await vercelRequest(ctx, config, 'GET', `/v10/projects/${project(config)}/env`);
  if (!isOk(response.status)) throw wholeCallError(response);

  const body = response.body as { envs?: EnvRecord[] } | EnvRecord[] | EnvRecord;
  const records = Array.isArray(body) ? body : 'envs' in body && body.envs ? body.envs : [body as EnvRecord];

  const ours = new Set(config.targets);
  return records.filter(
    (record) =>
      (record.gitBranch || undefined) === config.gitBranch && targetsOf(record).some((target) => ours.has(target)),
  );
}

function targetsOf(record: EnvRecord): VercelTarget[] {
  if (Array.isArray(record.target)) return record.target;
  return record.target ? [record.target] : [];
}

function project(config: VercelConfig): string {
  return encodeURIComponent(config.projectId);
}

// https://vercel.com/docs/rest-api (Authorization: Bearer; teamId selects the team)
function vercelRequest(
  ctx: SyncContext,
  config: VercelConfig,
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
  query: Record<string, string> = {},
): Promise<JsonResponse> {
  const params = new URLSearchParams({ ...query, ...(config.teamId ? { teamId: config.teamId } : {}) });
  const search = params.size > 0 ? `?${params}` : '';
  return requestJson(ctx, {
    method,
    url: `${API}${path}${search}`,
    body,
    headers: { Authorization: `Bearer ${ctx.token}` },
  });
}

type VercelError = { code?: string; message?: string; invalidToken?: boolean; missingToken?: boolean };

function vercelError(response: JsonResponse): VercelError {
  const body = response.body as { error?: VercelError } | undefined;
  return (typeof body === 'object' && body?.error) || {};
}

function message(response: JsonResponse): string {
  const { code } = vercelError(response);
  const text = upstreamMessage(response.body, (body) => (body.error as VercelError | undefined)?.message);
  return `${text} (HTTP ${response.status}${code ? `, ${code}` : ''})`;
}

/**
 * Vercel answers 403 for a bad token, for "this token may not do that", and
 * for per-record refusals such as "The environment variable cannot be created
 * because it already exists". The body tells them apart; Vercel's CLI reads
 * the same fields (packages/cli/src/util/projects/link.ts in vercel/vercel).
 * https://vercel.com/docs/rest-api/errors
 */
function wholeCallFailure(response: JsonResponse): SyncProviderError | null {
  const error = vercelError(response);
  const fail = (code: SyncProviderErrorCode) =>
    new SyncProviderError(`Vercel: ${message(response)}`, code, response.status);

  if (response.status === 401 || error.invalidToken || error.missingToken) return fail('unauthorized');
  if (response.status === 403) {
    const denied = error.code === undefined || error.code === 'forbidden' || error.code === 'team_unauthorized';
    return denied ? fail('forbidden') : null;
  }
  const code = wholeCallCode(response.status);
  return code === null ? null : fail(code);
}

function wholeCallError(response: JsonResponse): SyncProviderError {
  return wholeCallFailure(response) ?? new SyncProviderError(`Vercel: ${message(response)}`, 'upstream', response.status);
}

function keyFailure(response: JsonResponse): string {
  const failure = wholeCallFailure(response);
  if (failure !== null) throw failure;
  return `Vercel rejected this variable: ${message(response)}`;
}
