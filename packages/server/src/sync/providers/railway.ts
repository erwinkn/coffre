import { optionalEnum, optionalString, readFields, requiredString } from '../config.ts';
import { isOk, requestJson, wholeCallCode, type JsonResponse } from '../http.ts';
import { SyncProviderError, type SyncApplyResult, type SyncContext, type SyncProvider } from '../types.ts';

export type RailwayConfig = {
  projectId: string;
  environmentId: string;
  /** Omitted: the environment's shared variables. */
  serviceId?: string;
  /** "account" covers account and workspace tokens; both are bearer tokens. */
  tokenKind?: 'account' | 'project';
};

// https://docs.railway.com/reference/public-api
const API = 'https://backboard.railway.com/graphql/v2';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const idRule = (what: string) => ({ pattern: UUID, hint: `must be a Railway ${what} ID (a UUID)` });

// Query and mutation shapes: https://docs.railway.com/guides/manage-variables
const LIST = `query variables($projectId: String!, $environmentId: String!, $serviceId: String, $unrendered: Boolean) {
  variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId, unrendered: $unrendered)
}`;
const UPSERT = `mutation variableCollectionUpsert($input: VariableCollectionUpsertInput!) {
  variableCollectionUpsert(input: $input)
}`;
const DELETE = `mutation variableDelete($input: VariableDeleteInput!) {
  variableDelete(input: $input)
}`;

type GraphQLBody<T> = { data?: T | null; errors?: { message?: string }[] };

/** One Railway environment's variables: a service's, or the shared ones. */
export function railway(): SyncProvider<RailwayConfig> {
  return provider;
}

const provider: SyncProvider<RailwayConfig> = {
  id: 'railway',
  label: 'Railway',
  brand: 'railway',
  fields: [
    { type: 'text', name: 'projectId', label: 'Project ID', placeholder: 'UUID' },
    { type: 'text', name: 'environmentId', label: 'Environment ID', placeholder: 'UUID' },
    {
      type: 'text',
      name: 'serviceId',
      label: 'Service ID',
      placeholder: 'UUID',
      optional: true,
      hint: 'Leave empty to write shared variables.',
    },
    {
      type: 'options',
      name: 'tokenKind',
      label: 'Token',
      options: [
        { value: 'project', label: 'Project token' },
        { value: 'account', label: 'Account or workspace token' },
      ],
      multiple: false,
      initial: ['project'],
    },
  ],
  credential: {
    placeholder: 'ops/sync/RAILWAY_TOKEN',
    hint: 'A project token for this one environment is the narrowest grant. Railway redeploys the service after every change.',
  },

  parseConfig(input) {
    const fields = readFields(input, 'Railway', ['projectId', 'environmentId', 'serviceId', 'tokenKind']);
    return {
      projectId: requiredString(fields, 'projectId', idRule('project')),
      environmentId: requiredString(fields, 'environmentId', idRule('environment')),
      serviceId: optionalString(fields, 'serviceId', idRule('service')),
      tokenKind: optionalEnum(fields, 'tokenKind', ['account', 'project'] as const),
    };
  },

  describe(config) {
    const short = (id: string) => id.slice(0, 8);
    const scope = config.serviceId ? `service ${short(config.serviceId)}` : 'shared variables';
    return `${scope} · environment ${short(config.environmentId)} · project ${short(config.projectId)}`;
  },

  checkKey(key) {
    if (key === '') return { ok: false, reason: 'Railway variable names cannot be empty' };
    // Railway's own CLI refuses these: "Keys reserved for Railway-provided
    // variables" (src/controllers/variables.rs in railwayapp/cli).
    if (key.startsWith('RAILWAY_')) return { ok: false, reason: 'Railway reserves names starting with RAILWAY_' };
    return { ok: true };
  },

  listKeys(ctx, config) {
    return listKeys(ctx, config);
  },

  async apply(ctx, config, plan) {
    const result: SyncApplyResult = { upserted: [], deleted: [], failed: [] };
    const scope = {
      projectId: config.projectId,
      environmentId: config.environmentId,
      ...(config.serviceId ? { serviceId: config.serviceId } : {}),
    };

    // Deletes run first and one at a time. variableDelete has no skipDeploys
    // flag, so each may trigger a redeploy of its own; serialising them, and
    // putting the upsert last, makes the last deploy triggered the one that
    // sees the final set of variables.
    if (plan.delete.length > 0) {
      // Listing first turns "already absent" into a no-op instead of relying
      // on whatever error Railway returns for a missing variable.
      const present = new Set(await listKeys(ctx, config));
      for (const key of plan.delete) {
        if (!present.has(key)) {
          result.deleted.push(key);
          continue;
        }
        const response = await graphql<{ variableDelete: boolean }>(ctx, config, DELETE, {
          input: { ...scope, name: key },
        });
        const failure = mutationFailure(response);
        if (failure === null) result.deleted.push(key);
        else result.failed.push({ key, operation: 'delete', message: failure });
      }
    }

    if (plan.upsert.length > 0) {
      // One call for every upsert, so the service redeploys once, not per key.
      // replace: false leaves variables coffre does not manage alone.
      // skipDeploys: false because a pushed value that nothing runs with is
      // silent drift: the point of syncing is that the service uses coffre's
      // values. Engines that want to batch deploys can revisit this.
      const response = await graphql<{ variableCollectionUpsert: boolean }>(ctx, config, UPSERT, {
        input: {
          ...scope,
          variables: Object.fromEntries(plan.upsert.map((variable) => [variable.key, variable.value])),
          replace: false,
          skipDeploys: false,
        },
      });
      // The call is all-or-nothing, so its one outcome applies to every key.
      const failure = mutationFailure(response);
      for (const { key } of plan.upsert) {
        if (failure === null) result.upserted.push(key);
        else result.failed.push({ key, operation: 'upsert', message: failure });
      }
    }

    return result;
  },
};

async function listKeys(ctx: SyncContext, config: RailwayConfig): Promise<string[]> {
  // unrendered: we only want names, so there is no point asking Railway to
  // resolve ${{ references }} into other services' values.
  const response = await graphql<{ variables: Record<string, string | null> }>(ctx, config, LIST, {
    projectId: config.projectId,
    environmentId: config.environmentId,
    serviceId: config.serviceId ?? null,
    unrendered: true,
  });
  const body = response.body as GraphQLBody<{ variables: Record<string, string | null> }>;
  if (!isOk(response.status) || body.errors?.length || !body.data?.variables) {
    throw wholeCallFailure(response) ?? railwayError(response, 'upstream');
  }
  // Railway-provided variables are not ours to list, since they cannot be managed.
  return Object.keys(body.data.variables).filter((key) => !key.startsWith('RAILWAY_'));
}

function graphql<T>(ctx: SyncContext, config: RailwayConfig, query: string, variables: object) {
  return requestJson(ctx, {
    method: 'POST',
    url: API,
    body: { query, variables },
    // "Project tokens use the Project-Access-Token header, not the
    // Authorization: Bearer header." https://docs.railway.com/reference/public-api
    headers:
      config.tokenKind === 'project'
        ? { 'Project-Access-Token': ctx.token }
        : { Authorization: `Bearer ${ctx.token}` },
  }) as Promise<JsonResponse & { body: GraphQLBody<T> | undefined }>;
}

function errorText(response: JsonResponse): string {
  const body = response.body as GraphQLBody<unknown> | string | undefined;
  if (body && typeof body === 'object' && body.errors?.length) {
    return body.errors.map((error) => error.message ?? 'unknown error').join('; ');
  }
  if (typeof body === 'string' && body) return `${body} (HTTP ${response.status})`;
  return `HTTP ${response.status}`;
}

function railwayError(response: JsonResponse, code: SyncProviderError['code']): SyncProviderError {
  return new SyncProviderError(`Railway: ${errorText(response)}`, code, response.status);
}

/**
 * Failures that doom the whole call. Railway reports a denied or unknown
 * token as HTTP 200 with the message "Not Authorized" ("A query that runs but
 * is denied returns 200; the failure is in errors"), and a malformed query
 * as a 400, which here can only mean the API changed under us.
 */
function wholeCallFailure(response: JsonResponse): SyncProviderError | null {
  if (/not authori[sz]ed/i.test(errorText(response))) return railwayError(response, 'unauthorized');
  if (response.status === 400) return railwayError(response, 'upstream');
  const code = wholeCallCode(response.status);
  return code === null ? null : railwayError(response, code);
}

/** Null when the mutation went through; throws when no key could succeed. */
function mutationFailure(response: JsonResponse): string | null {
  const whole = wholeCallFailure(response);
  if (whole !== null) throw whole;
  const body = response.body as GraphQLBody<Record<string, boolean>> | undefined;
  if (isOk(response.status) && !body?.errors?.length && body?.data) {
    const [outcome] = Object.values(body.data);
    if (outcome === true) return null;
  }
  return `Railway rejected this change: ${errorText(response)}`;
}
