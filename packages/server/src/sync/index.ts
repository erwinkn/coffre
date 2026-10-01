import { guard } from './guard.ts';
import { cloudflareWorkers } from './providers/cloudflare-workers.ts';
import { githubActions } from './providers/github-actions.ts';
import { railway } from './providers/railway.ts';
import { vercel } from './providers/vercel.ts';
import type { SyncBrand, SyncField, SyncProvider } from './types.ts';

export * from './types.ts';
export { cloudflareWorkers, githubActions, railway, vercel };
export type { CloudflareWorkersConfig } from './providers/cloudflare-workers.ts';
export type { GitHubActionsConfig } from './providers/github-actions.ts';
export type { RailwayConfig } from './providers/railway.ts';
export type { VercelConfig, VercelTarget } from './providers/vercel.ts';

const PROVIDER_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const BRANDS: readonly SyncBrand[] = ['github', 'vercel', 'railway', 'cloudflare', 'other'];

/**
 * A deployment's providers, the four built-ins unless it lists its own,
 * checked and each wrapped in guard(). The guard owns the invariants the
 * engine relies on (rejected keys never sent, nothing secret in any error
 * message), so no provider has to get them right on its own.
 */
export function resolveSyncProviders(listed?: readonly SyncProvider<any>[]): SyncProvider<unknown>[] {
  const providers = listed ?? [githubActions(), vercel(), railway(), cloudflareWorkers()];
  const seen = new Set<string>();
  for (const provider of providers) {
    checkProvider(provider);
    if (seen.has(provider.id)) throw new Error(`sync provider id "${provider.id}" is used twice`);
    seen.add(provider.id);
  }
  return providers.map((provider) => guard(provider));
}

/** A deployment's own provider is checked like coffre's: it is only typed, not trusted. */
function checkProvider(provider: SyncProvider<unknown>): void {
  if (typeof provider?.id !== 'string' || !PROVIDER_ID.test(provider.id)) {
    throw new Error(`sync provider id "${provider?.id}" must be 1-32 lowercase letters, digits or dashes`);
  }
  const fail = (problem: string) => {
    throw new Error(`sync provider ${provider.id} ${problem}`);
  };
  if (!filled(provider.label)) fail('needs a label');
  if (!BRANDS.includes(provider.brand)) fail(`has a brand that is not one of ${BRANDS.join(', ')}`);
  if (!filled(provider.credential?.placeholder) || !filled(provider.credential?.hint)) {
    fail('needs a credential placeholder and hint');
  }
  for (const method of ['parseConfig', 'describe', 'checkKey', 'listKeys', 'apply'] as const) {
    if (typeof provider[method] !== 'function') fail(`needs ${method}()`);
  }
  if (!Array.isArray(provider.fields)) fail('needs a list of fields');
  const names = new Set<string>();
  for (const field of provider.fields) {
    const problem = fieldProblem(field, provider.fields);
    if (problem !== null) fail(`field ${JSON.stringify(field?.name)} ${problem}`);
    if (names.has(field.name)) fail(`has two fields named ${field.name}`);
    names.add(field.name);
  }
}

function fieldProblem(field: SyncField, fields: readonly SyncField[]): string | null {
  if (!filled(field?.name) || !filled(field.label)) return 'needs a name and a label';
  if (field.type === 'text') {
    if (typeof field.placeholder !== 'string') return 'needs a placeholder';
    if (field.when === undefined) return null;
    const on = fields.find((other) => other.name === field.when!.field);
    if (on?.type !== 'options' || !Array.isArray(field.when.is)) return 'must depend on an options field';
    return null;
  }
  if (field.type !== 'options') return 'must be of type text or options';
  const values = Array.isArray(field.options) ? field.options.map((option) => option?.value) : [];
  if (values.length === 0 || !values.every(filled)) return 'needs options, each with a value';
  if (!Array.isArray(field.initial) || !field.initial.every((value) => values.includes(value))) {
    return 'can only start with its own options';
  }
  if (!field.multiple && field.initial.length !== 1) return 'takes one option, so starts with exactly one';
  return null;
}

const filled = (value: unknown): value is string => typeof value === 'string' && value.trim() !== '';
