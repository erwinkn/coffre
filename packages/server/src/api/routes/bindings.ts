import { isCredentialScope, isScope, managesService, MAX_SCOPE_PLACES, ROLE_ID, runsInstance, type Permission, type Place, type RoleDefinition } from '@coffre/core/access';
import {
  BindingInvalid,
  checkBinding,
  checkPolicy,
  isBearerProfile,
  keySummaries,
  KeysInvalid,
  PROFILE_RULES,
  PROFILE_URNS,
  uploadedKeys,
  type BindingClaims,
  type BindingPolicy,
  type KeySummary,
  type WorkloadProfile,
  type WorkloadsConfig,
} from '@coffre/core/identity';
import { isServiceMember, rowId, shownMember, slug } from '@coffre/core/schemas';
import type { Answers, Called, Change } from '@coffre/core/vault';
import { z } from 'zod';

import { serviceBindings, type BindingRow, type ServiceBindings } from '../../db/queries/bindings.ts';
import { discoverKeys, DiscoveryFailed } from '../../workloads/discovery.ts';
import { changed } from '../change.ts';
import type { ApiContext } from '../context.ts';
import { ApiError, badRequest, notFound, refusal } from '../errors.ts';
import { route } from '../route.ts';

/**
 * A service account's trust bindings (docs/design/0.16.md, "A workload
 * signing in"): which CI runs and workloads sign in as it, by their
 * platform's proof. The list is one call to the vault, `caller`, and one
 * statement; making, re-keying and removing one is one `change` each,
 * `token.bind` or `token.unbind`, which decides who may and what the
 * binding reaches. The app asks the issuer where its keys are, which only
 * it can, and checks the binding's shape with the rules the vault checks
 * it by, so that a mistake is told in words before anything is asked.
 */

/** A binding's policy as the API shows it: as stored, but its `reads` by path and key name. */
export type PolicyView = Omit<BindingPolicy, 'reads'> & { reads?: Record<string, readonly string[] | '*'> };

/** A binding as a manager of its service sees it, 0.14.7's shape. */
export type BindingView = {
  id: string;
  profile: WorkloadProfile;
  issuer: string;
  /** Where coffre fetches its issuer's keys; for one that carries them, `sha256:<hex>` of those. */
  jwksUri: string;
  /** The keys it carries, under which coffre verifies and fetches nothing; null when they are fetched from `jwksUri`. */
  keys: KeySummary[] | null;
  claims: BindingClaims;
  /** What the credentials it issues reach, by path and role; null for one that reaches nothing it says. */
  scope: Record<string, string> | null;
  /** A workload's binding's policy; null for one a CI run's exchange takes; `{}` for one its row keeps unreadable. */
  policy: PolicyView | null;
  label: string | null;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
};

/** A binding made or re-keyed: its id, and what it reaches, by path and role, as the vault sealed it. */
export type BindingMade = { id: string; scope: Record<string, string> };

/** The service a path names: a binding is a service account's, `token:<name>`, as the vault takes one. */
function serviceIn(raw: string): string {
  if (!isServiceMember(raw)) throw badRequest('a trust binding is a service account\'s: name it token:<name>');
  return raw;
}

/** The deployment's workloads, or the 404 that says how to turn them on. */
function workloadsOf(ctx: ApiContext): WorkloadsConfig {
  const workloads = ctx.auth.mode === 'signin' ? ctx.auth.signin.workloads : null;
  if (workloads === null) throw notFound('this instance trusts no workloads: its configuration turns them on, signin({ workloads: { limits } })');
  return workloads;
}

/** What `invalid` means of a binding: the vault's words for what its checks refuse, which the app's own checks word first where they can. */
const INVALID = 'a role the instance does not have, a read outside its scope or of a key its environment does not hold, a policy its reads break, keys that are no JWKS, or bindings replaced that reach nothing the service still holds';

/** `token.bind` or `token.unbind`, asked with what the request showed: its answer, or its refusal in the API's words. */
async function bindingChange<O extends 'token.bind' | 'token.unbind'>(ctx: ApiContext, change: Extract<Change, { op: O }>, member: string): Promise<Answers[O]> {
  try {
    return await changed<O>(ctx, change, shownMember(member));
  } catch (error) {
    if (error instanceof ApiError && error.reason === 'invalid') throw new ApiError('conflict', `${shownMember(member)}: ${INVALID}`, 'invalid');
    throw error;
  }
}

/** Whether the caller may list the service's bindings: the service itself, or whoever manages it (`manages`). A listing; it decides nothing. */
function lists(who: Called, member: string, found: ServiceBindings | null): boolean {
  return who.principal === member || manages(who, found);
}

/**
 * Whether the caller manages the service, and so may bind it: whoever runs
 * the instance, or a person on a session who manages it (`managesService`),
 * weighed as the vault weighs it, on its rows as they stand. It decides
 * nothing: the vault weighs it again on its own.
 */
function manages(who: Called, found: ServiceBindings | null): boolean {
  if (runsInstance(who.holds)) return true;
  if (!who.principal.startsWith('user:') || who.holds.credentialScope != null || found === null || found.status !== 'active') return false;
  let setting: unknown = null;
  try {
    setting = found.setting === null ? null : JSON.parse(found.setting);
  } catch {
    // As none.
  }
  if (!isScope(setting)) return false;
  const grants: { role: string; place: Place }[] = [];
  for (const grant of found.grants) {
    // A grant on a place that is gone: the vault reads the service as none.
    if (grant.project === null || (grant.environmentId !== null && grant.environment === null)) return false;
    // A deletion's tombstone holds nothing.
    if ((grant.environment ?? grant.project ?? '').includes('~')) continue;
    grants.push({ role: grant.role, place: grant.environmentId === null ? { projectId: grant.projectId } : { projectId: grant.projectId, environmentId: grant.environmentId, environmentSlug: grant.environment! } });
  }
  const named = Object.fromEntries(found.grants.flatMap((grant) => (grant.definition === null ? [] : [[grant.role, { name: grant.definition.name, description: '', permissions: grant.definition.permissions as Permission[], protected: grant.definition.protected as Permission[] } satisfies RoleDefinition]])));
  const holds = { ...who.holds, policy: { ...who.holds.policy, roles: { ...named, ...who.holds.policy.roles } } };
  return managesService(holds, setting, who.principal, { grants, admittedBy: found.admittedBy });
}

/** JSON as a binding's row keeps it, or `fallback` for text that does not parse. */
function parsed<T>(text: string | null, fallback: T): T {
  if (text === null) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

/** A plain object, as JSON keeps one. */
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** A policy's `reads` by path and key name, leaving out an entry the row keeps in another shape. */
function readsShown(reads: unknown, pathOf: (id: string) => string, keys: Readonly<Record<string, string>>): Record<string, readonly string[] | '*'> {
  if (!isRecord(reads)) return {};
  const shown: Record<string, readonly string[] | '*'> = {};
  for (const [id, read] of Object.entries(reads)) {
    if (!isRecord(read)) continue;
    if (read.keys === '*') shown[pathOf(id)] = '*';
    else if (read.keys === undefined || Array.isArray(read.keys)) shown[pathOf(id)] = (read.keys ?? []).filter((key): key is string => typeof key === 'string').map((key) => keys[key] ?? key).sort();
  }
  return shown;
}

/** A row as its service's page lists it: its places and keys by path and name, as they are named now; one gone, by its id. */
function view(row: BindingRow, paths: Readonly<Record<string, string>>, keys: Readonly<Record<string, string>>): BindingView {
  const scope = parsed<unknown>(row.scope, null);
  // A policy the row keeps that does not read as one still makes a workload's binding: shown as `{}`, never as none.
  const policy = row.policy === null ? null : parsed<unknown>(row.policy, {});
  // Any policy that is no object, JSON's `null` included, reads as `{}`: the column's own nullness says which kind the binding is.
  let carried: KeySummary[] | null = null;
  if (row.jwks !== null) {
    try {
      carried = keySummaries(row.jwks);
    } catch {
      carried = [];
    }
  }
  const pathOf = (id: string) => paths[id] ?? id;
  let shownPolicy: PolicyView | null = null;
  if (row.policy !== null) {
    const { reads, ...rest } = isRecord(policy) ? policy : {};
    shownPolicy = (reads === undefined ? rest : { ...rest, reads: readsShown(reads, pathOf, keys) }) as PolicyView;
  }
  return {
    id: row.id,
    profile: row.profile as WorkloadProfile,
    issuer: row.issuer,
    jwksUri: row.jwksUri,
    keys: carried,
    claims: parsed<BindingClaims>(row.claims, {}),
    scope: isCredentialScope(scope) ? Object.fromEntries(scope.map((grant) => [pathOf(grant.environmentId ?? grant.projectId ?? ''), grant.role]).sort(([a], [b]) => (a! < b! ? -1 : 1))) : null,
    policy: shownPolicy,
    label: row.label,
    createdAt: row.createdAt,
    createdBy: row.createdBy,
    lastUsedAt: row.lastUsedAt,
  };
}

/** A JWKS as a request sends one: its keys, each an object, which `uploadedKeys` checks. */
const jwks = z.object({ keys: z.array(z.record(z.string(), z.unknown())).max(64) }).passthrough();

/**
 * What the vault takes of a binding, as its contract says (`TokenBind`):
 * an input of another shape is a fault there, never a refusal, so the app
 * holds every request to it first, as a 400.
 */
/** Text the vault keeps as given: no NUL, no half of a surrogate pair. */
const kept = (most: number) => z.string().max(most).refine((value) => !value.includes('\0') && Buffer.from(value).toString() === value, 'well-formed text, with no NUL');
/** A place by path, `market` or `market/dev`. */
const placePath = z.string().refine((path) => {
  const [project, environment, ...more] = path.split('/');
  return more.length === 0 && slug.safeParse(project).success && (environment === undefined || slug.safeParse(environment).success);
}, 'a place is named by its path: <project> or <project>/<environment>');
/** An environment by path, `market/dev`. */
const environmentPath = z.string().refine((path) => /^[a-z0-9][a-z0-9-]{0,62}\/[a-z0-9][a-z0-9-]{0,62}$/.test(path), 'an environment is named by its path: <project>/<environment>');
/** What a binding's credentials reach, by path: 1 to 1,000 places, each with a role's id. */
const scopeByPath = z.record(placePath, z.string().regex(ROLE_ID, 'a role is named by its id')).refine((scope) => {
  const size = Object.keys(scope).length;
  return size > 0 && size <= MAX_SCOPE_PLACES;
}, `a scope names 1 to ${MAX_SCOPE_PLACES} places`);
/** A policy's `reads`: 64 environments at most, each its key names, 256 at most, or `"*"`. */
const readsByPath = z.record(environmentPath, z.union([z.literal('*'), z.array(kept(256).refine((key) => key !== '', 'a key has a name')).max(256)])).refine((reads) => Object.keys(reads).length <= 64, 'a binding reads in 64 environments at most');
/** A label as the vault keeps one: 1 to 120 characters, no control character, no space around it. */
const label = kept(120).refine((value) => value !== '' && value === value.trim() && !/\p{Cc}/u.test(value), 'a label is 1 to 120 characters, with no control character and no space around it');

/** Uploaded keys, checked as the vault checks them, or the 400 that says what is wrong with them. */
async function checkedKeys(value: unknown): Promise<void> {
  try {
    await uploadedKeys(value);
  } catch (error) {
    if (error instanceof KeysInvalid) throw badRequest(error.message);
    throw error;
  }
}

/**
 * Before the app asks an issuer anything for a binding: whether the caller
 * manages the service, so that no one else makes coffre fetch a host they
 * name. One `caller` and one statement, on that path alone; the vault
 * weighs it again, on its own rows, when it binds.
 */
async function mayBind(ctx: ApiContext, member: string): Promise<void> {
  const who = await ctx.caller();
  if (!manages(who, await serviceBindings(ctx.db, member, new Date()))) throw refusal('no_access', shownMember(member));
}

const NO_PREVIEW = new ApiError('not_implemented', "a binding's preview (?dryRun=1) is not served yet: the binding is made, and what it reaches is its answer");
const dryRun = z.object({ dryRun: z.string().optional() }).passthrough();

export const bindingRoutes = {
  /**
   * The service's live bindings, oldest first: to the service itself, and
   * to whoever manages it. One `caller` and one statement.
   */
  ...route('GET /members/:member/bindings', {
    run: async (ctx, { params }): Promise<{ bindings: BindingView[] }> => {
      workloadsOf(ctx);
      const member = serviceIn(params.member);
      const who = await ctx.caller();
      const found = await serviceBindings(ctx.db, member, new Date());
      if (!lists(who, member, found)) throw refusal('no_access', shownMember(member));
      if (found === null || found.status !== 'active') throw refusal('unknown_principal', shownMember(member));
      return { bindings: found.bindings.map((row) => view(row, found.paths, found.keys)) };
    },
  }),

  /**
   * A binding made, as 0.14.7 took it: checked against its profile, its
   * issuer asked where its keys are (unless it carries them, or its issuer
   * is a URN, which keeps one source of keys), then one `token.bind`. Its
   * answer is the binding's id and what it reaches, and the bindings it
   * replaced. Asking the issuer costs one `caller` and one statement more,
   * first, which keep it to whoever manages the service (`mayBind`).
   */
  ...route('POST /members/:member/bindings', {
    input: z.object({
      profile: z.string().max(64),
      issuer: kept(2048).min(1).nullable().optional(),
      claims: z.record(z.string(), z.unknown()),
      scope: scopeByPath.optional(),
      label: label.nullable().optional(),
      replaces: z.array(rowId).max(16).refine((ids) => new Set(ids).size === ids.length, 'each binding replaced once').optional(),
      jwks: jwks.optional(),
      policy: z.record(z.string(), z.unknown()).refine((policy) => policy.reads === undefined || readsByPath.safeParse(policy.reads).success, 'a policy\'s reads name environments by path, and each its keys by name, or "*"').optional(),
    }).strict(),
    query: dryRun,
    run: async (ctx, { params, input, query }): Promise<{ binding: BindingMade; replaced: string[] }> => {
      const workloads = workloadsOf(ctx);
      const member = serviceIn(params.member);
      if (query.dryRun !== undefined) throw NO_PREVIEW;
      const uploaded = input.jwks !== undefined;
      let issuer: string;
      try {
        const checked = checkBinding({ profile: input.profile, issuer: input.issuer ?? null, claims: input.claims }, { allowLoopback: workloads.allowLoopback, uploaded });
        issuer = checked.issuer;
        // A workload's binding: every one but a bearer binding with no policy, which a CI run's exchange takes; none under `useOnly`.
        if (!isBearerProfile(checked.profile) || input.policy !== undefined || workloads.useOnly) {
          const { reads, ...rest } = input.policy ?? {};
          if (reads !== undefined && workloads.noReads) throw refusal('no_reads');
          const rules = checkPolicy(checked.profile, rest, { service: member });
          PROFILE_RULES[checked.profile]?.binding(checked, rules);
        }
      } catch (error) {
        if (error instanceof BindingInvalid) throw badRequest(error.message);
        throw error;
      }
      if (uploaded) await checkedKeys(input.jwks);
      let keys: { uri: string } | { jwks: unknown };
      try {
        // Keys uploaded with it; a URN's, its issuer; else where its issuer's discovery says they are, asked only for whoever may bind.
        if (uploaded) keys = { jwks: input.jwks };
        else if (Object.hasOwn(PROFILE_URNS, input.profile)) keys = { uri: issuer };
        else {
          await mayBind(ctx, member);
          keys = { uri: await discoverKeys(ctx.transport, issuer, { allowLoopback: workloads.allowLoopback }) };
        }
      } catch (error) {
        if (error instanceof DiscoveryFailed) throw badRequest(`coffre could not use ${issuer}: ${error.message}`);
        throw error;
      }
      const binding = { profile: input.profile, issuer, claims: input.claims, keys, policy: input.policy ?? null, scope: input.scope ?? null, label: input.label ?? null, replaces: input.replaces ?? [] };
      const bound = await bindingChange<'token.bind'>(ctx, { op: 'token.bind', member, binding }, member);
      return { binding: bound.bindings[0]!, replaced: bound.replaced };
    },
  }),

  /**
   * The service's bindings on an issuer given new keys, uploaded: each
   * replaced by one the same but for its keys, in one `token.bind`. The
   * answer lists the bindings made in the order of those they replaced.
   */
  ...route('POST /members/:member/bindings/keys', {
    input: z.object({ issuer: kept(2048).min(1), jwks }).strict(),
    query: dryRun,
    run: async (ctx, { params, input, query }): Promise<{ bindings: BindingMade[]; replaced: string[] }> => {
      workloadsOf(ctx);
      const member = serviceIn(params.member);
      if (query.dryRun !== undefined) throw NO_PREVIEW;
      await checkedKeys(input.jwks);
      const bound = await bindingChange<'token.bind'>(ctx, { op: 'token.bind', member, keys: { issuer: input.issuer, jwks: input.jwks } }, member);
      return { bindings: bound.bindings, replaced: bound.replaced };
    },
  }),

  /** A binding removed, and what it issued ended with it: one `token.unbind`. */
  ...route('DELETE /members/:member/bindings/:id', {
    run: async (ctx, { params }): Promise<{ unbound: true }> => {
      workloadsOf(ctx);
      const member = serviceIn(params.member);
      await bindingChange<'token.unbind'>(ctx, { op: 'token.unbind', member, binding: params.id }, member);
      return { unbound: true };
    },
  }),
};
