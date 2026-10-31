import { MAX_PERSONAL_TOKEN_MINUTES, MAX_SCOPE_PLACES, PERMISSIONS, protects, type Permission } from '@coffre/core/access';
import { MAX_BINDINGS, MAX_CLAIMS, MAX_KEYS, WORKLOAD_PROFILES, type JSONWebKeySet, type WorkloadProfile } from '@coffre/core/identity';
import { MAX_RECIPE_LENGTH, recipeProblem } from '@coffre/core/recipe';
import { displayName, environmentSlug, folderName, instanceRole, roleId, scopeInput, secretKey, slug } from '@coffre/core/schemas';
import { POLICY_REVISION } from '@coffre/core/vault';
import { z } from 'zod';

import { setAccess } from './access.ts';
import { acceptAuditLoss, AUDIT_NEXT, auditKeys, listAudit, verifyAudit, verifyAuditReads, verifyAuditTrees } from './audit.ts';
import type { ApiContext } from './context.ts';
import { approveSession, listEnrollments, mintEnrollment, mintInput, promoteEnrollment, promoteInput } from './enrollments.ts';
import { badRequest, forbidden, notFound } from './errors.ts';
import { freeze, freezeInput, listFreezes, unfreeze } from './freezes.ts';
import { listMembers, memberAccess, memberReport, putMember, readersAt, removeMember } from './members.ts';
import { breakReference, listReferences } from './references.ts';
import { managedAccount } from './services.ts';
import type { IssuedToken, PersonalTokenInput, TokenPlan } from './signin.ts';
import { getSettings, putSettings } from './settings.ts';
import { missingKeys, setDismissals } from './missing.ts';
import { formatMember, parseGrantee, parseMember, parsePath, type ResolvedPath } from './paths.ts';
import { forkEnvironment, type Forked } from './forks.ts';
import { listPersonal, makePersonal } from './personal.ts';
import { deletePlace, listProjects, me, patchEnvironment, patchProject, putEnvironment, putProject, refileProjects, type EnvironmentView } from './projects.ts';
import { changeRole, listRoles, protectEnvironment, type RoleImpact, type RoleView } from './roles.ts';
import {
  dryRunSecrets,
  environmentVersion,
  generationProblem,
  inheritSecret,
  listSecrets,
  listVersions,
  patchSecret,
  refileSecrets,
  reveal,
  restoreVersion,
  SENSITIVITIES,
  setSecrets,
  type DryRunResult,
  type SetResult,
} from './secrets.ts';

/** A reveal's body, which `fetchApi` reads first for one key's (`namedReveal`). */
export const revealInput = z.object({ path: z.string().max(400), keys: z.array(secretKey).min(1).max(2000).optional() });

/** A permission at the route's place, or at its project for project-wide ones. */
export type Check = Permission | { permission: Permission; on: 'project' } | { anyOf: readonly Permission[] };

/**
 * What lists an environment, its keys, their history and versions, and
 * what it is missing: reading its values, or using them, as a Contributor
 * does, who writes values they never read. Key names are no secret within
 * a project (R6), and a plain value shows to whoever lists.
 */
const LISTS: Check = { anyOf: ['secret.read', 'secret.use'] };

type ParamNames<Pattern> = Pattern extends `${string}:${infer Name}/${infer Rest}`
  ? Name | ParamNames<`/${Rest}`>
  : Pattern extends `${string}:${infer Name}`
    ? Name
    : never;

export type Params<Key> = { [Name in ParamNames<Key>]: string };

/** Routes addressed by `:project` get it resolved, with its environment and secret. */
export type PlaceOf<Key> = 'project' extends ParamNames<Key> ? ResolvedPath : null;

type Schema = z.ZodType | undefined;
type Parsed<S extends Schema> = S extends z.ZodType ? z.output<S> : undefined;

export type Route<Key extends string, S extends Schema, Output, Q extends Schema = undefined> = {
  /** The body, or the query string for a GET. */
  input?: S;
  /** Flags in the query string of a route that takes a body, such as `?dryRun=1`. */
  query?: Q;
  /** Checked before `run`, and a refusal is logged. Handlers check anything subtler themselves. */
  needs?: Check | readonly Check[] | ((input: Parsed<S>, query: Parsed<Q>) => readonly Check[]);
  /** The audit action a refusal is logged under. */
  action?: string;
  /** The last level of the path may not exist yet: the route creates it. */
  creates?: true;
  /**
   * What `<env>@me` is while the caller has no personal config of it: dev
   * itself (`falls back`, a read), a new one (`makes`, a write), or left to
   * the handler (`handles`), which checks what it takes. Otherwise none: 404.
   */
  personal?: 'falls back' | 'makes' | 'handles';
  run: (
    ctx: ApiContext,
    call: { params: Params<Key>; place: PlaceOf<Key>; input: Parsed<S>; query: Parsed<Q> },
  ) => Promise<Output>;
};

function route<
  const Key extends string,
  S extends Schema = undefined,
  Output = unknown,
  Q extends Schema = undefined,
>(key: Key, def: Route<Key, S, Output, Q>): { [K in Key]: Route<Key, S, Output, Q> } {
  return { [key]: def } as { [K in Key]: Route<Key, S, Output, Q> };
}

// `name` is a label from before 0.6.2, when a place had one beside its
// slug: still taken from older CLIs, stored, and shown nowhere.
const placePatch = z
  .object({ name: displayName, slug, archived: z.boolean() })
  .partial()
  .strict();
// `protected`: whoever manages the project's environments protects one; only an Owner of its project, or of the whole instance, unprotects it.
const environmentPatch = placePatch.extend({ slug: environmentSlug.optional(), protected: z.boolean().optional() }).strict();

/** `?dryRun=1`: what the call would do, without doing it. Any other query is refused, not ignored. */
const dryRunFlag = z.object({ dryRun: z.enum(['1', 'true']).optional() }).strict();

/**
 * A role's change: `?dryRun=1` weighs it, and `?revision=57.3f9a0c2e81b4d7a6`,
 * its preview's, confirms it as weighed: refused, 409 `policy_changed`, if
 * the policy changed since.
 */
const roleChangeQuery = dryRunFlag.extend({ revision: z.string().regex(POLICY_REVISION).optional() }).strict();

function roleChange(query: z.infer<typeof roleChangeQuery>): { dryRun: boolean; revision?: string } {
  return { dryRun: query.dryRun !== undefined, ...(query.revision === undefined ? {} : { revision: query.revision }) };
}

const secretValue = z
  .string()
  .max(64 * 1024)
  .refine((value) => !value.includes('\0'), 'a value cannot contain NUL bytes')
  // A lone UTF-16 surrogate has no UTF-8: stored, it would come back as U+FFFD, a value other than the one written.
  .refine((value) => !/[\uD800-\uDFFF]/u.test(value), 'a value must be well-formed Unicode: it holds a lone surrogate');

/**
 * A value a client generated, and how: the server checks the recipe's shape
 * and that a key pair comes whole (`generationProblem`), and makes nothing.
 */
const generatedValue = z.object({
  value: secretValue,
  generated: z.object({
    recipe: z.string().max(MAX_RECIPE_LENGTH).superRefine((recipe, issues) => {
      const problem = recipeProblem(recipe);
      if (problem !== null) issues.addIssue({ code: 'custom', message: problem });
    }),
    pair: z.object({ private: secretKey, public: secretKey }).strict().optional(),
  }).strict(),
  // A regenerate's: the id of the version it replaces, as listed, or the write is refused (409).
  replaces: z.string().max(64).optional(),
  // Who sees it: a secret, or sensitive where the key is, unless it says.
  sensitivity: z.enum(['secret', 'sensitive']).optional(),
}).strict();

/**
 * A plain value: a key marked not secret, which whoever lists the
 * environment sees. Making a stored secret plain is the client's reveal of
 * it, then this write with the version it `replaces`.
 */
const plainValue = z.object({
  value: secretValue,
  plain: z.literal(true),
  replaces: z.string().max(64).optional(),
}).strict();

/** Who sees a key's value (`Sensitivity`): plain, secret or sensitive. */
const sensitivity = z.enum(SENSITIVITIES);

/**
 * A value and who sees it. `plain` is the plain value above, said this
 * way; a looser value than the key's needs only this, a new value.
 */
const sensitiveValue = z.object({
  value: secretValue,
  sensitivity,
  replaces: z.string().max(64).optional(),
}).strict();

/** The key's current value, kept, made stricter: as strict already is no change, and looser is refused (409). */
const marked = z.object({ sensitivity }).strict();

/** A role by id: one that ships, or one an Owner made; whether the instance defines it, the handler and the vault say. */
const role = roleId;
/** A role's definition, both columns (docs/design/roles.md): the vault checks it whole (`definitionProblem`). */
const roleDefinition = z.object({
  name: z.string().max(40),
  description: z.string().max(200),
  permissions: z.array(z.enum(PERMISSIONS)).max(PERMISSIONS.length),
  protected: z.array(z.enum(PERMISSIONS)).max(PERMISSIONS.length),
}).strict();
/** What one member should hold, each place by path: a role, a role until a date, or null for none. */
const accessPatch = z.record(
  z.string().max(200),
  z.union([role, z.object({ role, until: z.string().max(40).nullable() }).strict(), z.null()]),
);
/** A token's or a binding's scope, each place by path and its role: `{ "market/dev": "developer" }`. All its account holds when left out. */
const credentialScope = z
  .record(z.string().max(200), role)
  .refine((scope) => Object.keys(scope).length <= MAX_SCOPE_PLACES, `a scope names at most ${MAX_SCOPE_PLACES} places`)
  .optional();

/** Sessions and service tokens are coffre's own sign-in; behind Cloudflare Access there are none. */
function signin(ctx: ApiContext) {
  if (ctx.signin === null) throw notFound("this instance has no sign-in of its own");
  return ctx.signin;
}

/** MCP clients' consent: on when the deployment's sign-in says so (`signin({ mcp })`). */
function mcp(ctx: ApiContext) {
  if (ctx.mcp === null) throw notFound("this instance serves no MCP: the deployment's signin({ mcp }) turns it on");
  return ctx.mcp;
}

/** An OAuth authorization request's parameters, as the consent page carries them: each optional here, checked by the service. */
const authorizationRequest = z.object({
  client_id: z.string().max(2048).optional(),
  redirect_uri: z.string().max(2048).optional(),
  response_type: z.string().max(64).optional(),
  code_challenge: z.string().max(256).optional(),
  code_challenge_method: z.string().max(16).optional(),
  state: z.string().max(2048).optional(),
  scope: z.string().max(512).optional(),
  resource: z.string().max(2048).optional(),
});

/** An issuer's public keys, uploaded with a binding: a JWKS, whose keys `uploadedKeys` checks one by one. */
const keySet = z.object({ keys: z.array(z.record(z.string().max(64), z.unknown())).min(1).max(MAX_KEYS) });

/** Trust bindings for CI runs: on when the deployment's sign-in says so. */
function workloads(ctx: ApiContext) {
  if (ctx.workloads === null) throw notFound("this instance trusts no workloads: the deployment's signin({ workloads }) turns them on");
  return ctx.workloads;
}

function serviceId(member: string): string {
  const ref = parseMember(member);
  if (ref.type !== 'service') throw notFound('only tokens hold service tokens');
  return ref.id;
}

/** What a token is made with, as `POST /members/:member/tokens` takes it: a service's or a person's. */
const tokenInput = z.object({
  // Printed in lists, the log and terminals: no control character, which could rewrite what is shown around it.
  label: z.string().trim().min(1).max(120).refine((label) => !/\p{Cc}/u.test(label), 'a label cannot hold a control character').nullable().default(null),
  // A service token's lifetime, in days.
  expiresInDays: z.number().int().min(1).max(366).optional(),
  // A personal token's, in minutes: an afternoon's script or agent, a week at most.
  expiresInMinutes: z.number().int().min(1).max(MAX_PERSONAL_TOKEN_MINUTES).optional(),
  scope: credentialScope,
});

/**
 * A personal token's input, from a person for themselves: its label,
 * lifetime and scope all said, since a token reaching all its person holds
 * for months is what it is there to avoid.
 */
function personalInput(ctx: ApiContext, person: string, input: z.output<typeof tokenInput>): PersonalTokenInput {
  if (ctx.caller.principal.type !== 'user' || ctx.caller.principal.id !== person) {
    throw forbidden('a person makes personal tokens for themselves alone');
  }
  if (input.label === null) throw badRequest('a personal token needs a label, which every entry it makes names');
  if (input.expiresInMinutes === undefined || input.expiresInDays !== undefined) throw badRequest('a personal token lasts expiresInMinutes, not days');
  if (input.scope === undefined) throw badRequest('a personal token needs a scope: what it reaches, by path');
  return { label: input.label, expiresInMinutes: input.expiresInMinutes, scope: input.scope };
}

/**
 * The whole API, keyed by method and route. Each segment names one level, so
 * `/secrets/market/prod/versions` is a secret named `versions`, and a
 * secret's history is `/secrets/market/prod/KEY/versions`.
 */
export const routes = {
  ...route('GET /me', { run: (ctx) => me(ctx) }),

  // Places
  ...route('GET /projects', { run: (ctx) => listProjects(ctx) }),
  ...route('PUT /projects/:project', {
    input: z.object({ name: displayName.optional() }),
    creates: true,
    run: (ctx, { params, place, input }) => putProject(ctx, place, params.project, input),
  }),
  ...route('PATCH /projects/:project', {
    input: placePatch.extend({ folder: folderName.nullable().optional() }).strict(),
    needs: 'project.manage',
    action: 'project.update',
    run: (ctx, { place, input }) => patchProject(ctx, place, input),
  }),
  // Deleting an archived place for good, instance owners only. `?dryRun=1`
  // says what it would erase and revoke, and changes nothing.
  ...route('DELETE /projects/:project', {
    query: dryRunFlag,
    run: (ctx, { place, query }) => deletePlace(ctx, place, { dryRun: query.dryRun !== undefined }),
  }),
  ...route('PUT /projects/:project/:environment', {
    // `from` forks a sibling: its keys, values and folders, without history.
    // With `references`, each key a reference to its parent's instead of a copy;
    // with `inherit`, no key at all: it reads its parent's, live, but for those it sets or removes.
    input: z.object({ name: displayName.optional(), from: slug.optional(), references: z.boolean().optional(), inherit: z.boolean().optional() }),
    needs: { permission: 'environment.manage', on: 'project' },
    action: 'environment.create',
    creates: true,
    // `market/dev@me`: your personal config of dev, made if you have none; it takes read on dev, nothing more.
    personal: 'handles',
    run: async (ctx, { params, place, input }): Promise<{ environment: EnvironmentView; created: boolean; forked: Forked | null }> => {
      if (place.personal !== undefined) {
        if (input.from !== undefined || input.inherit !== undefined || input.references !== undefined) {
          throw badRequest('a personal config inherits from the environment it is a config of: no `from`');
        }
        const made = place.environment === null ? await makePersonal(ctx, place, 'environment.create') : { place, created: false };
        // Protected as the environment it is a config of is.
        const guarded = protects(ctx.caller.policy, place.personal.of.id);
        return { environment: { slug: params.environment, name: params.environment, archivedAt: null, protected: guarded }, created: made.created, forked: null };
      }
      // Not a slug a project's page has (`@coffre/core/pages`).
      environmentSlug.parse(params.environment);
      if (input.from === undefined && (input.inherit === true || input.references === true)) {
        throw badRequest('a fork names the environment it forks: `from`');
      }
      return input.from === undefined
        ? { ...(await putEnvironment(ctx, place, params.environment, input)), forked: null }
        : forkEnvironment(ctx, place, params.environment, {
            name: input.name,
            from: input.from,
            references: input.references === true,
            inherit: input.inherit === true,
          });
    },
  }),
  ...route('PATCH /projects/:project/:environment', {
    input: environmentPatch,
    needs: { permission: 'environment.manage', on: 'project' },
    action: 'environment.update',
    run: async (ctx, { place, input }) => {
      const { protected: guarded, ...patch } = input;
      if (guarded === undefined) return patchEnvironment(ctx, place, patch);
      // The vault's to change, with no transaction of the app's open across it: so asked alone, never with a rename or an
      // archive whose refusal would leave the protection changed and the rest not.
      if (Object.keys(patch).length > 0) throw badRequest('protect or unprotect an environment on its own, not with other changes');
      return patchEnvironment(await protectEnvironment(ctx, place, guarded), place, {});
    },
  }),
  ...route('DELETE /projects/:project/:environment', {
    query: dryRunFlag,
    run: (ctx, { place, query }) => deletePlace(ctx, place, { dryRun: query.dryRun !== undefined }),
  }),

  // A project's personal configs, for whoever manages its environments: whose, of what, and their key names, never values.
  ...route('GET /personal/:project', {
    needs: { permission: 'environment.manage', on: 'project' },
    action: 'personal.list',
    run: (ctx, { place }) => listPersonal(ctx, place),
  }),

  // What an environment lacks of its siblings' keys, and what its team dismissed.
  ...route('GET /projects/:project/:environment/missing', {
    needs: LISTS,
    personal: 'falls back',
    action: 'missing.list',
    run: (ctx, { place }) => missingKeys(ctx, place),
  }),
  // A version of what a read of it would open, which changes whenever that does: pollers ask it before reading.
  ...route('GET /projects/:project/:environment/version', {
    needs: LISTS,
    // What a read of `dev@me` would open: dev's while you have no personal config of it.
    personal: 'falls back',
    action: 'secret.version',
    run: (ctx, { place }) => environmentVersion(ctx, place),
  }),
  ...route('PATCH /projects/:project/:environment/dismissals', {
    // `true` dismisses a missing key, `null` restores it.
    input: z.record(secretKey, z.literal(true).nullable()),
    needs: 'secret.write',
    action: 'missing.dismiss',
    run: (ctx, { place, input }) => setDismissals(ctx, place, input),
  }),

  // Secrets
  ...route('GET /secrets/:project/:environment', {
    needs: LISTS,
    personal: 'falls back',
    action: 'secret.list',
    run: (ctx, { place }) => listSecrets(ctx, place),
  }),
  ...route('PATCH /secrets/:project/:environment', {
    // A string is a value; `{ "value", "generated": { "recipe": "bytes:32:hex" } }` one a client
    // generated; `{ "value", "sensitivity": "sensitive" }` one and who sees it (`{ "value", "plain": true }`,
    // as 0.9 said plain); `{ "sensitivity": "sensitive" }` the key's value as it is, made stricter;
    // `{ "ref": "market/prod/KEY" }` makes the key a reference to that secret.
    input: z.record(secretKey, z.union([secretValue, generatedValue, plainValue, sensitiveValue, marked, z.object({ ref: z.string().max(400) }).strict()]).nullable())
      .superRefine((patch, issues) => {
        const problem = generationProblem(patch);
        if (problem !== null) issues.addIssue({ code: 'custom', message: problem });
      }),
    // `?dryRun=1` answers what the patch would do and writes nothing. Any
    // other query is refused, not ignored: a mistyped flag must not write.
    query: dryRunFlag,
    // `market/dev@me` is made at its first write: your personal config of dev.
    personal: 'makes',
    // Each key is checked against its own permission: archiving needs more
    // than writing. A dry run is a read, which it checks and logs itself.
    needs: (patch, { dryRun }) =>
      dryRun !== undefined
        ? []
        : [
            ...(Object.values(patch).some((value) => value !== null) ? ['secret.write' as const] : []),
            ...(Object.values(patch).includes(null) ? ['secret.archive' as const] : []),
          ],
    action: 'secret.write',
    run: (ctx, { place, input, query }): Promise<SetResult | DryRunResult> =>
      query.dryRun !== undefined ? dryRunSecrets(ctx, place, input) : setSecrets(ctx, place, input),
  }),
  ...route('PATCH /secrets/:project/:environment/:key', {
    // In a fork, `inherit: true` resets a key to its parent's value, archiving its own;
    // `false` overrides it again with the value it had (docs/design/forking.md).
    input: z.object({ key: secretKey, archived: z.boolean(), folder: folderName.nullable(), inherit: z.boolean() }).partial().strict()
      .refine((patch) => patch.key !== undefined || patch.archived !== undefined || patch.folder !== undefined || patch.inherit !== undefined,
        'provide a key, an archived flag, a folder or inherit')
      .refine((patch) => patch.inherit === undefined || Object.keys(patch).length === 1, 'inherit goes alone'),
    needs: (patch) => [
      ...(patch.key !== undefined || patch.folder !== undefined || patch.inherit !== undefined ? ['secret.write' as const] : []),
      ...(patch.archived !== undefined ? ['secret.archive' as const] : []),
    ],
    action: 'secret.update',
    run: (ctx, { place, input }) => (input.inherit === undefined ? patchSecret(ctx, place, input) : inheritSecret(ctx, place, input.inherit)),
  }),
  ...route('GET /secrets/:project/:environment/:key/versions', {
    needs: LISTS,
    action: 'secret.history',
    run: (ctx, { place }) => listVersions(ctx, place),
  }),
  ...route('POST /secrets/:project/:environment/:key/restore', {
    input: z.object({ version: z.number().int().positive() }),
    needs: 'secret.write',
    action: 'secret.restore',
    run: (ctx, { place, input }) => restoreVersion(ctx, place, input.version),
  }),
  ...route('DELETE /secrets/:project/:environment/:key/reference', {
    run: (ctx, { place }) => breakReference(ctx, place),
  }),
  // Folders: a folder is a label, which exists while something is filed under it. Renaming one
  // re-files all of it; removing one takes all of it out, each project or key staying where it is.
  ...route('PATCH /folders/:folder', {
    input: z.object({ name: folderName }).strict(),
    action: 'project.move',
    run: (ctx, { params, input }) => refileProjects(ctx, params.folder, input.name),
  }),
  ...route('DELETE /folders/:folder', {
    action: 'project.move',
    run: (ctx, { params }) => refileProjects(ctx, params.folder, null),
  }),
  ...route('PATCH /folders/:project/:environment/:folder', {
    input: z.object({ name: folderName }).strict(),
    needs: 'secret.write',
    action: 'secret.move',
    run: (ctx, { params, place, input }) => refileSecrets(ctx, place, params.folder, input.name),
  }),
  ...route('DELETE /folders/:project/:environment/:folder', {
    needs: 'secret.write',
    action: 'secret.move',
    run: (ctx, { params, place }) => refileSecrets(ctx, place, params.folder, null),
  }),

  ...route('GET /references', {
    input: z.object({ path: z.string().max(400) }),
    run: (ctx, { input }) => listReferences(ctx, parsePath(input.path, [1, 2, 3]), () => readersAt(ctx)),
  }),
  ...route('POST /reveals', {
    // `keys`: of an environment, these only, as `coffre export --keys` reads them: the rest is neither opened nor logged.
    input: revealInput,
    run: async (ctx, { input }) => {
      const path = parsePath(input.path, [2, 3]);
      if (input.keys !== undefined && path.key !== undefined) throw badRequest('keys names keys of an environment: give its path, <project>/<environment>');
      // A read of a whole environment names what it left out: a person's sensitive values, and a workload's it only uses.
      const { operationId, values, sensitive, useOnly, version } = await reveal(ctx, path, undefined, input.keys);
      return { operationId, values, sensitive, useOnly, version };
    },
  }),

  // Who
  ...route('GET /members', {
    input: z.object({ path: z.string().max(200).optional() }),
    run: (ctx, { input }) =>
      listMembers(ctx, { path: input.path === undefined ? undefined : parsePath(input.path, [1, 2]) }),
  }),
  ...route('GET /members/:member', {
    run: (ctx, { params }) => memberReport(ctx, parseMember(params.member)),
  }),
  ...route('GET /members/:member/access', {
    run: (ctx, { params }) => memberAccess(ctx, parseMember(params.member)),
  }),
  ...route('PUT /members/:member', {
    input: z
      .object({
        role: instanceRole.optional(),
        scope: scopeInput.optional(),
        access: accessPatch.refine((access) => Object.keys(access).length > 0, 'name a place to grant').optional(),
      })
      .strict(),
    run: (ctx, { params, input }) => putMember(ctx, parseMember(params.member), input),
  }),
  ...route('DELETE /members/:member', {
    run: (ctx, { params }) => removeMember(ctx, parseMember(params.member)),
  }),
  // A member's tokens: a service account's bearer tokens, or a person's personal tokens, which act as them.
  ...route('GET /members/:member/tokens', {
    run: async (ctx, { params }) => ({
      tokens: await signin(ctx).listTokens(ctx, parseMember(params.member)),
    }),
  }),
  ...route('POST /members/:member/tokens', {
    input: tokenInput,
    // `?dryRun=1` answers what the token would reach, and issues nothing.
    query: dryRunFlag,
    run: (ctx, { params, input, query }): Promise<TokenPlan | IssuedToken> => {
      const member = parseMember(params.member);
      if (member.type === 'user') {
        const personal = personalInput(ctx, member.id, input);
        return query.dryRun !== undefined ? signin(ctx).planPersonalToken(ctx, personal) : signin(ctx).issuePersonalToken(ctx, personal);
      }
      if (input.expiresInDays === undefined || input.expiresInMinutes !== undefined) throw badRequest('a service token lasts expiresInDays');
      const service = { label: input.label, expiresInDays: input.expiresInDays, scope: input.scope };
      return query.dryRun !== undefined
        ? signin(ctx).planServiceToken(ctx, member.id, service)
        : signin(ctx).issueServiceToken(ctx, member.id, service);
    },
  }),
  // A handle, for `coffre run`: a placeholder for the values of `paths`, which only the credential proxy takes (docs/design/credential-proxy.md).
  ...route('POST /handles', {
    input: z.object({
      label: tokenInput.shape.label.unwrap().unwrap(),
      // Twelve hours unless told: a working day's dev loop, a week at most, as a personal token.
      expiresInMinutes: z.number().int().min(1).max(MAX_PERSONAL_TOKEN_MINUTES).default(12 * 60),
      paths: z.array(z.string().max(200)).min(1).max(MAX_SCOPE_PLACES),
    }),
    run: (ctx, { input }) => signin(ctx).issueHandle(ctx, input),
  }),
  // A run's handle ended with its command (`coffre run`): the caller's own, and a handle only, on a personal token too.
  ...route('DELETE /handles/:id', {
    run: (ctx, { params }) => signin(ctx).revokeCredential(ctx, params.id, 'own handle'),
  }),
  ...route('DELETE /members/:member/tokens/:id', {
    run: async (ctx, { params }) => {
      const member = parseMember(params.member);
      const managed = member.type === 'service' && (await managedAccount(ctx, ctx.caller, member.id)).managed;
      return signin(ctx).revokeCredential(ctx, params.id, { member: formatMember(member), managed });
    },
  }),
  ...route('GET /members/:member/bindings', {
    run: async (ctx, { params }) => ({
      bindings: await workloads(ctx).listBindings(ctx, serviceId(params.member)),
    }),
  }),
  ...route('POST /members/:member/bindings', {
    input: z.object({
      profile: z.enum(WORKLOAD_PROFILES as [WorkloadProfile, ...WorkloadProfile[]]),
      // github.com's or gitlab.com's when left out; a custom binding names its own.
      issuer: z.string().max(400).nullable().default(null),
      // A value, or for what started the run (event_name, pipeline_source), a list of them.
      claims: z
        .record(z.string().max(64), z.union([z.string().max(1024), z.array(z.string().max(64)).min(1).max(16)]))
        .refine((claims) => Object.keys(claims).length <= MAX_CLAIMS, `a binding names at most ${MAX_CLAIMS} claims`),
      scope: credentialScope,
      label: z.string().trim().min(1).max(120).nullable().default(null),
      replaces: z.array(z.string().uuid()).max(MAX_BINDINGS).default([]),
      // The issuer's keys, for one coffre asks nothing: then the issuer is any string its tokens name.
      jwks: keySet.optional(),
      // A workload's binding's policy (docs/design/workload-access.md, section 11), checked by its profile (`checkPolicy`).
      policy: z.record(z.string().max(32), z.unknown()).optional(),
    }).strict(),
    // `?dryRun=1` checks the binding and asks its issuer where its keys are, and writes nothing.
    query: dryRunFlag,
    run: (ctx, { params, input, query }) =>
      workloads(ctx).bind(ctx, serviceId(params.member), { ...input, jwks: input.jwks as JSONWebKeySet | undefined }, { dryRun: query.dryRun !== undefined }),
  }),
  // New keys, uploaded, for every binding of the service on the issuer: each replaced by one the same but for them.
  ...route('POST /members/:member/bindings/keys', {
    input: z.object({ issuer: z.string().min(1).max(400), jwks: keySet }).strict(),
    // `?dryRun=1` checks the keys and says which bindings would be replaced, and writes nothing.
    query: dryRunFlag,
    run: (ctx, { params, input, query }) =>
      workloads(ctx).replaceKeys(ctx, serviceId(params.member), { issuer: input.issuer, jwks: input.jwks as JSONWebKeySet }, { dryRun: query.dryRun !== undefined }),
  }),
  ...route('GET /workloads/lookup', {
    input: z.object({
      github: z.string().max(200).optional(),
      gitlab: z.string().max(400).optional(),
      gitlabUrl: z.string().max(400).optional(),
    }).strict(),
    run: (ctx, { input }) => workloads(ctx).lookup(ctx, input),
  }),
  // The repositories the deployment's GitHub App is installed on, private ones too; `{ app: null }` without one.
  ...route('GET /workloads/repositories', {
    run: (ctx) => workloads(ctx).repositories(ctx),
  }),
  ...route('DELETE /members/:member/bindings/:id', {
    run: (ctx, { params }) => workloads(ctx).unbind(ctx, serviceId(params.member), params.id),
  }),
  // Enrollment codes, for a workload on a platform that signs nothing (docs/design/workload-access.md, section 4.4):
  // a binding's codes, a new one for a deploy, the one a deploy that came up makes current, and a session approved.
  ...route('GET /members/:member/bindings/:id/enrollments', {
    run: (ctx, { params }) => listEnrollments(ctx, { member: params.member, id: params.id }),
  }),
  ...route('POST /members/:member/bindings/:id/enrollments', {
    input: mintInput,
    run: (ctx, { params, input }) => mintEnrollment(ctx, { member: params.member, id: params.id }, input),
  }),
  ...route('POST /members/:member/bindings/:id/enrollments/:enrollment/promote', {
    input: promoteInput,
    run: (ctx, { params, input }) => promoteEnrollment(ctx, { member: params.member, id: params.id, enrollment: params.enrollment }, input),
  }),
  ...route('POST /members/:member/tokens/:id/approve', {
    run: (ctx, { params }) => approveSession(ctx, { member: params.member, id: params.id }),
  }),
  // Freezes: every use under a target stopped at its next request, and lifted, its sessions, codes and bindings kept (section 8.2).
  ...route('GET /freezes', { run: (ctx) => listFreezes(ctx) }),
  ...route('POST /freezes', {
    input: freezeInput,
    run: (ctx, { input }) => freeze(ctx, input),
  }),
  ...route('DELETE /freezes/:target', {
    run: (ctx, { params }) => unfreeze(ctx, params.target),
  }),
  // The instance's roles, as an Owner edited and made them, for any member; an Owner of the whole instance edits them
  // (docs/design/roles.md). `?dryRun=1` answers what the change would do to everyone it reaches, and changes nothing.
  ...route('GET /roles', { run: (ctx) => listRoles(ctx) }),
  ...route('PUT /roles/:role', {
    input: roleDefinition,
    query: roleChangeQuery,
    run: (ctx, { params, input, query }): Promise<RoleImpact | { role: RoleView | null }> =>
      changeRole(ctx, 'role', params.role, input, roleChange(query)),
  }),
  // A built-in role back as it ships; one an Owner made, deleted, while no grant names it (409).
  ...route('DELETE /roles/:role', {
    query: roleChangeQuery,
    run: (ctx, { params, query }): Promise<RoleImpact | { role: RoleView | null }> =>
      changeRole(ctx, 'role', params.role, null, roleChange(query)),
  }),
  ...route('PUT /instance-roles/:role', {
    input: roleDefinition,
    query: roleChangeQuery,
    run: (ctx, { params, input, query }): Promise<RoleImpact | { role: RoleView | null }> =>
      changeRole(ctx, 'instance-role', params.role, input, roleChange(query)),
  }),
  ...route('DELETE /instance-roles/:role', {
    query: roleChangeQuery,
    run: (ctx, { params, query }): Promise<RoleImpact | { role: RoleView | null }> =>
      changeRole(ctx, 'instance-role', params.role, null, roleChange(query)),
  }),
  // The instance's settings: where people set up service accounts themselves.
  ...route('GET /settings', {
    run: (ctx) => getSettings(ctx),
  }),
  ...route('PUT /settings', {
    input: z.object({ serviceAccounts: scopeInput }).strict(),
    run: (ctx, { input }) => putSettings(ctx, input),
  }),
  ...route('PATCH /access/:member', {
    input: accessPatch,
    run: (ctx, { params, input }) => setAccess(ctx, parseGrantee(params.member), input),
  }),

  // Your own sign-in: where you are signed in, the accounts you sign in
  // with, and approving `coffre login` from the browser.
  ...route('GET /sessions', {
    run: async (ctx) => ({ sessions: await signin(ctx).listSessions(ctx, ctx.credentialId) }),
  }),
  ...route('DELETE /sessions/:id', {
    run: (ctx, { params }) => signin(ctx).revokeCredential(ctx, params.id),
  }),
  ...route('GET /identities', {
    run: async (ctx) => ({ identities: await signin(ctx).listIdentities(ctx) }),
  }),
  ...route('DELETE /identities/:id', {
    run: (ctx, { params }) => signin(ctx).unlinkIdentity(ctx, params.id),
  }),
  ...route('GET /device-logins/:code', {
    // Null for a code that is unknown, used or expired.
    run: async (ctx, { params }) => ({
      request: await signin(ctx).describeDevice(params.code),
      sessionDays: signin(ctx).config.cliSessionDays,
    }),
  }),
  ...route('POST /device-logins/:code', {
    input: z.object({ approve: z.boolean() }).strict(),
    run: (ctx, { params, input }) => signin(ctx).decideDevice(ctx, params.code, input.approve),
  }),

  // Connecting an MCP client: what the consent page shows, and the person's answer.
  ...route('GET /oauth/authorizations', {
    input: authorizationRequest,
    run: (ctx, { input }) => mcp(ctx).describe(ctx, input),
  }),
  ...route('POST /oauth/authorizations', {
    input: z.object({
      request: authorizationRequest,
      approve: z.boolean(),
      scopes: z.array(z.string().max(32)).max(16).default([]),
    }).strict(),
    run: (ctx, { input }) => mcp(ctx).decide(ctx, input.request, { approve: input.approve, scopes: input.scopes }),
  }),

  // A change an MCP client asked for, on the page where its person decides it.
  ...route('GET /approvals/:id', {
    run: async (ctx, { params }) => ({ approval: await mcp(ctx).approvals.view(ctx, params.id) }),
  }),
  ...route('POST /approvals/:id', {
    input: z.object({
      approve: z.boolean(),
      // Of the change the page showed: a change that is not it is refused.
      digest: z.string().regex(/^[0-9a-f]{64}$/),
      // What it replaces, as the page showed it: Approve refuses it once that changed.
      basis: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional(),
      // What the person typed, for a change that asks for a value.
      value: secretValue.optional(),
    }).strict(),
    run: (ctx, { params, input }) => mcp(ctx).approvals.decide(ctx, params.id, input),
  }),

  // The MCP clients you connected: Connected apps.
  ...route('GET /apps', {
    run: async (ctx) => ({ apps: await mcp(ctx).apps(ctx) }),
  }),
  ...route('DELETE /apps/:id', {
    run: (ctx, { params }) => mcp(ctx).disconnect(ctx, params.id),
  }),

  // The log
  ...route('GET /audit', {
    input: z.object({
      // A project, an environment, or a secret: `market/prod/DATABASE_URL` for who read or changed it.
      path: z.string().max(400).optional(),
      actor: z.string().max(330).optional(),
      decision: z.enum(['allow', 'deny']).optional(),
      // `?detail=1` includes sign-ins and technical steps, `DETAIL_ACTIONS`.
      detail: z.enum(['1', 'true']).optional(),
      // `?sealed=1` lists what 0.15's sealed log alone records too, sign-ins through trust bindings and tokens' issues,
      // revokes and sign-outs, paged by `next`.
      sealed: z.enum(['1', 'true']).optional(),
      // With `sealed`, `?hidden=1` counts what the page leaves out (`hidden`); a caller that asks follows `next`, as a
      // page counts no more than `HIDDEN_COUNTED` of 0.15's records and may show nothing.
      hidden: z.enum(['1', 'true']).optional(),
      // A page's `next`, where it stopped in 0.14's log and 0.15's (`-`: nothing older); or a seq, 0.14's log alone.
      before: z.union([z.coerce.number().int().positive(), z.string().regex(AUDIT_NEXT)]).optional(),
      limit: z.coerce.number().int().min(1).max(500).default(100),
    }),
    run: (ctx, { input }) =>
      listAudit(ctx, {
        ...input,
        detail: input.detail !== undefined,
        sealed: input.sealed !== undefined,
        hidden: input.hidden !== undefined,
        path: input.path === undefined ? undefined : parsePath(input.path),
      }),
  }),
  // From the newest checkpoint; or, with `from`, a stretch of the walk from the first entry (`start`), and on from each `next`.
  ...route('GET /audit/verification', {
    input: z.object({ from: z.union([z.literal('start'), z.string().regex(/^[0-9]{1,16}:[0-9a-f]{64}$/)]).optional() }),
    run: (ctx, { input }) => verifyAudit(ctx, input),
  }),
  // 0.15's log: its newest checkpoint and every entry since, as the audit page checks it on every visit.
  ...route('GET /audit/trees', { run: (ctx) => verifyAuditTrees(ctx) }),
  // The reads' listing held to 0.15's log, a stretch a request, from `start`, then each `next` (`coffre verify log`).
  ...route('GET /audit/reads', {
    input: z.object({ from: z.union([z.literal('start'), z.string().regex(/^[0-9]{1,19}:[0-9]{1,19}$/)]) }),
    run: (ctx, { input }) => verifyAuditReads(ctx, input),
  }),
  // What `coffre verify keys` checks an escrowed key against, on the operator's machine.
  ...route('GET /audit/keys', { run: (ctx) => auditKeys(ctx) }),
  // An Owner accepts that a range of the log is lost for good: the audit watch's anchor goes on past it.
  ...route('POST /audit/loss', {
    input: z.object({ from: z.number().int().min(0), to: z.number().int().min(0) }).refine(({ from, to }) => from <= to, 'from comes no later than to'),
    run: (ctx, { input }) => acceptAuditLoss(ctx, input),
  }),
};

export type Routes = typeof routes;
export type RouteKey = keyof Routes;

type InputSchema<K extends RouteKey> = NonNullable<Routes[K]['input']>;

/** What a caller sends: the body, or the query string for a GET. */
export type RouteInput<K extends RouteKey> = [InputSchema<K>] extends [never]
  ? undefined
  : InputSchema<K> extends z.ZodType
    ? z.input<InputSchema<K>>
    : never;

/** What the handler returns, before it is written as JSON. */
export type RouteOutput<K extends RouteKey> = Awaited<ReturnType<Routes[K]['run']>>;
