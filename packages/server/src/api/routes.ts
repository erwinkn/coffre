import { ROLE_NAMES, type Permission } from '@coffre/core/access';
import { MAX_BINDINGS, MAX_CLAIMS, WORKLOAD_PROFILES } from '@coffre/core/identity';
import { displayName, environmentSlug, folderName, instanceRole, scopeInput, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { setAccess } from './access.ts';
import { auditKeys, listAudit, verifyAudit } from './audit.ts';
import type { ApiContext } from './context.ts';
import { notFound } from './errors.ts';
import { listMembers, memberReport, putMember, readersAt, removeMember } from './members.ts';
import { breakReference, listReferences } from './references.ts';
import { missingKeys, setDismissals } from './missing.ts';
import { parseGrantee, parseMember, parsePath, type ResolvedPath } from './paths.ts';
import { forkEnvironment, type Forked } from './forks.ts';
import { deletePlace, listProjects, me, patchEnvironment, patchProject, putEnvironment, putProject, refileProjects, type PlaceView } from './projects.ts';
import {
  dryRunSecrets,
  listSecrets,
  listVersions,
  patchSecret,
  refileSecrets,
  reveal,
  restoreVersion,
  setSecrets,
  type DryRunResult,
  type SetResult,
} from './secrets.ts';

/** A permission at the route's place, or at its project for project-wide ones. */
export type Check = Permission | { permission: Permission; on: 'project' };

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

const placePatch = z
  .object({ name: displayName, slug, archived: z.boolean() })
  .partial()
  .strict();
const environmentPatch = placePatch.extend({ slug: environmentSlug.optional() }).strict();

/** `?dryRun=1`: what the call would do, without doing it. Any other query is refused, not ignored. */
const dryRunFlag = z.object({ dryRun: z.enum(['1', 'true']).optional() }).strict();

const secretValue = z
  .string()
  .max(64 * 1024)
  .refine((value) => !value.includes('\0'), 'a value cannot contain NUL bytes');

const role = z.enum(ROLE_NAMES);

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
    input: z.object({ name: displayName }),
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
    // With `references`, each key a reference to its parent's instead of a copy.
    input: z.object({ name: displayName, from: slug.optional(), references: z.boolean().optional() }),
    needs: { permission: 'environment.manage', on: 'project' },
    action: 'environment.create',
    creates: true,
    run: async (ctx, { params, place, input }): Promise<{ environment: PlaceView; created: boolean; forked: Forked | null }> => {
      // Not a slug a project's page has (`@coffre/core/pages`).
      environmentSlug.parse(params.environment);
      return input.from === undefined
        ? { ...(await putEnvironment(ctx, place, params.environment, input)), forked: null }
        : forkEnvironment(ctx, place, params.environment, { name: input.name, from: input.from, references: input.references === true });
    },
  }),
  ...route('PATCH /projects/:project/:environment', {
    input: environmentPatch,
    needs: { permission: 'environment.manage', on: 'project' },
    action: 'environment.update',
    run: (ctx, { place, input }) => patchEnvironment(ctx, place, input),
  }),
  ...route('DELETE /projects/:project/:environment', {
    query: dryRunFlag,
    run: (ctx, { place, query }) => deletePlace(ctx, place, { dryRun: query.dryRun !== undefined }),
  }),

  // What an environment lacks of its siblings' keys, and what its team dismissed.
  ...route('GET /projects/:project/:environment/missing', {
    needs: 'secret.read',
    action: 'missing.list',
    run: (ctx, { place }) => missingKeys(ctx, place),
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
    needs: 'secret.read',
    action: 'secret.list',
    run: (ctx, { place }) => listSecrets(ctx, place),
  }),
  ...route('PATCH /secrets/:project/:environment', {
    // A string is a value; `{ "ref": "market/prod/KEY" }` makes the key a reference to that secret.
    input: z.record(secretKey, z.union([secretValue, z.object({ ref: z.string().max(400) }).strict()]).nullable()),
    // `?dryRun=1` answers what the patch would do and writes nothing. Any
    // other query is refused, not ignored: a mistyped flag must not write.
    query: dryRunFlag,
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
    input: z.object({ key: secretKey, archived: z.boolean(), folder: folderName.nullable() }).partial().strict()
      .refine((patch) => patch.key !== undefined || patch.archived !== undefined || patch.folder !== undefined,
        'provide a key, an archived flag or a folder'),
    needs: (patch) => [
      ...(patch.key !== undefined || patch.folder !== undefined ? ['secret.write' as const] : []),
      ...(patch.archived !== undefined ? ['secret.archive' as const] : []),
    ],
    action: 'secret.update',
    run: (ctx, { place, input }) => patchSecret(ctx, place, input),
  }),
  ...route('GET /secrets/:project/:environment/:key/versions', {
    needs: 'secret.read',
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
    run: (ctx, { input }) => listReferences(ctx, parsePath(input.path, [1, 2, 3]), (places) => readersAt(ctx, places)),
  }),
  ...route('POST /reveals', {
    input: z.object({ path: z.string().max(400) }),
    run: (ctx, { input }) => reveal(ctx, parsePath(input.path, [2, 3])),
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
  ...route('PUT /members/:member', {
    input: z.object({ role: instanceRole.optional(), scope: scopeInput.optional() }).strict(),
    run: (ctx, { params, input }) => putMember(ctx, parseMember(params.member), input),
  }),
  ...route('DELETE /members/:member', {
    run: (ctx, { params }) => removeMember(ctx, parseMember(params.member)),
  }),
  ...route('GET /members/:member/tokens', {
    run: async (ctx, { params }) => ({
      tokens: await signin(ctx).listServiceTokens(ctx, serviceId(params.member)),
    }),
  }),
  ...route('POST /members/:member/tokens', {
    input: z.object({
      label: z.string().trim().min(1).max(120).nullable().default(null),
      expiresInDays: z.number().int().min(1).max(366),
    }),
    run: (ctx, { params, input }) => signin(ctx).issueServiceToken(ctx, serviceId(params.member), input),
  }),
  ...route('DELETE /members/:member/tokens/:id', {
    run: (ctx, { params }) => {
      serviceId(params.member);
      return signin(ctx).revokeCredential(ctx, params.id);
    },
  }),
  ...route('GET /members/:member/bindings', {
    run: async (ctx, { params }) => ({
      bindings: await workloads(ctx).listBindings(ctx, serviceId(params.member)),
    }),
  }),
  ...route('POST /members/:member/bindings', {
    input: z.object({
      profile: z.enum(WORKLOAD_PROFILES),
      // github.com's or gitlab.com's when left out; a custom binding names its own.
      issuer: z.string().max(400).nullable().default(null),
      // A value, or for what started the run (event_name, pipeline_source), a list of them.
      claims: z
        .record(z.string().max(64), z.union([z.string().max(1024), z.array(z.string().max(64)).min(1).max(16)]))
        .refine((claims) => Object.keys(claims).length <= MAX_CLAIMS, `a binding names at most ${MAX_CLAIMS} claims`),
      label: z.string().trim().min(1).max(120).nullable().default(null),
      replaces: z.array(z.string().uuid()).max(MAX_BINDINGS).default([]),
    }).strict(),
    // `?dryRun=1` checks the binding and asks its issuer where its keys are, and writes nothing.
    query: dryRunFlag,
    run: (ctx, { params, input, query }) =>
      workloads(ctx).bind(ctx, serviceId(params.member), input, { dryRun: query.dryRun !== undefined }),
  }),
  ...route('GET /workloads/lookup', {
    input: z.object({
      github: z.string().max(200).optional(),
      gitlab: z.string().max(400).optional(),
      gitlabUrl: z.string().max(400).optional(),
    }).strict(),
    run: (ctx, { input }) => workloads(ctx).lookup(ctx, input),
  }),
  ...route('DELETE /members/:member/bindings/:id', {
    run: (ctx, { params }) => workloads(ctx).unbind(ctx, serviceId(params.member), params.id),
  }),
  ...route('PATCH /access/:member', {
    input: z.record(
      z.string().max(200),
      z.union([role, z.object({ role, until: z.string().max(40).nullable() }).strict(), z.null()]),
    ),
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
      path: z.string().max(200).optional(),
      actor: z.string().max(330).optional(),
      decision: z.enum(['allow', 'deny']).optional(),
      // `?detail=1` includes sign-ins and technical steps, `DETAIL_ACTIONS`.
      detail: z.enum(['1', 'true']).optional(),
      before: z.coerce.number().int().positive().optional(),
      limit: z.coerce.number().int().min(1).max(500).default(100),
    }),
    run: (ctx, { input }) =>
      listAudit(ctx, {
        ...input,
        detail: input.detail !== undefined,
        path: input.path === undefined ? undefined : parsePath(input.path, [1, 2]),
      }),
  }),
  ...route('GET /audit/verification', { run: (ctx) => verifyAudit(ctx) }),
  // What `coffre verify keys` checks an escrowed key against, on the operator's machine.
  ...route('GET /audit/keys', { run: (ctx) => auditKeys(ctx) }),
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
