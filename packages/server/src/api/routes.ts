import { ROLE_NAMES, type Permission } from '@coffre/core/access';
import { displayName, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { setAccess } from './access.ts';
import { auditKeys, listAudit, verifyAudit } from './audit.ts';
import type { ApiContext } from './context.ts';
import { notFound } from './errors.ts';
import { listMembers, memberReport, putMember, removeMember } from './members.ts';
import { parseGrantee, parseMember, parsePath, type ResolvedPath } from './paths.ts';
import { listProjects, me, patchEnvironment, patchProject, putEnvironment, putProject } from './projects.ts';
import {
  dryRunSecrets,
  listSecrets,
  listVersions,
  patchSecret,
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
    input: placePatch,
    needs: 'project.manage',
    action: 'project.update',
    run: (ctx, { place, input }) => patchProject(ctx, place, input),
  }),
  ...route('PUT /projects/:project/:environment', {
    input: z.object({ name: displayName }),
    needs: { permission: 'environment.manage', on: 'project' },
    action: 'environment.create',
    creates: true,
    run: (ctx, { params, place, input }) => putEnvironment(ctx, place, params.environment, input),
  }),
  ...route('PATCH /projects/:project/:environment', {
    input: placePatch,
    needs: { permission: 'environment.manage', on: 'project' },
    action: 'environment.update',
    run: (ctx, { place, input }) => patchEnvironment(ctx, place, input),
  }),

  // Secrets
  ...route('GET /secrets/:project/:environment', {
    needs: 'secret.read',
    action: 'secret.list',
    run: (ctx, { place }) => listSecrets(ctx, place),
  }),
  ...route('PATCH /secrets/:project/:environment', {
    input: z.record(secretKey, secretValue.nullable()),
    // `?dryRun=1` answers what the patch would do and writes nothing. Any
    // other query is refused, not ignored: a mistyped flag must not write.
    query: z.object({ dryRun: z.enum(['1', 'true']).optional() }).strict(),
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
    input: z.object({ key: secretKey, archived: z.boolean() }).partial().strict()
      .refine((patch) => patch.key !== undefined || patch.archived !== undefined, 'provide a key or archived flag'),
    needs: (patch) => [
      ...(patch.key !== undefined ? ['secret.write' as const] : []),
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
    input: z.object({ owner: z.boolean().optional() }).strict(),
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
