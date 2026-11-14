import { isScope, MAX_PERSONAL_TOKEN_MINUTES, MAX_SCOPE_PLACES, managesService, runsInstance, type Permission, type Place, type RoleDefinition, type Scope, type ServiceAccount } from '@coffre/core/access';
import { generateToken, hashToken, tokenHint } from '@coffre/core/identity';
import { roleId, slug } from '@coffre/core/schemas';
import type { Answers, Called, TokenCreate } from '@coffre/core/vault';
import { z } from 'zod';

import { memberTokens, type MemberTokens, type TokenRow } from '../../db/queries/tokens.ts';
import { changed } from '../change.ts';
import type { ApiContext } from '../context.ts';
import { ApiError, badRequest, forbidden, notFound } from '../errors.ts';
import { route } from '../route.ts';
import { memberOf } from './members.ts';

/**
 * A member's tokens, handles, and ending a session (docs/design/0.16.md,
 * "Signing in from the server"), in 0.14.7's shapes. Making or ending one
 * is one change of the vault's (`token.create`, `credential.end`), which
 * decides it, and no statement; a member's list is one call to the vault,
 * `caller`, and one statement.
 */

/** A token as its list shows it: never its value. */
export type TokenView = {
  id: string;
  label: string | null;
  hint: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  /** What it reaches, each place by path and its role there: those still there. Null for a row that keeps none. */
  scope: Record<string, string> | null;
  /** A workload's key-bound session: the binding it signed in through. */
  session?: { bindingId: string | null };
};

/** A token made: its value, here and nowhere after. */
export type IssuedToken = { id: string; token: string; expiresAt: string; scope: Record<string, string> };

/** The most days a service's token lasts, as the vault takes it. */
const SERVICE_TOKEN_DAYS = 366;

/** A handle's environment by path, `market/dev`, or `market/dev@me` for its person's personal config of it: as the vault takes one. */
const HANDLE_PATH = /^[a-z0-9][a-z0-9-]{0,62}\/[a-z0-9][a-z0-9-]{0,62}(@me)?$/;

/** A label as the vault keeps one: printed in lists, the log and terminals, so no control character, which could rewrite what is shown around it; text it keeps, no lone surrogate. */
const label = z
  .string()
  .trim()
  .min(1)
  .max(120)
  .refine((text) => !/\p{Cc}/u.test(text) && Buffer.from(text).toString() === text, 'a label is text, with no control character');

/** A token's scope, each place by path and its role: `{ "market/dev": "developer" }`, 1 to 1,000 places. */
const scope = z
  .record(z.string().max(200), roleId)
  .refine((asked) => Object.keys(asked).length >= 1 && Object.keys(asked).length <= MAX_SCOPE_PLACES, `a scope names 1 to ${MAX_SCOPE_PLACES} places`)
  .refine((asked) => Object.keys(asked).every((path) => {
    const [project, environment, ...more] = path.split('/');
    return more.length === 0 && slug.safeParse(project).success && (environment === undefined || slug.safeParse(environment).success);
  }), 'a scope names each place by path: a project, or one of its environments, by slug');

/** What `POST /members/:member/tokens` takes: a service's token or a person's. */
const tokenInput = z.object({
  label: label.nullable().default(null),
  // A service token's lifetime, in days.
  expiresInDays: z.number().int().min(1).max(SERVICE_TOKEN_DAYS).optional(),
  // A personal token's, in minutes: an afternoon's script or agent, a week at most.
  expiresInMinutes: z.number().int().min(1).max(MAX_PERSONAL_TOKEN_MINUTES).optional(),
  scope: scope.optional(),
});

/** Sessions and tokens are coffre's own sign-in: behind Cloudflare Access there are none, as 0.14.7 answered. */
export function signsIn(ctx: ApiContext): void {
  if (ctx.auth.mode !== 'signin') throw notFound('this instance has no sign-in of its own');
}

/** A token drawn: its value, which only the answer carries, and what the vault is sent of it. */
function drawn(kind: 'personal' | 'handle' | 'service', minutes: number, named: string | null) {
  const token = generateToken(kind);
  return { token, credential: { token: hashToken(token).toString('hex'), minutes, label: named }, hint: tokenHint(token) };
}

/**
 * A token made, by one change of the vault's, worded as 0.14.7 worded what
 * it refused with words of its own: who makes no personal token or handle,
 * and an instance whose services sign in by key alone.
 */
async function made(ctx: ApiContext, change: TokenCreate, token: string, what: string): Promise<IssuedToken> {
  let answer: Answers['token.create'];
  try {
    answer = await changed(ctx, change, what);
  } catch (error) {
    if (error instanceof ApiError && error.reason === 'not_a_person') {
      throw new ApiError('forbidden', 'only a person makes a personal token or a handle: a service account reads its values', 'not_a_person');
    }
    if (error instanceof ApiError && error.reason === 'use_only') {
      throw new ApiError('forbidden', 'this instance issues no service token (useOnly): trust the workload with a binding, and it signs in with its key', 'use_only');
    }
    throw error;
  }
  return { id: answer.credential, token, expiresAt: answer.expiresAt, scope: answer.scope };
}

/** A token's scope, by path, from its row: each place by id, those still there; none for a row whose scope does not read as one. */
function scopeView(stored: string | null, slugs: Record<string, string>): Record<string, string> | null {
  if (stored === null) return null;
  let grants: unknown;
  try {
    grants = JSON.parse(stored);
  } catch {
    return {};
  }
  if (!Array.isArray(grants)) return {};
  const shown: [string, string][] = [];
  for (const grant of grants as unknown[]) {
    if (typeof grant !== 'object' || grant === null) continue;
    const { projectId, environmentId, role } = grant as Record<string, unknown>;
    if (typeof projectId !== 'string' || typeof role !== 'string' || !Object.hasOwn(slugs, projectId)) continue;
    if (environmentId == null) shown.push([slugs[projectId]!, role]);
    else if (typeof environmentId === 'string' && Object.hasOwn(slugs, environmentId)) shown.push([`${slugs[projectId]}/${slugs[environmentId]}`, role]);
  }
  return Object.fromEntries(shown.sort(([a], [b]) => (a < b ? -1 : 1)));
}

/** The binding a workload's session came through, by its `created_by`. */
const bindingOf = (createdBy: string) => (createdBy.startsWith('binding:') ? createdBy.slice('binding:'.length) : null);

function tokenView(row: TokenRow, slugs: Record<string, string>): TokenView {
  return {
    id: row.id,
    label: row.label,
    hint: row.hint ?? '',
    createdAt: row.createdAt,
    createdBy: row.createdBy,
    expiresAt: row.expiresAt,
    lastUsedAt: row.lastUsedAt,
    lastUsedIp: row.lastUsedIp,
    scope: scopeView(row.scope, slugs),
    ...(row.kind === 'workload' ? { session: { bindingId: bindingOf(row.createdBy) } } : {}),
  };
}

/**
 * Whether the caller manages the service account the rows describe, as
 * the vault weighs it (`managesSealed` in its ops/services.ts): whoever
 * runs the instance; else a person on a session who holds everything it
 * holds, inside the instance's setting, or who admitted it while it holds
 * nothing (`managesService`). A grant on a place the read did not find
 * makes it nobody's but whoever runs the instance; one on a deletion's
 * tombstone is none. From the rows unchecked: what it shows is a list.
 */
function manages(who: Called, read: MemberTokens): boolean {
  if (runsInstance(who.holds)) return true;
  if (who.holds.credentialScope != null || read.member === null) return false;
  let setting: Scope | null = null;
  try {
    const parsed: unknown = read.setting === null ? null : JSON.parse(read.setting);
    if (isScope(parsed)) setting = parsed;
  } catch {
    // None, as the vault reads a setting that is not one.
  }
  if (setting === null || read.member.grants.some((grant) => !grant.found)) return false;
  const kept = read.member.grants.filter((grant) => !grant.tombstone);
  const account: ServiceAccount = {
    grants: kept.map(({ projectId, environmentId, environmentSlug, role }) => ({ role, place: (environmentId === null ? { projectId } : { projectId, environmentId, environmentSlug: environmentSlug! }) as Place })),
    admittedBy: read.member.admittedBy,
  };
  // What its grants' roles hold, from their rows, beside the caller's own.
  const named = Object.fromEntries(kept.flatMap(({ role, definition }) => (definition === null ? [] : [[role, { name: definition.name, description: '', permissions: definition.permissions as Permission[], protected: definition.protected as Permission[] } satisfies RoleDefinition]])));
  return managesService({ ...who.holds, policy: { ...who.holds.policy, roles: { ...named, ...who.holds.policy.roles } } }, setting, who.principal, account);
}

export const tokenRoutes = {
  /**
   * A member's live tokens, newest first: a person's personal tokens and
   * handles, for them on a session of theirs and for whoever runs the
   * instance; a service account's tokens and its workloads' sessions, for
   * the account itself and whoever manages it. Never what a trust binding
   * issued a CI run. One call to the vault and one statement.
   */
  ...route('GET /members/:member/tokens', {
    run: async (ctx, { params }): Promise<{ tokens: TokenView[] }> => {
      signsIn(ctx);
      const member = memberOf(params.member);
      const who = await ctx.caller();
      const read = await memberTokens(ctx.db, member, new Date());
      const self = who.principal === member;
      if (member.startsWith('user:')) {
        // A person's own, on a session of theirs: a personal token lists none, as 0.14.7 let it reach none of these routes.
        if (!(self && who.holds.credentialScope == null) && !runsInstance(who.holds)) throw forbidden("only admins and owners of the whole instance may see other people's tokens");
      } else if (!self && !manages(who, read)) {
        throw forbidden('only those who manage this service account may see its tokens');
      }
      return { tokens: read.tokens.map((row) => tokenView(row, read.slugs)) };
    },
  }),

  /**
   * Make a token: a person's own personal token, which acts as them within
   * its scope (`expiresInMinutes`, a label and a scope all said), or a
   * service account's (`expiresInDays`; its scope, or every grant it holds).
   * The value is in the answer, and only there. One change, no statement.
   * `?dryRun=1`, 0.14.7's preview of what it would reach, is not served yet.
   */
  ...route('POST /members/:member/tokens', {
    input: tokenInput,
    query: z.object({ dryRun: z.string().optional() }),
    run: async (ctx, { params, input, query }): Promise<IssuedToken> => {
      signsIn(ctx);
      const member = memberOf(params.member);
      // Never a token made where only a preview was asked.
      if (query.dryRun !== undefined) throw new ApiError('not_implemented', "previewing what a token would reach is not served yet");
      if (member.startsWith('user:')) {
        if (input.label === null) throw badRequest('a personal token needs a label, which every entry it makes names');
        if (input.expiresInMinutes === undefined || input.expiresInDays !== undefined) throw badRequest('a personal token lasts expiresInMinutes, not days');
        if (input.scope === undefined) throw badRequest('a personal token needs a scope: what it reaches, by path');
        const { token, credential, hint } = drawn('personal', input.expiresInMinutes, input.label);
        return made(ctx, { op: 'token.create', kind: 'personal', member, credential, hint, scope: input.scope }, token, member);
      }
      if (input.expiresInDays === undefined || input.expiresInMinutes !== undefined) throw badRequest('a service token lasts expiresInDays');
      const { token, credential, hint } = drawn('service', input.expiresInDays * 24 * 60, input.label);
      return made(ctx, { op: 'token.create', kind: 'service', member, credential, hint, scope: input.scope ?? null }, token, member);
    },
  }),

  /**
   * End a token of a member's, or a workload's session of a service
   * account: theirs, for whoever manages the account, or for whoever runs
   * the instance. One change, no statement.
   */
  ...route('DELETE /members/:member/tokens/:id', {
    run: async (ctx, { params }): Promise<{ revoked: true }> => {
      signsIn(ctx);
      const member = memberOf(params.member);
      await changed(ctx, { op: 'credential.end', credential: params.id, of: { member } }, 'that token');
      return { revoked: true };
    },
  }),

  /**
   * A handle, for `coffre run` (docs/design/credential-proxy.md): a
   * placeholder for the values of `paths`, which only the credential proxy
   * takes. A person makes one, on a session or a personal token of theirs.
   * Twelve hours unless told, a week at most. One change, no statement.
   */
  ...route('POST /handles', {
    input: z.object({
      label,
      expiresInMinutes: z.number().int().min(1).max(MAX_PERSONAL_TOKEN_MINUTES).default(12 * 60),
      paths: z.array(z.string().max(200).regex(HANDLE_PATH, 'a handle names environments by path: project/environment, or project/environment@me')).min(1).max(MAX_SCOPE_PLACES),
    }),
    run: async (ctx, { input }): Promise<IssuedToken> => {
      signsIn(ctx);
      const { token, credential, hint } = drawn('handle', input.expiresInMinutes, input.label);
      return made(ctx, { op: 'token.create', kind: 'handle', credential, hint, paths: input.paths }, token, 'that handle');
    },
  }),

  /** A run's handle ended with its command (`coffre run`): a handle of the caller's own, on a personal token too. One change, no statement. */
  ...route('DELETE /handles/:id', {
    run: async (ctx, { params }): Promise<{ revoked: true }> => {
      signsIn(ctx);
      await changed(ctx, { op: 'credential.end', credential: params.id, of: 'handle' }, 'that handle');
      return { revoked: true };
    },
  }),

  /** End a session or token of the caller's own, or anyone's for whoever runs the instance. One change, no statement. */
  ...route('DELETE /sessions/:id', {
    run: async (ctx, { params }): Promise<{ revoked: true }> => {
      signsIn(ctx);
      await changed(ctx, { op: 'credential.end', credential: params.id, of: null }, 'that session');
      return { revoked: true };
    },
  }),
};
