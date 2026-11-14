import { isScope, runsInstance, setsUpServices, type Permission, type Place, type RoleDefinition, type ServiceSetting } from '@coffre/core/access';
import { BindingInvalid, checkFetchUrl, GITLAB_ISSUER, GitHubAppUnavailable, type GitHubAppRepositories } from '@coffre/core/identity';
import { z } from 'zod';

import { places } from '../../db/queries/places.ts';
import { serviceSetup } from '../../db/queries/policy.ts';
import { FetchRefused } from '../../workloads/transport.ts';
import { placeOf, projectsReached } from '../caller.ts';
import type { ApiContext } from '../context.ts';
import { ApiError, badRequest, forbidden, notFound } from '../errors.ts';
import { route } from '../route.ts';
import { workloadsOf } from './bindings.ts';

/**
 * What a trust binding names, looked up for whoever sets one up
 * (docs/design/0.16.md, "A workload signing in"): a GitHub repository's or
 * owner's IDs, a GitLab project's, and the repositories the deployment's
 * GitHub App is installed on. The pages cannot ask those hosts themselves,
 * since they connect only to coffre, and the vault reaches no network: the
 * app asks, and the vault is asked only who is calling. Neither route
 * writes anything, nor logs.
 *
 * What each asks outside, at most:
 *
 *   lookup        a GitHub owner, or a GitLab project: one request
 *                 (`transport`, 5 s, 64 KiB). A GitHub repository: through
 *                 the App when there is one, four requests (its
 *                 installation, a token, the repository, and once more on a
 *                 token GitHub refuses), then, when it is not installed
 *                 there, one public request.
 *   repositories  the App's listing: `MAX_LISTING_REQUESTS` (40) requests,
 *                 tokens and retries included, past which it answers the
 *                 repositories it reached, `truncated`.
 *
 * Every request has its own deadline (5 s public, 10 s the App's), and the
 * App's, all of a call's together, `GITHUB_DEADLINE_MS`: past it, 503
 * `deadline`, and nothing still asked goes on.
 */

/** All of one call's requests to the GitHub App, from the first to the last byte of the last. */
export const GITHUB_DEADLINE_MS = 20_000;

/**
 * The IDs a binding names, under the names the host gives them: `Acme/API`
 * looked up is `acme/api`, as its tokens name it. A GitHub owner, a user or
 * an organization, has an ID alone.
 */
export type WorkloadIds =
  | { github: string; repositoryId: string; ownerId: string }
  | { github: string; ownerId: string }
  | { gitlab: string; projectId: string; namespaceId: string };

const GITHUB_OWNER = /^[A-Za-z0-9-]{1,39}$/;
// GitHub names no repository `.` or `..`, which a URL would read as a step up its path.
const GITHUB_REPOSITORY = /^[A-Za-z0-9-]{1,39}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const GITLAB_PROJECT = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+){1,20}$/;

/**
 * Before anything is asked outside: whether the caller sets up any service
 * account, as 0.14.7 weighed it (`setsUpServices`): whoever runs the
 * instance, one `caller`; or a person on a session who could give one a
 * grant somewhere they reach, one `caller` and two statements, the
 * instance's setting with every project role, and those places. Anyone
 * else would only spend the
 * hour's lookups GitHub allows the deployment's address.
 */
async function setsUp(ctx: ApiContext): Promise<void> {
  const who = await ctx.caller();
  if (runsInstance(who.holds)) return;
  // A service account, or a credential with a scope, sets none up (`givesService`): refused before any statement.
  if (who.principal.startsWith('user:') && who.holds.credentialScope == null) {
    const { setting, roles } = await serviceSetup(ctx.db);
    const reached: Place[] = [];
    for (const project of await places(ctx.db, projectsReached(who))) {
      if (project.archived) continue;
      reached.push(placeOf(project, null));
      // A personal config is its owner's alone: no service account is given anything there.
      for (const environment of project.environments) if (!environment.archived && environment.owner === null) reached.push(placeOf(project, environment));
    }
    // The vault names only the roles the caller holds; any role may be one they could give, as the vault weighs it
    // (`member.put`): every one the rows define, under the vault's definitions of their own. The rows are read as they
    // are: they decide only whether to ask outside, and the vault decides every service account set up.
    const defined = Object.fromEntries(roles.map((row): [string, RoleDefinition] => [row.id, { name: row.name, description: row.description, permissions: row.permissions as Permission[], protected: row.protected as Permission[] }]));
    const holder = { ...who.holds, policy: { ...who.holds.policy, roles: { ...defined, ...who.holds.policy.roles } } };
    if (setsUpServices(holder, settingOf(setting), reached)) return;
  }
  throw forbidden('only those who set up service accounts may trust workloads');
}

/** The setting as the row keeps it; none for one that does not read as a scope, as the vault takes it. */
function settingOf(text: string | null): ServiceSetting | null {
  if (text === null) return null;
  try {
    const setting: unknown = JSON.parse(text);
    return isScope(setting) ? setting : null;
  } catch {
    return null;
  }
}

/** One of the GitHub App's answers, or its refusal in the API's words: past the deadline, `ms`, 503 `deadline`. */
export async function asApp<T>(ask: (signal: AbortSignal) => Promise<T>, ms = GITHUB_DEADLINE_MS): Promise<T> {
  const signal = AbortSignal.timeout(ms);
  try {
    return await ask(signal);
  } catch (error) {
    if (!(error instanceof GitHubAppUnavailable)) throw error;
    if (signal.aborted) throw new ApiError('unavailable', `GitHub did not answer within ${ms / 1000} s; type its IDs meanwhile`, 'deadline');
    throw new ApiError('unavailable', `${error.message}; type its IDs meanwhile`);
  }
}

/** An ID as GitHub and GitLab answer one, a number, as text; null for anything else. */
const idOf = (value: unknown) => (typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : null);
/** The name the host answered, when it is the one asked but for case; else the one asked. */
const nameOf = (value: unknown, given: string) => (typeof value === 'string' && value.toLowerCase() === given.toLowerCase() ? value : given);
const record = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});

/**
 * One public request, through the app's transport. Asked without signing
 * in, GitHub answers 60 an hour per address, which every user of a Workers
 * deployment shares: a 403 or a 429 says the hour's are spent.
 */
async function askPublic(ctx: ApiContext, url: URL, missing: ApiError = notFound(`${url.hostname} did not find it: for a private one, type its IDs`)): Promise<Record<string, unknown>> {
  try {
    return record(await ctx.transport.json(url));
  } catch (error) {
    if (!(error instanceof FetchRefused)) throw error;
    if (error.status === 403 || error.status === 429) {
      throw new ApiError('too_many_requests', `${url.hostname} allows only so many lookups an hour without signing in, and this hour's are spent: try again later, or type the IDs`);
    }
    if (error.status === 404) throw missing;
    throw new ApiError('unavailable', `${url.hostname} did not answer (${error.message}): try again, or type the IDs`);
  }
}

export const workloadRoutes = {
  /**
   * A GitHub repository's or owner's IDs, or a GitLab project's, which
   * bindings name rather than names. A repository resolves through the
   * deployment's GitHub App when it is installed there, private or not,
   * and through GitHub's public API otherwise; a private one neither
   * reaches is not found, and its IDs are typed in. A GitLab project is
   * gitlab.com's, or a GitLab's at `gitlabUrl`, held to what a binding's
   * issuer is (`checkFetchUrl`). Costs: `setsUp`, then what the file's
   * header says is asked outside.
   */
  ...route('GET /workloads/lookup', {
    input: z.object({
      github: z.string().max(200).optional(),
      gitlab: z.string().max(400).optional(),
      gitlabUrl: z.string().max(400).optional(),
    }).strict(),
    run: async (ctx, { input }): Promise<WorkloadIds> => {
      const workloads = workloadsOf(ctx);
      await setsUp(ctx);
      const { github, gitlab } = input;
      if (github !== undefined && GITHUB_OWNER.test(github)) {
        const owner = await askPublic(ctx, new URL(`https://api.github.com/users/${github}`));
        const ownerId = idOf(owner.id);
        if (ownerId === null) throw notFound(`GitHub does not know ${github}`);
        return { github: nameOf(owner.login, github), ownerId };
      }
      if (github !== undefined) {
        if (!GITHUB_REPOSITORY.test(github)) throw badRequest('a GitHub repository is <owner>/<name>, and an owner <owner>');
        const app = workloads.github;
        if (app !== null) {
          const found = await asApp((signal) => app.repository(github, { signal }));
          if (found !== null) return { github: found.github, repositoryId: found.repositoryId, ownerId: found.ownerId };
        }
        const owner = github.split('/')[0]!;
        const repository = await askPublic(
          ctx,
          new URL(`https://api.github.com/repos/${github}`),
          // `not_installed`: the pages say this, where a 404 is otherwise theirs to word.
          app === null ? undefined : new ApiError('not_found', `GitHub did not find it, and the GitHub App is not installed on it: install it on ${owner}, or type its IDs`, 'not_installed'),
        );
        const [repositoryId, ownerId] = [idOf(repository.id), idOf(record(repository.owner).id)];
        if (repositoryId === null || ownerId === null) throw notFound(`GitHub does not know ${github}`);
        return { github: nameOf(repository.full_name, github), repositoryId, ownerId };
      }
      if (gitlab !== undefined) {
        if (!GITLAB_PROJECT.test(gitlab)) throw badRequest('a GitLab project is <group>/<name>');
        const base = input.gitlabUrl ?? GITLAB_ISSUER;
        try {
          checkFetchUrl(base, 'the GitLab URL', { allowLoopback: workloads.allowLoopback, path: true, query: false });
        } catch (error) {
          if (error instanceof BindingInvalid) throw badRequest(error.message);
          throw error;
        }
        const project = await askPublic(ctx, new URL(`${base.replace(/\/$/, '')}/api/v4/projects/${encodeURIComponent(gitlab)}`));
        const [projectId, namespaceId] = [idOf(project.id), idOf(record(project.namespace).id)];
        if (projectId === null || namespaceId === null) throw notFound(`GitLab does not know ${gitlab}`);
        return { gitlab: nameOf(project.path_with_namespace, gitlab), projectId, namespaceId };
      }
      throw badRequest('look up a GitHub repository or a GitLab project');
    },
  }),

  /**
   * The repositories the deployment's GitHub App is installed on, private
   * ones too, for the pages' picker; `{ app: null }` when it has none.
   * Costs: `setsUp`, then the App's listing (the file's header).
   */
  ...route('GET /workloads/repositories', {
    run: async (ctx): Promise<GitHubAppRepositories | { app: null }> => {
      const app = workloadsOf(ctx).github;
      await setsUp(ctx);
      return app === null ? { app: null } : asApp((signal) => app.repositories({ signal }));
    },
  }),
};
