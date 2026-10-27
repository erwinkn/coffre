import type { AuthInfo, CoffreClient, Member } from '@coffre/client';
import { EVERYWHERE, INSTANCE_ROLES } from '@coffre/core/access';
import { QueryClient, queryOptions, type FetchQueryOptions, type QueryKey } from '@tanstack/react-query';

import { deriveUiCapabilities } from './capabilities.ts';
import { memberRef, statusOf, uiResult } from './coffre.ts';
import { isActiveAccessibleEnvironment } from './project-environments.ts';
import type { DirectoryPrincipal, GrantRow, Me, ProjectSummary } from '../shared/models';

/**
 * Every read the pages make, cached by TanStack Query: one cache per request
 * on the server, whose reads the page carries to the browser's, and one in the
 * browser for the whole visit.
 *
 * How fresh a page is. A read is reused for `FRESH_MS`, refetched when the
 * window regains focus, and refetched at once by any change made here, which
 * names what it touches (`affects`), so your own changes always show.
 * Someone else's change shows within that window. Nothing is decided on a
 * cached read: the server authorizes every call, so a stale screen can offer
 * an action the server then refuses, never grant one. The audit log is the
 * exception, read fresh on every visit: its whole point is to be current.
 * The chain's verification is read once a visit like the rest, and again
 * after any change made here.
 */
export const FRESH_MS = 10_000;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: FRESH_MS,
        refetchOnWindowFocus: true,
        // A read either answers or says why it cannot (`uiResult`), so a
        // throw is a fault, and asking again would only repeat it.
        retry: false,
      },
    },
  });
}

type Place = { project: string; environment: string };

/**
 * The keys, which `affects` names too. A project's keys start with it, so
 * one invalidation covers everything read under it.
 */
export const keys = {
  me: ['me'],
  auth: ['auth'],
  projects: ['projects'],
  grants: (project: string) => ['grants', project],
  secrets: ({ project, environment }: Place) => ['secrets', project, environment],
  references: (path: string) => ['references', path],
  missing: ({ project, environment }: Place) => ['missing', project, environment],
  personal: (project: string) => ['personal', project],
  directory: ['directory'],
  report: (member: string) => ['report', member],
  memberAccess: (member: string) => ['member-access', member],
  credentials: (member: string) => ['credentials', member],
  bindings: (member: string) => ['bindings', member],
  githubRepositories: ['github-repositories'],
  tokenPlan: (member: string, scope: Record<string, string>) => ['token-plan', member, scope],
  identities: ['identities'],
  sessions: ['sessions'],
  apps: ['apps'],
  audit: ['audit'],
  auditKeys: ['audit', 'keys'],
  settings: ['settings'],
  roles: ['roles'],
} satisfies Record<string, QueryKey | ((...args: never[]) => QueryKey)>;

/** Members' grants, as rows, and a row for each one whose instance role reaches the place listed. */
function grantRows(members: Member[]): GrantRow[] {
  return members.flatMap((member): GrantRow[] => [
    ...(member.reachesByRole
      ? [{
          id: `${member.member}/instance-role`,
          principalType: member.principalType,
          principalId: member.principalId,
          role: member.instanceRole,
          roleName: INSTANCE_ROLES[member.instanceRole].name,
          permissions: [...INSTANCE_ROLES[member.instanceRole].permissions],
          scope: 'instance-role' as const,
          environmentSlug: null,
          expiresAt: null,
        }]
      : []),
    ...member.grants.map((grant) => ({
      id: grant.id,
      principalType: member.principalType,
      principalId: member.principalId,
      role: grant.role,
      roleName: grant.roleName,
      permissions: grant.permissions,
      scope: grant.environment === null ? ('project' as const) : ('environment' as const),
      environmentSlug: grant.environment,
      expiresAt: grant.expiresAt,
    })),
  ]);
}

function listDirectory(client: CoffreClient) {
  return uiResult(async () => {
    const { members, removed } = await client.members.list();
    const principals: DirectoryPrincipal[] = members.map(
      ({ principalType, principalId, instanceRole, scope, tampered, managed, declared, grants }) => ({
        principalType,
        principalId,
        instanceRole,
        scope,
        tampered,
        managed,
        declared,
        grants: grants.map(({ project, environment }) => ({ project, environment })),
      }),
    );
    return { principals, removed };
  });
}

const readProjects = (client: CoffreClient) => uiResult(() => client.projects.list());

/** The projects you can see, or why they could not be listed. */
export type ProjectsResult = Awaited<ReturnType<typeof readProjects>>;

export type AuditSearch = { decision?: 'deny'; actorId?: string; detail?: '1' };

export const AUDIT_PAGE_SIZE = 200;

export const queries = {
  /** Who is looking; null when nobody is signed in. */
  me: (client: CoffreClient) =>
    queryOptions({
      queryKey: keys.me,
      queryFn: async (): Promise<Me | null> => {
        try {
          return await client.me();
        } catch (error) {
          if (statusOf(error) === 401) return null;
          throw error;
        }
      },
    }),

  /** How this instance signs people in. */
  auth: (client: CoffreClient) => queryOptions({ queryKey: keys.auth, queryFn: (): Promise<AuthInfo> => client.auth() }),

  /** The projects you can see, each with its distinct secret count. */
  projects: (client: CoffreClient) =>
    queryOptions({ queryKey: keys.projects, queryFn: () => readProjects(client) }),

  /**
   * The repositories the deployment's GitHub App is installed on, for the
   * Trust dialog's picker; `{ app: null }` without one. Each listing asks
   * GitHub, so it is kept a minute, and not asked again on focus.
   */
  githubRepositories: (client: CoffreClient) =>
    queryOptions({
      queryKey: keys.githubRepositories,
      queryFn: () => client.bindings.repositories(),
      staleTime: 60_000,
      refetchOnWindowFocus: false,
    }),

  /**
   * What a service's token would reach, as the server would issue it now,
   * and the sensitive values it would not read (`withheld`); issues
   * nothing. A scope the server refuses plans nothing: issuing says why.
   * Any other failure is one, asked once.
   */
  tokenPlan: (client: CoffreClient, member: string, scope: Record<string, string>) =>
    queryOptions({
      queryKey: keys.tokenPlan(member, scope),
      queryFn: () => client.tokens.preview(member, { label: null, expiresInDays: 1, scope }).catch((failure: unknown) => {
        const status = statusOf(failure);
        if (status !== undefined && status >= 400 && status < 500) return null;
        throw failure;
      }),
      staleTime: 60_000,
      refetchOnWindowFocus: false,
      retry: false,
    }),

  /** Who holds what in a project, for those who manage its access. */
  grants: (client: CoffreClient, project: string) =>
    queryOptions({
      queryKey: keys.grants(project),
      queryFn: () => uiResult(async () => ({ grants: grantRows((await client.members.list(project)).members) })),
    }),

  secrets: (client: CoffreClient, place: Place) =>
    queryOptions({
      queryKey: keys.secrets(place),
      queryFn: () => uiResult(() => client.secrets.list(`${place.project}/${place.environment}`)),
    }),

  /** What an environment lacks of its siblings' keys, read or not, and what its team dismissed. */
  missing: (client: CoffreClient, place: Place) =>
    queryOptions({
      queryKey: keys.missing(place),
      queryFn: () => uiResult(() => client.environments.missing(`${place.project}/${place.environment}`)),
    }),

  /** A project's personal configs, for whoever manages its environments: whose, of what, and their key names. */
  personal: (client: CoffreClient, project: string) =>
    queryOptions({
      queryKey: keys.personal(project),
      queryFn: () => uiResult(() => client.environments.personal(project)),
    }),

  /** The live references into and out of a place, and who reads through them, for whoever manages its access. */
  references: (client: CoffreClient, path: string) =>
    queryOptions({
      queryKey: keys.references(path),
      queryFn: () => uiResult(() => client.references.list(path)),
    }),

  /**
   * Everyone in the directory, and who was removed. The API shows grant
   * managers the members of their projects; the directory pages are admins'
   * and owners', and asking for anyone else would only log a refusal, so
   * nobody else is asked.
   */
  directory: (client: CoffreClient, owner: boolean) =>
    queryOptions({
      queryKey: [...keys.directory, { owner }],
      queryFn: () =>
        owner
          ? listDirectory(client)
          : Promise.resolve({
              ok: false as const,
              error: 'Only admins and owners manage users, and service accounts are set up by those who hold access where the instance lets them.',
              signedOut: false,
            }),
    }),

  /**
   * One member's instance role and scope, and the grants you manage, in one
   * read: their page's Access tab. Null for whoever may list nobody, which
   * asking would only log as a refusal.
   */
  memberAccess: (client: CoffreClient, member: string, allowed: boolean) =>
    queryOptions({
      queryKey: [...keys.memberAccess(member), { allowed }],
      queryFn: () => (allowed ? uiResult(() => client.members.access(member)) : Promise.resolve(null)),
    }),

  /** What one member can reach and has seen; null for anyone but owners, who alone may ask. */
  report: (client: CoffreClient, member: string, owner: boolean) =>
    queryOptions({
      queryKey: [...keys.report(member), { owner }],
      queryFn: () =>
        owner
          ? uiResult(async () => {
              try {
                return { report: await client.members.get(member) };
              } catch (error) {
                // No such member is an answer, not a failure.
                if (statusOf(error) === 404) return { report: null };
                throw error;
              }
            })
          : Promise.resolve(null),
    }),

  /**
   * A token's credentials; null where they cannot be listed. Only owners
   * issue and see them, and only coffre's own sign-in issues any.
   */
  credentials: (client: CoffreClient, member: string, allowed: boolean) =>
    queryOptions({
      queryKey: [...keys.credentials(member), { allowed }],
      queryFn: () => (allowed ? uiResult(() => client.tokens.list(member)) : Promise.resolve(null)),
    }),

  /**
   * A token's trust bindings: the CI runs that may sign in as it. Null for
   * anyone but an owner, and where the deployment trusts no workloads
   * (`features.workloads`), so there is nothing to ask.
   */
  bindings: (client: CoffreClient, member: string, allowed: boolean) =>
    queryOptions({
      queryKey: [...keys.bindings(member), { allowed }],
      queryFn: () => (allowed ? uiResult(() => client.bindings.list(member)) : Promise.resolve(null)),
    }),

  /** The accounts you sign in with, under coffre's own sign-in. */
  identities: (client: CoffreClient) =>
    queryOptions({ queryKey: keys.identities, queryFn: () => uiResult(() => client.identities.list()) }),

  /** Where you are signed in, under coffre's own sign-in. */
  sessions: (client: CoffreClient) =>
    queryOptions({ queryKey: keys.sessions, queryFn: () => uiResult(() => client.sessions.list()) }),
  /** The MCP clients I connected, where the deployment serves MCP (`features.mcp`). */
  apps: (client: CoffreClient) =>
    queryOptions({ queryKey: keys.apps, queryFn: () => uiResult(() => client.apps.list()) }),

  /**
   * What the keys an operator keeps are checked against: the vault's ID and
   * the app key's fingerprint, no secret. Null for anyone but owners and root
   * admins, who alone may ask.
   */
  auditKeys: (client: CoffreClient, allowed: boolean) =>
    queryOptions({
      queryKey: [...keys.auditKeys, { allowed }],
      queryFn: () => (allowed ? uiResult(() => client.audit.keys()) : Promise.resolve(null)),
    }),

  /** The instance's settings: null for anyone but those who run it, who alone may ask. */
  settings: (client: CoffreClient, allowed: boolean) =>
    queryOptions({
      queryKey: [...keys.settings, { allowed }],
      queryFn: () => (allowed ? uiResult(() => client.settings.get()) : Promise.resolve(null)),
    }),

  /**
   * The instance's roles and instance roles, as an Owner edited and made
   * them (docs/design/roles.md), and whether the caller edits them. Any
   * member reads them: they are what every grant picker offers.
   */
  roles: (client: CoffreClient) =>
    queryOptions({ queryKey: keys.roles, queryFn: () => uiResult(() => client.roles.list()) }),

  /** A page of the log, as filtered: always read fresh. */
  auditEntries: (client: CoffreClient, search: AuditSearch) =>
    queryOptions({
      queryKey: [...keys.audit, 'entries', search],
      staleTime: 0,
      // Detail is left out by the server unless asked for, and counted.
      queryFn: () =>
        uiResult(() =>
          client.audit.list({
            limit: AUDIT_PAGE_SIZE,
            decision: search.decision,
            actor: search.actorId,
            detail: search.detail,
          }),
        ),
    }),

  /**
   * Whether the log holds: verified with each visit, and rendered with the
   * page, the loader's read to carry to the browser: it is not asked again on
   * mount, and not for a filter change or a hover, which `FRESH_MS` covers.
   * It reads what was written since the newest checkpoint, so it takes as
   * long as five minutes of the log, however long the log. It never rejects:
   * a check that could not run is its verdict (`unknown`).
   */
  auditChain: (client: CoffreClient) =>
    queryOptions({ queryKey: [...keys.audit, 'chain'], refetchOnMount: false, queryFn: () => verifyChain(client) }),
  /** What deleting `market` or `market/prod` would take, asked afresh each time it is shown. */
  deletion: (client: CoffreClient, path: string) =>
    queryOptions({
      queryKey: ['deletion', path],
      staleTime: 0,
      gcTime: 0,
      queryFn: () =>
        uiResult(async () => {
          const { deletion } = path.includes('/')
            ? await client.environments.previewDelete(path)
            : await client.projects.previewDelete(path);
          return { deletion };
        }),
    }),
};

/**
 * Whether the log holds, or why that is not known. Verifying is for those
 * who read the whole log (an Auditor, Admin or Owner whose scope narrows
 * nothing): anyone else reads their projects' part of it, and a part cannot be
 * checked as a chain, so for them it is a fact about the page, not a fault.
 */
async function verifyChain(client: CoffreClient) {
  // Each settled apart: a check of 0.15's log that could not run says so beside 0.14's verdict, never in its place.
  const [chain, trees] = await Promise.allSettled([client.audit.verify(), client.audit.verifyTrees()]);
  if (chain.status === 'rejected') return chainUnknown(chain.reason);
  if (trees.status === 'fulfilled') return chainResult(chain.value, false, trees.value);
  // Whatever turned it away, a refusal included (access narrowed between the two, review r11): not checked, never "Verified".
  const failed = chainUnknown(trees.reason);
  const problem = failed.integrity === 'unknown' ? failed.problem : 'the request was refused (HTTP 403)';
  return { ...chainResult(chain.value, false), ...(chain.value.ok ? { treesFailed: `coffre could not check the sealed log: ${problem}` } : {}) };
}

/** 0.15's log as its check found it (`audit.verifyTrees`): `kept` false where the instance keeps 0.14's alone. */
export type TreesResult = Awaited<ReturnType<CoffreClient['audit']['verifyTrees']>>;

/**
 * A verdict as the page shows it: `whole` when it comes from the walk
 * from the first entry, which someone asked for, not from the newest
 * checkpoint's. Where the instance keeps 0.15's log too, its check
 * (`trees`) is part of it: what it finds breaks the log as 0.14's would.
 */
export function chainResult(result: Awaited<ReturnType<CoffreClient['audit']['verify']>>, whole: boolean, trees: TreesResult = { kept: false }) {
  if (result.ok && trees.kept && trees.problems.length > 0) {
    const more = trees.problems.length - 1;
    return {
      integrity: 'broken' as const,
      through: result.through,
      failedAtSeq: null,
      author: 'vault' as const,
      reason: `the sealed log: ${trees.problems[0]}${more > 0 ? ` (and ${more} more)` : ''}`,
    };
  }
  return result.ok
    ? {
        integrity: 'intact' as const,
        whole,
        through: result.through,
        entries: result.entries,
        // A server older than 0.10.1 checked from the first entry, and reached the head.
        from: result.from ?? 0,
        remaining: result.remaining ?? 0,
        checkpoint: result.checkpoint,
        pending: result.pending ?? 0,
        /** Why the check of 0.15's log could not run, when it could not: the chain's verdict stands, the sealed log's is not known. */
        treesFailed: null as string | null,
        /** 0.15's log, where it is kept: the newest pair its check reached. */
        trees: trees.kept ? { checkpoint: trees.checkpoint } : null,
      }
    : {
        integrity: 'broken' as const,
        through: result.through,
        failedAtSeq: result.failedAtSeq,
        author: result.author,
        reason: result.reason,
      };
}

/**
 * What the page shows, of the check from the newest checkpoint (`quick`)
 * and the walk from the first entry, once someone ran it (`whole`). A break
 * the walk found stands; otherwise the newer check says how the log is now,
 * broken, partly checked or not checked at all; and only while it found the
 * log whole too does the walk's verdict, which read further back, stand
 * over it.
 *
 *   whole broken                                              → whole
 *   whole intact, quick intact, 0 remaining, sealed log checked → whole
 *   whole intact, quick anything else                         → quick
 *
 * A newer check that could not check the sealed log (review r10) is
 * "anything else": the walk's seal would stand over a log nobody can now
 * say holds.
 */
export function shownChain(quick: ChainResult, whole: ChainResult | null): ChainResult {
  if (whole === null || whole.integrity === 'broken') return whole ?? quick;
  return quick.integrity === 'intact' && quick.remaining === 0 && quick.treesFailed === null && whole.integrity === 'intact' ? whole : quick;
}

/** Why the log's verdict is not known: closed to the caller, or no answer. */
export function chainUnknown(error: unknown) {
  const status = statusOf(error);
  if (status === 403) return { integrity: 'owners-only' as const };
  return {
    integrity: 'unknown' as const,
    problem: status === undefined ? 'the request never got an answer' : `the request failed with HTTP ${status}`,
  };
}

export type ChainResult = Awaited<ReturnType<typeof verifyChain>>;

/**
 * Who is looking, how this instance signs people in, and the projects they
 * can see: what the shell needs on every screen. For someone signed out or
 * not yet a member the project list is refused, and they get the sign-in or
 * closed-door page.
 */
export function shellOf(
  auth: AuthInfo,
  me: Me | null,
  projects: ProjectsResult,
) {
  const listed = projects.ok ? projects.projects : [];
  const member: Me | null = me?.registered === true ? me : null;
  return {
    auth,
    principal: me === null ? null : me.principal,
    instanceRole: member?.instanceRole ?? null,
    /** Where their instance role applies, projects by slug. */
    scope: member?.scope ?? EVERYWHERE,
    projects: listed,
    capabilities: deriveUiCapabilities(member, listed),
    registrationRequired: me !== null && !me.registered,
    /** A member the vault refuses: their record failed its integrity check. */
    accessTampered: me?.tampered === true,
    /** What the deployment's configuration turns on: MCP clients, as their endpoint's URL, and CI runs signing in by their ID tokens. */
    features: member?.features ?? { mcp: null, workloads: false },
    /** Every environment you hold something in, and what: what you may give a service account there (`givable`). */
    environments: member?.environments ?? [],
    /** Where you set up service accounts yourself, the instance's setting, projects by slug. */
    serviceSetup: member?.serviceSetup ?? null,
  };
}

export type Shell = ReturnType<typeof shellOf>;

/**
 * How a loader reads. `fresh`, a page's own reads: the cached answer within
 * `FRESH_MS`, else the network's, waited for. `cached`, a tab's: its page's
 * layout has read the same, so it takes the cached answer at once, however
 * old, and refetches behind it, and switching tabs never waits on the
 * network. A read the cache lacks is waited for either way.
 */
export type Freshness = 'fresh' | 'cached';

function read<T, TKey extends QueryKey>(queryClient: QueryClient, options: FetchQueryOptions<T, Error, T, TKey>, freshness: Freshness): Promise<T> {
  return freshness === 'fresh' ? queryClient.fetchQuery(options) : queryClient.ensureQueryData({ ...options, revalidateIfStale: true });
}

/**
 * Whether a tab may open: from the cache, and where the cache says no, from
 * the network, which a no needs before the tab sends anyone away. A stale
 * no could be an account since added back, or a role since given.
 */
export async function tabOpens(opens: (freshness: Freshness) => Promise<boolean>): Promise<boolean> {
  return (await opens('cached')) || opens('fresh');
}

/**
 * The shell, as every loader reads it: from the cache while fresh, so a
 * child route never asks again for what the root has.
 */
export async function loadShell(queryClient: QueryClient, client: CoffreClient, freshness: Freshness = 'fresh'): Promise<Shell> {
  const [auth, me, projects] = await Promise.all([
    read(queryClient, queries.auth(client), freshness),
    read(queryClient, queries.me(client), freshness),
    read(queryClient, queries.projects(client), freshness),
  ]);
  return shellOf(auth, me, projects);
}

/**
 * One project and, when you manage its access, its grants. A project that is
 * not there for you fails with no message: the page words that itself.
 */
export function projectOf(projects: ProjectsResult, slug: string) {
  if (!projects.ok) return projects;
  const project = projects.projects.find((entry) => entry.slug === slug);
  if (project === undefined) return { ok: false as const, error: null };
  return { ok: true as const, project, managesAccess: project.permissions.includes('grant.manage') };
}

/** What a project page reads: the project list, and its grants when you manage them. */
export async function loadProject(queryClient: QueryClient, client: CoffreClient, slug: string) {
  const found = projectOf(await queryClient.fetchQuery(queries.projects(client)), slug);
  if (found.ok && found.managesAccess) await queryClient.fetchQuery(queries.grants(client, slug));
}

/**
 * What an environment's page reads: its secrets and, for whoever reads them,
 * the references that read them from elsewhere and the keys it lacks,
 * rendered with them. Where the project tree the shell holds says you read
 * it, all three are asked at once, one round trip; elsewhere the others wait
 * for the secrets, so a refused visit is one refusal in the log, not three.
 */
export async function loadEnvironment(queryClient: QueryClient, client: CoffreClient, place: Place) {
  const others = () =>
    Promise.all([
      queryClient.fetchQuery(queries.references(client, `${place.project}/${place.environment}`)),
      queryClient.fetchQuery(queries.missing(client, place)),
    ]);
  const found = projectOf(await queryClient.ensureQueryData(queries.projects(client)), place.project);
  // Neither in an archived project nor archived itself: the API serves neither.
  const here = found.ok && found.project.archivedAt === null
    ? found.project.environments.find((environment) => environment.slug === place.environment)
    : undefined;
  if (here !== undefined && isActiveAccessibleEnvironment(here)) {
    const [secrets] = await Promise.all([queryClient.fetchQuery(queries.secrets(client, place)), others()]);
    return secrets;
  }
  const secrets = await queryClient.fetchQuery(queries.secrets(client, place));
  if (secrets.ok) await others();
  return secrets;
}

/**
 * What the audit page reads: a page of the log and the verification from
 * the newest checkpoint, asked together and rendered together, so the badge
 * arrives with the page. The verification never fails the load: a check that
 * could not run is its verdict.
 */
export async function loadAudit(queryClient: QueryClient, client: CoffreClient, search: AuditSearch) {
  const [entries] = await Promise.all([
    queryClient.fetchQuery(queries.auditEntries(client, search)),
    queryClient.fetchQuery(queries.auditChain(client)),
  ]);
  return entries;
}

/** The directory pages' read: the directory, for owners. */
export async function loadDirectory(queryClient: QueryClient, client: CoffreClient) {
  const shell = await loadShell(queryClient, client);
  return queryClient.fetchQuery(queries.directory(client, shell.capabilities.canManageGrants));
}

/** The instance's settings: the directory's counts, where people set up service accounts, and what its keys are checked against. */
export async function loadSettings(queryClient: QueryClient, client: CoffreClient) {
  const shell = await loadShell(queryClient, client);
  await Promise.all([
    loadDirectory(queryClient, client),
    queryClient.fetchQuery(queries.settings(client, shell.capabilities.runsInstance)),
    queryClient.fetchQuery(queries.auditKeys(client, shell.capabilities.runsInstance)),
    queryClient.fetchQuery(queries.roles(client)),
  ]);
}

/** Whether the Service accounts page lists anyone: to admins and owners, and to whoever sets one up, those they manage. */
export function listsServices(shell: Shell): boolean {
  return shell.capabilities.canManageGrants || shell.capabilities.setsUpServices;
}

/**
 * How the caller may have a service account sign in, from its list entry
 * or its access: bearer tokens under coffre's own sign-in, trusted
 * workloads where the deployment trusts them, each only for an account they
 * manage.
 */
export function waysFor(shell: Shell, managed: boolean): { tokens: boolean; workloads: boolean } {
  return { tokens: managed && shell.auth.signin !== null, workloads: managed && shell.features.workloads };
}

/**
 * The service accounts page: the directory, and each account's bindings and
 * tokens, read here as its own page reads them, so the list shows how each
 * signs in from the first paint and the browser asks for nothing that may be
 * refused (a deployment that trusts no workloads answers bindings with one).
 */
export async function loadServiceDirectory(queryClient: QueryClient, client: CoffreClient) {
  const shell = await loadShell(queryClient, client);
  const directory = await queryClient.fetchQuery(queries.directory(client, listsServices(shell)));
  if (!directory.ok) return directory;
  await Promise.all(
    directory.principals
      .filter((principal) => principal.principalType === 'service')
      .flatMap((principal) => {
        const member = memberRef('service', principal.principalId);
        const ways = waysFor(shell, principal.managed === true);
        return [
          queryClient.fetchQuery(queries.credentials(client, member, ways.tokens)),
          queryClient.fetchQuery(queries.bindings(client, member, ways.workloads)),
        ];
      }),
  );
  return directory;
}

/** Who a user or service account is to the instance, its pages' header: null to anyone who does not run it. */
export async function loadMember(queryClient: QueryClient, client: CoffreClient, member: string, freshness: Freshness = 'fresh') {
  const shell = await loadShell(queryClient, client, freshness);
  return read(queryClient, queries.report(client, member, shell.capabilities.runsInstance), freshness);
}

export type MemberReport = Awaited<ReturnType<typeof loadMember>>;

/**
 * What a user's or service account's Access tab reads: their role, scope
 * and the grants you manage, in one request, which the server answers in
 * one query, however many projects they hold grants in.
 */
export async function loadAccess(queryClient: QueryClient, client: CoffreClient, member: string, freshness: Freshness = 'fresh') {
  const shell = await loadShell(queryClient, client, freshness);
  return read(queryClient, queries.memberAccess(client, member, listsAccess(shell)), freshness);
}

/**
 * A user's or service account's page: what every tab but Activity shows,
 * read once by its layout, so its tabs open at once. Who they are, what they
 * hold and, for a service account, how it signs in.
 */
export async function loadPrincipal(queryClient: QueryClient, client: CoffreClient, principalType: 'user' | 'service', principalId: string) {
  const member = memberRef(principalType, principalId);
  await Promise.all([
    loadMember(queryClient, client, member),
    principalType === 'service' ? loadSignIn(queryClient, client, member) : loadAccess(queryClient, client, member),
  ]);
}

/**
 * A service account's Sign-in tab: its bearer tokens and trust bindings, as
 * far as its page shows them (`signInWays`), which it returns: null where it
 * shows neither.
 */
export async function loadSignIn(queryClient: QueryClient, client: CoffreClient, member: string, freshness: Freshness = 'fresh') {
  const [shell, access] = await Promise.all([
    loadShell(queryClient, client, freshness),
    loadAccess(queryClient, client, member, freshness),
  ]);
  const ways = signInWays(shell, access);
  if (ways !== null) {
    await Promise.all([
      read(queryClient, queries.credentials(client, member, ways.tokens), freshness),
      read(queryClient, queries.bindings(client, member, ways.workloads), freshness),
    ]);
  }
  return ways;
}

/**
 * Whether the caller may ask what someone holds: admins and owners,
 * whoever manages a project's access, and whoever sets up service accounts,
 * of those they manage.
 */
export function listsAccess(shell: Shell): boolean {
  return shell.capabilities.canManageGrants || shell.capabilities.setsUpServices || managedProjects(shell.projects).length > 0;
}

export type MemberAccessResult = Awaited<ReturnType<typeof loadAccess>>;

/**
 * How a service account's page lets it sign in: bearer tokens under
 * coffre's own sign-in, trusted workloads where the deployment trusts them.
 * Null where it shows neither: to anyone who does not manage it (its access
 * says, `managed`), and for an account that is not active, which can be
 * issued nothing.
 */
export function signInWays(shell: Shell, access: MemberAccessResult): { tokens: boolean; workloads: boolean } | null {
  const managed = access?.ok === true && access.managed && access.status === 'active';
  const ways = waysFor(shell, managed);
  return ways.tokens || ways.workloads ? ways : null;
}

/**
 * Whether a user has a Connected apps tab: for an owner, where the
 * deployment serves MCP, and while the user is registered and not removed,
 * since removal disconnects every app. The tab, and the route under it,
 * both ask.
 */
export function hasAppsTab(shell: Shell, report: MemberReport): boolean {
  const found = report?.ok === true ? report.report : null;
  return Boolean(shell.features.mcp) && shell.capabilities.runsInstance && found !== null && found.status !== 'removed';
}

export function managedProjects(projects: ProjectSummary[]): ProjectSummary[] {
  return projects.filter((project) => project.permissions.includes('grant.manage'));
}

/**
 * What each change touches, which `useAction` refetches when it lands. Every
 * change also lands in the audit log, which is always read fresh.
 */
export const affects = {
  /**
   * A project or environment made, renamed or archived: the tree, where you
   * hold access, and the personal configs listed of it, which go with it.
   */
  places: (): QueryKey[] => [keys.projects, keys.me, ['personal']],
  /** Secrets written, renamed, restored or archived: the environment, the counts, and the personal configs' key names. */
  secrets: (place: Place): QueryKey[] => [keys.secrets(place), keys.projects, ['references'], ['missing'], ['personal']],
  /**
   * Someone's access in a project changed: its grants, their report, and, as
   * it may be your own, what you can see.
   */
  access: (project: string, member: string): QueryKey[] => [
    keys.grants(project),
    keys.memberAccess(member),
    keys.report(member),
    keys.projects,
    keys.me,
  ],
  /**
   * Someone let in: the directory, and whatever was read of them before
   * they were there, which said there was no such member: a new service
   * account's row asks how it signs in as soon as it shows.
   */
  admission: (member: string): QueryKey[] => [
    keys.directory,
    keys.report(member),
    keys.memberAccess(member),
    keys.credentials(member),
    keys.bindings(member),
  ],
  /**
   * An instance role changed: the directory, their report, and, as it may be
   * your own, what you can see and do.
   */
  role: (member: string): QueryKey[] => [keys.directory, keys.report(member), keys.memberAccess(member), keys.me, keys.projects],
  /** Someone removed: the directory, their report, and every grant, which removal ends, those on every project too. */
  removal: (member: string): QueryKey[] => [keys.directory, keys.report(member), keys.memberAccess(member), ['grants'], keys.projects],
  /**
   * Where people set up service accounts changed: the setting, and what you
   * may do, which the directory and `/me` say.
   */
  settings: (): QueryKey[] => [keys.settings, keys.me, keys.directory],
  /**
   * A role edited, made, reset or deleted, or an environment protected:
   * what everyone holds may change, so the roles, what you hold, and every
   * grant and environment read with what it holds.
   */
  roles: (): QueryKey[] => [keys.roles, keys.me, keys.projects, ['grants'], ['member-access'], ['secrets']],
  credentials: (member: string): QueryKey[] => [keys.credentials(member)],
  bindings: (member: string): QueryKey[] => [keys.bindings(member)],
  /** Unlinking an account also ends the sessions it signed in. */
  identities: (): QueryKey[] => [keys.identities, keys.sessions],
  sessions: (): QueryKey[] => [keys.sessions],
  apps: (): QueryKey[] => [keys.apps],
};

/**
 * Refetch what a change touched: at once where it is on screen, on next use
 * elsewhere. Every change lands in the audit log, so the log and its
 * verification are always among them.
 */
export async function refresh(queryClient: QueryClient, touched: QueryKey[]): Promise<void> {
  await Promise.all([...touched, keys.audit].map((queryKey) => queryClient.invalidateQueries({ queryKey })));
}
