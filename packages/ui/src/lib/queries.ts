import type { AuthInfo, CoffreClient, Member } from '@coffre/client';
import { QueryClient, queryOptions, type QueryKey } from '@tanstack/react-query';

import { deriveUiCapabilities } from './capabilities.ts';
import { memberRef, statusOf, uiResult } from './coffre.ts';
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
 * an action the server then refuses, never grant one. The audit log and the
 * chain's verification are the exception, read fresh on every visit: their
 * whole point is to be current.
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
  directory: ['directory'],
  report: (member: string) => ['report', member],
  credentials: (member: string) => ['credentials', member],
  bindings: (member: string) => ['bindings', member],
  identities: ['identities'],
  sessions: ['sessions'],
  apps: ['apps'],
  audit: ['audit'],
  auditKeys: ['audit', 'keys'],
} satisfies Record<string, QueryKey | ((...args: never[]) => QueryKey)>;

/** One member's grants, as rows. */
function grantRows(members: Member[]): GrantRow[] {
  return members.flatMap((member) =>
    member.grants.map((grant) => ({
      id: grant.id,
      principalType: member.principalType,
      principalId: member.principalId,
      role: grant.role,
      roleName: grant.roleName,
      permissions: grant.permissions,
      scope: grant.project === '*' ? ('every-project' as const) : grant.environment === null ? ('project' as const) : ('environment' as const),
      environmentSlug: grant.environment,
      expiresAt: grant.expiresAt,
    })),
  );
}

function listDirectory(client: CoffreClient) {
  return uiResult(async () => {
    const { members, removed } = await client.members.list();
    const principals: DirectoryPrincipal[] = members.map(
      ({ principalType, principalId, instanceRole, isRootAdmin, tampered, grants }) => ({
        principalType,
        principalId,
        instanceRole,
        isRootAdmin,
        tampered,
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

  /** What an environment lacks of its siblings' keys, those you read, and what its team dismissed. */
  missing: (client: CoffreClient, place: Place) =>
    queryOptions({
      queryKey: keys.missing(place),
      queryFn: () => uiResult(() => client.environments.missing(`${place.project}/${place.environment}`)),
    }),

  /** The live references into and out of a place, and who reads through them, for whoever manages its access. */
  references: (client: CoffreClient, path: string) =>
    queryOptions({
      queryKey: keys.references(path),
      queryFn: () => uiResult(() => client.references.list(path)),
    }),

  /**
   * Everyone in the directory, and who was removed. The API shows grant
   * managers the members of their projects; the directory pages stay the
   * owners' own, and asking for anyone else would only log a refusal, so
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
              error: 'Only owners can manage users and service accounts.',
              signedOut: false,
            }),
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
   * Whether the log holds: verified on every visit, and never waited for.
   * It re-reads the whole log, so it takes as long as the log is long; the
   * page shows the entries first and the verdict when it comes.
   */
  auditChain: (client: CoffreClient) =>
    queryOptions({ queryKey: [...keys.audit, 'chain'], staleTime: 0, queryFn: () => verifyChain(client) }),
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
 * Whether the log holds, or why that is not known. Verifying is for owners:
 * anyone else reads their projects' part of the log, and a part cannot be
 * checked as a chain, so for them it is a fact about the page, not a fault.
 */
async function verifyChain(client: CoffreClient) {
  try {
    const result = await client.audit.verify();
    return result.ok
      ? {
          integrity: 'intact' as const,
          through: result.through,
          entries: result.entries,
          checkpoint: result.checkpoint,
          pending: result.pending ?? 0,
        }
      : {
          integrity: 'broken' as const,
          through: result.through,
          failedAtSeq: result.failedAtSeq,
          author: result.author,
          reason: result.reason,
        };
  } catch (error) {
    const status = statusOf(error);
    if (status === 403) return { integrity: 'owners-only' as const };
    return {
      integrity: 'unknown' as const,
      problem: status === undefined ? 'the request never got an answer' : `the request failed with HTTP ${status}`,
    };
  }
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
    projects: listed,
    capabilities: deriveUiCapabilities(member, listed),
    registrationRequired: me !== null && !me.registered,
    /** A member the vault refuses: their record failed its integrity check. */
    accessTampered: me?.tampered === true,
    /** What the deployment's configuration turns on: MCP clients, and CI runs signing in by their ID tokens. */
    features: member?.features ?? { mcp: false, workloads: false },
  };
}

export type Shell = ReturnType<typeof shellOf>;

/**
 * The shell, as every loader reads it: from the cache while fresh, so a
 * child route never asks again for what the root has.
 */
export async function loadShell(queryClient: QueryClient, client: CoffreClient): Promise<Shell> {
  const [auth, me, projects] = await Promise.all([
    queryClient.fetchQuery(queries.auth(client)),
    queryClient.fetchQuery(queries.me(client)),
    queryClient.fetchQuery(queries.projects(client)),
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

/** The directory pages' read: the directory, for owners. */
export async function loadDirectory(queryClient: QueryClient, client: CoffreClient) {
  const shell = await loadShell(queryClient, client);
  return queryClient.fetchQuery(queries.directory(client, shell.capabilities.canManageGrants));
}

/** The instance's settings: the directory's counts, and what its keys are checked against. */
export async function loadSettings(queryClient: QueryClient, client: CoffreClient) {
  const shell = await loadShell(queryClient, client);
  await Promise.all([
    loadDirectory(queryClient, client),
    queryClient.fetchQuery(queries.auditKeys(client, shell.capabilities.canManageGrants)),
  ]);
}

/**
 * The service accounts page: the directory, and each account's bindings and
 * tokens, read here as its own page reads them, so the list shows how each
 * signs in from the first paint and the browser asks for nothing that may be
 * refused (a deployment that trusts no workloads answers bindings with one).
 */
export async function loadServiceDirectory(queryClient: QueryClient, client: CoffreClient) {
  const shell = await loadShell(queryClient, client);
  const directory = await loadDirectory(queryClient, client);
  const allowed = shell.capabilities.canManageGrants && shell.auth.signin !== null;
  const trusts = shell.capabilities.canManageGrants && shell.features.workloads;
  if (!directory.ok || !allowed) return directory;
  await Promise.all(
    directory.principals
      .filter((principal) => principal.principalType === 'service')
      .flatMap((principal) => {
        const member = memberRef('service', principal.principalId);
        return [
          queryClient.fetchQuery(queries.credentials(client, member, allowed)),
          queryClient.fetchQuery(queries.bindings(client, member, trusts)),
        ];
      }),
  );
  return directory;
}

/** Who a user or service account is to the instance, its pages' header: null to anyone but an owner. */
export async function loadMember(queryClient: QueryClient, client: CoffreClient, member: string) {
  const shell = await loadShell(queryClient, client);
  return queryClient.fetchQuery(queries.report(client, member, shell.capabilities.canManageGrants));
}

export type MemberReport = Awaited<ReturnType<typeof loadMember>>;

/**
 * What a user's or service account's Access tab reads: the grants of every
 * project where you manage access. There is no "grants of this member"
 * call, so each project you manage is asked for its grants and the tab
 * keeps this member's. Projects where you do not hold grant.manage are
 * skipped rather than asked: the refusal would land in the audit log as a
 * denial in your name.
 */
export async function loadAccess(queryClient: QueryClient, client: CoffreClient) {
  const shell = await loadShell(queryClient, client);
  await Promise.all(managedProjects(shell.projects).map((project) => queryClient.fetchQuery(queries.grants(client, project.slug))));
}

/**
 * How a service account's page lets it sign in: bearer tokens under
 * coffre's own sign-in, trusted workloads where the deployment trusts them.
 * Null where it shows neither: to anyone but an owner, and for an account
 * that is not active, which can be issued nothing.
 */
export function signInWays(shell: Shell, report: MemberReport): { tokens: boolean; workloads: boolean } | null {
  const owner = shell.capabilities.canManageGrants;
  const ways = { tokens: owner && shell.auth.signin !== null, workloads: owner && shell.features.workloads };
  const active = report?.ok === true && report.report?.status === 'active';
  return active && (ways.tokens || ways.workloads) ? ways : null;
}

export function managedProjects(projects: ProjectSummary[]): ProjectSummary[] {
  return projects.filter((project) => project.permissions.includes('grant.manage'));
}

/**
 * What each change touches, which `useAction` refetches when it lands. Every
 * change also lands in the audit log, which is always read fresh.
 */
export const affects = {
  /** A project or environment made, renamed or archived: the tree, and where you hold access. */
  places: (): QueryKey[] => [keys.projects, keys.me],
  /** Secrets written, renamed, restored or archived: the environment and the counts. */
  secrets: (place: Place): QueryKey[] => [keys.secrets(place), keys.projects, ['references'], ['missing']],
  /**
   * Someone's access in a project changed: its grants, their report, and, as
   * it may be your own, what you can see.
   */
  access: (project: string, member: string): QueryKey[] => [
    keys.grants(project),
    keys.report(member),
    keys.projects,
    keys.me,
  ],
  /**
   * Someone's access on every project changed: every project's grants, which
   * list it where it reaches, the list of them, their report, and what you
   * can see, as it may be your own.
   */
  everyProject: (member: string): QueryKey[] => [['grants'], keys.projects, keys.report(member), keys.me],
  /** Someone let in: the directory. */
  admission: (): QueryKey[] => [keys.directory],
  /**
   * An instance role changed: the directory, their report, and, as it may be
   * your own, what you can see and do.
   */
  role: (member: string): QueryKey[] => [keys.directory, keys.report(member), keys.me, keys.projects],
  /** Someone removed: the directory, their report, and every grant, which removal ends, those on every project too. */
  removal: (member: string): QueryKey[] => [keys.directory, keys.report(member), ['grants'], keys.projects],
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
