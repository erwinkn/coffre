import type { CoffreClient, ConnectedApp, IdentityRow, OffboardingReport, SecretKey, SessionRow } from '@coffre/client';
import { EVERYWHERE, unscoped, type InstanceRole, type Role, type Scope } from '@coffre/core/access';
import type { QueryKey } from '@tanstack/react-query';

import { failureMessage, memberRef, Refusal } from './coffre.ts';
import { projectAccessLabel } from './project-access.ts';
import type { Change, ListShape, Target, Words } from './optimistic.ts';
import { affects, keys } from './queries.ts';
import { applySecretEditBatch, type SecretChange, type SecretDraft, type SecretEditBatchResult } from './secret-edit-batch.ts';
import type { DirectoryPrincipal, GrantRow, ProjectSummary } from '../shared/models.ts';

/**
 * Every change the pages make before the server answers, one per kind, each
 * with the list it shows in (`lib/optimistic.ts`). Issuing a token is not
 * here: only the server can show what it issued.
 */

type Failure = { ok: false; error: string };

/** A list held in a read's `field`, when the read answered. */
function listOf<TItem, TData extends { ok: boolean } | null>(
  queryKey: QueryKey,
  field: string,
  id: (item: TItem) => string,
): ListShape<TData, TItem> {
  return {
    queryKey,
    items: (data) => (data?.ok === true ? ((data as unknown as Record<string, TItem[]>)[field] ?? []) : []),
    withItems: (data, items) => (data?.ok === true ? { ...data, [field]: items } : data),
    id,
  };
}

const ARCHIVING: Words = { pending: 'Archiving…', done: 'archived', failed: 'Not archived.' };
const REVOKING: Words = { pending: 'Revoking…', done: 'revoked', failed: 'Not revoked.' };
const DISCONNECTING: Words = { pending: 'Disconnecting…', done: 'disconnected', failed: 'Not disconnected.' };

const saving = (id: string): Target => ({ id, kind: 'saving' });
const removing = (id: string): Target => ({ id, kind: 'removing' });

// --- access --------------------------------------------------------------------

type Grants = ({ ok: true; grants: GrantRow[] } | Failure);

/** A grant's identity, before the server has given it an id: who, and where; or who, by their instance role. */
export function grantId(grant: Pick<GrantRow, 'principalType' | 'principalId' | 'environmentSlug'> & { scope?: GrantRow['scope'] }): string {
  const member = memberRef(grant.principalType, grant.principalId);
  return grant.scope === 'instance-role' ? `${member}#role` : `${member}@${grant.environmentSlug ?? ''}`;
}

export function grantsList(project: string) {
  return listOf<GrantRow, Grants>(keys.grants(project), 'grants', grantId);
}

/** Where a grant applies, as the API names it: `market`, or `market/prod`. */
export function grantPlace(project: string, environmentSlug: string | null): string {
  return environmentSlug === null ? project : `${project}/${environmentSlug}`;
}

export type GrantVars = {
  principalType: GrantRow['principalType'];
  principalId: string;
  role: string;
  /** How the role is shown while it saves. */
  roleName: string;
  environmentSlug: string | null;
  expiresAt: string | null;
};

/**
 * Give someone a role at one place. Access is declarative, so asking for what
 * they already hold is not an error, whoever asked first: `existed` says so.
 */
export function grantAccess(client: CoffreClient, project: string): Change<Grants, GrantRow, GrantVars, { existed: boolean }> {
  const list = grantsList(project);
  return {
    list,
    label: (vars) => `${vars.roleName} for ${vars.principalId}`,
    targets: (vars) => [saving(grantId(vars))],
    apply: (grants, vars) => {
      const row: GrantRow = {
        id: `pending:${grantId(vars)}`,
        principalType: vars.principalType,
        principalId: vars.principalId,
        role: vars.role,
        roleName: vars.roleName,
        permissions: [],
        scope: vars.environmentSlug === null ? 'project' : 'environment',
        environmentSlug: vars.environmentSlug,
        expiresAt: vars.expiresAt,
      };
      const id = grantId(vars);
      return grants.some((grant) => grantId(grant) === id)
        ? grants.map((grant) => (grantId(grant) === id ? { ...row, id: grant.id } : grant))
        : [...grants, row];
    },
    affects: (vars) => affects.access(project, memberRef(vars.principalType, vars.principalId)),
    run: async (vars) => {
      const place = grantPlace(project, vars.environmentSlug);
      const role = vars.role as Role;
      const { changes } = await client.access.set(memberRef(vars.principalType, vars.principalId), {
        [place]: vars.expiresAt === null ? role : { role, until: vars.expiresAt },
      });
      return { existed: changes[place] === 'unchanged' };
    },
  };
}

export function revokeGrant(client: CoffreClient, project: string): Change<Grants, GrantRow, GrantRow, unknown> {
  return {
    list: grantsList(project),
    label: (grant) => `${projectAccessLabel(grant)} for ${grant.principalId}`,
    targets: (grant) => [removing(grantId(grant))],
    removing: REVOKING,
    affects: (grant) => affects.access(project, memberRef(grant.principalType, grant.principalId)),
    run: (grant) =>
      client.access.set(memberRef(grant.principalType, grant.principalId), {
        [grantPlace(project, grant.environmentSlug)]: null,
      }),
  };
}

// --- the directory -------------------------------------------------------------

type Directory = ({ ok: true; principals: DirectoryPrincipal[] } | Failure);

const principalId = (principal: Pick<DirectoryPrincipal, 'principalType' | 'principalId'>) =>
  memberRef(principal.principalType, principal.principalId);

/** The directory as admins and owners read it: the only ones who change it. */
export const directoryList = listOf<DirectoryPrincipal, Directory>([...keys.directory, { owner: true }], 'principals', principalId);

/** A person's instance role and where it applies, projects by slug: what Add and Change role set. */
export type RoleVars = { role: InstanceRole; scope: Scope };

export type InviteVars = { principalType: DirectoryPrincipal['principalType']; principalId: string } & RoleVars;

/** What the API takes for a role: the scope only when it narrows anything. */
function roleInput({ role, scope }: RoleVars): RoleVars | { role: InstanceRole } {
  return role === 'member' || unscoped(scope) ? { role } : { role, scope };
}

export function invite(client: CoffreClient): Change<Directory, DirectoryPrincipal, InviteVars, void> {
  return {
    list: directoryList,
    label: (vars) => vars.principalId,
    targets: (vars) => [saving(principalId(vars))],
    // Someone already listed is not added twice: the server will say they exist.
    apply: (principals, vars) =>
      principals.some((principal) => principalId(principal) === principalId(vars)) ? principals : [
      ...principals,
      {
        principalType: vars.principalType,
        principalId: vars.principalId,
        instanceRole: vars.principalType === 'user' ? vars.role : 'member',
        scope: vars.principalType === 'user' ? vars.scope : EVERYWHERE,
        isRootAdmin: false,
      },
    ],
    affects: () => affects.admission(),
    run: async (vars) => {
      // Adding is an idempotent PUT that would also set the role of someone
      // already here; this is only for someone new.
      const member = memberRef(vars.principalType, vars.principalId);
      const { members } = await client.members.list();
      if (members.some((entry) => entry.member === member)) throw new Refusal('That principal already exists.');
      await client.members.add(member, vars.principalType === 'user' ? roleInput(vars) : {});
    },
  };
}

export function changeRole(client: CoffreClient): Change<Directory, DirectoryPrincipal, { principalId: string } & RoleVars, unknown> {
  const id = (vars: { principalId: string }) => memberRef('user', vars.principalId);
  return {
    list: directoryList,
    label: (vars) => `the role of ${vars.principalId}`,
    targets: (vars) => [saving(id(vars))],
    apply: (principals, vars) =>
      principals.map((principal) =>
        principalId(principal) === id(vars) ? { ...principal, instanceRole: vars.role, scope: vars.scope } : principal,
      ),
    affects: (vars) => affects.role(id(vars)),
    run: (vars) => client.members.add(id(vars), roleInput(vars)),
  };
}

export function removeMember(client: CoffreClient): Change<Directory, DirectoryPrincipal, DirectoryPrincipal, unknown> {
  return {
    list: directoryList,
    label: (principal) => principal.principalId,
    targets: (principal) => [removing(principalId(principal))],
    affects: (principal) => affects.removal(principalId(principal)),
    run: (principal) => client.members.remove(principalId(principal)),
  };
}

// --- credentials, sessions, linked accounts --------------------------------------

type Credential = { id: string; hint: string };
type Credentials = ({ ok: true; tokens: Credential[] } | Failure) | null;

export function revokeCredential(client: CoffreClient, serviceId: string): Change<Credentials, Credential, Credential, unknown> {
  const member = memberRef('service', serviceId);
  return {
    list: listOf<Credential, Credentials>([...keys.credentials(member), { allowed: true }], 'tokens', (token) => token.id),
    label: (token) => `token ${token.hint}`,
    targets: (token) => [removing(token.id)],
    removing: REVOKING,
    affects: () => affects.credentials(member),
    run: (token) => client.tokens.revoke(member, token.id),
  };
}

type Binding = { id: string; label: string | null };
type Bindings = ({ ok: true; bindings: Binding[] } | Failure) | null;

/** Removing a trust binding: its tombstone, as far as the page goes, is the row leaving. */
export function removeBinding(client: CoffreClient, serviceId: string): Change<Bindings, Binding, Binding, unknown> {
  const member = memberRef('service', serviceId);
  return {
    list: listOf<Binding, Bindings>([...keys.bindings(member), { allowed: true }], 'bindings', (binding) => binding.id),
    label: (binding) => (binding.label === null ? 'the binding' : `binding ${binding.label}`),
    targets: (binding) => [removing(binding.id)],
    removing: { pending: 'Removing…', done: 'removed', failed: 'Not removed.' },
    affects: () => affects.bindings(member),
    run: (binding) => client.bindings.remove(member, binding.id),
  };
}

type Sessions = ({ ok: true; sessions: SessionRow[] } | Failure);

export function endSession(client: CoffreClient): Change<Sessions, SessionRow, SessionRow, unknown> {
  return {
    list: listOf<SessionRow, Sessions>(keys.sessions, 'sessions', (session) => session.id),
    label: () => 'the session',
    targets: (session) => [removing(session.id)],
    removing: { pending: 'Ending…', done: 'ended', failed: 'Not ended.' },
    affects: () => affects.sessions(),
    run: (session) => client.sessions.revoke(session.id),
  };
}

type Apps = ({ ok: true; apps: ConnectedApp[] } | Failure);

export function disconnectApp(client: CoffreClient): Change<Apps, ConnectedApp, ConnectedApp, unknown> {
  return {
    list: listOf<ConnectedApp, Apps>(keys.apps, 'apps', (app) => app.id),
    label: (app) => app.name,
    targets: (app) => [removing(app.id)],
    removing: DISCONNECTING,
    affects: () => affects.apps(),
    run: (app) => client.apps.disconnect(app.id),
  };
}

type Report = { ok: true; report: OffboardingReport | null } | Failure | null;

/** An owner disconnecting someone's app, on their page: their report lists it, as the owner reads it. */
export function disconnectMemberApp(client: CoffreClient, member: string): Change<Report, ConnectedApp, ConnectedApp, unknown> {
  return {
    list: {
      queryKey: [...keys.report(member), { owner: true }],
      items: (data) => (data?.ok === true ? (data.report?.apps ?? []) : []),
      withItems: (data, apps) => (data?.ok === true && data.report !== null ? { ...data, report: { ...data.report, apps } } : data),
      id: (app) => app.id,
    },
    label: (app) => app.name,
    targets: (app) => [removing(app.id)],
    removing: DISCONNECTING,
    // Their report counts what removing them would end; an owner's own apps may be among them.
    affects: () => [keys.report(member), ...affects.apps()],
    run: (app) => client.apps.disconnect(app.id),
  };
}

type Identities = ({ ok: true; identities: IdentityRow[] } | Failure);

export function unlinkIdentity(client: CoffreClient): Change<Identities, IdentityRow, IdentityRow & { label: string }, unknown> {
  return {
    list: listOf<IdentityRow, Identities>(keys.identities, 'identities', (identity) => identity.id),
    label: (identity) => `the ${identity.label} account`,
    targets: (identity) => [removing(identity.id)],
    removing: { pending: 'Unlinking…', done: 'unlinked', failed: 'Not unlinked.' },
    affects: () => affects.identities(),
    run: (identity) => client.identities.unlink(identity.id),
  };
}

// --- projects and environments ---------------------------------------------------

type Projects = ({ ok: true; projects: ProjectSummary[] } | Failure);

export const projectsList = listOf<ProjectSummary, Projects>(keys.projects, 'projects', (project) => project.slug);

export function createProject(client: CoffreClient): Change<Projects, ProjectSummary, { slug: string; name: string }, void> {
  return {
    list: projectsList,
    label: (vars) => `project ${vars.slug}`,
    targets: (vars) => [saving(vars.slug)],
    apply: (projects, vars) => [
      ...projects,
      {
        slug: vars.slug,
        name: vars.name,
        archivedAt: null,
        folder: null,
        // Its maker manages it by their instance role, an Admin's or an Owner's.
        permissions: ['audit.read', 'environment.manage', 'grant.manage', 'project.manage'],
        environments: [],
        secretCount: null,
      },
    ],
    affects: () => affects.places(),
    run: async (vars) => {
      // Creating is an idempotent PUT; a slug that is taken is refused here.
      const { created } = await client.projects.create(vars.slug, { name: vars.name });
      if (!created) throw new Refusal(`A project named "${vars.slug}" already exists.`);
    },
  };
}

type Environment = ProjectSummary['environments'][number];

/** One project's environments, held in the project list. */
/** File a project in a folder, or in none: shown at once, under its new heading. */
export function moveProject(client: CoffreClient): Change<Projects, ProjectSummary, { slug: string; folder: string | null }, unknown> {
  return {
    list: projectsList,
    label: (vars) => `project ${vars.slug}`,
    targets: (vars) => [saving(vars.slug)],
    apply: (projects, vars) => projects.map((project) => (project.slug === vars.slug ? { ...project, folder: vars.folder } : project)),
    affects: () => affects.places(),
    run: (vars) => client.projects.update(vars.slug, { folder: vars.folder }),
  };
}

export function environmentsList(project: string): ListShape<Projects, Environment> {
  const environmentsOf = (data: Projects) =>
    data.ok ? (data.projects.find((entry) => entry.slug === project)?.environments ?? []) : [];
  return {
    queryKey: keys.projects,
    items: environmentsOf,
    withItems: (data, environments) =>
      data.ok
        ? { ...data, projects: data.projects.map((entry) => (entry.slug === project ? { ...entry, environments } : entry)) }
        : data,
    // Under the project's name: the projects list, in the same read, uses bare slugs.
    id: (environment) => environmentId(project, environment.slug),
  };
}

export function environmentId(project: string, environment: string): string {
  return `${project}/${environment}`;
}

/** A new environment, empty or, `from` a sibling, forked: each of its keys copied. */
export function createEnvironment(client: CoffreClient, project: string): Change<Projects, Environment, { slug: string; name: string; from?: string; references?: boolean }, void> {
  return {
    list: environmentsList(project),
    label: (vars) => `environment ${vars.slug}`,
    targets: (vars) => [saving(environmentId(project, vars.slug))],
    apply: (environments, vars) => [
      ...environments,
      { slug: vars.slug, name: vars.name, accessible: false, details: { archivedAt: null, secretCount: 0 } },
    ],
    affects: () => affects.places(),
    run: async (vars) => {
      const { created } = await client.environments.create(`${project}/${vars.slug}`, {
        name: vars.name,
        ...(vars.from === undefined ? {} : { from: vars.from }),
        ...(vars.references === true ? { references: true } : {}),
      });
      if (!created) throw new Refusal(`An environment named "${vars.slug}" already exists.`);
    },
  };
}

export type RenameVars = { from: string; slug: string; name: string };

export function renameEnvironment(client: CoffreClient, project: string): Change<Projects, Environment, RenameVars, unknown> {
  return {
    list: environmentsList(project),
    label: (vars) => `environment ${vars.from}`,
    targets: (vars) =>
      vars.slug === vars.from
        ? [saving(environmentId(project, vars.from))]
        : [saving(environmentId(project, vars.from)), saving(environmentId(project, vars.slug))],
    apply: (environments, vars) =>
      environments.map((environment) =>
        environment.slug === vars.from ? { ...environment, slug: vars.slug, name: vars.name } : environment,
      ),
    affects: () => affects.places(),
    run: (vars) => client.environments.update(`${project}/${vars.from}`, { slug: vars.slug, name: vars.name }),
  };
}

/**
 * Archive an environment or bring it back. Archiving ends every read of it,
 * so it waits for the server, as a removal does; restoring shows at once.
 */
export function archiveEnvironment(client: CoffreClient, project: string): Change<Projects, Environment, { slug: string; archived: boolean }, unknown> {
  const archivedAt = (archived: boolean) => (archived ? new Date().toISOString() : null);
  const withArchived = (environment: Environment, archived: boolean): Environment =>
    environment.details === null
      ? environment
      : { ...environment, details: { ...environment.details, archivedAt: archivedAt(archived) } };
  return {
    list: environmentsList(project),
    label: (vars) => `environment ${vars.slug}`,
    targets: (vars) => [
      vars.archived ? removing(environmentId(project, vars.slug)) : saving(environmentId(project, vars.slug)),
    ],
    removing: ARCHIVING,
    apply: (environments, vars) =>
      vars.archived
        ? environments
        : environments.map((environment) => (environment.slug === vars.slug ? withArchived(environment, false) : environment)),
    confirmed: (environments, _vars, archived) =>
      environments.map((environment) =>
        archived.has(environmentId(project, environment.slug)) ? withArchived(environment, true) : environment,
      ),
    affects: () => affects.places(),
    run: (vars) => client.environments.update(`${project}/${vars.slug}`, { archived: vars.archived }),
  };
}

// --- secrets ---------------------------------------------------------------------

type Secrets = ({ ok: true; keys: SecretKey[] } | Failure);

export function secretsList(place: { project: string; environment: string }) {
  return listOf<SecretKey, Secrets>(keys.secrets(place), 'keys', (entry) => entry.key);
}

/** A save that stopped partway: what is left to retry, as the ledger holds it. */
export class UnsavedEdits extends Refusal {
  readonly outcome: SecretEditBatchResult;

  constructor(outcome: SecretEditBatchResult) {
    const message = outcome.error instanceof Error ? outcome.error.message : failureMessage(outcome.error);
    // Only renames can have landed before a failure: the patch is all or nothing.
    super(
      outcome.applied === 0
        ? message
        : `${message} The renames before it were saved; nothing else was, and the rest is ready to retry.`,
    );
    this.outcome = outcome;
  }
}

export type SaveSecretsVars = {
  active: SecretKey[];
  drafts: SecretDraft[];
  changes: Record<string, SecretChange>;
};

/**
 * Write the ledger's pending edits, as `applySecretEditBatch` does: renames
 * one by one, then the rest as one patch that lands whole or not at all.
 * New and edited secrets show at once; archived ones stay, struck through,
 * until the server confirms.
 */
export function saveSecrets(
  client: CoffreClient,
  place: { project: string; environment: string },
  /** Who is saving, shown as the author until the list is read back. */
  author: string | null,
): Change<Secrets, SecretKey, SaveSecretsVars, number> {
  const path = `${place.project}/${place.environment}`;
  const edits = (vars: SaveSecretsVars) =>
    vars.active.flatMap((entry) => {
      const change = vars.changes[entry.key];
      return change === undefined ? [] : [{ entry, change }];
    });
  return {
    list: secretsList(place),
    label: (vars) => {
      const named = [...vars.drafts.map((draft) => draft.key.trim()), ...edits(vars).map(({ entry }) => entry.key)];
      return named.length === 1 ? named[0]! : `${named.length} changes`;
    },
    targets: (vars) => [
      ...vars.drafts.map((draft) => saving(draft.key.trim())),
      ...edits(vars).flatMap(({ entry, change }) =>
        change.archived
          ? [removing(entry.key)]
          : change.key.trim() === entry.key
            ? [saving(entry.key)]
            : [saving(entry.key), saving(change.key.trim())],
      ),
    ],
    removing: ARCHIVING,
    apply: (entries, vars) => {
      const now = new Date().toISOString();
      const bumped = (entry: SecretKey | undefined, key: string): SecretKey => ({
        key,
        // A rename keeps its folder; a new secret is in none.
        folder: entry?.folder ?? null,
        // A value of its own: no longer a reference.
        reference: null,
        archived: false,
        version: (entry?.version ?? 0) + 1,
        updatedAt: now,
        updatedBy: author,
      });
      let next = entries.map((entry) => {
        const change = vars.changes[entry.key];
        if (change === undefined || change.archived) return entry;
        const key = change.key.trim();
        return change.value === null ? { ...entry, key } : bumped(entry, key);
      });
      for (const draft of vars.drafts) {
        const key = draft.key.trim();
        const existing = next.find((entry) => entry.key === key);
        next = existing === undefined ? [bumped(undefined, key), ...next] : next.map((entry) => (entry.key === key ? bumped(entry, key) : entry));
      }
      return next;
    },
    confirmed: (entries, _vars, archived) =>
      entries.map((entry) => (archived.has(entry.key) ? { ...entry, archived: true } : entry)),
    affects: () => affects.secrets(place),
    run: async (vars) => {
      const outcome = await applySecretEditBatch({
        active: vars.active,
        drafts: vars.drafts,
        changes: vars.changes,
        operations: {
          rename: async (key, nextKey) => {
            try {
              await client.secrets.rename(`${path}/${key}`, nextKey);
            } catch (error) {
              // A refused rename names the key it stopped at.
              throw new Refusal(`${key}: ${failureMessage(error)}`);
            }
          },
          write: async (patch) => {
            try {
              await client.secrets.set(path, patch);
            } catch (error) {
              throw new Refusal(failureMessage(error));
            }
          },
        },
      });
      if (outcome.error !== null) throw new UnsavedEdits(outcome);
      return outcome.applied;
    },
  };
}

/** File a secret in a folder, or in none: shown at once, under its new heading. */
export function moveSecret(
  client: CoffreClient,
  place: { project: string; environment: string },
): Change<Secrets, SecretKey, { key: string; folder: string | null }, unknown> {
  return {
    list: secretsList(place),
    label: (vars) => vars.key,
    targets: (vars) => [saving(vars.key)],
    apply: (entries, vars) => entries.map((entry) => (entry.key === vars.key ? { ...entry, folder: vars.folder } : entry)),
    affects: () => affects.secrets(place),
    run: (vars) => client.secrets.update(`${place.project}/${place.environment}/${vars.key}`, { folder: vars.folder }),
  };
}

/** Restore an archived secret, from the Archived list. */
export function restoreSecret(
  client: CoffreClient,
  place: { project: string; environment: string },
): Change<Secrets, SecretKey, { key: string }, unknown> {
  return {
    list: secretsList(place),
    label: (vars) => vars.key,
    targets: (vars) => [saving(vars.key)],
    apply: (entries, vars) => entries.map((entry) => (entry.key === vars.key ? { ...entry, archived: false } : entry)),
    affects: () => affects.secrets(place),
    run: (vars) => client.secrets.update(`${place.project}/${place.environment}/${vars.key}`, { archived: false }),
  };
}

/** Archive one secret, as Undo after a restore does: it stays, struck through, until confirmed. */
export function archiveSecret(
  client: CoffreClient,
  place: { project: string; environment: string },
): Change<Secrets, SecretKey, { key: string }, unknown> {
  return {
    list: secretsList(place),
    label: (vars) => vars.key,
    targets: (vars) => [removing(vars.key)],
    removing: ARCHIVING,
    confirmed: (entries, _vars, archived) =>
      entries.map((entry) => (archived.has(entry.key) ? { ...entry, archived: true } : entry)),
    affects: () => affects.secrets(place),
    run: (vars) => client.secrets.update(`${place.project}/${place.environment}/${vars.key}`, { archived: true }),
  };
}
