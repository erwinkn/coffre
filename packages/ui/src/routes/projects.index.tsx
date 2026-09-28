import { useState } from 'react';
import { createFileRoute, Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import type { CoffreClient } from '../../../../packages/client/src/index.ts';
import { deriveUiCapabilities } from '../lib/capabilities';
import { Refusal, uiResult, useCoffre } from '../lib/coffre';
import { useAction } from '../lib/use-action';
import type { ProjectSummary } from '../shared/models';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { slugProblem } from '../lib/validation';
import { EmptyState, ErrorLine, Modal, Spinner } from '../components/ui';
import { ClosedDoor, PageHeader } from '../components/page';
import { Tile } from '../components/tile';
import { AlertTriangle, Folder, Hash, Layers, Plus } from '../components/icons';
import {
  ProjectEmptyStateCopy,
  RootAdminOnly,
} from '../components/affordances';

export const Route = createFileRoute('/projects/')({
  loader: async ({ context: { client } }) => {
    const result = await uiResult(async () => {
      const [me, { projects }] = await Promise.all([client.me(), client.projects.list()]);
      return { projects, capabilities: deriveUiCapabilities(me, projects) };
    });
    return { result, secrets: result.ok ? await countSecrets(client, result.projects) : {} };
  },
  component: ProjectsPage,
});

/**
 * Distinct secret names per project, across the environments you can open.
 *
 * The project summary only counts secrets per environment, and the same key
 * in dev and prod is one secret, not two. So this lists the keys of every
 * environment you can open and counts the names. Listing keys reads no value
 * and writes no audit row. Environments you cannot open are not asked: the
 * refusal would be audited.
 *
 * A project whose keys could not all be listed gets no count rather than a
 * short one.
 */
async function countSecrets(
  client: CoffreClient,
  projects: ProjectSummary[],
): Promise<Record<string, number | null>> {
  const counts = await Promise.all(
    projects
      .filter((project) => project.archivedAt === null)
      .map(async (project) => {
        const environments = project.environments.filter(isActiveAccessibleEnvironment);
        if (environments.length === 0) return [project.slug, null] as const;
        const lists = await Promise.all(
          environments.map((environment) => uiResult(() => client.secrets.list(`${project.slug}/${environment.slug}`))),
        );
        const names = new Set<string>();
        for (const list of lists) {
          if (!list.ok) return [project.slug, null] as const;
          for (const key of list.keys) if (!key.archived) names.add(key.key);
        }
        return [project.slug, names.size] as const;
      }),
  );
  return Object.fromEntries(counts);
}

function ProjectsPage() {
  const { result, secrets } = Route.useLoaderData();

  if (!result.ok) {
    return (
      <ClosedDoor
        icon={<AlertTriangle size={18} />}
        title="Projects could not be listed"
        actions={
          <Link className="btn" to="/login">
            Sign in again
          </Link>
        }
      >
        {result.error}
      </ClosedDoor>
    );
  }

  const active = result.projects.filter((project) => project.archivedAt === null);
  const archived = result.projects.filter((project) => project.archivedAt !== null);

  return (
    <>
      <PageHeader
        title="Projects"
        actions={
          <RootAdminOnly capabilities={result.capabilities}>
            <NewProject />
          </RootAdminOnly>
        }
      />

      {active.length === 0 ? (
        <div className="card">
          <EmptyState title="Nothing here for you yet">
            <ProjectEmptyStateCopy
              capabilities={result.capabilities}
              hasArchivedProjects={archived.length > 0}
            />
          </EmptyState>
        </div>
      ) : (
        <section className="card" aria-label="Projects">
          <ProjectTable projects={active} secrets={secrets} />
        </section>
      )}

      {archived.length > 0 && (
        <section aria-labelledby="archived-projects">
          <h2 className="section-title" id="archived-projects">
            Archived
          </h2>
          <div className="card">
            <ProjectTable projects={archived} secrets={secrets} />
          </div>
        </section>
      )}
    </>
  );
}

function ProjectTable({
  projects,
  secrets,
}: {
  projects: ProjectSummary[];
  secrets: Record<string, number | null>;
}) {
  return (
    <div className="dt-wrap">
      <table className="dt projects stacks">
        <thead>
          <tr>
            <th className="n">#</th>
            <th className="col-project">
              <span className="th">
                <Folder size={14} />
                Project
              </span>
            </th>
            <th>
              <span className="th">
                <Layers size={14} />
                Environments
              </span>
            </th>
            <th className="col-shrink col-secrets">
              <span className="th">
                <Hash size={14} />
                Secrets
              </span>
            </th>
          </tr>
        </thead>
        <tbody>
          {projects.map((project, index) => (
            <ProjectRow
              key={project.slug}
              number={index + 1}
              project={project}
              secrets={secrets[project.slug] ?? null}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * One project. The whole row opens it; the environment links inside it sit
 * above that and go straight to the environment.
 */
function ProjectRow({
  number,
  project,
  secrets,
}: {
  number: number;
  project: ProjectSummary;
  secrets: number | null;
}) {
  const isArchived = project.archivedAt !== null;
  const listedEnvironments = project.environments.filter(
    (environment) =>
      environment.details === null || environment.details.archivedAt === null,
  );

  return (
    <tr className="row-link">
      <td className="n">{number}</td>
      <td className="col-project">
        <span className="cell-project">
          <Tile name={project.slug} />
          <span className="cell-stack">
            <Link
              className="cell-link stretch"
              to="/projects/$project"
              params={{ project: project.slug }}
            >
              {project.name}
            </Link>
            <small className="mono">{project.slug}</small>
          </span>
        </span>
      </td>
      <td className="col-envs" data-label="Environments">
        {isArchived || listedEnvironments.length === 0 ? (
          <span className="cell-muted">
            {listedEnvironments.length === 0
              ? 'No environments yet'
              : `${listedEnvironments.length} environment${listedEnvironments.length === 1 ? '' : 's'}`}
          </span>
        ) : (
          <span className="env-links" aria-label={`Environments in ${project.slug}`}>
            {listedEnvironments.map((environment) =>
              isActiveAccessibleEnvironment(environment) ? (
                <Link
                  key={environment.slug}
                  className="env-link"
                  to="/projects/$project/$environment"
                  params={{ project: project.slug, environment: environment.slug }}
                >
                  {environment.slug}
                  <span className="count">{environment.details.secretCount}</span>
                </Link>
              ) : (
                <span
                  key={environment.slug}
                  className="env-link"
                  title="You can see this environment exists, but not open it"
                >
                  {environment.slug}
                </span>
              ),
            )}
          </span>
        )}
      </td>
      <td className="col-secrets num nowrap">
        {secrets !== null && !isArchived ? (
          <>
            {secrets}
            <span className="narrow-only"> secret{secrets === 1 ? '' : 's'}</span>
          </>
        ) : (
          <span className="cell-muted wide-only">—</span>
        )}
      </td>
    </tr>
  );
}

function NewProject() {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [open, setOpen] = useState(false);
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const slugError = slug === '' ? null : slugProblem(slug);

  function close() {
    setOpen(false);
    setError(null);
  }

  return (
    <>
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        <Plus size={14} />
        New project
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title="New project"
        description="A project holds environments, and access is granted on it or on one of its environments. You become its owner."
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            run(
              async () => {
                // Creating is an idempotent PUT; the form reports a slug that is taken.
                const { created } = await coffre.projects.create(slug, { name });
                if (!created) throw new Refusal(`A project named "${slug}" already exists.`);
              },
              () => {
                toast.success(`Project ${slug} created`);
                setSlug('');
                setName('');
                setOpen(false);
              },
            );
          }}
        >
          <label className="field">
            <span className="label">Slug</span>
            <input
              className="input input-mono"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              placeholder="market"
              value={slug}
              aria-invalid={slugError !== null}
              aria-describedby="new-project-slug-hint"
              onChange={(event) => setSlug(event.target.value)}
            />
            <span className={`hint${slugError !== null ? ' edit-note-error' : ''}`} id="new-project-slug-hint">
              {slugError ?? 'Used in paths, as in market/prod. Renaming it later is safe.'}
            </span>
          </label>

          <label className="field">
            <span className="label">Display name</span>
            <input
              className="input"
              placeholder="Market data platform"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>

          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || slug === '' || slugError !== null || name.trim() === ''}
            >
              {pending && <Spinner />}
              Create project
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
