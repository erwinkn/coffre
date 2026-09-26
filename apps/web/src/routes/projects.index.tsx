import { useState } from 'react';
import { createFileRoute, Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import { createProject, listProjects } from '../server-functions/projects';
import { useAction } from '../lib/use-action';
import type { ProjectSummary } from '../shared/models';
import {
  hasEnvironmentDetails,
  isActiveAccessibleEnvironment,
} from '../lib/project-environments';
import { slugProblem } from '../lib/validation';
import { EmptyState, ErrorLine, Modal, Spinner } from '../components/ui';
import { Card, ClosedDoor, PageHeader } from '../components/page';
import { Tile } from '../components/tile';
import { AlertTriangle, Folder, Hash, Layers, Plus } from '../components/icons';
import {
  ProjectEmptyStateCopy,
  RootAdminOnly,
} from '../components/affordances';

export const Route = createFileRoute('/projects/')({
  loader: () => listProjects(),
  component: ProjectsPage,
});

function ProjectsPage() {
  const result = Route.useLoaderData();

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
  const secretTotal = active.reduce((sum, project) => sum + countSecrets(project), 0);

  return (
    <>
      <PageHeader
        title="Projects"
        meta={
          <>
            <span>
              <strong>{active.length}</strong> project{active.length === 1 ? '' : 's'} visible
              to you
            </span>
            {secretTotal > 0 && (
              <span>
                <strong>{secretTotal}</strong> secret{secretTotal === 1 ? '' : 's'} in the
                environments you can open
              </span>
            )}
          </>
        }
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
          <ProjectTable projects={active} />
        </section>
      )}

      {archived.length > 0 && (
        <div style={{ marginTop: '2rem' }}>
          <Card
            labelledBy="archived-projects"
            title="Archived"
            description="Hidden from listings and refused on read. Every row is still present, and the audit trail over them still verifies."
          >
            <ProjectTable projects={archived} />
          </Card>
        </div>
      )}
    </>
  );
}

function countSecrets(project: ProjectSummary): number {
  return project.environments
    .filter(hasEnvironmentDetails)
    .filter((environment) => environment.details.archivedAt === null)
    .reduce((sum, environment) => sum + (environment.details.secretCount ?? 0), 0);
}

function ProjectTable({ projects }: { projects: ProjectSummary[] }) {
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
            <th className="col-name">Name</th>
            <th>
              <span className="th">
                <Layers size={14} />
                Environments
              </span>
            </th>
            <th className="col-shrink">
              <span className="th">
                <Hash size={14} />
                Secrets
              </span>
            </th>
          </tr>
        </thead>
        <tbody>
          {projects.map((project, index) => (
            <ProjectRow key={project.slug} number={index + 1} project={project} />
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
function ProjectRow({ number, project }: { number: number; project: ProjectSummary }) {
  const isArchived = project.archivedAt !== null;
  const listedEnvironments = project.environments.filter(
    (environment) =>
      environment.details === null || environment.details.archivedAt === null,
  );
  const counted = project.environments
    .filter(hasEnvironmentDetails)
    .some(
      (environment) =>
        environment.details.archivedAt === null && environment.details.secretCount !== null,
    );

  return (
    <tr className="row-link">
      <td className="n">{number}</td>
      <td data-label="Project">
        <span className="cell-project">
          <Tile name={project.slug} />
          <Link
            className="cell-link stretch"
            to="/projects/$project"
            params={{ project: project.slug }}
          >
            {project.slug}
          </Link>
        </span>
      </td>
      <td className="cell-muted" data-label="Name">
        {project.name}
      </td>
      <td data-label="Environments">
        {isArchived || listedEnvironments.length === 0 ? (
          <span className="cell-muted">
            {listedEnvironments.length === 0 ? 'None yet' : listedEnvironments.length}
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
      <td className="num nowrap" data-label="Secrets">
        {counted && !isArchived ? countSecrets(project) : <span className="cell-muted">—</span>}
      </td>
    </tr>
  );
}

function NewProject() {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [open, setOpen] = useState(false);
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
              () => createProject({ data: { slug, name } }),
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
