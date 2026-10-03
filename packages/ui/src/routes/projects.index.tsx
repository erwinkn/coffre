import { useState } from 'react';
import { useSuspenseQuery } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import { Refusal, useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { useShell } from '../lib/use-shell';
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
  loader: ({ context: { client, queryClient } }) => queryClient.fetchQuery(queries.projects(client)),
  component: ProjectsPage,
});

function ProjectsPage() {
  const { data: result, refetch } = useSuspenseQuery(queries.projects(useCoffre()));
  const { capabilities } = useShell();

  if (!result.ok) {
    return (
      <ClosedDoor
        icon={<AlertTriangle size={18} />}
        title="Projects could not be listed"
        actions={
          result.signedOut ? (
            <Link className="btn" to="/login">
              Sign in again
            </Link>
          ) : (
            // An outage, not a sign-out: signing in again would not help, and asking again might.
            <button type="button" className="btn" onClick={() => void refetch()}>
              Try again
            </button>
          )
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
          <RootAdminOnly capabilities={capabilities}>
            <NewProject />
          </RootAdminOnly>
        }
      />

      {active.length === 0 ? (
        <div className="card">
          <EmptyState title="Nothing here for you yet">
            <ProjectEmptyStateCopy
              capabilities={capabilities}
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
        <section aria-labelledby="archived-projects">
          <h2 className="section-title" id="archived-projects">
            Archived
          </h2>
          <div className="card">
            <ProjectTable projects={archived} />
          </div>
        </section>
      )}
    </>
  );
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
  const secrets = project.secretCount;
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
              {
                affects: affects.places(),
                onSuccess: () => {
                  toast.success(`Project ${slug} created`);
                  setSlug('');
                  setName('');
                  setOpen(false);
                },
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
