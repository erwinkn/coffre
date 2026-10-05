import { useState } from 'react';
import { useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { createProject, projectsList } from '../lib/changes';
import { useCoffre } from '../lib/coffre';
import type { ItemStatus } from '../lib/optimistic';
import { queries } from '../lib/queries';
import { useChange, useChangeStatus } from '../lib/use-change';
import { useShell } from '../lib/use-shell';
import type { ProjectSummary } from '../shared/models';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import { slugProblem } from '../lib/validation';
import { RowFailure, RowPending, rowClass } from '../components/row-state';
import { EmptyState, Modal } from '../components/ui';
import { ClosedDoor, PageHeader } from '../components/page';
import { Tile } from '../components/tile';
import { AlertTriangle, Folder, Hash, Layers, Plus } from '../components/icons';
import {
  ProjectEmptyStateCopy,
  RootAdminOnly,
} from '../components/affordances';
import { ReachedBy, reaching, useEveryProject } from '../components/every-project';

export function ProjectsPage() {
  const { data: result, refetch } = useSuspenseQuery(queries.projects(useCoffre()));
  const { capabilities } = useShell();
  const { failedAdds } = useChangeStatus(projectsList.queryKey);
  const refusedProjects = result.ok ? failedAdds(result.projects.map((project) => project.slug)) : [];

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
      <PageHeader title="Projects" />

      {active.length === 0 && refusedProjects.length === 0 ? (
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
          <ProjectTable projects={active} refused />
        </section>
      )}

      <RootAdminOnly capabilities={capabilities}>
        <div className="table-actions">
          <NewProject />
        </div>
      </RootAdminOnly>

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

function ProjectTable({ projects, refused = false }: { projects: ProjectSummary[]; refused?: boolean }) {
  const { status, failedAdds, dismiss } = useChangeStatus(projectsList.queryKey);
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
              status={status(project.slug)}
              onDismiss={dismiss}
            />
          ))}
          {refused &&
            failedAdds<{ slug: string }>(projects.map((project) => project.slug)).map(
              ({ mutationId, vars, status: failed }) => (
                <RowFailure key={mutationId} status={failed} columns={4} onDismiss={() => dismiss(mutationId)}>
                  Project {vars.slug} was not created.
                </RowFailure>
              ),
            )}
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
  status,
  onDismiss,
}: {
  number: number;
  project: ProjectSummary;
  status: ItemStatus;
  onDismiss: (mutationId: number) => void;
}) {
  const secrets = project.secretCount;
  // A project on its way has no page yet.
  const pending = status.state === 'pending';
  const isArchived = project.archivedAt !== null;
  const listedEnvironments = project.environments.filter(
    (environment) =>
      environment.details === null || environment.details.archivedAt === null,
  );

  return (
    <>
      <tr className={`row-link ${rowClass(status)}`}>
        <td className="n">{number}</td>
        <td className="col-project">
          <span className="cell-project">
            <Tile name={project.slug} />
            <span className="cell-stack">
              {pending ? (
                <span>{project.name}</span>
              ) : (
                <Link
                  className="cell-link stretch"
                  to="/projects/$project"
                  params={{ project: project.slug }}
                >
                  {project.name}
                </Link>
              )}
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
          {pending ? (
            <RowPending status={status} />
          ) : secrets !== null && !isArchived ? (
            <>
              {secrets}
              <span className="narrow-only"> secret{secrets === 1 ? '' : 's'}</span>
            </>
          ) : (
            <span className="cell-muted wide-only">—</span>
          )}
        </td>
      </tr>
      <RowFailure
        status={status}
        columns={4}
        onDismiss={() => status.state === 'failed' && onDismiss(status.mutationId)}
      />
    </>
  );
}

function NewProject() {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [open, setOpen] = useState(false);
  const create = useChange(createProject(useCoffre()));
  const slugError = slug === '' ? null : slugProblem(slug);
  const reachedBy = reaching(useEveryProject(), null);

  function close() {
    setOpen(false);
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
            // Listed at once, as saving; the list says if the server refuses.
            create({ slug, name: name.trim() });
            setSlug('');
            setName('');
            close();
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

          <ReachedBy grants={reachedBy} lead="As soon as it exists, it is reached by" />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={slug === '' || slugError !== null || name.trim() === ''}
            >
              Create project
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
