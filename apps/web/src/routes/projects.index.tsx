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
import { ClosedDoor, PageHeader, Section } from '../components/page';
import { ArrowRight, Plus } from '../components/icons';
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
        eyebrow="Projects"
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
        eyebrow="Index"
        title="Projects"
        actions={
          <RootAdminOnly capabilities={result.capabilities}>
            <NewProject />
          </RootAdminOnly>
        }
        meta={
          <>
            <span>
              <strong>{active.length}</strong> project{active.length === 1 ? '' : 's'} visible
              to you
            </span>
            {secretTotal > 0 && (
              <span>
                <strong>{secretTotal}</strong> secret{secretTotal === 1 ? '' : 's'} across the
                environments you can open
              </span>
            )}
          </>
        }
      />

      {active.length === 0 ? (
        <EmptyState title="Nothing here for you yet">
          <ProjectEmptyStateCopy
            capabilities={result.capabilities}
            hasArchivedProjects={archived.length > 0}
          />
        </EmptyState>
      ) : (
        <ul className="index">
          {active.map((project) => (
            <ProjectRow key={project.slug} project={project} />
          ))}
        </ul>
      )}

      {archived.length > 0 && (
        <Section
          labelledBy="archived-projects"
          title="Archived"
          note="Hidden from listings and refused on read. Every row is still present, and the audit trail over them still verifies."
        >
          <ul className="index">
            {archived.map((project) => (
              <ProjectRow key={project.slug} project={project} />
            ))}
          </ul>
        </Section>
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

function ProjectRow({ project }: { project: ProjectSummary }) {
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
  const total = countSecrets(project);
  const isArchived = project.archivedAt !== null;

  return (
    <li className={`index-row${isArchived ? ' is-muted' : ''}`}>
      <div className="index-main">
        <Link
          className="index-title index-stretch"
          to="/projects/$project"
          params={{ project: project.slug }}
        >
          {project.slug}
        </Link>
        <span className="index-sub">{project.name}</span>
      </div>

      <div className="index-side">
        {!isArchived && listedEnvironments.length > 0 && (
          <div className="env-links" aria-label={`Environments in ${project.slug}`}>
            {listedEnvironments.map((environment) =>
              isActiveAccessibleEnvironment(environment) ? (
                <Link
                  key={environment.slug}
                  className="env-link"
                  to="/projects/$project/$environment"
                  params={{ project: project.slug, environment: environment.slug }}
                >
                  {environment.slug}
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
          </div>
        )}
        {isArchived && <span className="tag tag-red">archived</span>}
        {counted && !isArchived && (
          <span className="num nowrap">
            {total} secret{total === 1 ? '' : 's'}
          </span>
        )}
        <ArrowRight size={16} className="index-arrow" />
      </div>
    </li>
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
            <span className="caps">Slug</span>
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
            <span className="caps">Display name</span>
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
