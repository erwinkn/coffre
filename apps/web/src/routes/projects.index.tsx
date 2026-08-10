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
import { EmptyState, ErrorLine, Modal, Notice, Spinner } from '../components/ui';
import { Folder, Inbox, Layers, Plus } from '../components/icons';
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
      <>
        <div className="page-head">
          <h1>Projects</h1>
        </div>
        <Notice tone="bad">
          {result.error} <Link to="/login">Sign in</Link> to continue.
        </Notice>
      </>
    );
  }

  const active = result.projects.filter((project) => project.archivedAt === null);
  const archived = result.projects.filter((project) => project.archivedAt !== null);

  return (
    <>
      <div className="page-head">
        <h1>Projects</h1>
      </div>

      <div className="card">
        {active.length === 0 ? (
          <EmptyState icon={<Inbox size={26} />} title="Nothing granted yet">
            <ProjectEmptyStateCopy
              capabilities={result.capabilities}
              hasArchivedProjects={archived.length > 0}
            />
          </EmptyState>
        ) : (
          active.map((project) => <ProjectRow key={project.slug} project={project} />)
        )}
      </div>

      <RootAdminOnly capabilities={result.capabilities}>
        <NewProject />
      </RootAdminOnly>

      {archived.length > 0 && (
        <section className="section">
          <div className="section-head">
            <div>
              <h2>Archived</h2>
              <p className="sub">
                Hidden from listings and refused on read. Every row is still present and the
                audit trail over them is still valid.
              </p>
            </div>
          </div>
          <div className="card">
            {archived.map((project) => (
              <ProjectRow key={project.slug} project={project} />
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function ProjectRow({ project }: { project: ProjectSummary }) {
  const listedEnvironments = project.environments.filter(
    (environment) =>
      environment.details === null || environment.details.archivedAt === null,
  );
  const countedEnvironments = project.environments
    .filter(hasEnvironmentDetails)
    .filter(
      (environment) =>
        environment.details.archivedAt === null
        && environment.details.secretCount !== null,
    );
  const total = countedEnvironments.reduce(
    (sum, environment) => sum + (environment.details.secretCount ?? 0),
    0,
  );

  return (
    <div className="row row-interactive">
      <div className="row-title">
        <Folder size={15} style={{ color: 'var(--ink-3)', flex: 'none' }} />
        <Link className="row-key" to="/projects/$project" params={{ project: project.slug }}>
          {project.slug}
        </Link>
        <span className="meta">{project.name}</span>
      </div>

      {countedEnvironments.length > 0 && (
        <span className="meta numeric" style={{ flex: 'none' }}>
          {total} secret{total === 1 ? '' : 's'}
        </span>
      )}

      <div className="row-actions">
        {listedEnvironments.map((environment) =>
          isActiveAccessibleEnvironment(environment) ? (
            <Link
              key={environment.slug}
              className="btn btn-sm"
              to="/projects/$project/$environment"
              params={{ project: project.slug, environment: environment.slug }}
            >
              <Layers size={13} />
              {environment.slug}
            </Link>
          ) : (
            <span key={environment.slug} className="meta mono">
              {environment.slug}
            </span>
          ),
        )}
      </div>
    </div>
  );
}

function NewProject() {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [open, setOpen] = useState(false);
  const { pending, error, run } = useAction();

  return (
    <>
      <div style={{ marginTop: 'var(--space-5)' }}>
        <button className="btn" onClick={() => setOpen(true)}>
          <Plus size={14} />
          New project
        </button>
      </div>

      <Modal
        open={open}
        onOpenChange={setOpen}
        title="New project"
        description="Create a project, then add its environments and access."
      >
        <form
          className="dialog-form stack"
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
              className="input"
              autoFocus
              placeholder="market"
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
            />
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
            <button className="btn" type="button" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || slug === '' || name === ''}
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
