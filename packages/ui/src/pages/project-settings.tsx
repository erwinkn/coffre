import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from '@tanstack/react-router';
import { useShell } from '../lib/use-shell';
import { toast } from 'sonner';
import { useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import type { ProjectSummary } from '../shared/models';
import { ArchiveBlocked, archiveBlockers } from '../components/references';
import { folderProblem, slugProblem } from '../lib/validation';
import { ConfirmDialog, ErrorLine, Spinner } from '../components/ui';
import { Card } from '../components/page';
import { DeletePlaceDialog } from '../components/delete-place';
import { Archive, RotateBack, Trash } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import { useProject } from '../lib/project-page';
import type { projectSettings } from '../options';

const Route = pageRoute<typeof projectSettings>();

/** A project's settings: its slug, name and folder, and archiving or deleting it. */
export function ProjectSettingsPage() {
  const { project } = useProject(Route.useParams().project);
  return (
    <>
      <GeneralSettings project={project} />
      <DangerZone project={project} />
    </>
  );
}

/**
 * The project's name and slug, as a form on the page.
 *
 * Renaming changes paths other people and scripts use, so it is laid out in
 * plain sight with what it does and does not affect, rather than tucked
 * behind a menu.
 */
function GeneralSettings({ project }: { project: ProjectSummary }) {
  const router = useRouter();
  const [slug, setSlug] = useState(project.slug);
  const [name, setName] = useState(project.name);
  const [folder, setFolder] = useState(project.folder ?? '');
  const coffre = useCoffre();
  const { pending, error, run } = useAction();
  const slugError = slug === '' ? null : slugProblem(slug);
  const folderError = folderProblem(folder);
  const nextFolder = folder === '' ? null : folder;
  const dirty = slug !== project.slug || name.trim() !== project.name || nextFolder !== project.folder;

  // Follow a rename made elsewhere (another tab, another person) rather than
  // keep offering the old values back.
  useEffect(() => {
    setSlug(project.slug);
    setName(project.name);
    setFolder(project.folder ?? '');
  }, [project.slug, project.name, project.folder]);

  // Two fields and their Save need no card: the tab already says what they are.
  return (
    <section className="plain-form" aria-label="General">
      <form
        onSubmit={(event) => {
          event.preventDefault();
          run(
            () => coffre.projects.update(project.slug, {
              slug,
              name,
              // Only when it moves: a move is logged, as `project.move`.
              ...(nextFolder === project.folder ? {} : { folder: nextFolder }),
            }),
            {
              affects: affects.places(),
              onSuccess: async () => {
                toast.success(slug === project.slug && name.trim() === project.name ? 'Project moved' : 'Project saved');
                // The slug is part of the URL, so a rename has to navigate.
                if (slug !== project.slug) {
                  await router.navigate({ to: '/projects/$project/settings', params: { project: slug } });
                }
              },
            },
          );
        }}
      >
        <div className="form-row">
          <label className="field">
            <span className="label">Slug</span>
            <input
              className="input input-mono"
              spellCheck={false}
              value={slug}
              aria-invalid={slugError !== null}
              onChange={(event) => setSlug(event.target.value)}
            />
            <span className={`hint${slugError !== null ? ' edit-note-error' : ''}`}>
              {slugError ?? 'Scripts that name the old slug will need the new one.'}
            </span>
          </label>
          <label className="field">
            <span className="label">Display name</span>
            <input
              className="input"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label className="field">
            <span className="label">Folder</span>
            <input
              className="input"
              spellCheck={false}
              placeholder="No folder"
              value={folder}
              aria-invalid={folderError !== null}
              onChange={(event) => setFolder(event.target.value)}
            />
            <span className={`hint${folderError !== null ? ' edit-note-error' : ''}`}>
              {folderError ?? 'Where Projects lists it. Changes nothing else.'}
            </span>
          </label>
        </div>
        <div className="form-actions">
          <button
            className="btn btn-primary"
            type="submit"
            disabled={!dirty || pending || slug === '' || slugError !== null || name.trim() === '' || folderError !== null}
          >
            {pending && <Spinner />}
            Save
          </button>
          {error !== null && (
            <span className="hint">
              <ErrorLine error={error} />
            </span>
          )}
        </div>
      </form>
    </section>
  );
}

function DangerZone({ project }: { project: ProjectSummary }) {
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const coffre = useCoffre();
  const router = useRouter();
  const { instanceRole } = useShell();
  const { pending, error, run } = useAction();
  const isArchived = project.archivedAt !== null;
  // What archiving it would stop, asked once the dialog opens (D41); Archive waits for the answer.
  const archiving = confirming && !isArchived;
  const { data: lent } = useQuery({ ...queries.references(coffre, project.slug), enabled: archiving });
  const blockers = archiving && lent?.ok === true ? archiveBlockers(project.slug, lent.references) : [];
  const asking = archiving && lent === undefined;
  // Deleting is for instance owners, and only once the project is archived.
  const canDelete = isArchived && instanceRole !== 'user';

  return (
    <Card labelledBy="danger-zone" title="Danger zone" tone="danger">
      <div className="card-row">
        <div>
          <p className="card-row-title">{isArchived ? 'Restore project' : 'Archive project'}</p>
          {/* Restoring needs no warning: the button says what it does. */}
          {!isArchived && (
            <p className="card-row-desc">Stops every read until restored; nothing is deleted.</p>
          )}
          {error !== null && (
            <div style={{ marginTop: '0.5rem' }}>
              <ErrorLine error={error} />
            </div>
          )}
        </div>
        <button
          className={`btn ${isArchived ? '' : 'btn-danger-outline'}`}
          onClick={() => setConfirming(true)}
          disabled={pending}
        >
          {pending ? (
            <Spinner />
          ) : isArchived ? (
            <RotateBack size={14} />
          ) : (
            <Archive size={14} />
          )}
          {isArchived ? `Restore ${project.name}` : `Archive ${project.name}…`}
        </button>
      </div>

      {canDelete && (
        <div className="card-row">
          <div>
            <p className="card-row-title">Delete project</p>
            <p className="card-row-desc">
              Erases its values for good and frees its name; only names stay, for the audit log.
            </p>
          </div>
          <button className="btn btn-danger-outline" onClick={() => setDeleting(true)}>
            <Trash size={14} />
            {`Delete ${project.name}…`}
          </button>
        </div>
      )}
      {canDelete && (
        <DeletePlaceDialog
          path={project.slug}
          open={deleting}
          onOpenChange={setDeleting}
          onDeleted={async () => {
            toast.success(`${project.slug} deleted, and its name is free`);
            await router.navigate({ to: '/projects' });
          }}
        />
      )}

      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={
          <>
            {isArchived ? 'Restore' : 'Archive'} <span className="mono">{project.slug}</span>?
          </>
        }
        body={
          isArchived ? (
            <>
              The project reappears in listings and its environments start serving reads
              again, for everyone who holds a grant on it.
            </>
          ) : (
            <>
              Every environment in <span className="mono">{project.slug}</span> stops serving
              reads, including to machine callers already running. Nothing is deleted: values,
              versions and the audit trail over them stay intact, and you can restore it here
              at any time.
            </>
          )
        }
        detail={<ArchiveBlocked references={blockers} />}
        confirmLabel={isArchived ? `Restore ${project.name}` : `Archive ${project.name}`}
        confirmDisabled={asking || blockers.length > 0}
        destructive={!isArchived}
        onConfirm={() =>
          run(
            () =>
              coffre.projects.update(project.slug, { archived: !isArchived }),
            {
              affects: affects.places(),
              onSuccess: () =>
                toast.success(
                  isArchived ? `${project.slug} restored` : `${project.slug} archived`,
                ),
            },
          )
        }
      />
    </Card>
  );
}
