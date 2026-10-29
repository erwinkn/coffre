import { environmentId, protectEnvironment } from '../lib/changes';
import { useCoffre } from '../lib/coffre';
import type { ProjectEnvironment } from '../lib/project-environments';
import { keys } from '../lib/queries';
import { protectionInWords } from '../lib/roles';
import { useChange, useChangeStatus } from '../lib/use-change';
import { useRoles } from '../lib/use-roles';
import { useShell } from '../lib/use-shell';
import { Lock } from './icons';
import { ConfirmButton, ConfirmDialog, Toggletip } from './ui';

const MEANING = 'Protected: each person here holds their role’s protected column, which an Owner sets in Settings › Roles. Service accounts hold their role as anywhere else.';
const WHO_UNPROTECTS = 'Only an Owner of its project takes protection off.';

/**
 * Whether you change an environment's protection: whoever manages the
 * project's environments protects one, and only an Owner of its project,
 * or of the whole instance, takes it off, as the server says
 * (`unprotectable`). A personal config has none of its own: it is as its
 * parent is.
 */
export function changesProtection(projects: readonly { slug: string; permissions: readonly string[] }[], project: string, environment: ProjectEnvironment): boolean {
  const manages = projects.find((entry) => entry.slug === project)?.permissions.includes('environment.manage') === true;
  return manages && environment.details !== null && environment.personal !== true && (!environment.protected || environment.unprotectable === true);
}

/**
 * An environment's protection (docs/design/roles.md), on its card and its
 * page. On its card, for whoever changes it (`changesProtection`), the tag
 * is the button that does, behind a confirmation; its page changes it from
 * its actions menu, and shows the tag alone. Everyone else sees the tag,
 * whose note says what it means and who changes it, and nothing while it
 * is off.
 */
export function Protection({ project, environment, control = true }: { project: string; environment: ProjectEnvironment; control?: boolean }) {
  const { projects } = useShell();
  const guarded = environment.protected;
  if (control && changesProtection(projects, project, environment)) {
    return <ChangeProtection project={project} slug={environment.slug} guarded={guarded} unprotects={environment.unprotectable === true} />;
  }
  if (!guarded) return null;
  return (
    <Toggletip label={`${MEANING} ${WHO_UNPROTECTS}`}>
      <button type="button" className="tag tag-amber tag-button">
        <Lock size={11} />
        Protected
      </button>
    </Toggletip>
  );
}

/** The tag as the button that protects the environment, or takes it off, once confirmed. */
function ChangeProtection({ project, slug, guarded, unprotects }: { project: string; slug: string; guarded: boolean; unprotects: boolean }) {
  const { confirm, pending } = useProtectConfirm(project, slug, guarded, unprotects);
  const place = `${project}/${slug}`;
  return (
    <ConfirmButton
      trigger={
        <button
          type="button"
          className={`tag tag-button tag-control ${guarded ? 'tag-amber' : 'tag-outline'}`}
          aria-label={guarded ? `Protected: unprotect ${place}…` : `Protect ${place}…`}
        >
          <Lock size={11} />
          {guarded ? 'Protected' : 'Protect…'}
        </button>
      }
      // Once a change is on its way, the tag shows it already; another waits for its answer.
      disabled={pending}
      {...confirm}
    />
  );
}

/** Protecting the environment, or taking it off, as a dialog its opener holds open: an actions menu's. */
export function ProtectDialog({
  project,
  environment,
  open,
  onOpenChange,
}: {
  project: string;
  environment: ProjectEnvironment;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { confirm, pending } = useProtectConfirm(project, environment.slug, environment.protected, environment.unprotectable === true);
  // Once a change is on its way, another waits for its answer: the later of two would otherwise land as it likes.
  return <ConfirmDialog open={open} onOpenChange={onOpenChange} {...confirm} confirmDisabled={pending} />;
}

/** What protecting it, or taking it off, says before it does, and whether a change of it is on its way. */
function useProtectConfirm(project: string, slug: string, guarded: boolean, unprotects: boolean) {
  const { roles } = useRoles();
  const protect = useChange(protectEnvironment(useCoffre(), project));
  const { status } = useChangeStatus(keys.projects);
  const protection = protectionInWords(roles);
  return {
    pending: status(environmentId(project, slug)).state === 'pending',
    confirm: {
      title: (
        <>
          {guarded ? 'Unprotect' : 'Protect'} <span className="mono">{project}/{slug}</span>?
        </>
      ),
      body: guarded
        ? 'People holding a role here get its full column again, as in any other environment. Service accounts are unaffected.'
        : `People holding a role here get its protected column${protection === null ? ', which for now holds what the other does' : `: ${protection}`}. Service accounts are unaffected.${
            unprotects ? '' : ` ${WHO_UNPROTECTS}`
          }`,
      confirmLabel: guarded ? 'Unprotect' : 'Protect',
      destructive: guarded,
      onConfirm: () => protect({ slug, protected: !guarded }),
    },
  };
}
