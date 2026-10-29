import { environmentId, protectEnvironment } from '../lib/changes';
import { useCoffre } from '../lib/coffre';
import type { ProjectEnvironment } from '../lib/project-environments';
import { keys } from '../lib/queries';
import { protectionInWords } from '../lib/roles';
import { useChange, useChangeStatus } from '../lib/use-change';
import { useRoles } from '../lib/use-roles';
import { Lock } from './icons';
import { ConfirmDialog, Toggletip } from './ui';

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
 * An environment's protection (docs/design/roles.md), while it is on: a
 * tag on its page, a lock on its card, whose note says what it means and
 * who takes it off. Nothing while it is off. It is changed from the
 * environment's actions menu (`ProtectDialog`).
 */
export function Protection({ environment, compact = false }: { environment: ProjectEnvironment; compact?: boolean }) {
  if (!environment.protected) return null;
  return (
    <Toggletip label={`${MEANING} ${WHO_UNPROTECTS}`}>
      {compact ? (
        <button type="button" className="protected-mark" aria-label="Protected">
          <Lock size={13} />
        </button>
      ) : (
        <button type="button" className="tag tag-amber tag-button">
          <Lock size={11} />
          Protected
        </button>
      )}
    </Toggletip>
  );
}

/**
 * Protecting the environment, or taking it off, once confirmed: shown at
 * once on its card and its page, which say if the server refuses. Once a
 * change is on its way, another waits for its answer: the later of two
 * would otherwise land as it likes.
 */
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
  const { roles } = useRoles();
  const protect = useChange(protectEnvironment(useCoffre(), project));
  const { status } = useChangeStatus(keys.projects);
  const protection = protectionInWords(roles);
  const { slug, protected: guarded } = environment;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={
        <>
          {guarded ? 'Unprotect' : 'Protect'} <span className="mono">{project}/{slug}</span>?
        </>
      }
      body={
        guarded
          ? 'People holding a role here get its full column again, as in any other environment. Service accounts are unaffected.'
          : `People holding a role here get its protected column${protection === null ? ', which for now holds what the other does' : `: ${protection}`}. Service accounts are unaffected.${
              environment.unprotectable === true ? '' : ` ${WHO_UNPROTECTS}`
            }`
      }
      confirmLabel={guarded ? 'Unprotect' : 'Protect'}
      destructive={guarded}
      confirmDisabled={status(environmentId(project, slug)).state === 'pending'}
      onConfirm={() => protect({ slug, protected: !guarded })}
    />
  );
}
