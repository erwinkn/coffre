import { environmentId, protectEnvironment } from '../lib/changes';
import { useCoffre } from '../lib/coffre';
import type { ProjectEnvironment } from '../lib/project-environments';
import { keys } from '../lib/queries';
import { protectionInWords } from '../lib/roles';
import { useChange, useChangeStatus } from '../lib/use-change';
import { useRoles } from '../lib/use-roles';
import { useShell } from '../lib/use-shell';
import { Lock } from './icons';
import { ConfirmButton, Toggletip } from './ui';

const MEANING = 'Protected: each person here holds their role’s protected column, which an Owner sets in Settings › Roles. Service accounts hold their role as anywhere else.';

/**
 * An environment's protection (docs/design/roles.md), on its card and its
 * page. Whoever manages the project's environments protects one, and only
 * an Owner of the whole instance takes it off: for them the tag is the
 * button that does, behind a confirmation. Everyone else sees the tag, whose
 * note says what it means and who changes it, and nothing while it is off.
 * A personal config has none of its own: it is as its parent is.
 */
export function Protection({ project, environment }: { project: string; environment: ProjectEnvironment }) {
  const { capabilities, projects } = useShell();
  const manages = projects.find((entry) => entry.slug === project)?.permissions.includes('environment.manage') === true;
  const guarded = environment.protected;
  if (manages && environment.details !== null && environment.personal !== true && (!guarded || capabilities.ownsInstance)) {
    return <ChangeProtection project={project} slug={environment.slug} guarded={guarded} ownsInstance={capabilities.ownsInstance} />;
  }
  if (!guarded) return null;
  return (
    <Toggletip label={`${MEANING} Only an Owner of the whole instance takes protection off.`}>
      <button type="button" className="tag tag-amber tag-button">
        <Lock size={11} />
        Protected
      </button>
    </Toggletip>
  );
}

/** The tag as the button that protects the environment, or takes it off, once confirmed. */
function ChangeProtection({ project, slug, guarded, ownsInstance }: { project: string; slug: string; guarded: boolean; ownsInstance: boolean }) {
  const { roles } = useRoles();
  const protect = useChange(protectEnvironment(useCoffre(), project));
  const { status } = useChangeStatus(keys.projects);
  const protection = protectionInWords(roles);
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
      disabled={status(environmentId(project, slug)).state === 'pending'}
      title={
        <>
          {guarded ? 'Unprotect' : 'Protect'} <span className="mono">{place}</span>?
        </>
      }
      body={
        guarded
          ? 'People holding a role here get its full column again, as in any other environment. Service accounts are unaffected.'
          : `People holding a role here get its protected column${protection === null ? ', which for now holds what the other does' : `: ${protection}`}. Service accounts are unaffected.${
              ownsInstance ? '' : ' Only an Owner of the whole instance takes protection off.'
            }`
      }
      confirmLabel={guarded ? 'Unprotect' : 'Protect'}
      destructive={guarded}
      onConfirm={() => protect({ slug, protected: !guarded })}
    />
  );
}
