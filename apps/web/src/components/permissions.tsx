import { Popover } from 'radix-ui';
import type { Permission } from '../shared/models';
import { Check, ChevronDown } from './icons';

/**
 * What each permission actually lets you do, in the second person.
 *
 * The permission names are a fixed catalogue rather than a policy language, so
 * they can be explained exhaustively here instead of being rendered as opaque
 * dotted strings and left to the reader.
 */
const EXPLAINED: Record<Permission, string> = {
  'secret.read': 'Reveal secret values. Every reveal is written to the audit log.',
  'secret.write': 'Write new versions of a secret, rename it, import a .env file.',
  'secret.archive': 'Retire and restore secrets.',
  'audit.read': 'Read the audit log.',
  'environment.manage': 'Create, rename and archive environments.',
  'grant.manage': 'Grant and revoke access for other people and services.',
  'project.manage': 'Rename and archive the project itself.',
};

const SHORT: Record<Permission, string> = {
  'secret.read': 'read',
  'secret.write': 'write',
  'secret.archive': 'archive',
  'audit.read': 'audit log',
  'environment.manage': 'environments',
  'grant.manage': 'grants',
  'project.manage': 'project settings',
};

const ORDER = Object.keys(EXPLAINED) as Permission[];

/** "Read, write, archive" -- the permissions as a phrase, in catalogue order. */
export function permissionPhrase(permissions: readonly Permission[]): string {
  if (permissions.length === ORDER.length) return 'Everything';
  const words = ORDER.filter((permission) => permissions.includes(permission)).map(
    (permission) => SHORT[permission],
  );
  const phrase = words.join(', ');
  return phrase.charAt(0).toUpperCase() + phrase.slice(1);
}

/**
 * Your access here, as a short phrase that opens into the full list.
 *
 * Rendering all seven as pills next to the page title made the title compete
 * with reference information nobody reads twice, so the summary is one line in
 * the meta strip under the title, and the explanation waits behind it.
 */
export function PermissionSummary({ permissions }: { permissions: Permission[] }) {
  if (permissions.length === 0) {
    return <span>No permissions here</span>;
  }

  const canRead = permissions.includes('secret.read');

  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <button type="button" className="perm-trigger">
          Your access: <strong>{permissionPhrase(permissions)}</strong>
          <ChevronDown size={12} />
        </button>
      </Popover.Trigger>

      <Popover.Portal>
        <Popover.Content className="popover" sideOffset={8} align="start" collisionPadding={12}>
          <p className="popover-title">Your effective permissions</p>

          <ul className="perm-list">
            {ORDER.filter((permission) => permissions.includes(permission)).map((permission) => (
              <li key={permission}>
                <Check size={13} />
                <span>
                  <span className="mono">{permission}</span>
                  <span className="hint">{EXPLAINED[permission]}</span>
                </span>
              </li>
            ))}
          </ul>

          <p className="perm-foot">
            {canRead
              ? 'The union of every grant you hold here, at project and environment scope.'
              : 'You cannot read secret values here. The union of every grant you hold, at project and environment scope.'}
          </p>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
