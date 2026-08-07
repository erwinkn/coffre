import { Popover } from 'radix-ui';
import type { Permission } from '../shared/models';
import { Tip } from './ui';
import { ChevronDown, Eye, Key, ShieldCheck } from './icons';

/**
 * What each permission actually lets you do, in the second person.
 *
 * The permission names are a fixed catalogue rather than a policy language, so
 * they can be explained exhaustively here instead of being rendered as opaque
 * dotted strings and left to the reader.
 */
const EXPLAINED: Record<Permission, string> = {
  'secret.read': 'Reveal secret values. Every reveal is audited.',
  'secret.write': 'Write new versions of a secret.',
  'secret.archive': 'Retire and restore secrets.',
  'audit.read': 'Read the audit log.',
  'environment.manage': 'Create, rename and archive environments.',
  'grant.manage': 'Grant and revoke access for other principals.',
  'project.manage': 'Rename and archive the project itself.',
};

/**
 * A compact stand-in for the list of permissions.
 *
 * Rendering all seven as pills next to the page title made the title compete
 * with reference information nobody reads twice. Even spelled out in a word or
 * two it competed, so the trigger is down to the one glyph that carries the
 * distinction -- eye or shield, can read values or cannot -- and the detail
 * waits inside.
 */
export function PermissionSummary({ permissions }: { permissions: Permission[] }) {
  if (permissions.length === 0) {
    return <span className="pill pill-muted">no permissions here</span>;
  }

  const canRead = permissions.includes('secret.read');
  const label = canRead ? 'Can read values' : 'Cannot read values';

  return (
    <Popover.Root>
      {/* Tooltip outside, popover inside: Popover.Trigger forwards a ref, so
          Tooltip.Trigger can wrap it, but not the other way around. */}
      <Tip label={label}>
        <Popover.Trigger asChild>
          <button
            className="btn btn-head-action"
            aria-label={`${label}. ${permissions.length} permissions here.`}
          >
            {canRead ? <Eye size={15} /> : <ShieldCheck size={15} />}
            <ChevronDown size={13} />
          </button>
        </Popover.Trigger>
      </Tip>

      <Popover.Portal>
        <Popover.Content
          className="menu"
          sideOffset={6}
          align="end"
          collisionPadding={12}
          style={{ minWidth: '20rem', padding: 'var(--space-4)' }}
        >
          <p className="label" style={{ marginBottom: 'var(--space-3)' }}>
            Your effective permissions
          </p>

          <div className="stack" style={{ gap: 'var(--space-3)' }}>
            {permissions.map((permission) => (
              <div key={permission} className="cluster" style={{ gap: 'var(--space-3)' }}>
                <Key size={13} style={{ color: 'var(--ink-3)', flex: 'none' }} />
                <span style={{ minWidth: 0 }}>
                  <span className="mono" style={{ fontSize: 'var(--text-xs)' }}>
                    {permission}
                  </span>
                  <span className="meta" style={{ display: 'block' }}>
                    {EXPLAINED[permission]}
                  </span>
                </span>
              </div>
            ))}
          </div>

          <p className="meta" style={{ marginTop: 'var(--space-4)' }}>
            The union of every grant you hold at project and environment scope.
          </p>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
