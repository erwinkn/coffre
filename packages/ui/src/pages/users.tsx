import { useSuspenseQuery } from '@tanstack/react-query';

import { DirectoryTable } from '../components/directory';
import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { ClosedDoor, PageHeader } from '../components/page';
import { RemovedList } from '../components/offboarding';
import { Users } from '../components/icons';
import { Notice, Timestamp } from '../components/ui';
import type { RecoveredOwner } from '../shared/models';

export function UsersPage() {
  const { capabilities } = useShell();
  const { data: result } = useSuspenseQuery(queries.directory(useCoffre(), capabilities.canManageGrants));

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Users size={18} />} label="Users" title="Users are closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const users = result.principals.filter((principal) => principal.principalType === 'user');

  return (
    <>
      <PageHeader title="Users" />
      <Recoveries recovered={result.recovered} />
      <DirectoryTable
        principalType="user"
        principals={users}
        hasRemoved={result.removed.some((principal) => principal.principalType === 'user')}
      />
      <RemovedList principalType="user" removed={result.removed} />
    </>
  );
}

/**
 * Whom the deployment's operator made an Owner through the vault's
 * configuration in the last month, rather than an Owner: one you did not
 * expect means someone who deploys the vault took the instance over.
 */
function Recoveries({ recovered }: { recovered: RecoveredOwner[] }) {
  if (recovered.length === 0) return null;
  return (
    <Notice tone="warn">
      {recovered.map(({ member, at }) => (
        <p key={`${member}@${at}`}>
          <strong>{member.replace(/^user:/, '')}</strong> was made an Owner of the whole instance on <Timestamp iso={at} />{' '}
          by a recovery: the deployment's operator named them in the vault's configuration, not an Owner.
        </p>
      ))}
      <p>If you didn't expect it, check who can deploy the vault, and read the audit log.</p>
    </Notice>
  );
}
