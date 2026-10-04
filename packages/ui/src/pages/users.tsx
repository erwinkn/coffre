import { useSuspenseQuery } from '@tanstack/react-query';

import { AddPrincipal, DirectoryTable } from '../components/directory';
import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { ClosedDoor, PageHeader } from '../components/page';
import { RemovedList } from '../components/offboarding';
import { Users } from '../components/icons';

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
      <PageHeader title="Users" actions={<AddPrincipal principalType="user" />} />
      <DirectoryTable
        principalType="user"
        principals={users}
        hasRemoved={result.removed.some((principal) => principal.principalType === 'user')}
      />
      <RemovedList principalType="user" removed={result.removed} />
    </>
  );
}
