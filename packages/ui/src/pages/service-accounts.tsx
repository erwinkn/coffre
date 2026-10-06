import { useSuspenseQuery } from '@tanstack/react-query';

import { DirectoryTable } from '../components/directory';
import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { ClosedDoor, PageHeader } from '../components/page';
import { RemovedList } from '../components/offboarding';
import { Key } from '../components/icons';

export function ServiceAccountsPage() {
  const { capabilities } = useShell();
  const { data: result } = useSuspenseQuery(queries.directory(useCoffre(), capabilities.canManageGrants));

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Key size={18} />} label="Service accounts" title="Service accounts are closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const accounts = result.principals.filter((principal) => principal.principalType === 'service');

  return (
    <>
      <PageHeader
        title="Service accounts"
        description="Identities for CI and other automation."
      />
      <DirectoryTable
        principalType="service"
        principals={accounts}
        hasRemoved={result.removed.some((principal) => principal.principalType === 'service')}
      />
      <RemovedList principalType="service" removed={result.removed} />
    </>
  );
}
