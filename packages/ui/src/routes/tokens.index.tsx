import { useSuspenseQuery } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { AddPrincipal, DirectoryTable } from '../components/directory';
import { useCoffre } from '../lib/coffre';
import { loadDirectory, queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { ClosedDoor, PageHeader } from '../components/page';
import { RemovedList } from '../components/offboarding';
import { Key } from '../components/icons';

export const Route = createFileRoute('/tokens/')({
  loader: ({ context: { client, queryClient } }) => loadDirectory(queryClient, client),
  component: TokensPage,
});

function TokensPage() {
  const { capabilities } = useShell();
  const { data: result } = useSuspenseQuery(queries.directory(useCoffre(), capabilities.canManageGrants));

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Key size={18} />} label="Tokens" title="Tokens are closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const tokens = result.principals.filter((principal) => principal.principalType === 'service');

  return (
    <>
      <PageHeader title="Tokens" actions={<AddPrincipal principalType="service" />} />
      <DirectoryTable
        principalType="service"
        principals={tokens}
        hasRemoved={result.removed.some((principal) => principal.principalType === 'service')}
      />
      <RemovedList principalType="service" removed={result.removed} />
    </>
  );
}
