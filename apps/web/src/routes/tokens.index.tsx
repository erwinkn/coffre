import { createFileRoute } from '@tanstack/react-router';
import { AddPrincipal, DirectoryTable, loadDirectory } from '../components/directory';
import { ClosedDoor, PageHeader } from '../components/page';
import { RemovedList } from '../components/offboarding';
import { Key } from '../components/icons';

export const Route = createFileRoute('/tokens/')({
  loader: async ({ context: { client }, parentMatchPromise }) =>
    loadDirectory(client, (await parentMatchPromise).loaderData?.capabilities.canManageGrants ?? false),
  component: TokensPage,
});

function TokensPage() {
  const result = Route.useLoaderData();

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
      <DirectoryTable principalType="service" principals={tokens} />
      <RemovedList principalType="service" removed={result.removed} />
    </>
  );
}
