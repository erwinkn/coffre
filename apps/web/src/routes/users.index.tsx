import { createFileRoute } from '@tanstack/react-router';
import { AddPrincipal, DirectoryTable, loadDirectory } from '../components/directory';
import { ClosedDoor, PageHeader } from '../components/page';
import { RemovedList } from '../components/offboarding';
import { Users } from '../components/icons';

export const Route = createFileRoute('/users/')({
  loader: async ({ context: { client }, parentMatchPromise }) =>
    loadDirectory(client, (await parentMatchPromise).loaderData?.capabilities.canManageGrants ?? false),
  component: UsersPage,
});

function UsersPage() {
  const result = Route.useLoaderData();

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
      <DirectoryTable principalType="user" principals={users} />
      <RemovedList principalType="user" removed={result.removed} />
    </>
  );
}
