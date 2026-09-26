import { createFileRoute } from '@tanstack/react-router';
import { listDirectoryPrincipals } from '../server-functions/access';
import { AddPrincipal, DirectoryTable } from '../components/directory';
import { ClosedDoor, PageHeader } from '../components/page';
import { Users } from '../components/icons';

export const Route = createFileRoute('/users')({
  loader: () => listDirectoryPrincipals(),
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
  const owners = users.filter((principal) => principal.instanceRole !== 'user').length;

  return (
    <>
      <PageHeader
        title="Users"
        description="People who may use coffre, matched on the email Cloudflare Access authenticates. Being listed here grants nothing by itself: what each user can do is granted per project."
        meta={
          <>
            <span>
              <strong>{users.length}</strong> user{users.length === 1 ? '' : 's'}
            </span>
            <span>
              <strong>{owners}</strong> owner{owners === 1 ? '' : 's'} or root admin
              {owners === 1 ? '' : 's'}
            </span>
          </>
        }
        actions={<AddPrincipal principalType="user" />}
      />
      <DirectoryTable principalType="user" principals={users} />
    </>
  );
}
