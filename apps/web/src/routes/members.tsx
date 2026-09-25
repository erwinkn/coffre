import { createFileRoute } from '@tanstack/react-router';
import { listDirectoryPrincipals } from '../server-functions/access';
import { AddPrincipal, DirectoryTable } from '../components/directory';
import { ClosedDoor, PageHeader } from '../components/page';
import { Users } from '../components/icons';

export const Route = createFileRoute('/members')({
  loader: () => listDirectoryPrincipals(),
  component: MembersPage,
});

function MembersPage() {
  const result = Route.useLoaderData();

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Users size={18} />} label="Members" title="Members are closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const members = result.principals.filter((principal) => principal.principalType === 'user');
  const owners = members.filter((principal) => principal.instanceRole !== 'user').length;

  return (
    <>
      <PageHeader
        title="Members"
        description="People who may use coffre, matched on the email Cloudflare Access authenticates. Being listed here grants nothing by itself: what each member can do is granted per project."
        meta={
          <>
            <span>
              <strong>{members.length}</strong> member{members.length === 1 ? '' : 's'}
            </span>
            <span>
              <strong>{owners}</strong> owner{owners === 1 ? '' : 's'} or root admin
              {owners === 1 ? '' : 's'}
            </span>
          </>
        }
        actions={<AddPrincipal principalType="user" />}
      />
      <DirectoryTable principalType="user" principals={members} />
    </>
  );
}
