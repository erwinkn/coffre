import { createFileRoute } from '@tanstack/react-router';
import { listDirectoryPrincipals } from '../server-functions/access';
import { AddPrincipal, DirectoryTable } from '../components/directory';
import { ClosedDoor, PageHeader } from '../components/page';
import { Key } from '../components/icons';

export const Route = createFileRoute('/tokens')({
  loader: () => listDirectoryPrincipals(),
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
      <PageHeader
        title="Tokens"
        description="Machines that call coffre, such as CI and deploys. Each is a Cloudflare Access service token, registered by its common name because those tokens carry no email. What a token can read is granted per project."
        meta={
          <span>
            <strong>{tokens.length}</strong> token{tokens.length === 1 ? '' : 's'}
          </span>
        }
        actions={<AddPrincipal principalType="service" />}
      />
      <DirectoryTable principalType="service" principals={tokens} />
    </>
  );
}
