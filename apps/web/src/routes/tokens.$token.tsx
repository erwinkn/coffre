import { createFileRoute } from '@tanstack/react-router';
import { loadPrincipalPage, PrincipalPage } from '../components/principal-page';
import { ServiceTokens } from '../components/service-tokens';
import { listServiceTokens } from '../server-functions/signin';

export const Route = createFileRoute('/tokens/$token')({
  loader: async ({ params, parentMatchPromise }) => {
    const root = (await parentMatchPromise).loaderData;
    // Only owners issue and see credentials; asking as anyone else would
    // only earn a refusal.
    const [page, credentials] = await Promise.all([
      loadPrincipalPage('service', params.token, root),
      root?.capabilities.canManageGrants
        ? listServiceTokens({ data: { serviceId: params.token } })
        : Promise.resolve(null),
    ]);
    return { page, credentials };
  },
  component: TokenPage,
});

function TokenPage() {
  const { token } = Route.useParams();
  const { page, credentials } = Route.useLoaderData();
  const known =
    page.directory?.ok === true &&
    page.directory.principals.some(
      (principal) => principal.principalType === 'service' && principal.principalId === token,
    );
  return (
    <>
      <PrincipalPage principalType="service" principalId={token} data={page} />
      {known && credentials?.ok === true && credentials.mode === 'signin' && (
        <ServiceTokens serviceId={token} tokens={credentials.tokens} />
      )}
    </>
  );
}
