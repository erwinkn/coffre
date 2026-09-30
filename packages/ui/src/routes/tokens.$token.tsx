import { createFileRoute } from '@tanstack/react-router';
import { loadPrincipalPage, PrincipalPage } from '../components/principal-page';
import { ServiceTokens } from '../components/service-tokens';
import { memberRef, uiResult } from '../lib/coffre';

export const Route = createFileRoute('/tokens/$token')({
  loader: async ({ context: { client }, params, parentMatchPromise }) => {
    const root = (await parentMatchPromise).loaderData;
    // Only owners issue and see credentials; asking as anyone else would
    // only earn a refusal. Only coffre's own sign-in issues any.
    const [page, credentials] = await Promise.all([
      loadPrincipalPage(client, 'service', params.token, root),
      root?.capabilities.canManageGrants && root.auth.signin !== null
        ? uiResult(() => client.tokens.list(memberRef('service', params.token)))
        : Promise.resolve(null),
    ]);
    return { page, credentials };
  },
  component: TokenPage,
});

function TokenPage() {
  const { token } = Route.useParams();
  const { page, credentials } = Route.useLoaderData();
  // A removed service can be issued nothing; its page shows what it left behind.
  const active = page.report?.ok === true && page.report.report?.status === 'active';
  return (
    <>
      <PrincipalPage principalType="service" principalId={token} data={page} />
      {active && credentials?.ok === true && (
        <ServiceTokens serviceId={token} tokens={credentials.tokens} />
      )}
    </>
  );
}
