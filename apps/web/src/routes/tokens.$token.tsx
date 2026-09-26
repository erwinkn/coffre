import { createFileRoute } from '@tanstack/react-router';
import { loadPrincipalPage, PrincipalPage } from '../components/principal-page';

export const Route = createFileRoute('/tokens/$token')({
  loader: async ({ params, parentMatchPromise }) =>
    loadPrincipalPage('service', params.token, (await parentMatchPromise).loaderData),
  component: TokenPage,
});

function TokenPage() {
  const { token } = Route.useParams();
  return (
    <PrincipalPage principalType="service" principalId={token} data={Route.useLoaderData()} />
  );
}
