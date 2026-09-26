import { createFileRoute } from '@tanstack/react-router';
import { loadPrincipalPage, PrincipalPage } from '../components/principal-page';

export const Route = createFileRoute('/users/$user')({
  loader: async ({ params, parentMatchPromise }) =>
    loadPrincipalPage('user', params.user, (await parentMatchPromise).loaderData),
  component: UserPage,
});

function UserPage() {
  const { user } = Route.useParams();
  return <PrincipalPage principalType="user" principalId={user} data={Route.useLoaderData()} />;
}
