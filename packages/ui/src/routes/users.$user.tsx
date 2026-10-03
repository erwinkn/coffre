import { createFileRoute } from '@tanstack/react-router';
import { PrincipalPage } from '../components/principal-page';
import { loadPrincipal } from '../lib/queries';

export const Route = createFileRoute('/users/$user')({
  loader: ({ context: { client, queryClient }, params }) => loadPrincipal(queryClient, client, 'user', params.user),
  component: UserPage,
});

function UserPage() {
  const { user } = Route.useParams();
  return <PrincipalPage principalType="user" principalId={user} />;
}
