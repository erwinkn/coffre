import { PrincipalPage } from '../components/principal-page';
import { pageRoute, type Parent } from '../lib/page-route';
import type { user } from '../routes';

const Route = pageRoute<ReturnType<typeof user<Parent>>>();

export function UserPage() {
  const { user } = Route.useParams();
  return <PrincipalPage principalType="user" principalId={user} />;
}
