import { PrincipalPage } from '../components/principal-page';
import { pageRoute } from '../lib/page-route';
import type { user } from '../options';

const Route = pageRoute<typeof user>();

export function UserPage() {
  const { user } = Route.useParams();
  return <PrincipalPage principalType="user" principalId={user} />;
}
