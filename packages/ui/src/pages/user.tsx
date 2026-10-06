import { ActionsLog } from '../components/actions-log';
import { PrincipalAccess, PrincipalLayout } from '../components/principal-page';
import { memberRef } from '../lib/coffre';
import { pageRoute } from '../lib/page-route';
import type { user } from '../options';

const Route = pageRoute<typeof user>();

/** A user's page, around its tabs. */
export function UserLayout() {
  return <PrincipalLayout principalType="user" principalId={Route.useParams().user} />;
}

/** Their first tab: their access, or once removed, their offboarding. */
export function UserAccessPage() {
  return <PrincipalAccess principalType="user" principalId={Route.useParams().user} />;
}

/** Everything they did, from the audit log. */
export function UserActivityPage() {
  return <ActionsLog member={memberRef('user', Route.useParams().user)} />;
}
