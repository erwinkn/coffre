import { useSuspenseQuery } from '@tanstack/react-query';

import { ActionsLog } from '../components/actions-log';
import { ConnectedAppsCard } from '../components/connected-apps';
import { PrincipalAccess, PrincipalLayout } from '../components/principal-page';
import { disconnectMemberApp } from '../lib/changes';
import { memberRef, useCoffre } from '../lib/coffre';
import { pageRoute } from '../lib/page-route';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
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

/** The MCP clients they connected, for an owner, who may disconnect any of them. */
export function UserAppsPage() {
  const client = useCoffre();
  const member = memberRef('user', Route.useParams().user);
  const { data: report } = useSuspenseQuery(queries.report(client, member, useShell().capabilities.runsInstance));
  // Their layout says why there is no report.
  if (report?.ok !== true || report.report === null) return null;
  return (
    <ConnectedAppsCard
      apps={report.report.apps}
      change={disconnectMemberApp(client, member)}
      description="AI assistants and other MCP clients they connected. Removing them from coffre disconnects every one."
      empty="They have connected none."
    />
  );
}

/** Everything they did, from the audit log. */
export function UserActivityPage() {
  return <ActionsLog member={memberRef('user', Route.useParams().user)} />;
}
