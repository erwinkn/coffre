import { useSuspenseQuery } from '@tanstack/react-query';

import { ActionsLog } from '../components/actions-log';
import { PrincipalAccess, PrincipalLayout } from '../components/principal-page';
import { ServiceTokens } from '../components/service-tokens';
import { TrustedWorkloads } from '../components/trusted-workloads';
import { Notice } from '../components/ui';
import { memberRef, useCoffre } from '../lib/coffre';
import { listsAccess, queries, signInWays } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { pageRoute } from '../lib/page-route';
import type { serviceAccount } from '../options';

const Route = pageRoute<typeof serviceAccount>();

/** A service account's page, around its tabs. */
export function ServiceAccountLayout() {
  return <PrincipalLayout principalType="service" principalId={Route.useParams().account} />;
}

/** Its first tab, while it shows one: the ways it signs in, OIDC first, the one with nothing to store. */
export function ServiceAccountSignInPage() {
  const { account } = Route.useParams();
  const client = useCoffre();
  const shell = useShell();
  const member = memberRef('service', account);
  const { data: access } = useSuspenseQuery(queries.memberAccess(client, member, listsAccess(shell)));
  // Nothing to issue once it is removed, which its loader sent elsewhere; its layout then shows no such tab.
  const ways = signInWays(shell, access) ?? { tokens: false, workloads: false };
  const { data: credentials } = useSuspenseQuery(queries.credentials(client, member, ways.tokens));
  const { data: bindings } = useSuspenseQuery(queries.bindings(client, member, ways.workloads));
  return (
    <>
      {bindings !== null &&
        (bindings.ok ? <TrustedWorkloads serviceId={account} bindings={bindings.bindings} /> : <Notice tone="bad">{bindings.error}</Notice>)}
      {credentials !== null &&
        (credentials.ok ? <ServiceTokens serviceId={account} tokens={credentials.tokens} /> : <Notice tone="bad">{credentials.error}</Notice>)}
    </>
  );
}

/** Its access, or once removed, its offboarding. */
export function ServiceAccountAccessPage() {
  return <PrincipalAccess principalType="service" principalId={Route.useParams().account} />;
}

/** Everything it did, from the audit log. */
export function ServiceAccountActivityPage() {
  return <ActionsLog member={memberRef('service', Route.useParams().account)} />;
}
