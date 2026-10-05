import { useSuspenseQuery } from '@tanstack/react-query';

import { PrincipalPage } from '../components/principal-page';
import { ServiceTokens } from '../components/service-tokens';
import { TrustedWorkloads } from '../components/trusted-workloads';
import { memberRef, useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { pageRoute } from '../lib/page-route';
import type { token } from '../options';

const Route = pageRoute<typeof token>();

export function TokenPage() {
  const { token } = Route.useParams();
  const client = useCoffre();
  const { auth, capabilities } = useShell();
  const member = memberRef('service', token);
  const owner = capabilities.canManageGrants;
  const { data: report } = useSuspenseQuery(queries.report(client, member, owner));
  const { data: credentials } = useSuspenseQuery(queries.credentials(client, member, owner && auth.signin !== null));
  const { data: bindings } = useSuspenseQuery(queries.bindings(client, member, owner && auth.signin !== null));
  // A removed service can be issued nothing; its page shows what it left behind.
  const active = report?.ok === true && report.report?.status === 'active';
  return (
    <>
      <PrincipalPage principalType="service" principalId={token} />
      {/* The two ways a service account signs in: OIDC first, the one with nothing to store. */}
      {active && bindings?.ok === true && <TrustedWorkloads serviceId={token} bindings={bindings.bindings} />}
      {active && credentials?.ok === true && (
        <ServiceTokens serviceId={token} tokens={credentials.tokens} />
      )}
    </>
  );
}
