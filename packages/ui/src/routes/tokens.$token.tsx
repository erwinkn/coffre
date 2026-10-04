import { useSuspenseQuery } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { PrincipalPage } from '../components/principal-page';
import { ServiceTokens } from '../components/service-tokens';
import { TrustedWorkloads } from '../components/trusted-workloads';
import { memberRef, useCoffre } from '../lib/coffre';
import { loadPrincipal, queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';

export const Route = createFileRoute('/tokens/$token')({
  loader: ({ context: { client, queryClient }, params }) => loadPrincipal(queryClient, client, 'service', params.token),
  component: TokenPage,
});

function TokenPage() {
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
      {active && credentials?.ok === true && (
        <ServiceTokens serviceId={token} tokens={credentials.tokens} />
      )}
      {active && bindings?.ok === true && <TrustedWorkloads serviceId={token} bindings={bindings.bindings} />}
    </>
  );
}
