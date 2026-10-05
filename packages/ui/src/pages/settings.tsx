import { useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { Card, Fact, PageHeader } from '../components/page';
import { Toggletip } from '../components/ui';
import { Info } from '../components/icons';

/** The instance's settings. Your own are under Account, at the sidebar's foot. */

export function SettingsPage() {
  const { auth, capabilities } = useShell();
  const { data: directory } = useSuspenseQuery(queries.directory(useCoffre(), capabilities.canManageGrants));
  const providers = auth?.signin?.providers.map((provider) => provider.label) ?? [];

  const principals = directory?.ok === true ? directory.principals : null;
  const rootAdmins = principals?.filter((entry) => entry.isRootAdmin) ?? [];
  const users = principals?.filter((entry) => entry.principalType === 'user').length ?? 0;
  const tokens = principals?.filter((entry) => entry.principalType === 'service').length ?? 0;

  return (
    <>
      <PageHeader title="Settings" />

      <Card
        labelledBy="instance"
        title="Instance"
        description="Set in the deployment's configuration, so shown here rather than edited."
      >
        <dl className="facts">
          <Fact label="Sign-in">
            <span>
              {auth?.signin ? providers.join(', ') : 'Cloudflare Access'}
              <Toggletip
                label={
                  auth?.signin
                    ? 'coffre’s own sign-in. Only invited members get in.'
                    : 'coffre has no sign-in of its own: every request carries an Access assertion, verified at the origin.'
                }
              >
                <button type="button" className="fact-tip" aria-label="About sign-in">
                  <Info size={14} />
                </button>
              </Toggletip>
            </span>
          </Fact>
          {principals !== null && (
            <>
              <Fact label="Root admins">
                <span className="fact-list">
                  {rootAdmins.map((admin) => (
                    <span key={admin.principalId} className="mono">
                      {admin.principalId}
                    </span>
                  ))}
                </span>
              </Fact>
              <Fact label="Directory">
                <span>
                  <Link to="/users">
                    {users} user{users === 1 ? '' : 's'}
                  </Link>
                  {' · '}
                  <Link to="/tokens">
                    {tokens} service account{tokens === 1 ? '' : 's'}
                  </Link>
                </span>
              </Fact>
            </>
          )}
        </dl>
      </Card>
    </>
  );
}
