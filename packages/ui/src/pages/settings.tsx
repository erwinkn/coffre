import type { RouteOutput } from '@coffre/client';
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
  const client = useCoffre();
  const { data: directory } = useSuspenseQuery(queries.directory(client, capabilities.canManageGrants));
  const { data: keys } = useSuspenseQuery(queries.auditKeys(client, capabilities.canManageGrants));
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
        description="Set in the deployment's configuration, not here."
      >
        <dl className="facts">
          <Fact label="Sign-in">
            <span>
              {auth?.signin ? providers.join(', ') : 'Cloudflare Access'}
              <Toggletip
                label={
                  auth?.signin
                    ? 'coffre’s own sign-in. Only invited members get in.'
                    : 'Cloudflare Access signs people in, and coffre verifies each request.'
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
                  <Link to="/service-accounts">
                    {tokens} service account{tokens === 1 ? '' : 's'}
                  </Link>
                </span>
              </Fact>
            </>
          )}
        </dl>
      </Card>

      {keys?.ok === true && <Keys keys={keys} />}
    </>
  );
}

/**
 * What the keys you keep are checked against: no secret, so shown. The keys
 * themselves are checked by `coffre verify keys`, on your machine: a vault
 * key typed into a web page would be within reach of everything running in it.
 */
function Keys({ keys }: { keys: RouteOutput<'GET /audit/keys'> }) {
  const { current, checks } = keys.vault;
  const replaced = new Set(checks.map((check) => check.vaultId).filter((id) => id !== current.vaultId)).size;
  return (
    <Card
      labelledBy="keys"
      title="Keys"
      description={
        <>
          To check your vault key and app key against these, run <code>coffre verify keys</code>.
          It reads them on your machine and sends neither.
        </>
      }
    >
      <dl className="facts">
        <Fact label="Vault ID">
          <span className="mono">{current.vaultId}</span>
        </Fact>
        <Fact label="Vault key">
          <span>
            Held by <span className="mono">{current.provider}</span>
            {replaced > 0 && `; ${replaced} earlier vault key${replaced === 1 ? '' : 's'} still checkable`}
          </span>
        </Fact>
        <Fact label="App key">
          <span className="mono">{keys.app.keyId}</span>
        </Fact>
      </dl>
    </Card>
  );
}

