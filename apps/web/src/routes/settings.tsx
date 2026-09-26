import type { ReactNode } from 'react';
import { createFileRoute, Link, useLoaderData } from '@tanstack/react-router';
import { getLoginAuthState } from '../server-functions/auth';
import { listDirectoryPrincipals } from '../server-functions/access';
import { Card, PageHeader } from '../components/page';
import { ThemeCards } from '../components/theme';
import { roleLabel } from '../components/shell';

export const Route = createFileRoute('/settings')({
  // Instance facts come from the directory, which only owners may list.
  // Asking on everyone's behalf would write a refusal to the audit log for
  // every user who opens their own settings, so it is only asked for them.
  loader: async ({ parentMatchPromise }) => {
    const root = await parentMatchPromise;
    const canManage = root.loaderData?.capabilities.canManageGrants ?? false;
    const [auth, directory] = await Promise.all([
      getLoginAuthState(),
      canManage ? listDirectoryPrincipals() : Promise.resolve(null),
    ]);
    return { auth, directory };
  },
  component: SettingsPage,
});

function SettingsPage() {
  const { auth, directory } = Route.useLoaderData();
  const { principal, instanceRole } = useLoaderData({ from: '__root__' });

  const principals = directory?.ok === true ? directory.principals : null;
  const rootAdmins = principals?.filter((entry) => entry.isRootAdmin) ?? [];
  const users = principals?.filter((entry) => entry.principalType === 'user').length ?? 0;
  const tokens = principals?.filter((entry) => entry.principalType === 'service').length ?? 0;

  return (
    <>
      <PageHeader
        title="Settings"
        description="Your preferences on this device, and how this coffre instance is set up."
      />

      <Card
        labelledBy="appearance"
        title="Appearance"
        description="Kept in this browser. Match system follows your operating system's light or dark setting."
      >
        <div className="card-body">
          <ThemeCards />
        </div>
      </Card>

      {principal !== null && (
        <Card
          labelledBy="identity"
          title="Your identity"
          description="As coffre sees you. Every read and write you make is recorded against it."
        >
          <dl className="facts">
            <Fact label="Identity">
              <span className="mono">{principal.id}</span>
            </Fact>
            <Fact label="Kind">{principal.type === 'user' ? 'User' : 'Token'}</Fact>
            <Fact label="Instance role">{roleLabel(principal, instanceRole)}</Fact>
          </dl>
        </Card>
      )}

      <Card
        labelledBy="instance"
        title="Instance"
        description="Set in the deployment's configuration, so shown here rather than edited."
      >
        <dl className="facts">
          <Fact label="Sign-in">
            {auth.mode === 'cloudflare' ? (
              'Cloudflare Access. coffre has no sign-in of its own; every request carries an Access assertion that is verified at the origin.'
            ) : (
              <>
                Local development. Personas are minted by the dev identity provider; production
                runs with Cloudflare Access instead.
              </>
            )}
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
                <span className="hint">
                  From <code>COFFRE_ROOT_ADMINS</code>. They bootstrap an empty instance and
                  cannot be removed from the interface.
                </span>
              </Fact>
              <Fact label="Directory">
                <span>
                  <Link to="/users">
                    {users} user{users === 1 ? '' : 's'}
                  </Link>
                  {' · '}
                  <Link to="/tokens">
                    {tokens} token{tokens === 1 ? '' : 's'}
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

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
