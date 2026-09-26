import { createFileRoute, useLoaderData } from '@tanstack/react-router';
import { Card, Fact, PageHeader } from '../components/page';
import { ThemeCards } from '../components/theme';
import { InstanceRole } from '../components/directory';

/**
 * Your own settings: how coffre looks here, and who it takes you for. The
 * sidebar's Settings is the workspace's; this page is reached from your
 * account at the sidebar's foot.
 */
export const Route = createFileRoute('/account')({
  component: AccountPage,
});

function AccountPage() {
  const { principal, instanceRole } = useLoaderData({ from: '__root__' });

  return (
    <>
      <PageHeader title="Account" />

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
            {principal.type === 'user' && (
              <Fact label="Instance role">
                <InstanceRole
                  principal={{
                    principalType: 'user',
                    principalId: principal.id,
                    instanceRole: instanceRole ?? 'user',
                    isRootAdmin: instanceRole === 'root-admin',
                  }}
                />
              </Fact>
            )}
          </dl>
        </Card>
      )}
    </>
  );
}
