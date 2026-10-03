import { createFileRoute, Link } from '@tanstack/react-router';
import { loadDirectory } from '../components/directory';
import { Card, Fact, PageHeader } from '../components/page';

/** The instance's settings. Your own are under Account, at the sidebar's foot. */
export const Route = createFileRoute('/settings')({
  // Instance facts come from the directory, which only owners may list.
  // Asking on everyone's behalf would write a refusal to the audit log for
  // every user who opens the page, so it is only asked for them.
  loader: async ({ context: { client }, parentMatchPromise }) => {
    const root = (await parentMatchPromise).loaderData;
    const canManage = root?.capabilities.canManageGrants ?? false;
    return { auth: root?.auth, directory: canManage ? await loadDirectory(client, true) : null };
  },
  component: SettingsPage,
});

const listFormat = new Intl.ListFormat('en', { type: 'disjunction' });

function SettingsPage() {
  const { auth, directory } = Route.useLoaderData();
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
            {auth?.signin
              ? `coffre’s own sign-in, with ${listFormat.format(providers)}. Only invited members get in.`
              : 'Cloudflare Access. coffre has no sign-in of its own; every request carries an Access assertion that is verified at the origin.'}
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
