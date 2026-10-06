import type { IdentityRow, SessionRow } from '@coffre/client';
import { Link, Outlet } from '@tanstack/react-router';
import { useSuspenseQuery } from '@tanstack/react-query';

import { Fragment } from 'react';
import { useShell } from '../lib/use-shell';
import { Card, Fact, PageHeader } from '../components/page';
import { PageTabs } from '../components/tabs';
import { ThemeCards } from '../components/theme';
import { InstanceRole } from '../components/directory';
import { ConfirmButton, CopyButton, EmptyState, ErrorLine, Notice, Timestamp } from '../components/ui';
import { Link as LinkIcon, Monitor, ProviderMark, SignOut, Sun, Terminal, User, X } from '../components/icons';
import { signinErrorMessage } from '../lib/signin-errors';
import { useOneTime } from '../lib/one-time';
import { useCoffre } from '../lib/coffre';
import { useMounted } from '../lib/mounted';
import { disconnectApp, endSession, unlinkIdentity } from '../lib/changes';
import { queries } from '../lib/queries';
import { useChange, useChangeStatus } from '../lib/use-change';
import { RowFailure, RowPending, rowClass } from '../components/row-state';
import { ConnectedAppsCard } from '../components/connected-apps';
import { pageRoute } from '../lib/page-route';
import type { accountProfile } from '../options';

const Route = pageRoute<typeof accountProfile>();

/**
 * Your own account, around its tabs: who coffre takes you for and, when
 * coffre runs its own sign-in, which accounts you sign in with, where you
 * are signed in, the MCP clients you connected, and how coffre looks here.
 * The sidebar's Settings is the instance's; this page is reached from your
 * account at the sidebar's foot. It keeps the name it had as one page, which
 * a deployment's `_coffre/account.tsx` mounts.
 */
export function AccountPage() {
  const { principal, auth, features } = useShell();
  const mounted = useMounted();
  const person = principal?.type === 'user';

  return (
    <>
      <PageHeader title="Account" actions={principal !== null && <SignOutButton />} />

      <PageTabs label="Account sections">
        {[
          <Link key="profile" to="/account" activeOptions={{ exact: true, includeSearch: false }}>
            <User size={15} />
            Profile
          </Link>,
          person && auth.signin !== null && mounted('/account/sessions') && (
            <Link key="sessions" to="/account/sessions">
              <Monitor size={15} />
              Sessions
            </Link>
          ),
          person && features.mcp && mounted('/account/apps') && (
            <Link key="apps" to="/account/apps">
              <LinkIcon size={15} />
              Connected apps
            </Link>
          ),
          mounted('/account/appearance') && (
            <Link key="appearance" to="/account/appearance">
              <Sun size={15} />
              Appearance
            </Link>
          ),
        ]}
      </PageTabs>

      <Outlet />
    </>
  );
}

/** Its first tab: who you are to coffre, and the accounts you sign in with. */
export function AccountProfilePage() {
  const { principal, instanceRole, auth } = useShell();
  if (principal === null) return null;
  return (
    <>
      <Card labelledBy="identity" title="Identity">
        <dl className="facts">
          <Fact label={principal.type === 'user' ? 'Email' : 'Name'}>
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

      {auth.signin !== null && principal.type === 'user' && (
        <SigninAccounts email={principal.id} providers={auth.signin.providers} />
      )}
    </>
  );
}

/** Where you are signed in, browsers and command lines. */
export function AccountSessionsPage() {
  const { auth } = useShell();
  const { data: sessions } = useSuspenseQuery(queries.sessions(useCoffre()));
  if (!sessions.ok) return <ErrorLine error={sessions.error} />;
  return <Sessions sessions={sessions.sessions} providers={auth.signin?.providers ?? []} />;
}

/** How to connect Claude, then the apps you connected. */
export function AccountAppsPage() {
  const { features } = useShell();
  return (
    <>
      {features.mcp !== null && <ConnectAnApp url={features.mcp} />}
      <ConnectedApps />
    </>
  );
}

/** How coffre looks in this browser. */
export function AccountAppearancePage() {
  return <ThemeCards />;
}

/**
 * Sign-out is a form post: a GET could be triggered by any image tag on any
 * page, and the server's origin check covers form posts.
 */
function SignOutButton() {
  return (
    <form method="post" action="/auth/signout">
      <button className="btn" type="submit">
        <SignOut size={14} />
        Sign out
      </button>
    </form>
  );
}

type Provider = { id: string; label: string; brand: string };

function providerLabel(providers: Provider[], id: string | null) {
  return providers.find((provider) => provider.id === id)?.label ?? id ?? 'unknown';
}

/** Which accounts you sign in with. */
function SigninAccounts({ email, providers }: { email: string; providers: Provider[] }) {
  const { data } = useSuspenseQuery(queries.identities(useCoffre()));
  if (!data.ok) return <ErrorLine error={data.error} />;
  return <SigninAccountsCard email={email} providers={providers} identities={data.identities} />;
}

function SigninAccountsCard({
  email,
  providers,
  identities,
}: {
  email: string;
  providers: Provider[];
  identities: IdentityRow[];
}) {
  // Shown once: a reload shows the accounts, not the last link's outcome again.
  const { linked, error } = useOneTime(Route.useSearch(), ['linked', 'error']);
  const message = signinErrorMessage(error);
  const change = unlinkIdentity(useCoffre());
  const unlink = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);

  return (
    <>
      <Card
        labelledBy="signin-accounts"
        title="Sign-in accounts"
        description="coffre recognises you by these accounts, never by an email address alone. A new account is linked here, while you are signed in."
      >
        {(linked !== undefined || message !== null) && (
          <div className="card-body">
            {linked !== undefined && (
              <Notice tone="good">{providerLabel(providers, linked)} account linked.</Notice>
            )}
            <ErrorLine error={message} />
          </div>
        )}

        {identities.length === 0 ? (
          <EmptyState title="No account linked">
            Your next sign-in with a verified <span className="mono">{email}</span> links that
            account.
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt stacks stacks-inline">
              <thead>
                <tr>
                  <th>Account</th>
                  <th className="col-shrink">Linked (UTC)</th>
                  <th className="col-shrink">Last sign-in</th>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {identities.map((identity) => {
                  const label = providerLabel(providers, identity.provider);
                  const brand = providers.find((p) => p.id === identity.provider)?.brand ?? 'oidc';
                  const state = status(identity.id);
                  return (
                    <Fragment key={identity.id}>
                      <tr className={rowClass(state)}>
                        <td>
                          <span className="cell-account">
                            <ProviderMark brand={brand} />
                            <span className="cell-stack">
                              <span>{label}</span>
                              {identity.email !== null && <small className="mono">{identity.email}</small>}
                            </span>
                          </span>
                        </td>
                        <td className="nowrap" data-label="Linked (UTC)">
                          <Timestamp iso={identity.createdAt} />
                        </td>
                        <td className="nowrap cell-muted" data-label="Last sign-in">
                          {identity.lastSignInAt === null ? (
                            'Never'
                          ) : (
                            <Timestamp iso={identity.lastSignInAt} display="relative" />
                          )}
                        </td>
                        <td className="col-actions">
                          {state.state === 'pending' ? (
                            <RowPending status={state} />
                          ) : (
                            <ConfirmButton
                              trigger={
                                <button className="act">
                                  <X size={13} />
                                  Unlink
                                </button>
                              }
                              title={`Unlink this ${label} account?`}
                              body={
                                identities.length === 1 ? (
                                  <>
                                    It stops signing you in, and every session it opened ends now,
                                    this one included if you signed in with it. Your next sign-in
                                    with any account whose verified email is{' '}
                                    <span className="mono">{email}</span> links that account instead.
                                  </>
                                ) : (
                                  <>
                                    It stops signing you in, and every session it opened ends now,
                                    this one included if you signed in with it.
                                  </>
                                )
                              }
                              confirmLabel="Unlink"
                              onConfirm={() => unlink({ ...identity, label })}
                            />
                          )}
                        </td>
                      </tr>
                      <RowFailure
                        status={state}
                        columns={4}
                        onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)}
                      />
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {providers.length > 0 && (
        <div className="table-actions">
          <span className="hint">Link another account</span>
          {providers.map((provider) => (
            <a
              key={provider.id}
              className="btn"
              href={`/auth/signin/${encodeURIComponent(provider.id)}?link=1`}
            >
              <ProviderMark brand={provider.brand} size={14} />
              {provider.label}
            </a>
          ))}
        </div>
      )}
    </>
  );
}

function Sessions({
  sessions,
  providers,
}: {
  sessions: SessionRow[];
  providers: Provider[];
}) {
  const change = endSession(useCoffre());
  const end = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);

  return (
    <Card
      labelledBy="sessions"
      title="Sessions"
      description="Browsers and command lines signed in as you. Ending one signs it out at its next request."
    >
      {sessions.length === 0 ? (
        <EmptyState title="No sessions">Nothing is signed in as you right now.</EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt stacks stacks-inline">
            <thead>
              <tr>
                <th>Where</th>
                <th className="col-shrink">Last active</th>
                <th className="col-shrink">Expires</th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => {
                const state = status(session.id);
                return (
                  <Fragment key={session.id}>
                    <tr className={rowClass(state)}>
                      <td>
                        <span className="cell-account">
                          {session.kind === 'cli' ? <Terminal size={15} /> : <Monitor size={15} />}
                          <span className="cell-stack">
                            <span>
                              {session.label ?? (session.kind === 'cli' ? 'Command line' : 'Browser')}{' '}
                              {session.current && <span className="tag tag-blue">This browser</span>}
                            </span>
                            <small>
                              {session.kind === 'cli'
                                ? 'coffre login'
                                : `via ${providerLabel(providers, session.provider)}`}
                              {session.lastUsedIp !== null && (
                                <>
                                  {' · '}
                                  <span className="mono">{session.lastUsedIp}</span>
                                </>
                              )}
                            </small>
                          </span>
                        </span>
                      </td>
                      <td className="nowrap cell-muted" data-label="Last active">
                        <Timestamp iso={session.lastUsedAt ?? session.createdAt} display="relative" />
                      </td>
                      <td className="nowrap cell-muted" data-label="Expires">
                        <Timestamp iso={session.expiresAt} display="relative" />
                      </td>
                      <td className="col-actions">
                        {session.current ? (
                          <form method="post" action="/auth/signout">
                            <button className="act" type="submit">
                              <SignOut size={13} />
                              Sign out
                            </button>
                          </form>
                        ) : state.state === 'pending' ? (
                          <RowPending status={state} />
                        ) : (
                          <ConfirmButton
                            trigger={
                              <button className="act">
                                <X size={13} />
                                End
                              </button>
                            }
                            title={`End this ${session.kind === 'cli' ? 'command line' : 'browser'} session?`}
                            body={
                              <>
                                {session.label ?? (session.kind === 'cli' ? 'The command line' : 'The browser')}
                                {session.lastUsedIp !== null && (
                                  <>
                                    {' '}at <span className="mono">{session.lastUsedIp}</span>
                                  </>
                                )}
                                , last active{' '}
                                <Timestamp iso={session.lastUsedAt ?? session.createdAt} display="relative" />, is
                                signed out at its next request.
                              </>
                            }
                            confirmLabel="End session"
                            onConfirm={() => end(session)}
                          />
                        )}
                      </td>
                    </tr>
                    <RowFailure
                      status={state}
                      columns={4}
                      onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)}
                    />
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** How to connect an MCP client: this instance's endpoint, as `/me` reports it, and the steps for Claude Code and claude.ai. */
function ConnectAnApp({ url }: { url: string }) {
  return (
    <Card
      labelledBy="connect"
      title="Connect an app"
      description="Claude, or another MCP client, connects at this address. It asks you to approve it here, then acts as you."
    >
      <dl className="facts">
        <Fact label="MCP URL">
          <CopyLine value={url} label="Copy the URL" />
        </Fact>
        <Fact label="Claude Code">
          <CopyLine value={`claude mcp add --transport http coffre ${url}`} label="Copy the command" />
          <span className="hint">
            Then run <span className="mono">/mcp</span> in Claude Code to sign in.
          </span>
        </Fact>
        <Fact label="claude.ai">
          <span>In Customize › Connectors, choose Add custom connector, then paste the URL.</span>
        </Fact>
      </dl>
    </Card>
  );
}

/** A value to copy whole, in a box of its own. */
function CopyLine({ value, label }: { value: string; label: string }) {
  return (
    <div className="copy-line">
      <code className="mono">{value}</code>
      <CopyButton value={value} label={label} />
    </div>
  );
}

/** The MCP clients you connected, such as Claude: each acts as you until it is disconnected or expires. */
function ConnectedApps() {
  const client = useCoffre();
  const { data: apps } = useSuspenseQuery(queries.apps(client));
  return (
    <ConnectedAppsCard
      apps={apps.ok ? apps.apps : { error: apps.error }}
      change={disconnectApp(client)}
      description="Each acts as you, never beyond your access, and every call it makes is in the audit log. Disconnecting one stops it at its next request."
      empty="An app you connect shows here once you approve it."
    />
  );
}
