import type { IdentityRow, SessionRow } from '@coffre/client';
import { useSuspenseQueries } from '@tanstack/react-query';

import { Fragment } from 'react';
import { useShell } from '../lib/use-shell';
import { Card, Fact, PageHeader } from '../components/page';
import { ThemeCards } from '../components/theme';
import { InstanceRole } from '../components/directory';
import { ConfirmButton, EmptyState, ErrorLine, Notice, Timestamp } from '../components/ui';
import { Monitor, ProviderMark, SignOut, Terminal, X } from '../components/icons';
import { signinErrorMessage } from '../lib/signin-errors';
import { useOneTime } from '../lib/one-time';
import { useCoffre } from '../lib/coffre';
import { endSession, unlinkIdentity } from '../lib/changes';
import { queries } from '../lib/queries';
import { useChange, useChangeStatus } from '../lib/use-change';
import { RowFailure, RowPending, rowClass } from '../components/row-state';
import { pageRoute } from '../lib/page-route';
import type { account } from '../options';

const Route = pageRoute<typeof account>();

type Search = { linked?: string; error?: string };

/**
 * Your own settings: how coffre looks here, who it takes you for and, when
 * coffre runs its own sign-in, which accounts you sign in with and where you
 * are signed in. The sidebar's Settings is the instance's; this page is
 * reached from your account at the sidebar's foot.
 */

export function AccountPage() {
  const { principal, instanceRole, auth } = useShell();

  return (
    <>
      <PageHeader title="Account" actions={principal !== null && <SignOutButton />} />

      <Card labelledBy="appearance" title="Appearance">
        <div className="card-body">
          <ThemeCards />
        </div>
      </Card>

      {principal !== null && (
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
      )}

      {auth.signin !== null && principal?.type === 'user' && (
        <SignIn email={principal.id} providers={auth.signin.providers} />
      )}
    </>
  );
}

/** Which accounts you sign in with, and where you are signed in. */
function SignIn({ email, providers }: { email: string; providers: Provider[] }) {
  const client = useCoffre();
  const [{ data: identities }, { data: sessions }] = useSuspenseQueries({
    queries: [queries.identities(client), queries.sessions(client)],
  });
  if (!identities.ok) return <ErrorLine error={identities.error} />;
  if (!sessions.ok) return <ErrorLine error={sessions.error} />;
  return (
    <>
      <SigninAccounts email={email} providers={providers} identities={identities.identities} />
      <Sessions sessions={sessions.sessions} providers={providers} />
    </>
  );
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

function SigninAccounts({
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
