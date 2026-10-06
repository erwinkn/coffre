import { useState } from 'react';
import type { AuthorizationView, RouteInput } from '@coffre/client';
import { MCP_SCOPE_INFO, MCP_SCOPES, supersedes, type McpScope } from '@coffre/core/mcp';

import { failureMessage, statusOf, useCoffre } from '../lib/coffre';
import { ClosedDoor } from '../components/page';
import { ErrorLine, Notice, Spinner } from '../components/ui';
import { ArrowRight, Link as LinkIcon, SlashCircle } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { oauthAuthorize } from '../options';

const Route = pageRoute<typeof oauthAuthorize>();

type Ready = Extract<AuthorizationView, { status: 'ready' }>;

/**
 * Where an MCP client, such as Claude, sends you to connect: who it is,
 * where coffre's answer goes, and what it may do as you, of every scope,
 * whatever it asked for: what it asked for starts ticked. Nothing is granted
 * until you press Approve, and every connection asks again: there is no
 * silent re-consent. Either answer goes back to the app by `location`,
 * never a form post, which the page's `form-action 'self'` would stop.
 */

export function OauthAuthorizePage() {
  const loaded = Route.useLoaderData();
  const [leaving, setLeaving] = useState(false);

  if (leaving) {
    return (
      <ClosedDoor icon={<ArrowRight size={18} />} label="Connect an app" title="Sending you back to the app">
        <p>You can close this tab if the app has already opened.</p>
      </ClosedDoor>
    );
  }
  if (!loaded.result.ok) return <CannotConnect message={loaded.result.error} />;
  const view = loaded.result;
  if (view.status === 'invalid') return <CannotConnect message={view.message} />;
  if (view.status === 'refused') {
    return (
      <ClosedDoor
        icon={<SlashCircle size={18} />}
        label="Connect an app"
        title="This request can't be approved"
        actions={
          <button
            className="btn"
            onClick={() => {
              setLeaving(true);
              location.assign(view.redirect);
            }}
          >
            Back to the app
          </button>
        }
      >
        <p>{view.message}. Nothing was granted.</p>
      </ClosedDoor>
    );
  }
  return (
    <Approve
      view={view}
      email={loaded.email}
      request={loaded.request}
      onLeave={(redirect) => {
        setLeaving(true);
        location.assign(redirect);
      }}
    />
  );
}

/** A client or redirect that fails its checks: said here, and never redirected to, which would be an open redirect. */
function CannotConnect({ message }: { message: string }) {
  return (
    <ClosedDoor icon={<SlashCircle size={18} />} label="Connect an app" title="This app can't connect">
      <p>{message}</p>
      <p>Nothing was sent to it. If you were trying to connect it, tell whoever makes it.</p>
    </ClosedDoor>
  );
}

function Approve({
  view,
  email,
  request,
  onLeave,
}: {
  view: Ready;
  email: string;
  request: RouteInput<'GET /oauth/authorizations'>;
  onLeave: (redirect: string) => void;
}) {
  const coffre = useCoffre();
  const [chosen, setChosen] = useState<ReadonlySet<McpScope>>(() => new Set(view.scopes));
  const [pending, setPending] = useState<'approve' | 'deny' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { client } = view;
  const unverified = client.registration === 'dcr';
  // A step-up: the connections this one grants all of and more end once the app has its new one.
  const granted = MCP_SCOPES.filter((scope) => chosen.has(scope));
  const replaced = view.connections.filter((held) => supersedes(granted, held)).length;
  const kept = view.connections.length - replaced;

  async function decide(approve: boolean) {
    setPending(approve ? 'approve' : 'deny');
    try {
      const { redirect } = await coffre.oauth.decide({ request, approve, scopes: [...chosen] });
      onLeave(redirect);
    } catch (error) {
      setError(
        statusOf(error) === undefined ? 'The answer could not be sent. Nothing was approved.' : failureMessage(error),
      );
      setPending(null);
    }
  }

  function toggle(scope: McpScope, on: boolean) {
    const next = new Set(chosen);
    if (on) next.add(scope);
    else next.delete(scope);
    setChosen(next);
  }

  return (
    <section className="card signin" aria-labelledby="consent-title">
      <div className="signin-head">
        <h1 className="signin-title" id="consent-title">
          Connect {client.name} to coffre?
        </h1>
      </div>

      <div className="consent-client">
        <LinkIcon size={16} />
        {/* The website first, which a name cannot fake; a registration has none, and says so. */}
        <span className="cell-stack">
          {client.host !== null ? (
            <span className="consent-host mono">{client.host}</span>
          ) : (
            <span className="consent-host">{client.name}</span>
          )}
          <span>
            {client.host !== null && <>{client.name} </>}
            {unverified && <span className="tag tag-amber">Unverified</span>}
            {unverified && <small> It registered itself: its name is its own claim.</small>}
          </span>
        </span>
      </div>

      <dl className="facts device-facts">
        <div className="fact">
          <dt>As</dt>
          <dd className="mono">{email}</dd>
        </div>
        <div className="fact">
          <dt>Answer goes to</dt>
          <dd className="mono">{view.redirectHost}</dd>
        </div>
        <div className="fact">
          <dt>For</dt>
          <dd>{view.days} days</dd>
        </div>
      </dl>

      <fieldset className="consent-scopes">
        <legend className="label">
          It may <span className="hint">· to add a scope later, you connect it again</span>
        </legend>
        {MCP_SCOPES.map((scope) => {
          const { label, description } = MCP_SCOPE_INFO[scope];
          const locked = scope === 'read';
          return (
            <label key={scope} className="consent-scope">
              <input
                type="checkbox"
                checked={chosen.has(scope)}
                disabled={locked || pending !== null}
                onChange={(event) => toggle(scope, event.target.checked)}
              />
              <span className="cell-stack">
                <span>
                  {label}
                  {locked && <span className="hint"> · always</span>}
                </span>
                <small>{description}</small>
              </span>
            </label>
          );
        })}
      </fieldset>

      <div className="consent-notices">
        {chosen.has('reveal') && (
          <Notice tone="bad">
            Values will be sent to {client.name}, into the conversation. Anyone who can read that
            conversation, wherever {client.name} stores it, has them.
          </Notice>
        )}
        {view.loopbackOnly && (
          <Notice tone="warn">
            The answer goes to a program on this computer, <span className="mono">{view.redirectHost}</span>.
            Any program running here could be it. Approve only if you just started {client.name} yourself.
          </Notice>
        )}
        {replaced > 0 && (
          <Notice tone="info">
            This replaces your earlier connection{replaced === 1 ? '' : 's'} of {client.name}.
          </Notice>
        )}
        {kept > 0 && (
          <Notice tone="info">
            You have connected {client.name} {kept === 1 ? 'once' : `${kept} times`} already.
            This adds another connection.
          </Notice>
        )}
        <ErrorLine error={error} />
      </div>

      <div className="device-actions">
        <button className="btn" disabled={pending !== null} onClick={() => void decide(false)}>
          {pending === 'deny' && <Spinner />}
          Deny
        </button>
        <button className="btn btn-primary" disabled={pending !== null} onClick={() => void decide(true)}>
          {pending === 'approve' && <Spinner />}
          Approve
        </button>
      </div>
    </section>
  );
}
