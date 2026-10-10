import { useState } from 'react';

import { useShell } from '../lib/use-shell';
import { signinErrorMessage } from '../lib/signin-errors';
import { useOneTime } from '../lib/one-time';
import { ErrorLine, Spinner } from '../components/ui';
import { ClosedDoor } from '../components/page';
import { Lock, ProviderMark, ShieldCheck } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { login } from '../options';

const Route = pageRoute<typeof login>();

/**
 * The front door, as `GET /api/auth` describes it.
 *
 * With coffre's own sign-in, one button per provider. Behind Cloudflare
 * Access, Access authenticates people before any request arrives, so this
 * page only explains why it is showing at all.
 */
export function LoginPage() {
  const { signin, access } = useShell().auth;
  if (signin !== null) return <ProviderLoginPage {...signin} />;
  return access?.assertion ? <CloudflareAuthenticationFailed /> : <CloudflareAccessRequired />;
}

function CloudflareAccessRequired() {
  return (
    <ClosedDoor icon={<Lock size={18} />} label="Cloudflare Access" title="Open coffre through Access">
      <p>
        Cloudflare Access signs you in to coffre, and this request did not come through it.
        Open coffre at its Access-protected hostname.
      </p>
    </ClosedDoor>
  );
}

function CloudflareAuthenticationFailed() {
  return (
    <ClosedDoor
      icon={<ShieldCheck size={18} />}
      label="Cloudflare Access"
      title="Your identity could not be confirmed"
    >
      <p>
        coffre could not verify the identity Cloudflare Access sent. Your Access session may
        have expired.
      </p>
      <p>
        Reopen coffre through its Access-protected hostname. If this keeps happening, tell
        whoever runs coffre.
      </p>
    </ClosedDoor>
  );
}

function ProviderLoginPage({
  title,
  note,
  providers,
}: {
  title: string;
  note: string | null;
  providers: { id: string; label: string; brand: string }[];
}) {
  const search = Route.useSearch();
  const { next } = search;
  // Shown once: a reload is a clean retry.
  const once = useOneTime(search, ['error', 'with', 'via']);
  const label = (id: string) => providers.find((provider) => provider.id === id)?.label;
  const already = (once.with ?? '').split(',').map(label).filter((name): name is string => name !== undefined);
  const message = signinErrorMessage(once.error, { providers: already, via: once.via === undefined ? undefined : label(once.via) });
  const [leaving, setLeaving] = useState<string | null>(null);
  const query = next === undefined ? '' : `?next=${encodeURIComponent(next)}`;

  return (
    <section className="card signin" aria-labelledby="signin-title">
      <div className="signin-head">
        <h1 className="signin-title" id="signin-title">
          {title}
        </h1>
        <p className="signin-lede">
          {note ?? 'Sign in with your organization’s account. Only people an admin has invited can get in.'}
        </p>
      </div>

      {message !== null && (
        <div className="signin-error">
          <ErrorLine error={message} />
        </div>
      )}

      {providers.length === 0 ? (
        <p className="signin-empty">
          No sign-in provider is configured. Whoever runs coffre lists them in{' '}
          <span className="mono">signin({'{'} providers {'}'})</span>.
        </p>
      ) : (
        <ul className="providers">
          {providers.map((provider) => (
            <li key={provider.id}>
              {/* A plain link: the provider's page is a full navigation away. */}
              <a
                className="btn provider"
                href={`/auth/signin/${encodeURIComponent(provider.id)}${query}`}
                aria-busy={leaving === provider.id}
                onClick={() => setLeaving(provider.id)}
              >
                <span className="provider-mark" aria-hidden>
                  {leaving === provider.id ? <Spinner /> : <ProviderMark brand={provider.brand} />}
                </span>
                Continue with {provider.label}
              </a>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
