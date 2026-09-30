import { useState } from 'react';
import { createFileRoute, useLoaderData } from '@tanstack/react-router';
import { signinErrorMessage } from '../lib/signin-errors';
import { ErrorLine, Spinner } from '../components/ui';
import { ClosedDoor } from '../components/page';
import { Lock, ProviderMark, ShieldCheck } from '../components/icons';

export const Route = createFileRoute('/login')({
  // Where to resume after signing in. Same-origin paths only: an absolute URL
  // accepted here would make the sign-in page an open redirect.
  validateSearch: (search: Record<string, unknown>): { next?: string; error?: string } => {
    const out: { next?: string; error?: string } = {};
    const { next, error } = search;
    if (typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')) {
      out.next = next;
    }
    if (typeof error === 'string' && /^[a-z_]{1,40}$/.test(error)) out.error = error;
    return out;
  },
  component: LoginPage,
});

/**
 * The front door, as `GET /api/auth` describes it.
 *
 * With coffre's own sign-in, one button per provider. Behind Cloudflare
 * Access, Access authenticates people before any request arrives, so this
 * page only explains why it is showing at all.
 */
function LoginPage() {
  const { signin, access } = useLoaderData({ from: '__root__' }).auth;
  if (signin !== null) return <ProviderLoginPage {...signin} />;
  return access?.assertion ? <CloudflareAuthenticationFailed /> : <CloudflareAccessRequired />;
}

function CloudflareAccessRequired() {
  return (
    <ClosedDoor icon={<Lock size={18} />} label="Cloudflare Access" title="Open coffre through Access">
      <p>
        This instance has no sign-in of its own. Cloudflare Access authenticates you before
        a request ever reaches coffre, and this request arrived without an Access
        assertion.
      </p>
      <p>
        Use the Access-protected hostname. A request straight to the origin is refused by
        design.
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
        Cloudflare Access forwarded an identity assertion, but coffre could not verify it.
        The Access session may have expired, or the identity verifier may be unavailable.
      </p>
      <p>
        Reopen coffre through its Access-protected hostname. If this keeps happening, tell
        whoever operates coffre.
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
  const { next, error } = Route.useSearch();
  const message = signinErrorMessage(error);
  const [leaving, setLeaving] = useState<string | null>(null);
  const query = next === undefined ? '' : `?next=${encodeURIComponent(next)}`;

  return (
    <section className="card signin" aria-labelledby="signin-title">
      <div className="signin-head">
        <h1 className="signin-title" id="signin-title">
          {title}
        </h1>
        <p className="signin-lede">
          {note ?? 'Sign in with your organization’s account. Only people an owner has invited can get in.'}
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
