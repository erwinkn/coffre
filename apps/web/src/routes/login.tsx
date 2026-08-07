import { useState } from 'react';
import { createFileRoute, useRouter } from '@tanstack/react-router';
import { devSignIn, getLoginAuthState } from '../server-functions/auth';
import { ErrorLine, Notice, Spinner } from '../components/ui';
import { Vault } from '../components/icons';

export const Route = createFileRoute('/login')({
  // Where to resume after signing in. Same-origin paths only: an absolute URL
  // accepted here would make the sign-in page an open redirect.
  validateSearch: (search: Record<string, unknown>): { next?: string } => {
    const next = search.next;
    if (typeof next !== 'string') return {};
    if (!next.startsWith('/') || next.startsWith('//')) return {};
    return { next };
  },
  loader: () => getLoginAuthState(),
  component: LoginPage,
});

const SEEDED: [email: string, role: string, note: string][] = [
  ['erwin@equisafe.io', 'root admin', 'Everything, including the audit log.'],
  ['lead@equisafe.io', 'owner on market', 'Environments, access and secrets.'],
  ['dev@equisafe.io', 'developer', 'Read and write, on market/dev only.'],
  ['auditor@equisafe.io', 'auditor', 'Reads the audit log. Cannot read secret values.'],
  ['accessmgr@equisafe.io', 'access manager', 'Grants access. Cannot read secret values.'],
  ['outsider@equisafe.io', 'no grants', 'Useful for seeing what a denial looks like.'],
];

/**
 * Local sign-in only.
 *
 * There is no login system here and there never will be. In production
 * Cloudflare Access authenticates the user before any request reaches this
 * app. This page exists so the same UI runs locally against the dev IdP.
 */
function LoginPage() {
  const { mode, hasForwardedAccessJwt } = Route.useLoaderData();
  if (mode === 'cloudflare') {
    return hasForwardedAccessJwt ? (
      <CloudflareAuthenticationFailed />
    ) : (
      <CloudflareAccessRequired />
    );
  }
  return <DevLoginPage />;
}

function CloudflareAccessRequired() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Cloudflare Access required</h1>
          <p className="sub">
            This production instance has no local sign-in. Open coffre through its
            Access-protected hostname so Cloudflare can authenticate you before the request
            reaches the application.
          </p>
        </div>
      </div>

      <Notice tone="bad">
        No forwarded Access assertion was present. This is the expected closed door for a
        direct-origin request; no development persona or cookie can bypass it.
      </Notice>
    </>
  );
}

function CloudflareAuthenticationFailed() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Authentication unavailable</h1>
          <p className="sub">
            Cloudflare Access forwarded an identity assertion, but coffre could not
            authenticate it with the API.
          </p>
        </div>
      </div>

      <Notice tone="bad">
        The Access session may have expired, or the API or its identity verifier may be
        unavailable. Reopen the Access-protected hostname; if this continues, contact the
        coffre operator.
      </Notice>
    </>
  );
}

function DevLoginPage() {
  const router = useRouter();
  const { next } = Route.useSearch();
  const [email, setEmail] = useState('erwin@equisafe.io');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function signIn(as: string) {
    setPending(true);
    try {
      const result = await devSignIn({ data: { email: as } });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setError(null);
      // The cookie is set on the response to the server function, so the
      // loaders have to run again before anything reflects the new identity.
      await router.invalidate();
      // `navigate` types `to` against the route tree at compile time, and
      // `next` is only known at runtime, so resuming goes through history.
      if (next === undefined) {
        await router.navigate({ to: '/projects' });
      } else {
        router.history.push(next);
      }
    } catch {
      setError('The sign-in request could not be sent.');
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Sign in</h1>
          <p className="sub">
            Local development only. In production Cloudflare Access authenticates you before
            this page is ever reached, and coffre has no login of its own.
          </p>
        </div>
      </div>

      <div className="card card-pad">
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            signIn(email);
          }}
        >
          <label className="field grow">
            <span className="label">Sign in as</span>
            <input
              className="input"
              name="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@equisafe.io"
            />
          </label>
          <button className="btn btn-primary" type="submit" disabled={pending || email === ''}>
            {pending ? <Spinner /> : <Vault size={14} />}
            Sign in
          </button>
        </form>

        {error !== null && (
          <div style={{ marginTop: 'var(--space-4)' }}>
            <ErrorLine error={error} />
          </div>
        )}
      </div>

      <section className="section">
        <div className="section-head">
          <div>
            <h2>Seeded identities</h2>
            <p className="sub">
              Each one sees a different application. The last three exist to prove that
              reading the audit log and administering access do not require the ability to
              read a single secret.
            </p>
          </div>
        </div>

        <div className="card">
          {SEEDED.map(([seededEmail, role, note]) => (
            <div className="row row-interactive" key={seededEmail}>
              <div className="row-title">
                <span className="row-key">{seededEmail}</span>
                <span className="pill">{role}</span>
              </div>
              <span className="meta">{note}</span>
              <div className="row-actions">
                <button
                  className="btn btn-sm"
                  disabled={pending}
                  onClick={() => {
                    setEmail(seededEmail);
                    signIn(seededEmail);
                  }}
                >
                  Sign in
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
