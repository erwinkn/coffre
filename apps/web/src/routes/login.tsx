import { useState } from 'react';
import { createFileRoute, useRouter } from '@tanstack/react-router';
import { devSignIn, getLoginAuthState } from '../server-functions/auth';
import { ErrorLine, Spinner } from '../components/ui';
import { ClosedDoor, PageHeader, Section } from '../components/page';
import { ArrowRight } from '../components/icons';

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
  ['erwin@equisafe.io', 'root admin', 'Everything, including the audit log and the directory.'],
  ['lead@equisafe.io', 'owner of market', 'Environments, access and secrets on one project.'],
  ['dev@equisafe.io', 'developer', 'Reads and writes secrets on market/dev only.'],
  ['auditor@equisafe.io', 'auditor', 'Reads the audit log. Cannot read a single secret value.'],
  ['accessmgr@equisafe.io', 'access manager', 'Grants and revokes access. Cannot read secret values.'],
  ['outsider@equisafe.io', 'no grants', 'Registered, but holds nothing. What a denial looks like.'],
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
    <ClosedDoor eyebrow="Cloudflare Access" title="Open coffre through Access">
      <p>
        This instance has no sign-in of its own. Cloudflare Access authenticates you before
        a request ever reaches coffre, and this request arrived without an Access
        assertion.
      </p>
      <p style={{ marginTop: '0.875rem' }}>
        Use the Access-protected hostname. A request straight to the origin is refused by
        design, and no development persona or cookie can get around that.
      </p>
    </ClosedDoor>
  );
}

function CloudflareAuthenticationFailed() {
  return (
    <ClosedDoor eyebrow="Cloudflare Access" title="Your identity could not be confirmed">
      <p>
        Cloudflare Access forwarded an identity assertion, but coffre could not verify it.
        The Access session may have expired, or the identity verifier may be unavailable.
      </p>
      <p style={{ marginTop: '0.875rem' }}>
        Reopen coffre through its Access-protected hostname. If this keeps happening, tell
        whoever operates coffre.
      </p>
    </ClosedDoor>
  );
}

function DevLoginPage() {
  const router = useRouter();
  const { next } = Route.useSearch();
  const [email, setEmail] = useState('erwin@equisafe.io');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  async function signIn(as: string) {
    setPending(as);
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
      setPending(null);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Local development"
        title="Sign in"
        lede="In production, Cloudflare Access authenticates you before any request reaches coffre, and there is no sign-in page at all. Locally, choose who to be."
      />

      <form
        className="signin-form"
        onSubmit={(event) => {
          event.preventDefault();
          void signIn(email);
        }}
      >
        <label className="field">
          <span className="caps">Email</span>
          <input
            className="input input-mono"
            name="email"
            type="email"
            autoComplete="off"
            spellCheck={false}
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@equisafe.io"
          />
        </label>
        <button
          className="btn btn-primary"
          type="submit"
          style={{ height: '2.375rem' }}
          disabled={pending !== null || email === ''}
        >
          {pending === email && <Spinner />}
          Sign in
        </button>
      </form>

      {error !== null && (
        <div style={{ marginTop: '0.875rem' }}>
          <ErrorLine error={error} />
        </div>
      )}

      <Section
        labelledBy="seeded-identities"
        title="Seeded identities"
        note="Each sees a different coffre. The auditor and the access manager exist to prove that reading the log and granting access need no power to read a secret."
      >
        <ul className="personas">
          {SEEDED.map(([seededEmail, role, note]) => (
            <li key={seededEmail}>
              <button
                type="button"
                className="persona"
                disabled={pending !== null}
                onClick={() => {
                  setEmail(seededEmail);
                  void signIn(seededEmail);
                }}
              >
                <span className="persona-who">
                  <span className="persona-email">{seededEmail}</span>
                  <span className="tag tag-outline">{role}</span>
                </span>
                <span className="persona-note">{note}</span>
                <span className="persona-go" aria-hidden>
                  {pending === seededEmail ? <Spinner size={13} /> : <ArrowRight size={14} />}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </Section>
    </>
  );
}
