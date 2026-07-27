export const dynamic = 'force-dynamic';

/**
 * Local sign-in only.
 *
 * There is no login system here and there never will be. In production
 * Cloudflare Access authenticates the user before any request reaches this
 * app. This page exists so the same UI runs locally against the dev IdP.
 */
export default function LoginPage() {
  return (
    <>
      <h1>Sign in</h1>
      <p className="sub">
        Local development only. In production Cloudflare Access authenticates you before
        this page is ever reached, and coffre has no login of its own.
      </p>

      <div className="card">
        <form action="/api/session" method="post" className="form-row">
          <input
            className="grow"
            name="email"
            type="email"
            defaultValue="erwin@equisafe.io"
            placeholder="you@equisafe.io"
          />
          <button className="primary" type="submit">
            Sign in as this user
          </button>
        </form>
      </div>

      <h2>Seeded identities</h2>
      <div className="card">
        {[
          ['erwin@equisafe.io', 'root admin — everything, plus the audit log'],
          ['lead@equisafe.io', 'project admin on market — environments and access'],
          ['dev@equisafe.io', 'write, on market/dev only'],
          ['auditor@equisafe.io', 'read across the whole market project'],
          ['outsider@equisafe.io', 'no grants — useful for seeing a denial'],
        ].map(([email, description]) => (
          <div className="row" key={email}>
            <div className="key">{email}</div>
            <span className="meta">{description}</span>
          </div>
        ))}
      </div>
    </>
  );
}
