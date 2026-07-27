import './globals.css';
import type { ReactNode } from 'react';
import { coffreFetch, type Me } from '../lib/api';

export const metadata = {
  title: 'coffre',
  description: 'Secrets, with an audit log',
};

export const dynamic = 'force-dynamic';

export default async function RootLayout({ children }: { children: ReactNode }) {
  const me = await coffreFetch<Me>('/v1/me');

  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="top">
            <div className="brand">
              coffre<span>secrets, with an audit log</span>
            </div>
            <nav className="top-nav">
              <a href="/">Projects</a>
              <a href="/access">Access</a>
              <a href="/audit">Audit log</a>
              {me.ok ? (
                <span className="whoami">
                  {me.data.principal.id} ({me.data.principal.type})
                </span>
              ) : (
                <a href="/login">Sign in</a>
              )}
            </nav>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
