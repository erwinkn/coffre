import { Children, type ReactNode } from 'react';

/**
 * A page's sections as tabs under its header. Each is a `<Link>` to a route
 * nested under the page's layout, the first to its index with
 * `activeOptions={{ exact: true, includeSearch: false }}`, and the router
 * marks the one shown `aria-current="page"`. The caller leaves out a tab
 * nobody may open.
 */
export function PageTabs({ label, children }: { label: string; children: ReactNode }) {
  // One tab is no choice at all.
  if (Children.toArray(children).length < 2) return null;
  return (
    <nav className="tabs" aria-label={label}>
      {children}
    </nav>
  );
}
