import { Fragment, type ReactNode } from 'react';

export type TabItem<K extends string> = { key: K; label: string; icon: ReactNode };

/** What a tab's link is handed: its label and whether it is the page shown. */
export type TabLinkProps = { children: ReactNode; 'aria-current': 'page' | undefined };

/**
 * A page's sections as tabs under its header. Each is a link, so a section
 * has a URL; `link` says which, so where tabs live (a search parameter today,
 * nested routes later) changes in the page and not here.
 */
export function PageTabs<K extends string>({
  label,
  tabs,
  current,
  link,
}: {
  label: string;
  tabs: TabItem<K>[];
  current: K;
  link: (key: K, props: TabLinkProps) => ReactNode;
}) {
  // One tab is no choice at all.
  if (tabs.length < 2) return null;
  return (
    <nav className="tabs" aria-label={label}>
      {tabs.map(({ key, label, icon }) => (
        <Fragment key={key}>
          {link(key, {
            children: (
              <>
                {icon}
                {label}
              </>
            ),
            'aria-current': key === current ? 'page' : undefined,
          })}
        </Fragment>
      ))}
    </nav>
  );
}
