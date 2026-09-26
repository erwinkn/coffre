import type { ReactNode } from 'react';
import { Tile } from './tile';

/**
 * The head of every page: an optional project tile, the title with a muted
 * aside, one line of description or facts, and the page's own actions.
 *
 * Where you are is already in the top bar's path, so the head does not repeat
 * it; it says what this page is.
 */
export function PageHeader({
  tile,
  lead,
  title,
  aside,
  description,
  meta,
  actions,
}: {
  tile?: string;
  /** Stands where the tile would, for pages that are not about a project. */
  lead?: ReactNode;
  title: ReactNode;
  aside?: ReactNode;
  description?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div className="page-head-text">
        {tile !== undefined && <Tile name={tile} size="lg" />}
        {lead}
        <div style={{ minWidth: 0 }}>
          <h1 className="page-title">
            <span>{title}</span>
            {aside !== undefined && aside !== null && (
              <span className="page-title-aside">{aside}</span>
            )}
          </h1>
          {description !== undefined && <p className="page-desc">{description}</p>}
          {meta !== undefined && <div className="page-meta">{meta}</div>}
        </div>
      </div>
      {actions !== undefined && actions !== false && (
        <div className="page-actions">{actions}</div>
      )}
    </header>
  );
}

/** A bordered panel with a titled head; tables inside it run edge to edge. */
export function Card({
  title,
  description,
  actions,
  children,
  labelledBy,
  tone,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  labelledBy: string;
  tone?: 'danger';
}) {
  return (
    <section
      className={`card${tone === 'danger' ? ' card-danger' : ''}`}
      aria-labelledby={labelledBy}
    >
      <div className="card-head">
        <div>
          <h2 className="card-title" id={labelledBy}>
            {title}
          </h2>
          {description !== undefined && <p className="card-desc">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

/**
 * A page that cannot be shown: no access, no such thing, or no session.
 *
 * It says which page, why in a sentence, and offers the one useful way out.
 */
export function ClosedDoor({
  icon,
  label,
  title,
  children,
  actions,
}: {
  icon?: ReactNode;
  label?: ReactNode;
  title: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="closed" role="status">
      {icon !== undefined && (
        <div className="closed-icon" aria-hidden>
          {icon}
        </div>
      )}
      {label !== undefined && <p className="closed-label">{label}</p>}
      <h1 className="closed-title">{title}</h1>
      <div className="closed-body">{children}</div>
      {actions !== undefined && <div className="closed-actions">{actions}</div>}
    </div>
  );
}
