import type { ReactNode } from 'react';

/**
 * The head of every page: a small-caps line of context, a serif title, and the
 * page's own actions, closed off by a heavy rule the way a register opens.
 *
 * `meta` is the line of facts under the rule (counts, your access). Keeping it
 * out of the title block is what lets the title stay one word.
 */
export function PageHeader({
  eyebrow,
  title,
  aside,
  actions,
  lede,
  meta,
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  aside?: ReactNode;
  actions?: ReactNode;
  lede?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <>
      <header className="page-head">
        <div className="page-head-text">
          {eyebrow !== undefined && <div className="eyebrow caps">{eyebrow}</div>}
          <h1 className="page-title">
            <span>{title}</span>
            {aside !== undefined && <span className="page-title-aside">{aside}</span>}
          </h1>
          {lede !== undefined && <p className="page-lede">{lede}</p>}
        </div>
        {actions !== undefined && <div className="page-actions">{actions}</div>}
      </header>
      {meta !== undefined && <div className="page-meta">{meta}</div>}
    </>
  );
}

/** A section of a page: a serif heading on a thin rule, with its own actions. */
export function Section({
  title,
  note,
  actions,
  children,
  labelledBy,
}: {
  title: ReactNode;
  note?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  labelledBy: string;
}) {
  return (
    <section className="section" aria-labelledby={labelledBy}>
      <div className="section-head">
        <div>
          <h2 className="section-title" id={labelledBy}>
            {title}
          </h2>
          {note !== undefined && <p className="section-note">{note}</p>}
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
 * It keeps the page head so the reader still knows where they tried to go,
 * then says why in a sentence and offers the one useful way out.
 */
export function ClosedDoor({
  eyebrow,
  title,
  children,
  actions,
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <>
      <PageHeader eyebrow={eyebrow} title={title} />
      <div className="closed">
        <div className="closed-body">{children}</div>
        {actions !== undefined && <div className="closed-actions">{actions}</div>}
      </div>
    </>
  );
}
