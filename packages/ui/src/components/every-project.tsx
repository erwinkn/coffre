import { useSuspenseQuery } from '@tanstack/react-query';
import type { InheritedGrant } from '@coffre/client';
import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { Notice } from './ui';

/**
 * Grants on every project (`*`, the projects made later too) and on one
 * environment slug in every project (`*` and the slug): only owners give
 * them, from the CLI or the API, and the pages show who holds them.
 */

/** Where a grant on every project is, as people read it: "All projects", or "dev in every project". */
export function everyProjectPlace(environmentSlug: string | null): string {
  return environmentSlug === null ? 'All projects' : `${environmentSlug} in every project`;
}

/** The slug a grant on every project covers, from its path: null for `*`. */
function slugOf(place: string): string | null {
  return place === '*' ? null : place.slice('*/'.length);
}

/** The grants on every project, for those shown them: who makes places, and who manages access. */
export function useEveryProject(): InheritedGrant[] {
  const { data } = useSuspenseQuery(queries.projects(useCoffre()));
  return data.ok ? data.everyProject : [];
}

/** Those grants that reach a place: a project (`environment` null), or an environment of that slug. */
export function reaching(grants: InheritedGrant[], environment: string | null): InheritedGrant[] {
  return grants.filter((grant) => grant.place === '*' || (environment !== null && slugOf(grant.place) === environment));
}

/** A member as a line names them: `ada@acme.example`, or a token's name. */
function who(member: string): string {
  return member.slice(member.indexOf(':') + 1);
}

/**
 * Who reaches a place through grants on every project, said in its dialog
 * before it is made or renamed: making a place there gives them access at once.
 */
export function ReachedBy({ grants, lead }: { grants: InheritedGrant[]; lead: string }) {
  if (grants.length === 0) return null;
  return (
    <Notice tone="info">
      {lead}{' '}
      {grants.map((grant, index) => (
        <span key={`${grant.member} ${grant.place}`}>
          {index > 0 && ', '}
          <strong className="mono">{who(grant.member)}</strong> ({grant.roleName.toLowerCase()},{' '}
          {everyProjectPlace(slugOf(grant.place)).toLowerCase()})
        </span>
      ))}
      .
    </Notice>
  );
}

/** One member's grants on every project, on their page: "All projects · Developer". */
export function EveryProjectGrants({ member }: { member: string }) {
  const grants = useEveryProject().filter((grant) => grant.member === member);
  if (grants.length === 0) return null;
  return (
    <section className="every-project" aria-label="Access to every project">
      <h2 className="section-title">Every project</h2>
      <ul className="every-project-list">
        {grants.map((grant) => (
          <li key={grant.place}>
            <span className={`tag${grant.role === 'owner' ? ' tag-violet' : ''}`}>
              {everyProjectPlace(slugOf(grant.place))} · {grant.roleName}
            </span>
            {grant.expiresAt !== null && <span className="cell-mono cell-muted">until {grant.expiresAt.slice(0, 10)}</span>}
          </li>
        ))}
      </ul>
      <p className="hint">
        Reaches the projects made later too. Owners change it with{' '}
        <span className="mono">coffre grant '*'</span> and <span className="mono">coffre revoke '*'</span>.
      </p>
    </section>
  );
}
