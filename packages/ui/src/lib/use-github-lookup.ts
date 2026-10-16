import { useEffect, useState } from 'react';
import { useCoffre } from './coffre';
import { answered, lookupable, lookupFailure, lookupKey, lookupOf, type GitHubIds, type GitHubLookup, type GitHubLookups } from './bindings';

/** How long a name rests in its field before it is looked up. */
export const LOOKUP_PAUSE_MS = 700;

/**
 * A GitHub repository's or owner's IDs, looked up through coffre once its
 * name has rested in the field for `LOOKUP_PAUSE_MS`, or at once when the
 * field loses focus (`settle`). GitHub answers 60 lookups an hour to a
 * server that does not sign in, shared by everyone a Workers deployment
 * serves, so each name is asked once for as long as the page lives, whatever
 * its case. Nothing public there is final; no answer, such as when the
 * hour's are spent, is asked again on the next `settle`.
 *
 * `remember` records IDs known otherwise, so that they are never asked for:
 * a repository's owner, once the repository is found, or what a picker
 * knows of the repositories it lists.
 */
export function useGitHubLookup(target: { kind: 'repository' | 'owner'; name: string }): {
  lookup: GitHubLookup | null;
  settle: () => void;
  remember: (ids: GitHubIds) => void;
} {
  const coffre = useCoffre();
  const [known, setKnown] = useState<GitHubLookups>(new Map());
  const key = lookupKey(target.name);
  const valid = lookupable(target);
  const lookup = lookupOf(known, target);

  const record = (name: string, answer: GitHubLookup) => setKnown((current) => answered(current, name, answer));

  function remember(ids: GitHubIds) {
    record(ids.github, { state: 'found', ids });
  }

  function ask(name: string) {
    record(name, { state: 'looking' });
    coffre.bindings.lookup({ github: name }).then(
      (ids) => {
        if (!('github' in ids)) return;
        remember(ids);
        // The owner of a repository found is known too: no lookup when the binding turns to the whole organization.
        if ('repositoryId' in ids) remember({ github: ids.github.split('/')[0]!, ownerId: ids.ownerId });
      },
      (failure: unknown) => record(name, lookupFailure(name, failure)),
    );
  }

  useEffect(() => {
    if (!valid || lookup !== null) return;
    const timer = setTimeout(() => ask(target.name), LOOKUP_PAUSE_MS);
    return () => clearTimeout(timer);
    // Once per name: `ask` and the name's spelling may change each render, and a lookup under way is not asked again.
  }, [key, valid, lookup === null]);

  return {
    lookup,
    settle: () => {
      if (valid && (lookup === null || lookup.state === 'failed')) ask(target.name);
    },
    remember,
  };
}
