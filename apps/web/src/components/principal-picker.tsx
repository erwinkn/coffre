import { useEffect, useId, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { listDirectoryPrincipals } from '../server-functions/access';
import { projectAccessLabel } from '../lib/project-access';
import type { DirectoryPrincipal, GrantRow } from '../shared/models';
import { KIND } from './directory';
import { PrincipalAvatar } from './principal';
import { Spinner } from './ui';
import { Check, Search } from './icons';

type PrincipalType = DirectoryPrincipal['principalType'];
type Directory = Awaited<ReturnType<typeof listDirectoryPrincipals>>;

/**
 * Who a grant is for: picked from the registered users or tokens, each shown
 * with what it already holds on this project, or typed when the list is not
 * yours to read.
 *
 * Only instance owners may list the directory. Asking on anyone else's behalf
 * would write a refusal to the audit log in their name, so they get a text
 * field and the server's answer instead. The list is asked for when the
 * dialog opens rather than with the page, since most visits never open it.
 */
export function PrincipalPicker({
  principalType,
  canList,
  grants,
  value,
  onChange,
}: {
  principalType: PrincipalType;
  /** Whether you may list the directory: instance owners only. */
  canList: boolean;
  /** The project's grants, to show what each entry already holds. */
  grants: GrantRow[];
  value: string;
  onChange: (principalId: string) => void;
}) {
  const [directory, setDirectory] = useState<Directory | null>(null);
  const [query, setQuery] = useState('');
  const name = useId();
  const kind = KIND[principalType];
  const label = principalType === 'user' ? 'User' : 'Token';

  useEffect(() => {
    if (!canList) return;
    let live = true;
    void listDirectoryPrincipals().then((result) => {
      if (live) setDirectory(result);
    });
    return () => {
      live = false;
    };
  }, [canList]);

  if (!canList || directory?.ok === false) {
    return (
      <label className="field">
        <span className="label">
          {principalType === 'user' ? 'Email' : 'Service token common name'}
        </span>
        <input
          className="input input-mono"
          autoFocus
          spellCheck={false}
          autoComplete="off"
          placeholder={principalType === 'user' ? 'someone@acme.example' : 'ci-deploy.access'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
        <span className="hint">
          The {kind} must already be registered under {principalType === 'user' ? 'Users' : 'Tokens'}.
        </span>
      </label>
    );
  }

  const registered =
    directory?.principals.filter((principal) => principal.principalType === principalType) ?? [];
  const needle = query.trim().toLowerCase();
  const matches = registered.filter((principal) =>
    principal.principalId.toLowerCase().includes(needle),
  );

  return (
    <fieldset className="field picker">
      <legend className="label">{label}</legend>

      <label className="input-group">
        <span className="visually-hidden">Filter {kind}s by name</span>
        <Search size={14} className="input-icon" />
        <input
          className="input"
          type="search"
          autoFocus
          spellCheck={false}
          autoComplete="off"
          placeholder={principalType === 'user' ? 'Filter by email…' : 'Filter by name…'}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            // Narrowed to one, Enter picks it rather than sending the form.
            if (event.key === 'Enter' && matches.length === 1) {
              event.preventDefault();
              onChange(matches[0].principalId);
            }
          }}
        />
      </label>

      <div className="picker-list">
        {directory === null ? (
          <p className="picker-empty">
            <Spinner size={13} />
            Loading {kind}s…
          </p>
        ) : registered.length === 0 ? (
          <p className="picker-empty">
            No {kind}s are registered yet.{' '}
            <Link to={principalType === 'user' ? '/users' : '/tokens'}>Add one</Link> first.
          </p>
        ) : matches.length === 0 ? (
          <p className="picker-empty">No registered {kind} matches “{query.trim()}”.</p>
        ) : (
          matches.map((principal) => {
            const held = grants
              .filter(
                (grant) =>
                  grant.principalType === principalType &&
                  grant.principalId === principal.principalId,
              )
              .map(projectAccessLabel);
            const chosen = principal.principalId === value;
            return (
              <label
                key={principal.principalId}
                className={`picker-option${chosen ? ' is-chosen' : ''}`}
              >
                <input
                  type="radio"
                  className="visually-hidden"
                  name={name}
                  value={principal.principalId}
                  checked={chosen}
                  onChange={() => onChange(principal.principalId)}
                />
                <PrincipalAvatar type={principalType} id={principal.principalId} />
                <span className="picker-name">{principal.principalId}</span>
                {held.length > 0 && (
                  <span className="picker-held">
                    <span className="visually-hidden">holds</span>
                    {held.map((access) => (
                      <span key={access} className="tag">
                        {access}
                      </span>
                    ))}
                  </span>
                )}
                <Check size={14} className="picker-check" />
              </label>
            );
          })
        )}
      </div>
    </fieldset>
  );
}
