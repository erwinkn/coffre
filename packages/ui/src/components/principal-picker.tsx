import { useQuery } from '@tanstack/react-query';
import { useId, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { projectAccessLabel } from '../lib/project-access';
import type { DirectoryPrincipal, GrantRow } from '../shared/models';
import { KIND } from './directory';
import { PrincipalAvatar } from './principal';
import { Spinner } from './ui';
import { Check, Plus, Search } from './icons';

type PrincipalType = DirectoryPrincipal['principalType'];

/** A name the vault takes for a new service account: no spaces, and no colon first. */
const SERVICE_NAME = /^[^\s:]\S*$/;

/**
 * Who a grant is for: picked from the registered users or service accounts, each shown
 * with what it already holds on this project, or typed when the list is not
 * yours to read. Whoever sets up service accounts may name a new one instead,
 * the last option, which the grant then makes (`admit`).
 *
 * Admins and owners list the directory, and whoever sets up service accounts
 * lists those they manage, and those on their projects. Asking on anyone
 * else's behalf would write a refusal to the audit log in their name, so they
 * get a text field and the server's answer instead. The list is asked for when the
 * dialog opens rather than with the page, since most visits never open it,
 * and shared with the Users and Service accounts pages through the cache.
 */
export function PrincipalPicker({
  principalType,
  canList,
  grants,
  canCreate = false,
  value,
  admit = false,
  onChange,
}: {
  principalType: PrincipalType;
  /** Whether you may list the directory: admins and owners, and for service accounts, whoever sets one up. */
  canList: boolean;
  /** The project's grants, to show what each entry already holds. */
  grants: GrantRow[];
  /** Whether a new service account may be named: whoever sets one up. */
  canCreate?: boolean;
  value: string;
  /** Whether `value` is a new service account, to be made with the grant. */
  admit?: boolean;
  onChange: (principalId: string, admit: boolean) => void;
}) {
  const coffre = useCoffre();
  const directory = useQuery(queries.directory(coffre, canList)).data ?? null;
  const [query, setQuery] = useState('');
  const name = useId();
  const kind = KIND[principalType];
  const label = principalType === 'user' ? 'User' : 'Service account';

  if (!canList || directory?.ok === false) {
    return (
      <label className="field">
        <span className="label">
          {principalType === 'user' ? 'Email' : 'Service account name'}
        </span>
        <input
          className="input input-mono"
          autoFocus
          spellCheck={false}
          autoComplete="off"
          placeholder={principalType === 'user' ? 'someone@acme.example' : 'ci-deploy'}
          value={value}
          onChange={(event) => onChange(event.target.value, false)}
        />
        <span className="hint">
          The {kind} must already be registered under {principalType === 'user' ? 'Users' : 'Service accounts'}.
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
  // A name no account has: offered as a new one, which follows the filter as it is typed.
  const creatable = (text: string) =>
    canCreate && SERVICE_NAME.test(text.trim()) && !registered.some((principal) => principal.principalId === text.trim());
  const typed = query.trim();

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
          placeholder={principalType === 'user' ? 'Filter by email…' : canCreate ? 'Filter by name, or name a new one…' : 'Filter by name…'}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            if (admit) onChange(creatable(event.target.value) ? event.target.value.trim() : '', creatable(event.target.value));
          }}
          onKeyDown={(event) => {
            // Narrowed to one, Enter picks it rather than sending the form; to none, the new one.
            if (event.key !== 'Enter') return;
            if (matches.length === 1) {
              event.preventDefault();
              onChange(matches[0].principalId, false);
            } else if (matches.length === 0 && creatable(query)) {
              event.preventDefault();
              onChange(typed, true);
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
        ) : registered.length === 0 && canCreate ? (
          typed === '' && <p className="picker-empty">No {kind}s yet: type a name to make one.</p>
        ) : registered.length === 0 ? (
          <p className="picker-empty">
            No {kind}s are registered yet.{' '}
            <Link to={principalType === 'user' ? '/users' : '/service-accounts'}>Add one</Link> first.
          </p>
        ) : matches.length === 0 && canCreate ? null : matches.length === 0 ? (
          <p className="picker-empty">No registered {kind} matches “{typed}”.</p>
        ) : (
          matches.map((principal) => {
            const held = grants
              .filter(
                (grant) =>
                  grant.principalType === principalType &&
                  grant.principalId === principal.principalId,
              )
              .map(projectAccessLabel);
            const chosen = !admit && principal.principalId === value;
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
                  onChange={() => onChange(principal.principalId, false)}
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
        {creatable(query) && (
          <label className={`picker-option${admit ? ' is-chosen' : ''}`}>
            <input
              type="radio"
              className="visually-hidden"
              name={name}
              value={typed}
              checked={admit}
              onChange={() => onChange(typed, true)}
            />
            <span className="avatar avatar-new" aria-hidden>
              <Plus size={13} />
            </span>
            <span className="picker-name">{typed}</span>
            <span className="picker-held">
              <span className="visually-hidden">a new {kind}, made with this access</span>
              <span className="tag" aria-hidden>
                New
              </span>
            </span>
            <Check size={14} className="picker-check" />
          </label>
        )}
        {canCreate && typed !== '' && !SERVICE_NAME.test(typed) && (
          <p className="picker-empty">A {kind}'s name has no spaces, and does not start with a colon.</p>
        )}
      </div>
    </fieldset>
  );
}
