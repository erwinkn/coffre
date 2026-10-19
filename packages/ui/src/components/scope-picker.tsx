import type { RoleView } from '@coffre/client';
import { credentialScopeInWords, type Role } from '@coffre/core/access';

import { roleNameOf } from '../lib/roles';
import { useRoles } from '../lib/use-roles';

/** A grant of the account's, as its Access tab lists it. */
export type HeldGrant = { project: string; environment: string | null; role: Role };

/** A token's or a binding's scope, by path: what the API takes and lists. */
export type ScopeByPath = Record<string, Role>;

const pathOf = (grant: HeldGrant) => (grant.environment === null ? grant.project : `${grant.project}/${grant.environment}`);

/** Everything the account holds, each grant as it is: what a new token or binding reaches unless narrowed. */
export function wholeScope(grants: readonly HeldGrant[]): ScopeByPath {
  return Object.fromEntries(grants.map((grant) => [pathOf(grant), grant.role]));
}

/**
 * The roles a credential may hold where its account holds `grant`: those it
 * holds all of, and that the place takes. Its own role always, whatever the
 * policy says of it now.
 */
function within(grant: HeldGrant, roles: readonly RoleView[]): Role[] {
  const held: readonly string[] = roles.find((role) => role.id === grant.role)?.permissions ?? [];
  const smaller = roles
    .filter((role) => (grant.environment === null || role.assignableToEnvironment) && role.permissions.every((permission) => held.includes(permission)))
    .map((role) => role.id);
  return smaller.includes(grant.role) ? smaller : [grant.role, ...smaller];
}

/**
 * What a new token or trust binding reaches: each of its account's grants,
 * kept or left out, at its role or a smaller one. Nothing the account is
 * given later reaches it, and it never changes after.
 */
export function ScopePicker({ grants, value, onChange }: { grants: readonly HeldGrant[]; value: ScopeByPath; onChange: (scope: ScopeByPath) => void }) {
  const { roles } = useRoles();
  if (grants.length === 0) {
    return <p className="hint">The account holds nothing yet: give it a grant first, since nothing it is given later reaches a token or binding made before.</p>;
  }
  const set = (path: string, role: Role | null) => {
    const { [path]: _, ...rest } = value;
    // In the account's order, as its Access tab lists them.
    const next: ScopeByPath = role === null ? rest : { ...rest, [path]: role };
    onChange(Object.fromEntries(grants.map(pathOf).flatMap((each) => (next[each] === undefined ? [] : [[each, next[each]!]]))));
  };
  return (
    <fieldset className="field checks">
      <legend className="label">Reaches</legend>
      {grants.map((grant) => {
        const path = pathOf(grant);
        const chosen = value[path];
        return (
          <div key={path} className="form-row">
            <label className="check mono">
              <input type="checkbox" checked={chosen !== undefined} onChange={(event) => set(path, event.target.checked ? grant.role : null)} />
              {path}
            </label>
            <select
              className="select"
              aria-label={`Role on ${path}`}
              value={chosen ?? grant.role}
              disabled={chosen === undefined}
              onChange={(event) => set(path, event.target.value as Role)}
            >
              {within(grant, roles).map((role) => (
                <option key={role} value={role}>
                  {roleNameOf(roles, role)}
                </option>
              ))}
            </select>
          </div>
        );
      })}
      <span className="hint">
        {Object.keys(value).length === 0 ? 'Choose at least one.' : `${credentialScopeInWords(value)}.`} At most what the account holds; nothing it is given
        later reaches it, and to change it, make another and remove this one.
      </span>
    </fieldset>
  );
}
