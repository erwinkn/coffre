import type { ImpactLine, RolesView, RoleView } from '@coffre/client';
import {
  assignableToEnvironment,
  FIXED_ROLES,
  INSTANCE_ROLES,
  PERMISSIONS,
  PROJECT_ONLY_PERMISSIONS,
  ROLES,
  type Permission,
  type RoleDefinition,
} from '@coffre/core/access';

/**
 * The instance's roles as the pages offer and name them (docs/design/roles.md):
 * each in two columns, what it holds in an environment and what a person
 * holds of it in a protected one. The policy is the vault's, read from
 * `GET /api/roles`; until it is, the roles as they ship stand in.
 */

/** Every permission in words, in the catalogue's order, what a short label leaves out, and its word on a role's card, under its row's. */
export const PERMISSION_WORDS: Record<Permission, { label: string; note?: string; verb: string; short: string }> = {
  'secret.read': { label: 'Read values', verb: 'read values', short: 'Read' },
  'secret.use': { label: 'Use values', note: 'placeholders, the proxy', verb: 'use values', short: 'Use' },
  'secret.write': { label: 'Write values', verb: 'write values', short: 'Write' },
  'secret.archive': { label: 'Retire values', verb: 'retire values', short: 'Retire' },
  'audit.read': { label: 'Read the log', verb: 'read the log', short: 'Read' },
  'environment.manage': { label: 'Manage environments', verb: 'manage environments', short: 'Environments' },
  'grant.manage': { label: 'Manage access', verb: 'manage access', short: 'Access' },
  'project.manage': { label: 'Manage the project', verb: 'manage the project', short: 'Project' },
};

/** The rows of a role's grid: secrets first, as a role is read, then the log, then what only a project holds. */
export const GRID_PERMISSIONS: readonly Permission[] = [
  'secret.read',
  'secret.use',
  'secret.write',
  'secret.archive',
  'audit.read',
  'environment.manage',
  'grant.manage',
  'project.manage',
];

export function projectWide(permission: Permission): boolean {
  return PROJECT_ONLY_PERMISSIONS.includes(permission);
}

/**
 * A role card's rows, the grid's permissions in its order, each on every
 * card, so that a permission sits in the same place on all of them:
 *
 *   Values   Read  Use  Write  Retire
 *   Log      Read
 *   Manage   Environments  Access  Project
 */
export const CARD_ROWS: readonly { name: string; permissions: readonly Permission[] }[] = [
  { name: 'Values', permissions: ['secret.read', 'secret.use', 'secret.write', 'secret.archive'] },
  { name: 'Log', permissions: ['audit.read'] },
  { name: 'Manage', permissions: ['environment.manage', 'grant.manage', 'project.manage'] },
];

/**
 * Where a role holds a permission: everywhere, only outside protected
 * environments (Developer's Read values), or nowhere. A project-wide one
 * held is held everywhere: a project is never protected.
 */
export type Reach = 'everywhere' | 'unprotected' | 'nowhere';

export function reachOf(role: Pick<RoleDefinition, 'permissions' | 'protected'>, permission: Permission): Reach {
  if (!role.permissions.includes(permission)) return 'nowhere';
  return projectWide(permission) || role.protected.includes(permission) ? 'everywhere' : 'unprotected';
}

/** A role's two columns, as the grid edits them. */
export type Columns = { permissions: Permission[]; protected: Permission[] };
export type Column = 'normal' | 'protected';

/**
 * One checkbox of the grid flipped, and the rules the vault holds a role to
 * kept true by the boxes it takes along (`definitionProblem`):
 *
 *   checking Read checks Use              unchecking Use unchecks Read
 *   checking a protected box checks its   unchecking a normal box unchecks
 *   normal one                            its protected one
 *
 * A project-wide permission has no protected box: flipping one is no change.
 */
export function toggle(columns: Pick<RoleDefinition, 'permissions' | 'protected'>, permission: Permission, column: Column, on: boolean): Columns {
  if (column === 'protected' && projectWide(permission)) return ordered(columns);
  const normal = new Set(columns.permissions);
  const guarded = new Set(columns.protected);
  // Reading takes using; giving up using gives up reading.
  const along: Permission[] = on ? (permission === 'secret.read' ? ['secret.use'] : []) : permission === 'secret.use' ? ['secret.read'] : [];
  for (const each of [permission, ...along]) {
    if (on) {
      normal.add(each);
      if (column === 'protected') guarded.add(each);
    } else {
      guarded.delete(each);
      if (column === 'normal') normal.delete(each);
    }
  }
  return ordered({ permissions: [...normal], protected: [...guarded] });
}

/** Each column in catalogue order, as the vault keeps it, so that comparing two says whether they differ. */
export function ordered(columns: Pick<RoleDefinition, 'permissions' | 'protected'>): Columns {
  return {
    permissions: PERMISSIONS.filter((permission) => columns.permissions.includes(permission)),
    protected: PERMISSIONS.filter((permission) => columns.protected.includes(permission)),
  };
}

/** Whether two definitions hold the same, named and described the same. */
export function sameDefinition(a: RoleDefinition, b: RoleDefinition): boolean {
  const [x, y] = [ordered(a), ordered(b)];
  return a.name.trim() === b.name.trim() && a.description === b.description
    && x.permissions.join() === y.permissions.join() && x.protected.join() === y.protected.join();
}

/** A column in words, for a role's row: "read, use and write values", or "nothing". */
export function columnInWords(permissions: readonly Permission[]): string {
  const values = ['secret.read', 'secret.use', 'secret.write', 'secret.archive'] as const;
  const held = values.filter((permission) => permissions.includes(permission));
  const verbs = { 'secret.read': 'read', 'secret.use': 'use', 'secret.write': 'write', 'secret.archive': 'retire' } as const;
  const parts = [
    ...(held.length === 0 ? [] : [`${list(held.map((permission) => verbs[permission]))} values`]),
    ...GRID_PERMISSIONS.filter((permission) => !(values as readonly string[]).includes(permission) && permissions.includes(permission)).map((permission) => PERMISSION_WORDS[permission].verb),
  ];
  return parts.length === 0 ? 'nothing' : list(parts);
}

function list(words: readonly string[]): string {
  return words.length <= 1 ? (words[0] ?? '') : `${words.slice(0, -1).join(', ')} and ${words.at(-1)}`;
}

/** A role's id, made from its name as it is typed: "Release manager" is `release-manager`. */
export function roleIdFrom(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^[^a-z]+/, '')
    .replace(/-+$/, '')
    .slice(0, 32)
    .replace(/-+$/, '');
}

/** What is wrong with a new role's id, or null: its shape, and not one the instance has. */
export function roleIdProblem(id: string, taken: readonly string[]): string | null {
  if (id === '') return 'A role needs an id.';
  if (!/^[a-z0-9-]+$/.test(id)) return 'An id is lowercase letters, digits and dashes.';
  if (!/^[a-z]/.test(id)) return 'An id starts with a letter.';
  if (id.length < 2 || id.length > 32) return 'An id is 2 to 32 characters.';
  if (taken.includes(id)) return `There is a role ${id} already.`;
  return null;
}

/** The roles as they ship: what the pages offer and name until the instance's are read, or where they cannot be. */
export const SHIPPED_ROLES: RolesView = {
  roles: Object.entries(ROLES).map(([id, definition]) => shippedView(id, definition, FIXED_ROLES.roles.includes(id), assignableToEnvironment(id))),
  instanceRoles: Object.entries(INSTANCE_ROLES).map(([id, definition]) =>
    shippedView(id, definition, (FIXED_ROLES.instanceRoles as readonly string[]).includes(id), false)),
  editable: false,
};

function shippedView(id: string, definition: RoleDefinition, fixed: boolean, assignable: boolean): RoleView {
  const shipped = { name: definition.name, description: definition.description, ...ordered(definition) };
  return { id, ...shipped, builtin: true, edited: false, fixed, default: shipped, assignableToEnvironment: assignable, grants: 0 };
}

/** A role's name by its id, as the instance defines it; one it does not know, as itself. */
export function roleNameOf(roles: readonly Pick<RoleView, 'id' | 'name'>[], id: string): string {
  return roles.find((role) => role.id === id)?.name ?? id;
}

/**
 * One line of a change's impact, in words, from the dry run's count:
 *
 *   widens secret.read, protected, 6 people, 4 environments
 *     6 people can now read values in 4 protected environments
 *   narrows secret.write, 2 people, 1 environment, ["ada@… on market/dev", …]
 *     2 people can no longer write values in market/dev
 *
 * One place is named, from its examples; more are counted.
 */
export function impactInWords(line: ImpactLine): string {
  const people = [
    line.people > 0 ? (line.people === 1 ? '1 person' : `${line.people} people`) : null,
    line.services > 0 ? (line.services === 1 ? '1 service account' : `${line.services} service accounts`) : null,
  ].filter((part) => part !== null).join(' and ');
  const can = line.change === 'widens' ? 'can now' : 'can no longer';
  const wide = projectWide(line.permission);
  const count = wide ? line.projects : line.environments;
  const only = count === 1 ? placeOf(line.examples[0]) : null;
  const where = only !== null
    ? `${wide ? 'on' : 'in'} ${only}${line.protected ? ', protected' : ''}`
    : `${wide ? 'on' : 'in'} ${count} ${line.protected ? 'protected ' : ''}${wide ? (count === 1 ? 'project' : 'projects') : count === 1 ? 'environment' : 'environments'}`;
  return `${people} ${can} ${PERMISSION_WORDS[line.permission].verb} ${where}`;
}

/** The place of an impact's example, `ada@acme.example on market/prod`: `market/prod`. */
function placeOf(example: string | undefined): string | null {
  const at = example?.lastIndexOf(' on ') ?? -1;
  return example === undefined || at < 0 ? null : example.slice(at + ' on '.length);
}

/** Who an impact line reaches, for its note: `ada@acme.example on market/prod, bo@acme.example on market/prod`. */
export function impactExamples(line: ImpactLine): string | null {
  return line.examples.length === 0 ? null : `${line.examples.join(', ')}${line.people + line.services > line.examples.length ? ', …' : ''}`;
}

/**
 * What protecting an environment does, said by a role whose two columns
 * differ, Developer first: "Developers use and write values, and read
 * none". Null where no role's do, so protecting changes nothing.
 */
export function protectionInWords(roles: readonly Pick<RoleView, 'id' | 'name' | 'permissions' | 'protected'>[]): string | null {
  const differs = (role: Pick<RoleView, 'permissions' | 'protected'>) =>
    role.permissions.some((permission) => !projectWide(permission) && !role.protected.includes(permission));
  const role = roles.find((each) => each.id === 'developer' && differs(each)) ?? roles.find(differs);
  if (role === undefined) return null;
  const held = columnInWords(role.protected);
  const loses = role.permissions.includes('secret.read') && !role.protected.includes('secret.read') && role.protected.length > 0;
  return `${role.name}s ${held === 'nothing' ? 'hold nothing' : held}${loses ? ', and read none' : ''}`;
}
