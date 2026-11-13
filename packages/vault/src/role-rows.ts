import { INSTANCE_ROLES, ROLES, type RoleDefinition } from '@coffre/core/access';

import { canonical, roleObject, roleRef, sealed, type Op, type Ref, type RolesInput, type RoleTable, type SealKeys } from './inputs.ts';

/**
 * A row of `roles`, with the seal its object's newest change
 * left: null for a change that left none (a deletion), undefined for an
 * object the log has no change of.
 */
export type StoredRole = { scope: string; name: string; definition: RoleDefinition | null; seal: Buffer | null; newest: Buffer | null | undefined };

const TABLES: readonly (readonly [RoleTable, 'project' | 'instance', Readonly<Record<string, RoleDefinition>>])[] = [
  ['roles', 'project', ROLES],
  ['instanceRoles', 'instance', INSTANCE_ROLES],
];

/**
 * The changes that make every role's row what `whole`, the roles object as
 * the log holds it, says, sealed (formal/Roles.tla's sync): a change of each
 * role whose row is not sealed by the vault over what that object makes of
 * it, or not its object's newest change's (SyncEveryRole: a row put back is
 * sealed, and current on its own object, which 0.15.0 never writes), each
 * to what the whole object says, never to what the row says
 * (SyncFromConfig). A role with no row is in step when it is no role; one
 * that ships, or one the object holds, has a row to make. Every role that
 * ships, every one the object holds, and every row there is, in one order.
 * `except`, the role a change is about to write itself (EditSyncs).
 *
 *   whole: { roles: { developer: D } }, rows: none
 *     → developer to D, each other role that ships to none (its own), each sealed
 *   whole: { roles: {} }, rows: router (made, then deleted by 0.15.0: unsealed)
 *     → router to no object: its row deleted
 */
export function roleChanges(keys: SealKeys, whole: RolesInput, rows: readonly StoredRole[], except?: { table: RoleTable; role: string }): { ref: Ref & { kind: 'role' }; op: Op }[] {
  const changes: { ref: Ref & { kind: 'role' }; op: Op }[] = [];
  for (const [table, scope, shipped] of TABLES) {
    const edits = whole[table] as Readonly<Record<string, RoleDefinition>>;
    const stored = new Map(rows.filter((row) => row.scope === scope).map((row) => [row.name, row]));
    const names = [...new Set([...Object.keys(shipped), ...Object.keys(edits), ...stored.keys()])].sort();
    for (const role of names) {
      if (except?.table === table && except.role === role) continue;
      const definition = Object.hasOwn(edits, role) ? edits[role]! : null;
      if (inStep(keys, roleRef(table, role), roleObject(table, role, definition), stored.get(role))) continue;
      changes.push({ ref: roleRef(table, role), op: { op: 'role.define', table, role, definition } });
    }
  }
  return changes;
}

/** Whether a role's row is what its object should be, sealed by the vault and by its object's newest change. */
function inStep(keys: SealKeys, ref: Ref, object: ReturnType<typeof roleObject>, row: StoredRole | undefined): boolean {
  if (object === null) return row === undefined;
  if (row === undefined || row.seal === null || row.newest == null || !row.newest.equals(row.seal)) return false;
  return canonical(row.definition) === canonical(object.definition) && sealed(keys, ref, object, row.seal);
}
