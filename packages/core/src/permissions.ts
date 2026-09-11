import { VaultError, type Grant, type Permission, type Principal, type Scope, type Snapshot } from '../../contracts/src/index';
export function applies(grant: Grant, target: Scope, snapshot: Snapshot): boolean {
  if (grant.scope.type === 'instance') return grant.scope.id === snapshot.instanceId;
  if (grant.scope.type === target.type && grant.scope.id === target.id) return true;
  return target.type === 'environment' && grant.scope.type === 'project' && snapshot.environments.some(e => e.id === target.id && e.projectId === grant.scope.id);
}
export function allows(snapshot: Snapshot, principal: Principal, permission: Permission, scope: Scope, now = Date.now()): boolean {
  if (principal.disabled || (principal.expiresAt && Date.parse(principal.expiresAt) <= now)) return false;
  return snapshot.grants.some(g => g.principalId === principal.id && (!g.expiresAt || Date.parse(g.expiresAt) > now) && g.permissions.includes(permission) && applies(g, scope, snapshot));
}
export function requirePermission(s: Snapshot, p: Principal, permission: Permission, scope: Scope) {
  if (!allows(s, p, permission, scope)) throw new VaultError('FORBIDDEN', 'You do not have permission for this operation');
}
export function validateScope(s: Snapshot, scope: Scope) {
  if (scope.type === 'instance' ? scope.id !== s.instanceId : scope.type === 'project' ? !s.projects.some(p => p.id === scope.id && !p.archived) : !s.environments.some(e => e.id === scope.id && !e.archived)) throw new VaultError('NOT_FOUND', 'Scope not found');
}
