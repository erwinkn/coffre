// Which scope each API route needs when a request comes in through MCP
// (docs/design/mcp.md, section 5, the third layer). The tools call the API
// as their person; this table holds a tool with a bug to its connection's
// scopes all the same. It is typed over the route table, so a route added to
// the API fails the typecheck here until it says whether MCP may reach it.
import type { McpScope } from '@coffre/core/mcp';

import type { RouteKey } from '../api/routes.ts';

/** The scope a route needs through MCP; null for one MCP never reaches, whatever its scopes. */
export const ROUTE_SCOPES: { [K in RouteKey]: McpScope | null } = {
  'GET /me': 'read',
  'GET /projects': 'read',
  'PUT /projects/:project': 'write',
  'PATCH /projects/:project': 'write',
  // Permanent deletion stays with people, in the pages and the CLI.
  'DELETE /projects/:project': null,
  'PUT /projects/:project/:environment': 'write',
  'PATCH /projects/:project/:environment': 'write',
  'DELETE /projects/:project/:environment': null,
  'GET /projects/:project/:environment/missing': 'read',
  'GET /personal/:project': 'read',
  'GET /projects/:project/:environment/version': 'read',
  'PATCH /projects/:project/:environment/dismissals': 'write',
  'GET /secrets/:project/:environment': 'read',
  'PATCH /secrets/:project/:environment': 'write',
  'PATCH /secrets/:project/:environment/:key': 'write',
  'GET /secrets/:project/:environment/:key/versions': 'read',
  'POST /secrets/:project/:environment/:key/restore': 'write',
  'DELETE /secrets/:project/:environment/:key/reference': 'write',
  'PATCH /folders/:folder': 'write',
  'DELETE /folders/:folder': 'write',
  'PATCH /folders/:project/:environment/:folder': 'write',
  'DELETE /folders/:project/:environment/:folder': 'write',
  'GET /references': 'read',
  'POST /reveals': 'reveal',
  'GET /members': 'read',
  'GET /members/:member': 'read',
  'GET /members/:member/access': 'read',
  'PUT /members/:member': 'manage-access',
  'DELETE /members/:member': 'manage-access',
  'GET /members/:member/tokens': 'read',
  'POST /members/:member/tokens': 'manage-access',
  'DELETE /members/:member/tokens/:id': 'manage-access',
  // A placeholder is for a person's own app, made by `coffre run`: a connected app holds no handle.
  'POST /handles': null,
  'DELETE /handles/:id': null,
  'GET /members/:member/bindings': 'read',
  'POST /members/:member/bindings': 'manage-access',
  'POST /members/:member/bindings/keys': 'manage-access',
  'GET /workloads/lookup': 'read',
  'GET /workloads/repositories': 'read',
  'DELETE /members/:member/bindings/:id': 'manage-access',
  'GET /members/:member/bindings/:id/enrollments': 'read',
  // A code is a deploy's credential, minted by CI or a person: a connected app holds none, as it holds no handle.
  'POST /members/:member/bindings/:id/enrollments': null,
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote': null,
  'POST /members/:member/tokens/:id/approve': null,
  'GET /freezes': 'read',
  // Freezing and lifting stay with people, in the pages and the CLI: an app that could lift one could undo a person's.
  'POST /freezes': null,
  'DELETE /freezes/:target': null,
  'PATCH /access/:member': 'manage-access',
  'GET /roles': 'read',
  // The instance's roles stay with its Owners, in the pages and the CLI, as its settings do.
  'PUT /roles/:role': null,
  'DELETE /roles/:role': null,
  'PUT /instance-roles/:role': null,
  'DELETE /instance-roles/:role': null,
  'GET /settings': 'read',
  // The instance's settings stay with people, in the pages and the CLI, as permanent deletion does.
  'PUT /settings': null,
  // The person's own sign-in, connecting apps and deciding their changes: never an app's to touch.
  'GET /sessions': null,
  'DELETE /sessions/:id': null,
  'GET /identities': null,
  'DELETE /identities/:id': null,
  'GET /device-logins/:code': null,
  'POST /device-logins/:code': null,
  'GET /oauth/authorizations': null,
  'POST /oauth/authorizations': null,
  'GET /approvals/:id': null,
  'POST /approvals/:id': null,
  'GET /apps': null,
  'DELETE /apps/:id': null,
  'GET /audit': 'read',
  'GET /audit/verification': 'read',
  'GET /audit/keys': null,
};

/**
 * What an `insufficient_scope` challenge names: everything the connection
 * holds, and what is missing, since a client asks for exactly what the
 * challenge says (Claude's docs ask for the union).
 */
export function challengeScopes(held: readonly McpScope[], needed: McpScope): McpScope[] {
  return held.includes(needed) ? [...held] : [...held, needed];
}
