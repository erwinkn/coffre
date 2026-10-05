// Which scope each API route needs when a request comes in through MCP
// (docs/design/mcp.md, section 5, the third layer). The tools call the API
// as their person; this table holds a tool with a bug to its connection's
// scopes all the same. It is typed over the route table, so a route added to
// the API fails the typecheck here until it says whether MCP may reach it.
import type { McpScope } from '@coffre/core/mcp';

import type { RouteKey } from '../api/routes.ts';

/** The scope a route needs through MCP; null for one MCP never reaches, whatever its scopes. */
export const ROUTE_SCOPES: { [K in RouteKey]: McpScope | null } = {
  'GET /me': 'browse',
  'GET /projects': 'browse',
  'PUT /projects/:project': 'write',
  'PATCH /projects/:project': 'write',
  // Permanent deletion stays with people, in the pages and the CLI.
  'DELETE /projects/:project': null,
  'PUT /projects/:project/:environment': 'write',
  'PATCH /projects/:project/:environment': 'write',
  'DELETE /projects/:project/:environment': null,
  'GET /projects/:project/:environment/missing': 'browse',
  'PATCH /projects/:project/:environment/dismissals': 'write',
  'GET /secrets/:project/:environment': 'browse',
  'PATCH /secrets/:project/:environment': 'write',
  'PATCH /secrets/:project/:environment/:key': 'write',
  'GET /secrets/:project/:environment/:key/versions': 'browse',
  'POST /secrets/:project/:environment/:key/restore': 'write',
  'DELETE /secrets/:project/:environment/:key/reference': 'write',
  'PATCH /folders/:folder': 'write',
  'DELETE /folders/:folder': 'write',
  'PATCH /folders/:project/:environment/:folder': 'write',
  'DELETE /folders/:project/:environment/:folder': 'write',
  'GET /references': 'browse',
  'POST /reveals': 'read-values',
  'GET /members': 'browse',
  'GET /members/:member': 'browse',
  'PUT /members/:member': 'manage-access',
  'DELETE /members/:member': 'manage-access',
  'GET /members/:member/tokens': 'browse',
  'POST /members/:member/tokens': 'manage-access',
  'DELETE /members/:member/tokens/:id': 'manage-access',
  'GET /members/:member/bindings': 'browse',
  'POST /members/:member/bindings': 'manage-access',
  'GET /workloads/lookup': 'browse',
  'DELETE /members/:member/bindings/:id': 'manage-access',
  'PATCH /access/:member': 'manage-access',
  // The person's own sign-in, and connecting apps: never an app's to touch.
  'GET /sessions': null,
  'DELETE /sessions/:id': null,
  'GET /identities': null,
  'DELETE /identities/:id': null,
  'GET /device-logins/:code': null,
  'POST /device-logins/:code': null,
  'GET /oauth/authorizations': null,
  'POST /oauth/authorizations': null,
  'GET /apps': null,
  'DELETE /apps/:id': null,
  'GET /audit': 'browse',
  'GET /audit/verification': 'browse',
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
