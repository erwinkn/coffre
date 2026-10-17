// Which API routes a personal token reaches (docs/design/personal-tokens.md).
// A token acts as its person within its scope, which names places: their
// secrets, environments and log. Everything about the instance's people,
// access and sign-in stays with the person, signed in as themselves, so a
// token can make nothing that outlives it or holds more than it does: no
// token, session, connected app, grant, member, service account or trust
// binding. Typed over the route table, so a route added to the API fails the
// typecheck here until it says whether a token may reach it.
import type { RouteKey } from './routes.ts';

/** Whether a personal token reaches a route; one it does not is refused, and the refusal logged. */
export const PERSONAL_TOKEN_ROUTES: { [K in RouteKey]: boolean } = {
  'GET /me': true,
  'GET /projects': true,
  'PUT /projects/:project': true,
  'PATCH /projects/:project': true,
  // Permanent deletion stays with people, as through MCP.
  'DELETE /projects/:project': false,
  'PUT /projects/:project/:environment': true,
  'PATCH /projects/:project/:environment': true,
  'DELETE /projects/:project/:environment': false,
  'GET /projects/:project/:environment/missing': true,
  // Whose personal configs a project holds names people: theirs to look up, signed in as themselves.
  'GET /personal/:project': false,
  // A poller's question before it reads (`coffre export --watch`): what a read would open, which the token may read.
  'GET /projects/:project/:environment/version': true,
  'PATCH /projects/:project/:environment/dismissals': true,
  'GET /secrets/:project/:environment': true,
  'PATCH /secrets/:project/:environment': true,
  'PATCH /secrets/:project/:environment/:key': true,
  'GET /secrets/:project/:environment/:key/versions': true,
  'POST /secrets/:project/:environment/:key/restore': true,
  'DELETE /secrets/:project/:environment/:key/reference': true,
  'PATCH /folders/:folder': true,
  'DELETE /folders/:folder': true,
  'PATCH /folders/:project/:environment/:folder': true,
  'DELETE /folders/:project/:environment/:folder': true,
  'GET /references': true,
  'POST /reveals': true,
  // People, service accounts and access: who holds what is the person's to see and change.
  'GET /members': false,
  'GET /members/:member': false,
  'GET /members/:member/access': false,
  'PUT /members/:member': false,
  'DELETE /members/:member': false,
  'GET /members/:member/tokens': false,
  'POST /members/:member/tokens': false,
  'DELETE /members/:member/tokens/:id': false,
  'GET /members/:member/bindings': false,
  'POST /members/:member/bindings': false,
  'POST /members/:member/bindings/keys': false,
  'GET /workloads/lookup': false,
  'GET /workloads/repositories': false,
  'DELETE /members/:member/bindings/:id': false,
  'PATCH /access/:member': false,
  'GET /settings': false,
  'PUT /settings': false,
  // The person's own sign-in, connecting apps and deciding their changes.
  'GET /sessions': false,
  'DELETE /sessions/:id': false,
  'GET /identities': false,
  'DELETE /identities/:id': false,
  'GET /device-logins/:code': false,
  'POST /device-logins/:code': false,
  'GET /oauth/authorizations': false,
  'POST /oauth/authorizations': false,
  'GET /approvals/:id': false,
  'POST /approvals/:id': false,
  'GET /apps': false,
  'DELETE /apps/:id': false,
  // The log of the places it reaches; the whole log, and verifying it, are the instance's.
  'GET /audit': true,
  'GET /audit/verification': false,
  'GET /audit/keys': false,
};
