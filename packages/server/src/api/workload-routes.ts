// Which API routes a workload's key-bound session reaches
// (docs/design/workload-access.md, section 6.1): every route a service
// token reaches today, whose handler decides as it does for a service, so
// CI keeps its writes and its log. What only a person does stays theirs: a
// handle, their own sign-in, connected apps and approvals, approving a
// session, and setting or lifting a freeze. A session's own sign-in
// (renew, narrow, logout) is under `/api/auth`, outside this table. Typed
// over the route table, so a route added to the API fails the typecheck
// here until it says whether a session may reach it. A `narrow` child
// reaches none of them: only `/use`, narrow and logout. Enforced by that
// design's PR 1a; any other route answers 403 `workload`. Routes that
// answer values answer only plain keys and those its binding lists.
//
// A session issues no credential and changes no one's access, in any mode
// (`ISSUING_ROUTES`, 403 `workload_cannot_issue`): a token, a binding or an
// enrollment code it made would read by column what the session may only
// use by key, and a grant or a role it changed would widen another service
// that does. Writes, use and deploy-on-push stay.
import type { RouteKey } from './routes.ts';

/**
 * The routes that issue a credential or change access, which a workload's
 * session never reaches, refused with `workload_cannot_issue`: service
 * tokens, bindings and enrollment codes; members, grants, roles and who
 * sets up service accounts.
 */
export const ISSUING_ROUTES: ReadonlySet<RouteKey> = new Set<RouteKey>([
  'PUT /members/:member',
  'DELETE /members/:member',
  'POST /members/:member/tokens',
  'POST /members/:member/bindings',
  'POST /members/:member/bindings/keys',
  'DELETE /members/:member/bindings/:id',
  'POST /members/:member/bindings/:id/enrollments',
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote',
  'PATCH /access/:member',
  'PUT /roles/:role',
  'DELETE /roles/:role',
  'PUT /instance-roles/:role',
  'DELETE /instance-roles/:role',
  'PUT /settings',
]);

/** Whether a workload's session reaches a route. */
export const WORKLOAD_ROUTES: { [K in RouteKey]: boolean } = {
  'GET /me': true,
  'GET /projects': true,
  'PUT /projects/:project': true,
  'PATCH /projects/:project': true,
  'DELETE /projects/:project': true,
  'PUT /projects/:project/:environment': true,
  'PATCH /projects/:project/:environment': true,
  'DELETE /projects/:project/:environment': true,
  'GET /projects/:project/:environment/missing': true,
  'GET /personal/:project': true,
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
  'GET /members': true,
  'GET /members/:member': true,
  'GET /members/:member/access': true,
  'PUT /members/:member': false,
  'DELETE /members/:member': false,
  'GET /members/:member/tokens': true,
  'POST /members/:member/tokens': false,
  'DELETE /members/:member/tokens/:id': true,
  // A handle is a person's app's placeholder: a service reads its values.
  'POST /handles': false,
  'DELETE /handles/:id': false,
  'GET /members/:member/bindings': true,
  'POST /members/:member/bindings': false,
  'POST /members/:member/bindings/keys': false,
  'DELETE /members/:member/bindings/:id': false,
  'GET /workloads/lookup': true,
  'GET /workloads/repositories': true,
  'GET /members/:member/bindings/:id/enrollments': true,
  'POST /members/:member/bindings/:id/enrollments': false,
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote': false,
  // Approving a session is a person's check of it.
  'POST /members/:member/tokens/:id/approve': false,
  'GET /freezes': true,
  // Freezing and lifting stay with people, as the pages' and the CLI's buttons.
  'POST /freezes': false,
  'DELETE /freezes/:target': false,
  'PATCH /access/:member': false,
  'GET /roles': true,
  'PUT /roles/:role': false,
  'DELETE /roles/:role': false,
  'PUT /instance-roles/:role': false,
  'DELETE /instance-roles/:role': false,
  'GET /settings': true,
  'PUT /settings': false,
  // A person's own sign-in, connected apps and approvals.
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
  'GET /audit': true,
  'GET /audit/verification': true,
  'GET /audit/keys': true,
};
