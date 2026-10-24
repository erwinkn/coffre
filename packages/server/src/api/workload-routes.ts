// Which API routes a workload's key-bound session reaches
// (docs/design/workload-access.md, section 6.1): every route a service
// token reaches today, whose handler decides as it does for a service, so
// CI keeps its writes, its grants where it manages access, and its log;
// and the enrollment codes it mints and promotes for the service a
// binding's `mintedBy` names. What only a person does stays theirs: a
// handle, their own sign-in, connected apps and approvals, approving a
// session, and setting or lifting a freeze. A session's own sign-in
// (renew, narrow, logout) is under `/api/auth`, outside this table. Typed
// over the route table, so a route added to the API fails the typecheck
// here until it says whether a session may reach it. A `narrow` child
// reaches none of them: only `/use`, narrow and logout. Enforced by that
// design's PR 1a; any other route answers 403 `workload`. Routes that
// answer values answer only plain keys and those its binding lists.
import type { RouteKey } from './routes.ts';

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
  'PUT /members/:member': true,
  'DELETE /members/:member': true,
  'GET /members/:member/tokens': true,
  'POST /members/:member/tokens': true,
  'DELETE /members/:member/tokens/:id': true,
  // A handle is a person's app's placeholder: a service reads its values.
  'POST /handles': false,
  'DELETE /handles/:id': false,
  'GET /members/:member/bindings': true,
  'POST /members/:member/bindings': true,
  'POST /members/:member/bindings/keys': true,
  'DELETE /members/:member/bindings/:id': true,
  'GET /workloads/lookup': true,
  'GET /workloads/repositories': true,
  'GET /members/:member/bindings/:id/enrollments': true,
  'POST /members/:member/bindings/:id/enrollments': true,
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote': true,
  // Approving a session is a person's check of it.
  'POST /members/:member/tokens/:id/approve': false,
  'GET /freezes': true,
  // Freezing and lifting stay with people, as the pages' and the CLI's buttons.
  'POST /freezes': false,
  'DELETE /freezes/:target': false,
  'PATCH /access/:member': true,
  'GET /roles': true,
  'PUT /roles/:role': true,
  'DELETE /roles/:role': true,
  'PUT /instance-roles/:role': true,
  'DELETE /instance-roles/:role': true,
  'GET /settings': true,
  'PUT /settings': true,
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
