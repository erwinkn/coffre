// Which API routes a workload's key-bound session reaches
// (docs/design/workload-access.md, section 6.1). A session acts as its
// service, within its scope: what a service token reaches today, the
// writes of CI included, and a code minted and promoted for the service a
// binding's `mintedBy` names. It makes nothing that outlives it or holds
// more than it does: no token, handle or trust binding, and no change to
// who holds access, which stays with people; nor does it lift or set a
// freeze. Its own sign-in (renew, narrow, logout) is under `/api/auth`,
// outside this table. Typed over the route table, so a route added to the
// API fails the typecheck here until it says whether a session may reach
// it. A `narrow` child reaches none of them: only `/use`, narrow and
// logout. Enforced by that design's PR 1a; any other route answers 403
// `workload`.
import type { RouteKey } from './routes.ts';

/** Whether a workload's session reaches a route. */
export const WORKLOAD_ROUTES: { [K in RouteKey]: boolean } = {
  'GET /me': true,
  'GET /projects': true,
  'PUT /projects/:project': true,
  'PATCH /projects/:project': true,
  // Permanent deletion stays with people.
  'DELETE /projects/:project': false,
  'PUT /projects/:project/:environment': true,
  'PATCH /projects/:project/:environment': true,
  'DELETE /projects/:project/:environment': false,
  'GET /projects/:project/:environment/missing': true,
  // Whose personal configs a project holds names people.
  'GET /personal/:project': false,
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
  // It answers only plain keys and those its binding lists in `reads`.
  'POST /reveals': true,
  // Who holds what, as a service token reads it where its account may.
  'GET /members': true,
  'GET /members/:member': true,
  'GET /members/:member/access': true,
  'PUT /members/:member': false,
  'DELETE /members/:member': false,
  'GET /members/:member/tokens': true,
  // A bearer token, a handle or a binding would outlive the session, or read where it uses.
  'POST /members/:member/tokens': false,
  'DELETE /members/:member/tokens/:id': false,
  'POST /handles': false,
  'GET /members/:member/bindings': true,
  'POST /members/:member/bindings': false,
  'POST /members/:member/bindings/keys': false,
  'DELETE /members/:member/bindings/:id': false,
  'GET /workloads/lookup': false,
  'GET /workloads/repositories': false,
  // CI's deploy: a code for the app it deploys, and the one it makes current once the deploy is up. Never from a session an
  // enrollment made, nor a child: the route refuses those, which would otherwise outlive every deploy.
  'GET /members/:member/bindings/:id/enrollments': true,
  'POST /members/:member/bindings/:id/enrollments': true,
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote': true,
  // Approving a session is a person's check of it.
  'POST /members/:member/tokens/:id/approve': false,
  'GET /freezes': true,
  'POST /freezes': false,
  'DELETE /freezes/:target': false,
  'PATCH /access/:member': false,
  'GET /roles': true,
  'PUT /roles/:role': false,
  'DELETE /roles/:role': false,
  'PUT /instance-roles/:role': false,
  'DELETE /instance-roles/:role': false,
  'GET /settings': false,
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
  // The log where its account may read it; verifying the whole log is the instance's.
  'GET /audit': true,
  'GET /audit/verification': false,
  'GET /audit/keys': false,
};
