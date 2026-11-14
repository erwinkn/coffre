import { ApiError } from '../errors.ts';
import { route } from '../route.ts';

/**
 * Routes 0.14 served that 0.16 declares and does not serve yet, each
 * answered 501 `not_implemented` (docs/design/0.16.md, "The server"):
 * listed first in `routes.ts`, so the area that serves one replaces it by
 * listing its own, and deletes its line here. With them the table is
 * 0.14.7's whole API, but for `GET /audit/verification` and
 * `POST /audit/loss`, which 0.16 drops (docs/design/0.16.md, "What plugs
 * into it").
 */
const unserved = <const Key extends string>(key: Key, what: string) =>
  route(key, {
    run: async () => {
      throw new ApiError('not_implemented', `${what} is not served yet`);
    },
  });

export const unservedRoutes = {
  // Every freeze standing, for the service accounts' pages: freezing and lifting one are served (routes/freezes.ts).
  ...unserved('GET /freezes', 'the freezes standing'),
  // A workload's session approved, and a binding's enrollments.
  ...unserved('POST /members/:member/tokens/:id/approve', 'approving a token'),
  ...unserved('GET /members/:member/bindings/:id/enrollments', "a binding's enrollments"),
  ...unserved('POST /members/:member/bindings/:id/enrollments', 'enrolling a workload'),
  ...unserved('POST /members/:member/bindings/:id/enrollments/:enrollment/promote', 'promoting an enrollment'),
  // A missing key dismissed, or restored.
  ...unserved('PATCH /projects/:project/:environment/dismissals', 'dismissing a missing key'),
  // A GitHub or GitLab repository looked up for a binding, and those the deployment's GitHub App is installed on.
  ...unserved('GET /workloads/lookup', 'looking up a repository'),
  ...unserved('GET /workloads/repositories', "the GitHub App's repositories"),
  // A person's own sessions and sign-in accounts, listed: ending one is served (routes/tokens.ts, routes/signin.ts).
  ...unserved('GET /sessions', 'the sessions listed'),
  ...unserved('GET /identities', 'the sign-in accounts listed'),
  // MCP: connecting an app and its consent page, the apps connected, and a change an app asked for, on the page where its person decides it.
  ...unserved('GET /oauth/authorizations', "an app's authorization request"),
  ...unserved('POST /oauth/authorizations', 'authorizing an app'),
  ...unserved('GET /apps', 'the connected apps'),
  ...unserved('DELETE /apps/:id', 'disconnecting an app'),
  ...unserved('GET /approvals/:id', "an app's change to approve"),
  ...unserved('POST /approvals/:id', "deciding an app's change"),
  // The log, a page of it proved by its tiles; and what `coffre verify keys` checks an escrowed key against.
  ...unserved('GET /audit', 'the audit log'),
  ...unserved('GET /audit/keys', "the keys' public material"),
};
