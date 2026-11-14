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
  // A workload's session approved, and a binding's enrollments.
  ...unserved('POST /members/:member/tokens/:id/approve', 'approving a token'),
  ...unserved('GET /members/:member/bindings/:id/enrollments', "a binding's enrollments"),
  ...unserved('POST /members/:member/bindings/:id/enrollments', 'enrolling a workload'),
  ...unserved('POST /members/:member/bindings/:id/enrollments/:enrollment/promote', 'promoting an enrollment'),
  // A GitHub or GitLab repository looked up for a binding, and those the deployment's GitHub App is installed on.
  ...unserved('GET /workloads/lookup', 'looking up a repository'),
  ...unserved('GET /workloads/repositories', "the GitHub App's repositories"),
  // What `coffre verify keys` checks an escrowed key against: the log's page is served (routes/audit.ts).
  ...unserved('GET /audit/keys', "the keys' public material"),
};
