import { ApiError } from '../errors.ts';
import { route } from '../route.ts';

/**
 * Routes 0.14 served that 0.16 declares and does not serve yet, each
 * answered 501 `not_implemented` (docs/design/0.16.md, "The server"):
 * listed first in `routes.ts`, so the area that serves one replaces it by
 * listing its own, and deletes its line here.
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
  // A workload's session approved, and a service account's trust bindings and their enrollments.
  ...unserved('POST /members/:member/tokens/:id/approve', 'approving a token'),
  ...unserved('GET /members/:member/bindings', "a service account's trust bindings"),
  ...unserved('POST /members/:member/bindings', 'making a trust binding'),
  ...unserved('POST /members/:member/bindings/keys', "changing a binding's keys"),
  ...unserved('DELETE /members/:member/bindings/:id', 'removing a trust binding'),
  ...unserved('GET /members/:member/bindings/:id/enrollments', "a binding's enrollments"),
  ...unserved('POST /members/:member/bindings/:id/enrollments', 'enrolling a workload'),
  ...unserved('POST /members/:member/bindings/:id/enrollments/:enrollment/promote', 'promoting an enrollment'),
};
