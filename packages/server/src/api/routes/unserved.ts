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
  // The instance's roles and settings: the vault's `policy.change` and `settings.change`.
  ...unserved('GET /roles', "the instance's roles"),
  ...unserved('PUT /roles/:role', 'changing a role'),
  ...unserved('DELETE /roles/:role', 'deleting a role'),
  ...unserved('PUT /instance-roles/:role', 'changing an instance role'),
  ...unserved('DELETE /instance-roles/:role', 'deleting an instance role'),
  ...unserved('GET /settings', "the instance's settings"),
  ...unserved('PUT /settings', "changing the instance's settings"),
  // A member's tokens and trust bindings.
  ...unserved('GET /members/:member/tokens', "a member's tokens"),
  ...unserved('POST /members/:member/tokens', 'issuing a token'),
  ...unserved('DELETE /members/:member/tokens/:id', 'revoking a token'),
  ...unserved('POST /members/:member/tokens/:id/approve', 'approving a token'),
  ...unserved('GET /members/:member/bindings', "a service account's trust bindings"),
  ...unserved('POST /members/:member/bindings', 'making a trust binding'),
  ...unserved('POST /members/:member/bindings/keys', "changing a binding's keys"),
  ...unserved('DELETE /members/:member/bindings/:id', 'removing a trust binding'),
  ...unserved('GET /members/:member/bindings/:id/enrollments', "a binding's enrollments"),
  ...unserved('POST /members/:member/bindings/:id/enrollments', 'enrolling a workload'),
  ...unserved('POST /members/:member/bindings/:id/enrollments/:enrollment/promote', 'promoting an enrollment'),
};
