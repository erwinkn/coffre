import { createFileRoute } from '@tanstack/react-router';

import { Notice } from '../components/ui';

export const Route = createFileRoute('/unregistered')({
  component: UnregisteredPage,
});

/**
 * Cloudflare Access has authenticated this person, but Coffre's own directory
 * has not admitted them. Keep this deliberately actionless: registration is
 * an owner decision, not a self-service privilege escalation path.
 */
function UnregisteredPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Registration required</h1>
          <p className="sub">
            Cloudflare Access authenticated you, but this Coffre instance has not
            registered your identity.
          </p>
        </div>
      </div>

      <Notice tone="bad">
        Ask a Coffre owner or root admin to add your Cloudflare Access email to the
        user directory. Until then, no projects, secrets, audit entries, or API
        operations are available.
      </Notice>
    </>
  );
}
