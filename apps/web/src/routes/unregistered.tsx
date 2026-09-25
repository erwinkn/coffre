import { createFileRoute, useLoaderData } from '@tanstack/react-router';

import { ClosedDoor } from '../components/page';

export const Route = createFileRoute('/unregistered')({
  component: UnregisteredPage,
});

/**
 * Cloudflare Access has authenticated this person, but Coffre's own directory
 * has not admitted them. Keep this deliberately actionless: registration is
 * an owner decision, not a self-service privilege escalation path.
 */
function UnregisteredPage() {
  const { principal } = useLoaderData({ from: '__root__' });

  return (
    <ClosedDoor eyebrow="Registration required" title="You are not in the directory yet">
      <p>
        Cloudflare Access knows who you are
        {principal !== null && (
          <>
            {' '}
            (<span className="mono">{principal.id}</span>)
          </>
        )}
        , but this coffre instance has not registered that identity. Until it does, no
        projects, secrets, audit entries or API operations are available to you.
      </p>
      <p style={{ marginTop: '0.875rem' }}>
        Ask a coffre owner or root admin to add your Access email to the directory.
      </p>
    </ClosedDoor>
  );
}
