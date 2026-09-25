import { createFileRoute, useLoaderData } from '@tanstack/react-router';

import { ClosedDoor } from '../components/page';
import { User } from '../components/icons';

export const Route = createFileRoute('/unregistered')({
  component: UnregisteredPage,
});

/**
 * Cloudflare Access has authenticated this person, but Coffre has not
 * registered them as a member. Keep this deliberately actionless: registration is
 * an owner decision, not a self-service privilege escalation path.
 */
function UnregisteredPage() {
  const { principal } = useLoaderData({ from: '__root__' });

  return (
    <ClosedDoor
      icon={<User size={18} />}
      label="Registration required"
      title="You are not a member yet"
    >
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
      <p>
        Ask a coffre owner or root admin to add your Access email under Members.
      </p>
    </ClosedDoor>
  );
}
