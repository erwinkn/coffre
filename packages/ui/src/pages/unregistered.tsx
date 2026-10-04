import { useShell } from '../lib/use-shell';

import { ClosedDoor } from '../components/page';
import { User } from '../components/icons';

/**
 * Cloudflare Access has authenticated this person, but Coffre has not
 * registered them as a member. Keep this deliberately actionless: registration is
 * an owner decision, not a self-service privilege escalation path.
 */
export function UnregisteredPage() {
  const { principal, accessTampered } = useShell();

  if (accessTampered) {
    return (
      <ClosedDoor icon={<User size={18} />} label="Integrity check failed" title="Your access is on hold">
        <p>
          Your access record
          {principal !== null && (
            <>
              {' '}
              (<span className="mono">{principal.id}</span>)
            </>
          )}{' '}
          was changed outside coffre, so its vault refuses it until someone looks. Nothing you
          held is available meanwhile.
        </p>
        <p>Ask a coffre owner to remove you under Users and add you again, which starts your access over.</p>
      </ClosedDoor>
    );
  }

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
        Ask a coffre owner or root admin to add your Access email under Users.
      </p>
    </ClosedDoor>
  );
}
