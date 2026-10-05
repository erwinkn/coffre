import { Link } from '@tanstack/react-router';
import { useMounted } from '../lib/mounted';
import type { DirectoryPrincipal } from '../shared/models';
import { Key } from './icons';

type PrincipalType = DirectoryPrincipal['principalType'];

/** A person's initial, or a key for a machine. */
export function PrincipalAvatar({
  type,
  id,
  size = 'sm',
}: {
  type: PrincipalType;
  id: string;
  size?: 'sm' | 'lg';
}) {
  const className = `avatar${type === 'service' ? ' avatar-token' : ''}${size === 'lg' ? ' avatar-lg' : ''}`;
  return (
    <span className={className} aria-hidden>
      {type === 'service' ? <Key size={size === 'lg' ? 18 : 13} /> : id.slice(0, 1)}
    </span>
  );
}

/**
 * A user or token, linking to its own page, if the deployment kept it.
 * `stretch` makes the link cover the whole table row it sits in.
 */
export function PrincipalLink({
  type,
  id,
  stretch = false,
}: {
  type: PrincipalType;
  id: string;
  stretch?: boolean;
}) {
  const className = `cell-link${stretch ? ' stretch' : ''}`;
  const mounted = useMounted();
  return (
    <span className="cell-principal">
      <PrincipalAvatar type={type} id={id} />
      {!mounted(type === 'user' ? '/users/$user' : '/tokens/$token') ? (
        <span>{type === 'user' ? id : `service:${id}`}</span>
      ) : type === 'user' ? (
        <Link className={className} to="/users/$user" params={{ user: id }}>
          {id}
        </Link>
      ) : (
        <Link className={className} to="/tokens/$token" params={{ token: id }}>
          service:{id}
        </Link>
      )}
    </span>
  );
}
