import { serviceName, shownMember } from '@coffre/client';
import { Fragment } from 'react';
import { Link } from '@tanstack/react-router';
import type { Part } from '../lib/audit-sentences';
import { breakAfterUnderscores } from './ui';

/** A sentence, its people and places links to their pages. */
export function Sentence({ parts }: { parts: Part[] }) {
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {typeof part === 'string' ? (
            part
          ) : 'place' in part ? (
            <PlaceLink path={part.place} />
          ) : (
            <MemberLink member={part.member} />
          )}
        </Fragment>
      ))}
    </>
  );
}

function PlaceLink({ path }: { path: string }) {
  const [project, environment] = path.split('/') as [string, string | undefined];
  const text = <span className="mono">{breakAfterUnderscores(path)}</span>;
  return environment === undefined ? (
    <Link to="/projects/$project" params={{ project }}>
      {text}
    </Link>
  ) : (
    <Link to="/projects/$project/$environment" params={{ project, environment }}>
      {text}
    </Link>
  );
}

/** A member from the log, which keeps `token:<name>`, shown as people read it: `service:<name>`, to its page. */
function MemberLink({ member }: { member: string }) {
  return member.startsWith('token:') ? (
    <Link to="/service-accounts/$account" params={{ account: serviceName(member) }}>
      {shownMember(member)}
    </Link>
  ) : (
    <Link to="/users/$user" params={{ user: memberName(member) }}>
      {memberName(member)}
    </Link>
  );
}

export function memberName(member: string): string {
  return member.startsWith('user:') ? member.slice('user:'.length) : shownMember(member);
}
