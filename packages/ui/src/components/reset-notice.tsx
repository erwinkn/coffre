import { Notice, Timestamp } from './ui';

/** "Ada reset your passkeys on 31 Oct": an Owner removed every one of yours, and you hold none since. */
export function ResetNotice({ reset }: { reset: { by: string; at: string } | null }) {
  if (reset === null) return null;
  return (
    <Notice tone="warn">
      <span className="mono">{reset.by}</span> reset your passkeys on <Timestamp iso={reset.at} />. Add one to sign in with
      it again.
    </Notice>
  );
}
