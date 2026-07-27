'use client';

import { useState, useTransition } from 'react';
import { verifyAuditChain } from '../actions';

/**
 * The "prove the log was not edited" button.
 *
 * Recomputes the hash chain over every row. Because the chain key is not in
 * the database, someone who rewrote a row cannot recompute the chain to match.
 */
export function VerifyButton() {
  const [result, setResult] = useState<
    { ok: true; rows: number; head: string } | { ok: false; error: string } | null
  >(null);
  const [pending, startTransition] = useTransition();

  return (
    <>
      <div className="spread" style={{ marginBottom: 14 }}>
        <span className="meta">
          Each entry commits to the one before it via HMAC.
        </span>
        <button
          className="primary"
          disabled={pending}
          onClick={() => startTransition(async () => setResult(await verifyAuditChain()))}
        >
          {pending ? 'Verifying...' : 'Verify chain integrity'}
        </button>
      </div>

      {result !== null &&
        (result.ok ? (
          <div className="notice good">
            Chain intact across {result.rows} entries. Head{' '}
            <code>{result.head.slice(0, 32)}...</code>
          </div>
        ) : (
          <div className="notice bad">{result.error}</div>
        ))}
    </>
  );
}
