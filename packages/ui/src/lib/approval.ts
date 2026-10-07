import type { ApprovalView } from '@coffre/client';

/**
 * What the approval page says once an approval no longer waits: its title,
 * and what became of it. Approved with no outcome yet, coffre is making
 * the change; a minute on with none, the server reports it failed, its
 * outcome unknown, and the page says coffre doesn't know whether it was made.
 */
export function settled(view: Pick<ApprovalView, 'status' | 'outcome'>): { title: string; text: string } {
  if (view.outcome?.error === 'unknown_outcome') {
    return { title: 'This change may not have been made', text: "You approved it, but coffre doesn't know whether it was made. Check before approving it again." };
  }
  if (view.status === 'approved' && view.outcome === null) return { title: 'You approved this', text: 'coffre is making the change. Refresh in a moment to see how it went.' };
  const title = {
    pending: 'Waiting for you',
    approved: 'You approved this',
    denied: 'You denied this',
    cancelled: 'The app cancelled this',
    failed: 'This change failed',
    expired: 'This approval expired',
  }[view.status];
  return { title, text: view.outcome?.text ?? (view.status === 'expired' ? 'Nothing changed. The app can ask again.' : 'Nothing changed.') };
}
