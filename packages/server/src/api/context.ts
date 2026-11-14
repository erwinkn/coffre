import type { Called, Presented, Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import { refusal } from './errors.ts';

/** What every handler works with: the app's database, the vault, and what the request showed. */
export type ApiContext = {
  /** The app's own tables: what a page lists. Never what decides a use or a change. */
  db: Database;
  vault: Vault;
  /** What the request showed, which every call to the vault starts with. */
  shown: Presented;
  /**
   * Who the request is and what it holds, for a page's queries: asked of
   * the vault once a request, and once for all the calls of a page's
   * render. A use or a change does not ask: the vault reads its caller
   * itself.
   */
  caller(): Promise<Called>;
  /** Background work that must outlive the response, that is explicitly scheduled. */
  waitUntil: (promise: Promise<unknown>) => void;
  /** Days a value may go unchanged before it is flagged for rotation (`rotateAfterDays`), or null for no flag. */
  rotateAfterDays: number | null;
};

/** Who a request is, as the vault answers it; its refusal, thrown as the API's. */
export async function callerOf(vault: Vault, shown: Presented): Promise<Called> {
  const answer = await vault.caller(shown);
  if ('refused' in answer) throw refusal(answer.refused);
  return answer;
}
