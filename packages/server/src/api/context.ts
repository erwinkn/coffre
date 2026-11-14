import type { AuthConfig } from '@coffre/core/identity';
import type { Called, Presented, Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { WorkloadTransport } from '../workloads/transport.ts';
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
  /**
   * Whether the request rides on the browser's cookie from another site's
   * page, or from a page of coffre's that another site embeds: a read that
   * makes coffre fetch something (an MCP client's metadata document) is
   * refused it, so that no site makes coffre fetch for it in a visitor's name.
   */
  crossSite: boolean;
  /** How the deployment signs people in: what a sign-in route says of it (`cliSessionDays`). */
  auth: AuthConfig;
  /** Days a value may go unchanged before the pages flag it for rotation, as the deployment says (`rotateAfterDays`); null for no flag. */
  rotateAfterDays: number | null;
  /** How the app asks an issuer where its keys are, when a binding is made (`discoverKeys`). */
  transport: WorkloadTransport;
};

/** Who a request is, as the vault answers it; its refusal, thrown as the API's. */
export async function callerOf(vault: Vault, shown: Presented): Promise<Called> {
  const answer = await vault.caller(shown);
  if ('refused' in answer) throw refusal(answer.refused);
  return answer;
}
