import { loadAuthConfig } from '../../../../packages/core/src/identity/auth-mode';

/**
 * Evaluated when the TanStack server loads its server functions, before one
 * handles a request. Invalid or contradictory authentication settings fail
 * configuration loading instead of silently changing the identity path.
 */
export const authConfig = loadAuthConfig(process.env);
