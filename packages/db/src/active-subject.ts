import { sql } from 'drizzle-orm';

/**
 * `identities.active_subject`: the subject while the account is bound, null
 * once revoked. A unique index on (provider, issuer_hash, active_subject)
 * binds an account to one person at a time. Plain column names, so the
 * expression reads the same on both databases.
 */
export const ACTIVE_SUBJECT = sql`CASE WHEN revoked_at IS NULL THEN subject END`;
