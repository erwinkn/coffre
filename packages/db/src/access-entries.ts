import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { sql, type SQL } from 'drizzle-orm';

/**
 * The vault's allowed access entries in 0.14's log: an add, restore, role
 * change or removal of a member, a grant or a revoke, as `ACCESS_ACTIONS`
 * names them. `audit_log_access_idx` holds them alone, by principal (on
 * SQLite after `author`, as the subject index): a principal's allowed
 * access entries, or the principals that have any, read in as many steps
 * however many other entries the log holds about them, refusals included
 * (T239, R48). A read that is to use the index repeats this condition word
 * for word, with no parameter, as `recorded` does for `log_changes`:
 * Postgres proves a partial index's condition only from constants, and
 * SQLite only from the same terms.
 */
export function accessAllowed(): SQL {
  const actions = ACCESS_ACTIONS.map((action) => `'${action}'`).join(', ');
  return sql.raw(`author = 'vault' AND decision = 'allow' AND action IN (${actions})`);
}
