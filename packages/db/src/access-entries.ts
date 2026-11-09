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

/**
 * Entries written by `author`, and with `decision` when given, as constants:
 * the condition of the audit log's partial indexes by author
 * (`audit_log_app_idx`, `audit_log_vault_idx`, `audit_log_vault_refused_idx`;
 * T245, R48). Bound as parameters, the
 * values let a plan made for them alone use those indexes: coffre's
 * statements are unnamed, each planned with its values, but a generic plan
 * (a named statement's from its sixth run, or `plan_cache_mode =
 * force_generic_plan`) could not prove the condition and would walk the
 * log by `seq` instead. As constants, every plan proves it.
 */
export function authoredBy(author: 'app' | 'vault', decision?: 'allow' | 'deny'): SQL {
  return sql.raw(`author = '${author}'${decision === undefined ? '' : ` AND decision = '${decision}'`}`);
}

/**
 * The vault's signed checkpoints: allowed `audit.checkpoint` entries, the
 * condition of `audit_log_signed_idx` (T245, R48), as constants, word for
 * word in the index and in each read that is to use it. Its own index,
 * with its whole condition, because the newest signed checkpoint is the
 * one lookup a run of refusals grows: Postgres walks back any index that
 * yields `seq` order (the primary key, `audit_log_vault_idx`,
 * `audit_log_action_idx`) with the rest as a filter whenever its
 * statistics hold signed checkpoints common, pricing the walk as the one
 * row the step down an index by `(action, seq)` costs, and after 100,000
 * refusals that walk read 3,250 to 4,880 pages (measured on Postgres 16).
 * An index that needs no filter is cheaper by its own estimate, every time.
 */
export function signedCheckpoints(): SQL {
  return sql.raw("author = 'vault' AND action = 'audit.checkpoint' AND decision = 'allow'");
}
