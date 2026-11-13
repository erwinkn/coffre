import { isUnsealed, type Vault, type VaultRefused } from '@coffre/core/vault';

import { ApiError, REFUSAL_UNSEALED_MESSAGE } from './api/errors.ts';
import { logged } from './logged.ts';

import type { AuditEntry } from './db/audit.ts';

/**
 * A key write or a member's first add the vault's decision refused on its read (docs/design/two-trips.md,
 * "As built: PR 6"). The app answers it as today's path would, for the caller that read decided, checked on its
 * rows as a served try's is: its router's check or its handler refuses it, with the same status and body. Where that
 * path appends a 0.14 deny entry of the action the vault refused, the vault records the refusal in 0.15's log instead
 * (`refuse`, in api/context.ts), once: the read and the record, two round trips, and no entry.
 *
 *   Ada's PATCH market/dev, no grant there   vault: refused, `no_grant`     the router: 403 "you need secret.write on
 *                                                                           market/dev", recorded by the vault
 *
 * A ticket expired meanwhile (the app took more than its 30 s) records nothing: the app appends the entry itself.
 */
export class RefusalRecord {
  readonly refused: VaultRefused;
  readonly #vault: Pick<Vault, 'recordRefusal'>;
  readonly #action: string;
  #recorded: Promise<boolean> | null = null;

  constructor(vault: Pick<Vault, 'recordRefusal'>, refused: VaultRefused, action: 'secret.write' | 'member.add') {
    this.#vault = vault;
    this.refused = refused;
    this.#action = action;
  }

  /** Whether a refusal's entry is this record's to stand for: a deny of the action the vault refused. */
  covers(entry: AuditEntry): boolean {
    return entry.decision === 'deny' && entry.action === this.#action;
  }

  /**
   * The record written and sealed, once however often asked; false where its ticket expired, nothing written. Written
   * but not sealed in time, it answers 503 as a change does, in words of its own: no change was made.
   */
  record(): Promise<boolean> {
    this.#recorded ??= this.#vault.recordRefusal!({ ticket: this.refused.ticket }).then(
      (outcome) => outcome.recorded,
      (error: unknown) => {
        if (!isUnsealed(error)) throw error;
        console.error("a refusal's record was not sealed in time", logged(error));
        throw new ApiError('unavailable', REFUSAL_UNSEALED_MESSAGE);
      },
    );
    return this.#recorded;
  }
}
