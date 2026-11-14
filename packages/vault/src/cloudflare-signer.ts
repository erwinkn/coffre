/**
 * The signer on Workers: one Durable Object of the vault Worker's for the
 * instance (docs/design/0.16.md, "The signer"). It holds the vault's keys,
 * since it checks each entry's MAC and adopts the database (adopt.ts), and
 * storage of its own, which whoever writes the database does not write. Its alarm is the signer's clock
 * (signer-host.ts).
 *
 * SQLite-backed, so that a run's changes are one transaction however many
 * keys they touch: `new_sqlite_classes` in the Worker's migration. Called
 * over RPC by the vault, through its `SIGNER` binding, always the object
 * named `signer`.
 */
import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';
import { DurableObject, type DurableObjectState } from 'cloudflare:workers';

import type { Adopting } from './adopt.ts';
import { keyOf } from './rows.ts';
import { SignerHost, type SignerAlert, type SignerStatus } from './signer-host.ts';

export type SignerConfig = Adopting & {
  database: PostgresDatabase;
  /** How long a use is kept, in days (`log.keepUsesDays` in config.ts). Null keeps every one. */
  keepUsesDays: number | null;
  alert?: ((alert: SignerAlert) => void | Promise<void>) | undefined;
};

/** How long the signer's connection sits idle before it closes: a busy instance's runs, a second apart, share one. */
const IDLE_DATABASE_MS = 5000;

/** The one object of the signer's class that runs: every caller names it the same. */
const SIGNER = 'signer';

/** The vault Worker's `SIGNER` binding, as far as the vault calls it. */
export type SignerNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { adopt(): Promise<boolean>; wake(hash: Uint8Array): Promise<void>; status(): Promise<SignerStatus> };
};

/** The instance's signer, through the binding: `signerOf(env.SIGNER).wake(hash)`. */
export const signerOf = (namespace: SignerNamespace) => namespace.get(namespace.idFromName(SIGNER));

/** The Durable Object class, configured from the Worker's `env`. */
export function signerObject<Env>(configure: (env: Env) => SignerConfig) {
  return class CoffreSigner extends DurableObject<Env> {
    readonly #host: SignerHost;

    constructor(ctx: DurableObjectState, env: Env) {
      super(ctx, env);
      const { database, signingKeys, keks, owners, keepUsesDays, alert } = configure(env);
      this.#host = new SignerHost({
        storage: ctx.storage,
        alone: (run) => ctx.blockConcurrencyWhile(run),
        keys: signingKeys.map(keyOf),
        // The object's client lasts as long as it does: it opens with a run's first statement and closes once idle.
        db: createDatabase(new HyperdrivePool(database.hyperdrive.connectionString, { closeIdleMs: IDLE_DATABASE_MS })),
        now: Date.now,
        keepUsesDays,
        alert,
        adopting: { signingKeys, keks, owners },
      });
    }

    /** Whether the database is adopted, after adopting it if it is not: the vault's question before it serves. */
    adopt(): Promise<boolean> {
      return this.#host.adopt();
    }

    /** The vault's word that an entry was committed, by its hash. */
    wake(hash: Uint8Array): Promise<void> {
      return this.#host.wake(hash);
    }

    /** When the last check completed, what stands of what the checks found, and whether the database is adopted. */
    status(): Promise<SignerStatus> {
      return this.#host.status();
    }

    alarm(): Promise<void> {
      return this.#host.alarm();
    }
  };
}
