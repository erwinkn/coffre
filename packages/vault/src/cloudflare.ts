/**
 * The vault as a Worker, behind an entrypoint the app's `VAULT` service
 * binding calls over RPC. It has no route and no HTTP surface. It decides
 * in the database the app uses, through two Hyperdrive bindings of its
 * own, the vault's login and its uses' (`coffre_vault_hot`), and seals its
 * log through the checkpointer's Durable Object:
 *
 *   import { checkpointer, postgres, vault } from '@coffre/vault/cloudflare';
 *
 *   export default vault((env: Env) => ({
 *     database: postgres(env.VAULT_HYPERDRIVE),
 *     hotDatabase: postgres(env.HOT_HYPERDRIVE),
 *     checkpointer: env.CHECKPOINTER,
 *     kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY }, // or awsKms({ keyArn, credentials }), with a signingKey
 *     owners: ['admin@acme.example'],
 *   }));
 *   export const CoffreCheckpointer = checkpointer();
 *
 * Any number of isolates run it side by side: every decision locks what it
 * is about in the database, so they share one log and one bulk limit.
 */
import type { ChangeBindingsInput, CutoverInput,
  AdmitInput,
  RemoveInput,
  RevokeCredentialInput,
  IssueTokenInput,
  ReferenceInput,
  EndReferencesInput,
  PrepareInput,
  RewrapInput,
  SetAccessInput,
  SetSettingsInput,
  SignInInput,
  ChangePolicyInput,
  UnwrapInput,
  NamedUseInput,
  UseInput,
  Vault,
  VerifyLogInput,
  WrapInput,
} from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';
import { WorkerEntrypoint } from 'cloudflare:workers';

import type { Witness } from './checkpointer.ts';
import { checkpointerObject, durableHeldOutside, durableSealThrough, startCheckpointer, type ObjectNamespace } from './checkpointer-workers.ts';
import { resolveVaultConfig, type VaultConfig } from './config.ts';
import { openVault, prepareVault, type PreparedVault } from './vault.ts';

export type { Vault, VaultConfig };
export { postgres, type PostgresDatabase } from '@coffre/db/hyperdrive';
export * from './index.ts';

/**
 * What the vault Worker's `vault(env => …)` returns, for 0.15's log
 * (docs/design/0.15-plan.md):
 * - `hotDatabase`: the uses' own Hyperdrive config, whose login is
 *   `coffre_vault_hot`, and `uses`, how many uses an isolate has in flight
 *   at most (by default `connections`, the share of that config's pool an
 *   isolate may hold: T112 measures it);
 * - `checkpointer`: the namespace of the checkpointer's Durable Object,
 *   `CoffreCheckpointer` (`checkpointer()`, below), bound beside the vault.
 *   A change answers once that object has sealed it (R51), and the
 *   verifier holds every check to the pair it remembers;
 * - `witnesses` (docs/design/audit-tree.md, R40: a deployment opts in).
 * A configuration without the first two is refused, at the first call.
 */
export type WorkersVaultConfig = VaultConfig & {
  database: PostgresDatabase;
  hotDatabase: PostgresDatabase;
  checkpointer: ObjectNamespace;
  witnesses?: readonly Witness[];
  uses?: { inFlight?: number; connections?: number; coverMs?: number; names?: number };
};

/** Set when the Worker's module runs `vault(…)`, before any call comes in. */
let configure: ((env: never) => WorkersVaultConfig) | null = null;

/**
 * The configuration, checked and made ready once per `env`, which the
 * isolate keeps: the ready value itself, never the work of making it, which
 * would belong to the call that started it (vault.ts, `PreparedVault`).
 */
const ready = new WeakMap<object, Ready>();

/**
 * One `env`'s vault, ready: its databases, its prepared state, and whether
 * a call of this isolate started the checkpointer, or when one last tried.
 */
type Ready = { database: PostgresDatabase; hotDatabase: PostgresDatabase; checkpointer: ObjectNamespace; prepared: PreparedVault; started: boolean; tried: number };

/** How long after a start that failed, the checkpointer's object out of reach, the next call tries again. */
const START_AGAIN_MS = 10_000;

/**
 * What the app's `VAULT` service binding calls. Each call gets a database of
 * its own, one client that its queries take turns on, since a Worker's
 * connections belong to the call that made them; it is closed once the
 * call is done.
 */
export class VaultEntrypoint extends WorkerEntrypoint implements Vault {
  async #call<T>(run: (vault: Required<Vault>) => Promise<T>): Promise<T> {
    const { prepared, database } = await this.#ready();
    const pool = new HyperdrivePool(database.hyperdrive.connectionString);
    try {
      return await run(openVault(createDatabase(pool), prepared));
    } finally {
      this.ctx.waitUntil(pool.end());
    }
  }

  /** 0.15's use: one connection of the hot path's config, for its one statement. */
  async use(input: UseInput) {
    const { prepared, hotDatabase } = await this.#ready();
    const pool = new HyperdrivePool(hotDatabase.hyperdrive.connectionString);
    try {
      const hot = createDatabase(pool);
      return await openVault(hot, prepared, hot).use!(input);
    } finally {
      this.ctx.waitUntil(pool.end());
    }
  }

  /** 0.15's use as the request names it: the same one connection, for its read of ids on a miss and its one use. */
  async useNamed(input: NamedUseInput) {
    const { prepared, hotDatabase } = await this.#ready();
    const pool = new HyperdrivePool(hotDatabase.hyperdrive.connectionString);
    try {
      const hot = createDatabase(pool);
      return await openVault(hot, prepared, hot).useNamed!(input);
    } finally {
      this.ctx.waitUntil(pool.end());
    }
  }

  async #ready(): Promise<Ready> {
    const env = this.env as object;
    let entry = ready.get(env);
    if (entry === undefined) {
      if (configure === null) throw new Error('the vault Worker must export default vault(…)');
      const config = configure(env as never);
      const { checkpointer: namespace, hotDatabase } = checked(config);
      const prepared = await prepareVault(resolveVaultConfig(config), {
        ...(config.uses === undefined ? {} : { uses: config.uses }),
        log: '0.15',
        sealThrough: durableSealThrough(namespace),
        heldOutside: durableHeldOutside(namespace),
      });
      // Calls that raced here each made one; the first kept serves them all from now on.
      entry = ready.get(env) ?? { database: config.database, hotDatabase, checkpointer: namespace, prepared, started: false, tried: -Infinity };
      ready.set(env, entry);
    }
    if (!entry.started && Date.now() - entry.tried >= START_AGAIN_MS) await start(entry);
    return entry;
  }

  async unwrap(input: UnwrapInput) { return this.#call((vault) => vault.unwrap(input)); }
  async wrap(input: WrapInput) { return this.#call((vault) => vault.wrap(input)); }
  async rewrap(input: RewrapInput) { return this.#call((vault) => vault.rewrap(input)); }
  async reference(input: ReferenceInput) { return this.#call((vault) => vault.reference(input)); }
  async endReferences(input: EndReferencesInput) { return this.#call((vault) => vault.endReferences(input)); }
  async access(principal: string) { return this.#call((vault) => vault.access(principal)); }
  async setAccess(input: SetAccessInput) { return this.#call((vault) => vault.setAccess(input)); }
  async admit(input: AdmitInput) { return this.#call((vault) => vault.admit(input)); }
  async remove(input: RemoveInput) { return this.#call((vault) => vault.remove(input)); }
  async settings() { return this.#call((vault) => vault.settings()); }
  async setSettings(input: SetSettingsInput) { return this.#call((vault) => vault.setSettings(input)); }
  async policy() { return this.#call((vault) => vault.policy()); }
  async changePolicy(input: ChangePolicyInput) { return this.#call((vault) => vault.changePolicy(input)); }
  async checkpoint() { return this.#call((vault) => vault.checkpoint()); }
  /** What the vault says of itself; its uses over the hot path's own config (`use`), which `#call`'s vault has not. */
  async about() {
    const about = await this.#call((vault) => vault.about());
    return about.log === '0.15' ? { ...about, uses: true as const } : about;
  }
  async keyChecks() { return this.#call((vault) => vault.keyChecks()); }
  async verifyLog(input: VerifyLogInput) { return this.#call((vault) => vault.verifyLog(input)); }
  async prepare(input: PrepareInput) { return this.#call((vault) => vault.prepare(input)); }
  async waitSealed(input: { number: string }) { return this.#call((vault) => vault.waitSealed(input)); }
  async signIn(input: SignInInput) { return this.#call((vault) => vault.signIn(input)); }
  async revokeCredential(input: RevokeCredentialInput) { return this.#call((vault) => vault.revokeCredential(input)); }
  async issueToken(input: IssueTokenInput) { return this.#call((vault) => vault.issueToken(input)); }
  async changeBindings(input: ChangeBindingsInput) { return this.#call((vault) => vault.changeBindings(input)); }
  async cutover(input?: CutoverInput) { return this.#call((vault) => vault.cutover(input)); }
  async verifyTrees() { return this.#call((vault) => vault.verifyTrees()); }

  /** No HTTP surface: only the app's service binding reaches the vault. */
  fetch() {
    return new Response('not found', { status: 404 });
  }
}

/** The bindings 0.15's log needs, present: a binding left out of wrangler.jsonc reads as undefined, and is refused here, by name. */
function checked(config: WorkersVaultConfig): { hotDatabase: PostgresDatabase; checkpointer: ObjectNamespace } {
  if (config.hotDatabase?.hyperdrive?.connectionString === undefined) {
    throw new Error("the vault's uses run through a Hyperdrive config of their own: set hotDatabase in vault(…), postgres(env.HOT_HYPERDRIVE), its login coffre_vault_hot");
  }
  if (typeof config.checkpointer?.idFromName !== 'function') {
    throw new Error("the vault answers a change once its checkpointer has sealed it: set checkpointer in vault(…), env.CHECKPOINTER, and bind the CoffreCheckpointer Durable Object beside the vault");
  }
  return { hotDatabase: config.hotDatabase, checkpointer: config.checkpointer };
}

/**
 * The checkpointer's object started, from a call of this isolate, before it
 * goes on: its alarm set, and it open, so that no call meets a log with no
 * checkpoint yet. Started again is harmless, so each isolate starts it once.
 * An object that refuses to open (a log it cannot take: docs/restore.md) is
 * started all the same, its alarm set, and says why in its alarms; one out
 * of reach is tried again by a later call. Neither stops this call: a use
 * needs no checkpointer, and a change fails on its seal.
 */
async function start(entry: Ready): Promise<void> {
  entry.tried = Date.now();
  try {
    await startCheckpointer(entry.checkpointer);
    entry.started = true;
  } catch (error) {
    if ((error as { status?: number }).status === 503) entry.started = true;
    console.warn(`coffre vault: ${(error as Error).message}`);
  }
}

/** The vault Worker's default export, `VaultEntrypoint`, configured from its `env`. */
export function vault<Env>(configure_: (env: Env) => WorkersVaultConfig): typeof VaultEntrypoint {
  configure = configure_ as (env: never) => WorkersVaultConfig;
  return VaultEntrypoint;
}

/**
 * 0.15's checkpointer, the Durable Object class a deployment binds beside
 * the vault, configured by the same `vault(env => …)`: its Hyperdrive, its
 * signing key, its witnesses. `export const CoffreCheckpointer = checkpointer()`.
 */
export function checkpointer() {
  return checkpointerObject((env: object) => {
    if (configure === null) throw new Error('the vault Worker must export default vault(…)');
    const config = configure(env as never);
    return { hyperdrive: config.database.hyperdrive, seed: resolveVaultConfig(config).signingKeys[0]!, witnesses: config.witnesses };
  });
}

export { checkpointerAlarms, checkpointerStatus, durableHeldOutside, durableSealThrough, startCheckpointer, type ObjectNamespace } from './checkpointer-workers.ts';
export { durableWitness, r2Archive, witnessObject as witness, type WitnessSettings } from './witness-workers.ts';
