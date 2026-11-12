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
import { gated, isStackOverflow, STACK_OVERFLOW, type NamedManyInput, type NamedUseInput, type ProxyItemInput, type RouteUseInput, type UseInput, type UseManyInput, type Vault, type VaultAnswer, type VaultEntry, type VaultMethod } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';
import { WorkerEntrypoint } from 'cloudflare:workers';

import type { Witness } from './checkpointer.ts';
import { checkpointerObject, durableHeldOutside, durableSealing, durableSealThrough, startCheckpointer, startProjector, type ObjectNamespace } from './checkpointer-workers.ts';
import { resolveVaultConfig, type ResolvedVaultConfig, type VaultConfig } from './config.ts';
import { openVault, prepareVault, type PreparedVault } from './vault.ts';

export type { Vault, VaultConfig, VaultEntry };
export { postgres, type PostgresDatabase } from '@coffre/db/hyperdrive';
export * from './index.ts';

/**
 * What the vault Worker's `vault(env => …)` returns, for 0.15's log
 * (docs/design/0.15-plan.md):
 * - `hotDatabase`: the uses' own Hyperdrive config, whose login is
 *   `coffre_vault_hot`, and `uses.batch`, the most keys a statement of a
 *   request's several makes uses of (100: `UseLimits.batch`). How many keys
 *   an isolate has in flight is derived, not set (`USES_IN_FLIGHT`,
 *   `@coffre/core/memory`);
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
  /** `coverMs` is deprecated: in `deployment.ts` since 0.16, `audit.repeatsWithinSeconds`, read until 0.17, which refuses it here. */
  uses?: { coverMs?: number; names?: number; batch?: number };
};

/**
 * The vault's configuration resolved with its uses' options: the cover a repeat rides, the deployment's
 * `audit.repeatsWithinSeconds`, which `uses.coverMs` gave until 0.16.
 */
function resolved(config: WorkersVaultConfig): { vault: ResolvedVaultConfig; uses: NonNullable<WorkersVaultConfig['uses']> } {
  const coverMs = config.uses?.coverMs;
  const vault = resolveVaultConfig(config, coverMs === undefined ? [] : [{ old: 'vault({ uses: { coverMs } })', options: { audit: { repeatsWithinSeconds: coverMs / 1000 } } }]);
  return { vault, uses: { ...config.uses, coverMs: vault.deployment.audit.repeatsWithinSeconds * 1000 } };
}

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
 * a call of this isolate started the checkpointer, when a start last
 * failed, and when a use last started one behind it: settled values, never
 * the start under way.
 */
type Ready = { database: PostgresDatabase; hotDatabase: PostgresDatabase; checkpointer: ObjectNamespace; prepared: PreparedVault; started: boolean; failed: number; kicked: number };

/** How long after a start that failed, the checkpointer's object out of reach, the next call tries again. */
const START_AGAIN_MS = 10_000;

/**
 * What the app's `VAULT` service binding calls: one method, `call(release,
 * method, args)`, the version gate (docs/design/proxy-ui.md, section 3,
 * "One version at a time"). It compares the release before anything else,
 * before the config is prepared or any pool opens: a call from an app on
 * another release answers this one's and runs nothing. Each method behind
 * it is private, the hot path's included. Each call gets a database of its
 * own, one client that its queries take turns on, since a Worker's
 * connections belong to the call that made them; it is closed once the
 * call is done. Its plain reads asked together go together, one round trip
 * (`groupReads`): a cold call's start asks its first reads so (`#start`
 * in vault.ts, T206).
 */
export class VaultEntrypoint extends WorkerEntrypoint implements VaultEntry {
  async call(release: string, method: VaultMethod, args: readonly unknown[]): Promise<VaultAnswer> {
    return gated(release, method, args, (name, given) => this.#dispatch(name, given)).catch((error: unknown) => {
      // A stack that ran out, as a plain `RangeError`, which RPC hands back with its type and message (`isStackOverflow`):
      // one wrapped in another error would lose its cause on the way.
      throw isStackOverflow(error) ? new RangeError(STACK_OVERFLOW) : error;
    });
  }

  #dispatch(method: VaultMethod, args: unknown[]): Promise<unknown> {
    switch (method) {
      case 'use': return this.#use(args[0] as UseInput);
      case 'useMany': return this.#useMany(args[0] as UseManyInput);
      case 'useNamed': return this.#useNamed(args[0] as NamedUseInput);
      case 'useNamedMany': return this.#useNamedMany(args[0] as NamedManyInput);
      case 'useRoute': return this.#hot(args[0] as RouteUseInput, (vault, input) => vault.useRoute(input));
      case 'proxyItem': return this.#hot(args[0] as ProxyItemInput, (vault, input) => vault.proxyItem(input));
      case 'about': return this.#about();
      case 'sealing': return this.#sealing();
      default: return this.#call((vault) => (vault[method] as (...given: unknown[]) => Promise<unknown>)(...args));
    }
  }

  async #call<T>(run: (vault: Required<Vault>) => Promise<T>): Promise<T> {
    const { prepared, database } = await this.#ready();
    const pool = new HyperdrivePool(database.hyperdrive.connectionString, { groupReads: true });
    try {
      return await run(openVault(createDatabase(pool), prepared));
    } finally {
      this.ctx.waitUntil(pool.end());
    }
  }

  /**
   * 0.15's use: one connection of the hot path's config, for its one statement. Closed once the call is done, and by
   * its deadline at the latest, so that a call answered `late` lets go of Hyperdrive by then, as its place in admission
   * lapses soon after (use.ts, `HELD_PAST_DEADLINE_MS`; T170).
   */
  async #use(input: UseInput) {
    const { prepared, hotDatabase } = this.#behind(await this.#prepared());
    const pool = new HyperdrivePool(hotDatabase.hyperdrive.connectionString);
    try {
      const hot = createDatabase(pool);
      return await openVault(hot, prepared, hot).use!(input);
    } finally {
      this.ctx.waitUntil(pool.end(closeBy(input)));
    }
  }

  /** A request's several keys (T167): the same one connection, for its one statement, or two. */
  async #useMany(input: UseManyInput) {
    const { prepared, hotDatabase } = this.#behind(await this.#prepared());
    if (hotDatabase === undefined) throw new Error("0.15's uses need the hot path's Hyperdrive config: set hotDatabase in vault(…)");
    const pool = new HyperdrivePool(hotDatabase.hyperdrive.connectionString);
    try {
      const hot = createDatabase(pool);
      return await openVault(hot, prepared, hot).useMany!(input);
    } finally {
      this.ctx.waitUntil(pool.end(closeBy(input)));
    }
  }

  /**
   * A route use, or `proxyItem`'s read (T186 PR C): the hot path's one connection, for its statements (one; two on a map
   * miss; more for a second round or a route of many keys), closed by the call's deadline at the latest, as a use's.
   */
  async #hot<T extends { deadline: number }, R>(input: T, run: (vault: Required<Vault>, input: T) => Promise<R>): Promise<R> {
    const { prepared, hotDatabase } = this.#behind(await this.#prepared());
    if (hotDatabase === undefined) throw new Error("0.15's uses need the hot path's Hyperdrive config: set hotDatabase in vault(…)");
    const pool = new HyperdrivePool(hotDatabase.hyperdrive.connectionString);
    try {
      const hot = createDatabase(pool);
      return await run(openVault(hot, prepared, hot), input);
    } finally {
      this.ctx.waitUntil(pool.end(closeBy(input)));
    }
  }

  /** A request's several keys as it names them (T165): the same one connection, for its one statement, or two or three. */
  async #useNamedMany(input: NamedManyInput) {
    const { prepared, hotDatabase } = this.#behind(await this.#prepared());
    if (hotDatabase === undefined) throw new Error("0.15's uses need the hot path's Hyperdrive config: set hotDatabase in vault(…)");
    const pool = new HyperdrivePool(hotDatabase.hyperdrive.connectionString);
    try {
      const hot = createDatabase(pool);
      return await openVault(hot, prepared, hot).useNamedMany!(input);
    } finally {
      this.ctx.waitUntil(pool.end(closeBy(input)));
    }
  }

  /** 0.15's use as the request names it: the same one connection, for its read of ids on a miss and its one use. */
  async #useNamed(input: NamedUseInput) {
    const { prepared, hotDatabase } = this.#behind(await this.#prepared());
    const pool = new HyperdrivePool(hotDatabase.hyperdrive.connectionString);
    try {
      const hot = createDatabase(pool);
      return await openVault(hot, prepared, hot).useNamed!(input);
    } finally {
      this.ctx.waitUntil(pool.end(closeBy(input)));
    }
  }

  /** What the vault says of itself; its uses over the hot path's own config (`#use`), which `#call`'s vault has not. */
  async #about() {
    const about = await this.#call((vault) => vault.about());
    return about.log === '0.15' ? { ...about, uses: true as const, batchUses: true as const } : about;
  }

  /** Whether the checkpointer seals (T169), asked of its object for at most 2 s; no database, and no start awaited. */
  async #sealing() {
    const { checkpointer: namespace } = this.#behind(await this.#prepared());
    return durableSealing(namespace)();
  }

  /** The vault ready, its checkpointer started from this call first, for at most 2 s (`start`). */
  async #ready(): Promise<Ready> {
    const entry = await this.#prepared();
    if (!entry.started && Date.now() - entry.failed >= START_AGAIN_MS) await start(entry);
    return entry;
  }

  /**
   * A use waits on no start (T169, R58): it needs no checkpointer, the days of uses the migrations made and the object
   * makes ahead of time aside. Its isolate's start goes on behind it, once each START_AGAIN_MS until one answers.
   */
  #behind(entry: Ready): Ready {
    if (!entry.started && Date.now() - entry.kicked >= START_AGAIN_MS) {
      entry.kicked = Date.now();
      this.ctx.waitUntil(start(entry));
    }
    return entry;
  }

  async #prepared(): Promise<Ready> {
    const env = this.env as object;
    let entry = ready.get(env);
    if (entry === undefined) {
      if (configure === null) throw new Error('the vault Worker must export default vault(…)');
      const config = configure(env as never);
      const { checkpointer: namespace, hotDatabase } = checked(config);
      const { vault: resolvedConfig, uses } = resolved(config);
      const prepared = await prepareVault(resolvedConfig, {
        uses,
        sealThrough: durableSealThrough(namespace),
        heldOutside: durableHeldOutside(namespace),
        callsEndWithRequest: true,
      });
      // Calls that raced here each made one; the first kept serves them all from now on.
      entry = ready.get(env) ?? { database: config.database, hotDatabase, checkpointer: namespace, prepared, started: false, failed: -Infinity, kicked: -Infinity };
      ready.set(env, entry);
    }
    return entry;
  }

  /** No HTTP surface: only the app's service binding reaches the vault. */
  fetch() {
    return new Response('not found', { status: 404 });
  }
}

/** When a use's connection closes at the latest: its deadline, if it names one (`checkInput` refuses it otherwise). */
function closeBy(input: { deadline?: unknown } | undefined): number | undefined {
  return typeof input?.deadline === 'number' && Number.isSafeInteger(input.deadline) ? input.deadline : undefined;
}

/**
 * What 0.15's log needs, configured: a setting left out of `vault(…)` is refused here, by name. A Hyperdrive binding
 * left out of wrangler.jsonc is refused before, by `postgres()`; a Durable Object's, here.
 */
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
 * checkpoint yet. Started again is harmless: until one start has answered,
 * each call makes its own and waits for it, never for another call's,
 * which a call may not await on Workers (AGENTS.md).
 * An object that refuses to open (a log it cannot take: docs/restore.md) is
 * started all the same, its alarm set, and says why in its alarms; one out
 * of reach, or that does not answer within 2 s (T169), is tried again by a
 * call 10 s later. Neither stops this call: a use needs no checkpointer (and
 * waits on no start: `#behind`), and a change fails on its seal.
 */
async function start(entry: Ready): Promise<void> {
  // The reads' projector beside it (T166), an object of its own, which opens nothing to start: one that fails to is
  // started by the next isolate's first call, and the audit pages say how far behind their reads are meanwhile.
  const projecting = startProjector(entry.checkpointer).catch((error: Error) => console.warn(`coffre vault: the reads' projector did not start: ${error.message}`));
  try {
    await startCheckpointer(entry.checkpointer);
    entry.started = true;
  } catch (error) {
    if ((error as { status?: number }).status === 503) entry.started = true;
    else entry.failed = Date.now();
    console.warn(`coffre vault: ${(error as Error).message}`);
  }
  await projecting;
}

/** The vault Worker's default export, `VaultEntrypoint`, configured from its `env`. */
export function vault<Env>(configure_: (env: Env) => WorkersVaultConfig): typeof VaultEntrypoint {
  configure = configure_ as (env: never) => WorkersVaultConfig;
  return VaultEntrypoint;
}

/**
 * 0.15's checkpointer, the Durable Object class a deployment binds beside
 * the vault, configured by the same `vault(env => …)`: its Hyperdrive, its
 * signing keys (the one it signs with, and those it replaced: T168), its witnesses. `export const CoffreCheckpointer = checkpointer()`.
 */
export function checkpointer() {
  return checkpointerObject((env: object) => {
    if (configure === null) throw new Error('the vault Worker must export default vault(…)');
    const config = configure(env as never);
    const { vault: resolvedConfig } = resolved(config);
    // Days of uses kept: the deployment's `audit.keepUsesDays`, every day when null (retention.ts).
    return { hyperdrive: config.database.hyperdrive, signingKeys: resolvedConfig.signingKeys, witnesses: config.witnesses, retainDays: resolvedConfig.deployment.audit.keepUsesDays };
  });
}

export { checkpointerAlarms, checkpointerStatus, durableHeldOutside, durableSealing, durableSealThrough, startCheckpointer, startProjector, type ObjectNamespace } from './checkpointer-workers.ts';
export { durableWitness, r2Archive, witnessObject as witness, type WitnessSettings } from './witness-workers.ts';
