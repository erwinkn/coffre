import { PURPOSES, type UseInput, type Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ResolvedVaultConfig } from './config.ts';
import { keyOf } from './rows.ts';
import { memoryOf, use, type Ask, type Serving } from './use.ts';

/**
 * The vault behind its contract (`Vault` in @coffre/core/vault,
 * docs/design/0.16.md, "The contract"): each call is the engine's, a use
 * or a change, with JSON on either side of it. Nothing is decided here.
 */

/**
 * What a process or an isolate keeps between calls: the keys, and the
 * vault's short memory. Settled values only, never work under way, which on
 * Workers would belong to the call that started it.
 */
export type PreparedVault = Pick<Serving, 'keys' | 'keks' | 'cap' | 'workloads' | 'memory'>;

export function prepareVault(config: ResolvedVaultConfig): PreparedVault {
  return { keys: config.signingKeys.map(keyOf), keks: config.keks, cap: config.bulkLimit, workloads: config.workloads, memory: memoryOf(config.memorySeconds) };
}

/** What one call runs on: its database, and the signer's wake-up, which never holds the reply nor fails the call. */
export type VaultOptions = { wake(hash: Buffer): void | Promise<void>; now?(): number };

const TOKEN = /^[0-9a-f]{64}$/;
/** A name as the vault takes one: text of a bounded length, which Postgres stores. What it names is the decision's to find, or not. */
const text = (value: unknown): value is string => typeof value === 'string' && value.length <= 256 && !value.includes('\0');

/**
 * A use as the engine takes it. The app is the caller's word for what a
 * request showed, not for its shape: a use that is not what the contract
 * says is a fault, before any read. Its purpose goes into the log under
 * the vault's MAC, so it is one the contract names.
 */
function asked(input: UseInput): Ask {
  const { token, proof, request, ip, project, environment, mine, purpose, upstream } = input;
  // A copy: an array that crossed from another isolate may have holes, which no check of its items sees.
  const keys = input.keys === null ? null : Array.isArray(input.keys) ? [...input.keys] : undefined;
  const named = keys === null || (keys !== undefined && keys.length <= 1000 && keys.every(text));
  const optional = [proof, request, ip, upstream].every((value) => value === null || text(value));
  if (!text(token) || !TOKEN.test(token) || !text(project) || !text(environment) || typeof mine !== 'boolean' || !named || !PURPOSES.includes(purpose) || !optional) {
    throw new TypeError('a use names a token by its SHA-256 in lowercase hex, a place by its slugs, 1,000 keys at most, and a purpose the contract has');
  }
  return { token: Buffer.from(token, 'hex'), proof, request, ip, project, environment, mine, keys: keys as string[] | null, purpose, credential: upstream };
}

export function openVault(db: Database, prepared: PreparedVault, { wake, now = Date.now }: VaultOptions): Vault {
  // A wake-up that throws, or whose promise rejects, fails nothing: the write it tells of has committed, and its answer is owed.
  const failed = (error: unknown) => console.error('coffre: the signer was not told of an entry', error);
  const told = (hash: Buffer) => {
    try {
      void Promise.resolve(wake(hash)).catch(failed);
    } catch (error) {
      failed(error);
    }
  };
  const serving: Serving = { ...prepared, db, now, wake: told };
  return {
    async use(input) {
      const answer = await use(serving, asked(input));
      if ('refused' in answer) return answer;
      return { ...answer, values: answer.values.map((value) => ('refused' in value ? value : { ...value, value: value.value.toString('utf8') })) };
    },
  };
}
