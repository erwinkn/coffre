import { keyCheckOf } from '@coffre/core/kek';
import { PURPOSES, type About, type Answers, type Asked, type Change, type McpUnasked, type Presented, type Unasked, type Upstream, type UseInput, type Vault, type WorkloadsUnasked } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ResolvedVaultConfig } from './config.ts';
import { caller } from './caller.ts';
import { change, weigh, type Operation, type Parts } from './change.ts';
import { OPERATIONS } from './ops/index.ts';
import { presented, text } from './ops/input.ts';
import { through } from './ops/via.ts';
import { keyOf } from './rows.ts';
import { memoryOf, peek, use, type Ask, type Serving } from './use.ts';

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
export type PreparedVault = Pick<Serving, 'keys' | 'keks' | 'cap' | 'workloads' | 'memory' | 'refused'> & Pick<Deciding, 'owners'> & { about: About };

export function prepareVault(config: ResolvedVaultConfig): PreparedVault {
  const [kek, ...previous] = config.keks.all.map(({ provider, keyId }) => ({ provider, id: keyId }));
  const about = { kek, previous, checks: config.signingKeys.map(keyCheckOf) };
  return { keys: config.signingKeys.map(keyOf), keks: config.keks, cap: config.bulkLimit, workloads: config.workloads, memory: memoryOf(config.memorySeconds, config.outageSeconds), refused: new Map(), owners: config.owners, about };
}

/** `about`, from the configuration alone: a copy each call, so no caller changes what the next is told. */
export function about(prepared: PreparedVault): About {
  return structuredClone(prepared.about);
}

/** What one call runs on: its database, and the signer's wake-up, which never holds the reply nor fails the call. */
export type VaultOptions = { wake(hash: Buffer): void | Promise<void>; now?(): number };

/**
 * A use as the engine takes it. The app is the caller's word for what a
 * request showed, not for its shape: a use that is not what the contract
 * says is a fault, before any read. Its purpose goes into the log under
 * the vault's MAC, so it is one the contract names.
 */
function asked(input: UseInput): Ask {
  const { project, environment, mine, purpose, upstream, fresh = false } = input;
  // A copy: an array that crossed from another isolate may have holes, which no check of its items sees.
  const keys = input.keys === null ? null : Array.isArray(input.keys) ? [...input.keys] : undefined;
  const named = keys === null || (keys !== undefined && keys.length <= 1000 && keys.every(text));
  const to = upstreamOf(upstream);
  if (!text(project) || !text(environment) || typeof mine !== 'boolean' || !named || !PURPOSES.includes(purpose) || to === undefined || typeof fresh !== 'boolean') {
    throw new TypeError('a use names a place by its slugs, 1,000 keys at most, a purpose the contract has, and its upstream as { credential, host?, egress?: true }');
  }
  return { ...presented(input), project, environment, mine, keys: keys as string[] | null, purpose, upstream: to, fresh };
}

/** A host as a URL's `hostname` spells it: lower case, a name, an IPv4 address or a bracketed IPv6 one. */
const HOSTNAME = /^(?=.{1,253}$)[a-z0-9.:[\]-]+$/;

/** A use's upstream, rebuilt from its fields alone; undefined for one the contract does not have. */
function upstreamOf(value: unknown): Upstream | null | undefined {
  if (value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) return undefined;
  const { credential, host, egress, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0 || !text(credential) || !(host === undefined || (typeof host === 'string' && HOSTNAME.test(host))) || !(egress === undefined || egress === true)) return undefined;
  return { credential, ...(host === undefined ? {} : { host }), ...(egress === true ? { egress } : {}) };
}

/** The changes nobody asks, by name: each rests on a proof, which a weighing would try and not spend. */
const UNASKED: Record<Unasked | WorkloadsUnasked | McpUnasked, true> = { signin: true, 'device.start': true, 'device.redeem': true, 'token.exchange': true, 'workload.signin': true, 'mcp.token': true, 'mcp.revoke': true, 'oauth.register': true };

/**
 * What every operation is given of the vault's configuration, past its
 * input: what it takes of workloads, and the people it names Owners
 * (`owners`), by email, whom no change demotes or removes while named.
 */
export type Deciding = Pick<Serving, 'workloads'> & { owners: readonly string[] };

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
  const operation = <O extends Change['op']>(input: Asked<O>) => {
    if (!Object.hasOwn(OPERATIONS, input.op)) throw new TypeError('a change names an operation the contract has');
    // The registry holds each operation under its own name: what it answers is that name's.
    const made = OPERATIONS[input.op] as unknown as (input: Asked<O>, vault: Deciding) => Operation<Parts, Answers[O], unknown>;
    const operation = made(input, { workloads: serving.workloads, owners: prepared.owners });
    // A change a person approved for an MCP connection: the same operation, the connection read and named beside it.
    if (!('via' in input) || input.via === undefined) return operation;
    if (Object.hasOwn(UNASKED, input.op)) throw new TypeError('a change nobody asks is made for no connection');
    return through(operation, input.via, presented(input as unknown as Presented).token);
  };
  return {
    async use(input) {
      const answer = await use(serving, asked(input));
      if ('refused' in answer) return answer;
      return { ...answer, values: answer.values.map((value) => ('refused' in value ? value : { ...value, value: value.value.toString('utf8') })) };
    },
    async peek(input) {
      return peek(serving, asked(input));
    },
    async caller(input) {
      return caller(serving, { ...presented(input), head: input.head === true });
    },
    async change(input) {
      return change(serving, operation(input));
    },
    async weigh(input) {
      if (Object.hasOwn(UNASKED, input.op)) throw new TypeError('a change nobody asks is not weighed');
      return weigh(serving, operation(input));
    },
    async about() {
      return about(prepared);
    },
  };
}
