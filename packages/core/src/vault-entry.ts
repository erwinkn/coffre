import manifest from '../package.json' with { type: 'json' };

import type { Vault } from './vault.ts';

/**
 * One release at a time (docs/design/proxy-ui.md, section 3, "One version
 * at a time"; decision 8). The app and the vault Workers run one release,
 * and a deploy or a rollback moves both. Every call between them goes
 * through one envelope, `call(release, method, args)`, and the vault
 * answers a call on another release with its own and runs nothing: no
 * read, no lock, no write, no entry. The app answers such a call 503
 * `deploying` with `Retry-After: 1`, for the seconds until both Workers
 * match. Nothing serves across two releases.
 *
 *   app 0.16.0 ── call('0.16.0', 'useNamed', [input]) ──▶ vault 0.16.0   { release: '0.16.0', result }
 *   app 0.16.1 ── call('0.16.1', 'useNamed', [input]) ──▶ vault 0.16.0   { release: '0.16.0' }: 503 deploying
 *
 * The release is the packages' one version, read from this package's own
 * manifest, which both Workers bundle: `pnpm bump` moves it, and nobody
 * bumps a protocol number by hand.
 */
export const RELEASE: string = manifest.version;

/** Every call the vault answers, in the order of the `Vault` interface: the only names `call` takes. */
export const VAULT_METHODS = [
  'unwrap',
  'wrap',
  'rewrap',
  'reference',
  'endReferences',
  'access',
  'setAccess',
  'admit',
  'remove',
  'settings',
  'setSettings',
  'policy',
  'changePolicy',
  'checkpoint',
  'about',
  'keyChecks',
  'verifyLog',
  'use',
  'useNamed',
  'useMany',
  'useNamedMany',
  'useRoute',
  'proxyItem',
  'prepare',
  'writeKeys',
  'admitRead',
  'admitWrite',
  'recordRefusal',
  'note',
  'check',
  'rebuildAudit',
  'beat',
  'waitSealed',
  'signIn',
  'revokeCredential',
  'issueToken',
  'changeBindings',
  'verifyTrees',
  'verifyReads',
  'vouch',
  'sealing',
  'proxy',
  'saveProxy',
  'reserveProxy',
  'releaseProxy',
  'proxySavedBy',
] as const satisfies readonly (keyof Vault)[];

export type VaultMethod = (typeof VAULT_METHODS)[number];

const METHOD_NAMES: ReadonlySet<string> = new Set(VAULT_METHODS);

/**
 * What the vault answers a call: its own release, always, and the method's
 * result only when the call named the same one. A refusal is an answer,
 * not a thrown error: a Workers RPC error keeps its message but not its
 * fields, and a Node failure maps to 500, so neither could say `deploying`.
 */
export type VaultAnswer = { release: string; result?: unknown };

/**
 * The vault as its transport reaches it: the Workers binding (the
 * `VaultEntrypoint`), a Node vault's socket (`connectVault`), or one in
 * this process (`openLocalVault`). Each gates once, at its outermost entry
 * (`gated`). The app speaks to it only through `versioned`.
 */
export interface VaultEntry {
  call(release: string, method: VaultMethod, args: readonly unknown[]): Promise<VaultAnswer>;
}

/**
 * The vault's side of the envelope: `run` the method only when `release`
 * is this one, before anything else, so that a call from an app on
 * another release reads, locks and writes nothing. A name that is no
 * vault call, or arguments that are no list, are a bug of the caller's.
 */
export async function gated(release: unknown, method: unknown, args: unknown, run: (method: VaultMethod, args: unknown[]) => Promise<unknown>): Promise<VaultAnswer> {
  if (release !== RELEASE) return { release: RELEASE };
  if (typeof method !== 'string' || !METHOD_NAMES.has(method) || !Array.isArray(args)) throw new Error(`not a vault call: ${String(method)}`);
  return { release: RELEASE, result: await run(method as VaultMethod, args) };
}

/**
 * Why a call was not run: the vault is on another release, for the seconds
 * of a deploy (the app answers 503 `deploying` with `Retry-After: 1`), or
 * answered with no release at all (an older vault's transport, which has
 * no envelope).
 */
export class Deploying extends Error {
  readonly code = 'deploying';
  readonly release: string;
  readonly vaultRelease: string | null;

  constructor(release: string, vaultRelease: string | null) {
    super(`the vault runs ${vaultRelease === null ? 'no release this app knows' : `release ${vaultRelease}`}, and this app ${release}: a deploy is under way`);
    this.name = 'Deploying';
    this.release = release;
    this.vaultRelease = vaultRelease;
  }
}

/** Whether `error` is a call refused across releases (`Deploying`), by its code: a bundle may hold two copies of the class. */
export function isDeploying(error: unknown): error is Deploying {
  return typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'deploying' && error instanceof Error;
}

/** Each entry's `Vault`, kept: on Workers the app's runtime is made per request, and the about cache is keyed by the vault object. */
const wrapped = new WeakMap<VaultEntry, { release: string; vault: Required<Vault> }>();

/**
 * The app's side of the envelope: the `Vault` the app speaks to, each
 * method one `entry.call(release, name, args)`. An answer on another
 * release, or with none, throws `Deploying`; no handler sees a mismatch.
 * The same object for the same entry and release, whichever request asks.
 */
export function versioned(entry: VaultEntry, release: string = RELEASE): Required<Vault> {
  const kept = wrapped.get(entry);
  if (kept !== undefined && kept.release === release) return kept.vault;
  const vault = Object.fromEntries(
    VAULT_METHODS.map((name) => [
      name,
      async (...args: unknown[]) => {
        const answer = (await entry.call(release, name, args)) as VaultAnswer | null | undefined;
        const theirs = typeof answer === 'object' && answer !== null && typeof answer.release === 'string' ? answer.release : null;
        if (theirs !== release) throw new Deploying(release, theirs);
        return answer!.result;
      },
    ]),
  ) as unknown as Required<Vault>;
  wrapped.set(entry, { release, vault });
  return vault;
}
