import '@tanstack/react-start/server-only';

import { AsyncLocalStorage } from 'node:async_hooks';

import type { IdentityVerifier } from '../../../../packages/core/src/identity/types.ts';
import {
  AccessIdentityVerifier,
  type AccessVerifierConfig,
} from '../../../../packages/core/src/identity/verifier.ts';
import { createDatabase, type Database } from '../../../../packages/db/src/database.ts';
import type { Vault } from '../../../../packages/vault/src/types.ts';
import type { ApiContext } from './api/context.ts';
import { SigninService } from './api/signin.ts';
import { SyncRunner } from './api/syncs.ts';
import type { AuthenticatedIdentity } from './auth.ts';
import { loadConfig, type Config } from './config.ts';
import { HyperdrivePool } from './database.ts';

export type CoffreRuntime = {
  db: Database;
  /** Keys, grants and members: the vault Worker, through its service binding. */
  vault: Vault;
  chainKey: Buffer;
  syncs: SyncRunner;
  /** Present in signin mode only. */
  signin: SigninService | null;
  auth: Config['auth'];
  verifier: IdentityVerifier;
  /** Background work that must outlive the response, such as syncs. */
  waitUntil: (promise: Promise<unknown>) => void;
};

/**
 * The Worker's bindings, vars and secrets. Everything but Hyperdrive and the
 * vault is a string, and sign-in providers add their own
 * `COFFRE_SIGNIN_<ID>_*` names, so the set is open rather than listed.
 */
export type WorkerBindings = {
  HYPERDRIVE: { connectionString: string };
  /** The vault Worker's `VaultEntrypoint`, whose RPC methods are the `Vault` interface. */
  VAULT: Vault;
} & Record<`COFFRE_${string}`, string | undefined>;

const requestRuntime = new AsyncLocalStorage<CoffreRuntime>();

/**
 * Construct the application services around an invocation-owned database.
 */
export function createRuntime(
  config: Config,
  db: Database,
  vault: Vault,
  waitUntil: CoffreRuntime['waitUntil'] = (promise) => {
    promise.catch((error: unknown) => console.error('background task failed', error));
  },
): CoffreRuntime {
  let signin: SigninService | null = null;
  let verifier: IdentityVerifier;
  if (config.auth.mode === 'signin') {
    signin = new SigninService({
      db,
      chainKey: config.auditChainKey,
      vault,
      signin: config.auth.signin,
    });
    verifier = signin;
  } else {
    verifier = accessVerifier(config.auth.access);
  }
  return {
    db,
    vault,
    chainKey: config.auditChainKey,
    syncs: new SyncRunner({ db, vault, chainKey: config.auditChainKey }),
    signin,
    auth: config.auth,
    verifier,
    waitUntil,
  };
}

/** What a handler gets: the runtime's stores and the request's caller. */
export function apiContext(runtime: CoffreRuntime, identity: AuthenticatedIdentity): ApiContext {
  return {
    db: runtime.db,
    chainKey: runtime.chainKey,
    vault: runtime.vault,
    waitUntil: runtime.waitUntil,
    syncs: runtime.syncs,
    signin: runtime.signin,
    caller: identity.caller,
    requestId: identity.requestId,
    sourceIp: identity.sourceIp,
    credentialId: identity.credentialId,
  };
}

const accessVerifiers = new Map<string, AccessIdentityVerifier>();

/**
 * One verifier per Access application for the isolate's lifetime. The
 * runtime is rebuilt on every invocation; the verifier holds the JWKS cache,
 * and rebuilding it with the runtime would fetch Access's keys on every
 * request.
 */
function accessVerifier(config: AccessVerifierConfig): AccessIdentityVerifier {
  const key = JSON.stringify([config.issuer, config.jwksUrl, config.audience]);
  let verifier = accessVerifiers.get(key);
  if (verifier === undefined) {
    verifier = new AccessIdentityVerifier(config);
    accessVerifiers.set(key, verifier);
  }
  return verifier;
}

/** Resolve the runtime attached to the current Worker invocation. */
export function getRuntime(): CoffreRuntime {
  const runtime = requestRuntime.getStore();
  if (runtime === undefined) {
    throw new Error('Coffre runtime is unavailable outside a Worker invocation');
  }
  return runtime;
}

/**
 * Attach Cloudflare bindings and a Hyperdrive client factory to one invocation.
 * No database I/O object escapes this async context.
 */
export function runWithWorkerRuntime<T>(
  bindings: WorkerBindings,
  operation: () => T,
  context?: { waitUntil: (promise: Promise<unknown>) => void },
): T {
  const { HYPERDRIVE, VAULT, ...environment } = bindings;
  const config = loadConfig({
    ...environment,
    DATABASE_URL: HYPERDRIVE.connectionString,
  });
  const runtime = createRuntime(
    config,
    createDatabase(new HyperdrivePool(HYPERDRIVE.connectionString)),
    VAULT,
    context === undefined ? undefined : (promise) => context.waitUntil(promise),
  );
  return requestRuntime.run(runtime, operation);
}
