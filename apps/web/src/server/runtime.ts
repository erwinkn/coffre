import '@tanstack/react-start/server-only';

import { AsyncLocalStorage } from 'node:async_hooks';

import type { IdentityVerifier } from '../../../../packages/core/src/identity/types.ts';
import {
  AccessIdentityVerifier,
  type AccessVerifierConfig,
} from '../../../../packages/core/src/identity/verifier.ts';
import { loadConfig, type Config } from './config.ts';
import { HyperdriveDatabase, type Database } from './database.ts';
import { AdminService } from './services/admin.ts';
import { AuditService } from './services/audit.ts';
import { SecretsService } from './services/secrets.ts';
import { SigninService } from './services/signin.ts';

export type CoffreRuntime = {
  pool: Database;
  admin: AdminService;
  audit: AuditService;
  secrets: SecretsService;
  /** Present in signin mode only. */
  signin: SigninService | null;
  auth: Config['auth'];
  verifier: IdentityVerifier;
  rootAdmins: readonly string[];
  /** Background work that must outlive the response, such as syncs. */
  waitUntil: (promise: Promise<unknown>) => void;
};

/**
 * The Worker's vars and secrets. Everything but Hyperdrive is a string, and
 * sign-in providers add their own `COFFRE_SIGNIN_<ID>_*` names, so the set
 * is open rather than listed.
 */
export type WorkerBindings = {
  HYPERDRIVE: { connectionString: string };
} & Record<`COFFRE_${string}`, string | undefined>;

const requestRuntime = new AsyncLocalStorage<CoffreRuntime>();

/**
 * Construct the application services around an invocation-owned database.
 */
export function createRuntime(
  config: Config,
  pool: Database,
  waitUntil: CoffreRuntime['waitUntil'] = (promise) => {
    promise.catch((error: unknown) => console.error('background task failed', error));
  },
): CoffreRuntime {
  let signin: SigninService | null = null;
  let verifier: IdentityVerifier;
  if (config.auth.mode === 'signin') {
    signin = new SigninService({
      pool,
      auditChainKey: config.auditChainKey,
      rootAdmins: config.rootAdmins,
      signin: config.auth.signin,
    });
    verifier = signin;
  } else {
    verifier = accessVerifier(config.auth.access);
  }
  const secrets = new SecretsService({
    pool,
    keks: config.keks,
    auditChainKey: config.auditChainKey,
    rootAdmins: config.rootAdmins,
  });
  const admin = new AdminService({
    pool,
    auditChainKey: config.auditChainKey,
    rootAdmins: config.rootAdmins,
  });
  const audit = new AuditService({
    pool,
    chainKey: config.auditChainKey,
    rootAdmins: config.rootAdmins,
  });
  return {
    pool,
    admin,
    audit,
    secrets,
    signin,
    auth: config.auth,
    verifier,
    rootAdmins: config.rootAdmins,
    waitUntil,
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
  const { HYPERDRIVE, ...environment } = bindings;
  const config = loadConfig({
    ...environment,
    DATABASE_URL: HYPERDRIVE.connectionString,
  });
  const runtime = createRuntime(
    config,
    new HyperdriveDatabase(HYPERDRIVE.connectionString),
    context === undefined ? undefined : (promise) => context.waitUntil(promise),
  );
  return requestRuntime.run(runtime, operation);
}
