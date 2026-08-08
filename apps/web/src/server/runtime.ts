import '@tanstack/react-start/server-only';

import { AsyncLocalStorage } from 'node:async_hooks';

import type { IdentityVerifier } from '../../../../packages/core/src/identity/types.ts';
import { AccessIdentityVerifier } from '../../../../packages/core/src/identity/verifier.ts';
import { loadConfig, type Config } from './config.ts';
import { HyperdriveDatabase, type Database } from './database.ts';
import { AdminService } from './services/admin.ts';
import { AuditService } from './services/audit.ts';
import { SecretsService } from './services/secrets.ts';

export type CoffreRuntime = {
  pool: Database;
  admin: AdminService;
  audit: AuditService;
  secrets: SecretsService;
  auth: Config['auth'];
  verifier: IdentityVerifier;
  rootAdmins: readonly string[];
};

export type WorkerBindings = {
  HYPERDRIVE: { connectionString: string };
  COFFRE_AUTH_MODE?: string;
  COFFRE_ACCESS_ISSUER?: string;
  COFFRE_ACCESS_JWKS_URL?: string;
  COFFRE_ACCESS_AUD?: string;
  COFFRE_DEV_IDP_URL?: string;
  COFFRE_ROOT_ADMINS?: string;
  COFFRE_KEK_LOCAL?: string;
  COFFRE_KEK_ID?: string;
  COFFRE_KEK_LOCAL_PREVIOUS?: string;
  COFFRE_AUDIT_CHAIN_KEY?: string;
};

const requestRuntime = new AsyncLocalStorage<CoffreRuntime>();

/**
 * Construct the application services around an invocation-owned database.
 */
export function createRuntime(config: Config, pool: Database): CoffreRuntime {
  const verifier = new AccessIdentityVerifier(config.auth.access);
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
    auth: config.auth,
    verifier,
    rootAdmins: config.rootAdmins,
  };
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
): T {
  const { HYPERDRIVE, ...environment } = bindings;
  const config = loadConfig({
    ...environment,
    DATABASE_URL: HYPERDRIVE.connectionString,
  });
  const runtime = createRuntime(
    config,
    new HyperdriveDatabase(HYPERDRIVE.connectionString),
  );
  return requestRuntime.run(runtime, operation);
}
