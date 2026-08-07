import '@tanstack/react-start/server-only';

import pg from 'pg';

import type { IdentityVerifier } from '../../../../packages/core/src/identity/types.ts';
import { AccessIdentityVerifier } from '../../../../packages/core/src/identity/verifier.ts';
import { loadConfig, type Config } from './config.ts';
import { startHeartbeat, type Heartbeat } from './heartbeat.ts';
import { AdminService } from './services/admin.ts';
import { AuditService } from './services/audit.ts';
import { SecretsService } from './services/secrets.ts';

export type CoffreRuntime = {
  pool: pg.Pool;
  admin: AdminService;
  audit: AuditService;
  secrets: SecretsService;
  auth: Config['auth'];
  verifier: IdentityVerifier;
  rootAdmins: readonly string[];
  heartbeat: Heartbeat;
};

let singleton: CoffreRuntime | undefined;

function runtimeLogger() {
  return {
    warn(value: unknown, message: string) {
      console.warn(message, value);
    },
  };
}

/**
 * Construct the process-owned runtime without opening a database connection.
 * pg connects on the first query; the heartbeat is the deliberate first use.
 */
export function createRuntime(config: Config = loadConfig()): CoffreRuntime {
  const pool = new pg.Pool({ connectionString: config.databaseUrl });
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
  const heartbeat = startHeartbeat(pool, runtimeLogger());

  return {
    pool,
    admin,
    audit,
    secrets,
    auth: config.auth,
    verifier,
    rootAdmins: config.rootAdmins,
    heartbeat,
  };
}

/** Lazily initialized so imports, route generation, and builds never touch DB. */
export function getRuntime(): CoffreRuntime {
  singleton ??= createRuntime();
  return singleton;
}

/** Called by the production server's graceful-shutdown hook. */
export async function disposeRuntime(): Promise<void> {
  const current = singleton;
  singleton = undefined;
  if (current === undefined) return;

  current.heartbeat.stop();
  await current.pool.end();
}
