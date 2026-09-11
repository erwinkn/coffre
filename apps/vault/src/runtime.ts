import { createArchive, type ArchiveEnvironment } from '../../../packages/archive/src/factory';
import { createLocalJWKSet } from 'jose';
import { z } from 'zod';
import { AccessAuthenticator } from '../../../packages/core/src/auth';
import { Vault } from '../../../packages/core/src/vault';
import { createKeyProvider, type KeyEnvironment } from '../../../packages/crypto/src/factory';
import { unb64 } from '../../../packages/crypto/src/index';
import { d1Storage, mysqlStorage, postgresStorage } from '../../../packages/storage/src/index';
import type { Storage } from '../../../packages/contracts/src/index';
export interface VaultEnvironment extends KeyEnvironment, ArchiveEnvironment { STAGE: 'local' | 'staging' | 'production'; INSTANCE_ID: string; ACCESS_ISSUER: string; ACCESS_AUDIENCE: string; BOOTSTRAP_SUBJECT?: string; REQUEST_INTEGRITY_KEY: string; STORAGE: 'd1' | 'postgres' | 'mysql'; DB?: D1Database; DATABASE_URL?: string; DATABASE_CA?: string; HYPERDRIVE?: Hyperdrive; REQUIRE_APPEND_ONLY?: string; LOCAL_JWKS?: string }
export function validateEnvironment(env: VaultEnvironment) {
  z.enum(['local', 'staging', 'production']).parse(env.STAGE); z.string().uuid().parse(env.INSTANCE_ID);
  if (env.STAGE !== 'local' && env.LOCAL_JWKS) throw new Error('Local identity keys are forbidden in deployed environments');
  if (env.STAGE !== 'local' && !env.ACCESS_ISSUER.startsWith('https://')) throw new Error('Production audit archive and HTTPS Access issuer are required');
  createArchive(env);
  if (unb64(env.REQUEST_INTEGRITY_KEY).length !== 32) throw new Error('Invalid request integrity key');
}
export function createStorage(env: VaultEnvironment): Storage {
  if (env.STORAGE === 'd1') { if (!env.DB) throw new Error('D1 binding is required'); return d1Storage(env.DB); }
  const options = { url: env.HYPERDRIVE?.connectionString ?? env.DATABASE_URL ?? '', hyperdrive: !!env.HYPERDRIVE, local: env.STAGE === 'local' && !env.HYPERDRIVE, ca: env.DATABASE_CA };
  if (env.STORAGE === 'postgres') return postgresStorage(options);
  if (env.STORAGE === 'mysql') return mysqlStorage(options);
  throw new Error('Unknown storage backend');
}
export function createVault(env: VaultEnvironment, storage: Storage): Vault {
  validateEnvironment(env);
  const resolver = env.STAGE === 'local' && env.LOCAL_JWKS ? createLocalJWKSet(JSON.parse(env.LOCAL_JWKS)) : undefined;
  return new Vault({ auth: new AccessAuthenticator(env.ACCESS_ISSUER, env.ACCESS_AUDIENCE, resolver, env.STAGE === 'local'), storage, keys: createKeyProvider(env), requestKey: unb64(env.REQUEST_INTEGRITY_KEY), bootstrapSubject: env.BOOTSTRAP_SUBJECT, instanceId: env.INSTANCE_ID, requireAppendOnly: env.REQUIRE_APPEND_ONLY === 'true' });
}
