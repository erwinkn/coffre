import { loadAuthConfig, type AuthConfig } from '../../../../packages/core/src/identity/auth-mode.ts';

type Environment = Readonly<Record<string, string | undefined>>;

function required(env: Environment, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value;
}

function requiredKey(env: Environment, name: string): Buffer {
  const raw = Buffer.from(required(env, name), 'base64');
  if (raw.length !== 32) {
    throw new Error(`${name} must decode to exactly 32 bytes, got ${raw.length}`);
  }
  return raw;
}

export type Config = {
  databaseUrl: string;
  auth: AuthConfig;
  auditChainKey: Buffer;
};

/** What the vault Worker holds now; the app refuses to start with any of it. */
const VAULT_ONLY = ['COFFRE_KEK_LOCAL', 'COFFRE_KEK_ID', 'COFFRE_KEK_LOCAL_PREVIOUS', 'COFFRE_ROOT_ADMINS', 'COFFRE_VAULT_SIGNING_KEY'];

/**
 * Load and validate web-runtime configuration.
 *
 * This function is intentionally side-effect free. The Worker entrypoint calls
 * it inside each invocation, never while Vite is discovering or building routes.
 */
export function loadConfig(env: Environment = process.env): Config {
  if (env.COFFRE_OWNER_DATABASE_URL !== undefined) {
    throw new Error(
      'COFFRE_OWNER_DATABASE_URL is obsolete; migration and web processes each use DATABASE_URL',
    );
  }

  const misplaced = VAULT_ONLY.filter((name) => env[name] !== undefined);
  if (misplaced.length > 0) {
    throw new Error(`${misplaced.join(', ')} belong to the vault Worker; the app holds no key`);
  }

  return {
    databaseUrl: required(env, 'DATABASE_URL'),
    auth: loadAuthConfig(env),
    auditChainKey: requiredKey(env, 'COFFRE_AUDIT_CHAIN_KEY'),
  };
}
