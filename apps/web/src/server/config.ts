import { LocalKekProvider } from '../../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../../packages/core/src/kek/registry.ts';
import {
  loadAuthConfig,
  type AuthConfig,
  type AuthMode,
} from '../../../../packages/core/src/identity/auth-mode.ts';

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
  keks: KekRegistry;
  auditChainKey: Buffer;
  /** Configuration-owned bootstrap authority. */
  rootAdmins: readonly string[];
};

function isHumanEmail(value: string): boolean {
  if (value.length > 254) return false;

  const parts = value.split('@');
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (
    local.length === 0 ||
    local.length > 64 ||
    local.startsWith('.') ||
    local.endsWith('.') ||
    local.includes('..') ||
    !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)
  ) {
    return false;
  }

  const labels = domain.split('.');
  if (labels.length < 2) return false;
  return labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
  );
}

export function parseRootAdmins(mode: AuthMode, raw: string | undefined): string[] {
  const rootAdmins = [
    ...new Set(
      (raw ?? '')
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0),
    ),
  ];

  if (mode === 'cloudflare') {
    if (rootAdmins.length === 0) {
      throw new Error(
        'COFFRE_ROOT_ADMINS must name at least one Cloudflare Access email in cloudflare mode',
      );
    }
    const invalid = rootAdmins.find((entry) => !isHumanEmail(entry));
    if (invalid) {
      throw new Error(
        `COFFRE_ROOT_ADMINS entries must be human email identities in cloudflare mode; invalid: ${invalid}`,
      );
    }
  }

  return rootAdmins;
}

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

  const auth = loadAuthConfig(env);
  const rootAdmins = parseRootAdmins(auth.mode, env.COFFRE_ROOT_ADMINS);

  const primary = LocalKekProvider.fromBase64(
    required(env, 'COFFRE_KEK_LOCAL'),
    env.COFFRE_KEK_ID ?? 'local-dev-1',
  );

  const secondary = (env.COFFRE_KEK_LOCAL_PREVIOUS ?? '')
    .split(',')
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const separator = entry.indexOf(':');
      if (separator <= 0 || separator === entry.length - 1) {
        throw new Error(
          'COFFRE_KEK_LOCAL_PREVIOUS entries must use the form key-id:base64-material',
        );
      }
      return LocalKekProvider.fromBase64(
        entry.slice(separator + 1),
        entry.slice(0, separator),
      );
    });

  return {
    databaseUrl: required(env, 'DATABASE_URL'),
    auth,
    keks: new KekRegistry(primary, secondary),
    auditChainKey: requiredKey(env, 'COFFRE_AUDIT_CHAIN_KEY'),
    rootAdmins,
  };
}
