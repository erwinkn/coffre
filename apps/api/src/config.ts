import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import {
  loadAuthConfig,
  type AuthConfig,
  type AuthMode,
} from '../../../packages/core/src/identity/auth-mode.ts';

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value;
}

function requiredKey(name: string): Buffer {
  const raw = Buffer.from(required(name), 'base64');
  if (raw.length !== 32) {
    throw new Error(`${name} must decode to exactly 32 bytes, got ${raw.length}`);
  }
  return raw;
}

export type Config = {
  databaseUrl: string;
  port: number;
  auth: AuthConfig;
  keks: KekRegistry;
  auditChainKey: Buffer;
  /**
   * Principals that hold admin everywhere, from configuration rather than from
   * the grants table. Without this there is no way to create the first grant.
   * Kept deliberately small and auditable: every action they take is still
   * logged like anyone else's.
   */
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
  const rootAdmins = (raw ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

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

export function loadConfig(): Config {
  const auth = loadAuthConfig(process.env);
  const rootAdmins = parseRootAdmins(auth.mode, process.env.COFFRE_ROOT_ADMINS);

  // KEK rotation is expressed as configuration: the primary wraps new versions,
  // the others stay available for unwrapping older rows.
  const primary = LocalKekProvider.fromBase64(
    required('COFFRE_KEK_LOCAL'),
    process.env.COFFRE_KEK_ID ?? 'local-dev-1',
  );

  const secondary = (process.env.COFFRE_KEK_LOCAL_PREVIOUS ?? '')
    .split(',')
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const [keyId, material] = entry.split(':');
      return LocalKekProvider.fromBase64(material, keyId);
    });

  return {
    databaseUrl: required('COFFRE_DATABASE_URL'),
    port: Number(process.env.COFFRE_PORT ?? 8080),
    auth,
    keks: new KekRegistry(primary, secondary),
    auditChainKey: requiredKey('COFFRE_AUDIT_CHAIN_KEY'),
    rootAdmins,
  };
}
