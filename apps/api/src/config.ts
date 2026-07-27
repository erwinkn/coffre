import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';

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
  access: { issuer: string; jwksUrl: string; audience: string };
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

export function loadConfig(): Config {
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
    access: {
      issuer: required('COFFRE_ACCESS_ISSUER'),
      jwksUrl: required('COFFRE_ACCESS_JWKS_URL'),
      audience: required('COFFRE_ACCESS_AUD'),
    },
    keks: new KekRegistry(primary, secondary),
    auditChainKey: requiredKey('COFFRE_AUDIT_CHAIN_KEY'),
    rootAdmins: (process.env.COFFRE_ROOT_ADMINS ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0),
  };
}
