import type { AccessVerifierConfig } from './verifier.ts';

export type AuthMode = 'dev' | 'cloudflare';

export type AuthConfig =
  | {
      mode: 'dev';
      access: AccessVerifierConfig;
      devIdpUrl: string;
    }
  | {
      mode: 'cloudflare';
      access: AccessVerifierConfig;
    };

type Environment = Readonly<Record<string, string | undefined>>;

function required(env: Environment, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new Error(`missing required environment variable: ${name}`);
  return value;
}

function origin(name: string, value: string, protocol: 'https:' | 'http-or-https'): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }

  const protocolAllowed =
    protocol === 'http-or-https'
      ? url.protocol === 'http:' || url.protocol === 'https:'
      : url.protocol === protocol;
  if (
    !protocolAllowed ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    const expected = protocol === 'https:' ? 'an HTTPS origin' : 'an HTTP(S) origin';
    throw new Error(`${name} must be ${expected} with no path, query, or credentials`);
  }

  return url.origin;
}

function accessConfig(env: Environment): AccessVerifierConfig {
  const audience = required(env, 'COFFRE_ACCESS_AUD');
  if (audience.length > 64 || /\s/.test(audience)) {
    throw new Error(
      'COFFRE_ACCESS_AUD must be a non-whitespace Access AUD tag of at most 64 characters',
    );
  }

  return {
    issuer: required(env, 'COFFRE_ACCESS_ISSUER'),
    jwksUrl: required(env, 'COFFRE_ACCESS_JWKS_URL'),
    audience,
  };
}

/**
 * Load the authentication boundary as one validated unit.
 *
 * No mode is inferred from the presence of a dev URL. That was convenient
 * locally but made one stray production variable turn persona minting into a
 * production identity path.
 */
export function loadAuthConfig(env: Environment): AuthConfig {
  const mode = required(env, 'COFFRE_AUTH_MODE');
  if (mode !== 'dev' && mode !== 'cloudflare') {
    throw new Error('COFFRE_AUTH_MODE must be exactly "dev" or "cloudflare"');
  }

  const access = accessConfig(env);

  if (mode === 'cloudflare') {
    if (env.COFFRE_DEV_IDP_URL?.trim()) {
      throw new Error('COFFRE_DEV_IDP_URL must not be set when COFFRE_AUTH_MODE=cloudflare');
    }

    const issuer = origin('COFFRE_ACCESS_ISSUER', access.issuer, 'https:');
    const issuerUrl = new URL(issuer);
    if (
      issuerUrl.port !== '' ||
      !issuerUrl.hostname.endsWith('.cloudflareaccess.com') ||
      issuerUrl.hostname === 'cloudflareaccess.com'
    ) {
      throw new Error(
        'COFFRE_ACCESS_ISSUER must be the HTTPS Cloudflare Access team domain',
      );
    }

    const expectedJwksUrl = `${issuer}/cdn-cgi/access/certs`;
    if (access.jwksUrl !== expectedJwksUrl) {
      throw new Error(`COFFRE_ACCESS_JWKS_URL must be exactly ${expectedJwksUrl}`);
    }

    return {
      mode,
      access: { ...access, issuer },
    };
  }

  const devIdpUrl = origin(
    'COFFRE_DEV_IDP_URL',
    required(env, 'COFFRE_DEV_IDP_URL'),
    'http-or-https',
  );
  const issuer = origin('COFFRE_ACCESS_ISSUER', access.issuer, 'http-or-https');
  if (issuer !== devIdpUrl) {
    throw new Error('COFFRE_ACCESS_ISSUER must match COFFRE_DEV_IDP_URL in dev mode');
  }

  const expectedJwksUrl = `${devIdpUrl}/cdn-cgi/access/certs`;
  if (access.jwksUrl !== expectedJwksUrl) {
    throw new Error(`COFFRE_ACCESS_JWKS_URL must be exactly ${expectedJwksUrl} in dev mode`);
  }

  return {
    mode,
    access: { ...access, issuer },
    devIdpUrl,
  };
}
