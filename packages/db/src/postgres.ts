import { checkServerIdentity } from 'node:tls';

import { parseIntoClientConfig } from 'pg-connection-string';
import type { ClientConfig } from 'pg';

/** Keep libpq's system-root shortcut from being read as a certificate filename by pg. */
export function postgresConnection(url: string): ClientConfig {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // A parse error must not print the URL's password.
    throw new Error('invalid Postgres URL');
  }
  const parameters = parsed.searchParams;
  if (parameters.getAll('sslrootcert').at(-1) !== 'system') return { connectionString: url };
  const mode = parameters.getAll('sslmode').at(-1);
  if (mode !== undefined && mode !== 'verify-full') {
    throw new Error('sslrootcert=system requires sslmode=verify-full');
  }
  parameters.delete('sslrootcert');
  parameters.set('sslmode', 'verify-full');
  const config = parseIntoClientConfig(parsed.toString());
  const host = config.host;
  if (!host) throw new Error('sslrootcert=system requires a Postgres hostname');
  // Do not pass a connectionString too: pg would replace these SSL options.
  // With no CA override, Node uses its default trusted roots. pg omits SNI
  // for IP addresses, so bind verification to the actual host explicitly.
  config.ssl = {
    ...config.ssl as object,
    rejectUnauthorized: true,
    checkServerIdentity: (_hostname, certificate) => checkServerIdentity(host, certificate),
  };
  return config;
}
