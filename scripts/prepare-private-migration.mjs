import { writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`missing required environment variable: ${name}`);
  return value;
}

function isPrivateIpv4(address) {
  if (isIP(address) !== 4) return false;
  const octets = address.split('.').map(Number);
  return octets[0] === 10
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168);
}

export function migrationUrls({
  caPath,
  expectedHost,
  expectedPort,
  ownerUrl,
  runtimePassword,
  runtimeRole,
}) {
  const owner = new URL(ownerUrl);
  if (owner.protocol !== 'postgresql:' && owner.protocol !== 'postgres:') {
    throw new Error('COFFRE_OWNER_DATABASE_URL must use PostgreSQL');
  }
  if (!isPrivateIpv4(expectedHost) || owner.hostname !== expectedHost) {
    throw new Error('owner database URL must use the routed private database IPv4 address');
  }
  const ownerPort = owner.port || '5432';
  if (expectedPort !== '5432' || ownerPort !== expectedPort) {
    throw new Error('owner database URL must use the routed PostgreSQL port');
  }
  if (decodeURIComponent(owner.username) !== 'coffre_owner') {
    throw new Error('COFFRE_OWNER_DATABASE_URL must use the coffre_owner identity');
  }
  if (runtimeRole !== 'coffre_runtime') {
    throw new Error('runtime role must be coffre_runtime');
  }

  owner.searchParams.set('sslmode', 'verify-ca');
  owner.searchParams.set('sslrootcert', caPath);
  const runtime = new URL(owner);
  runtime.username = runtimeRole;
  runtime.password = runtimePassword;
  return { ownerUrl: owner.toString(), runtimeUrl: runtime.toString() };
}

async function main() {
  const [ownerPath, runtimePath] = process.argv.slice(2);
  if (!ownerPath || !runtimePath) {
    throw new Error('owner and runtime output paths are required');
  }
  const urls = migrationUrls({
    caPath: requiredEnvironment('DATABASE_CA_PATH'),
    expectedHost: requiredEnvironment('DATABASE_PRIVATE_IP'),
    expectedPort: requiredEnvironment('DATABASE_PORT'),
    ownerUrl: requiredEnvironment('OWNER_DATABASE_URL'),
    runtimePassword: requiredEnvironment('RUNTIME_PASSWORD'),
    runtimeRole: requiredEnvironment('RUNTIME_ROLE'),
  });
  await Promise.all([
    writeFile(ownerPath, urls.ownerUrl, { mode: 0o600 }),
    writeFile(runtimePath, urls.runtimeUrl, { mode: 0o600 }),
  ]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
