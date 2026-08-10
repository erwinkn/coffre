import { pathToFileURL } from 'node:url';

const API_ROOT = 'https://api.cloudflare.com/client/v4';

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`missing required environment variable: ${name}`);
  return value;
}

export function positiveHours(value) {
  const hours = Number(value ?? '6');
  if (!Number.isInteger(hours) || hours < 1 || hours > 168) {
    throw new Error('COFFRE_WARP_STALE_AFTER_HOURS must be an integer from 1 through 168');
  }
  return hours;
}

async function cloudflareRequest(path, init = {}) {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${requiredEnvironment('CLOUDFLARE_ZERO_TRUST_API_TOKEN')}`,
      ...init.headers,
    },
  });
  const body = await response.json();
  if (!response.ok || body.success !== true) {
    const messages = [...(body.errors ?? []), ...(body.messages ?? [])]
      .map((entry) => entry.message)
      .filter(Boolean)
      .join('; ');
    throw new Error(`Cloudflare API request failed (${response.status}): ${messages || 'unknown error'}`);
  }
  return body;
}

async function listRegistrations(accountId) {
  const registrations = [];
  let cursor;
  do {
    const query = new URLSearchParams({ include: 'policy', per_page: '1000' });
    if (cursor) query.set('cursor', cursor);
    const body = await cloudflareRequest(
      `/accounts/${encodeURIComponent(accountId)}/devices/registrations?${query}`,
    );
    registrations.push(...body.result);
    cursor = body.result_info?.cursor || undefined;
  } while (cursor);
  return registrations;
}

export function isStaleCoffreRegistration(registration, { cutoff, identity, policyId }) {
  if (registration.deleted_at || registration.policy?.id !== policyId) return false;
  if (registration.user?.email !== identity) return false;
  const lastActivity = Date.parse(registration.last_seen_at ?? registration.created_at);
  return Number.isFinite(lastActivity) && lastActivity < cutoff;
}

async function main() {
  const accountId = requiredEnvironment('CLOUDFLARE_ACCOUNT_ID');
  const organization = requiredEnvironment('CLOUDFLARE_WARP_ORGANIZATION');
  const policyId = requiredEnvironment('CLOUDFLARE_WARP_DEVICE_PROFILE_ID');
  const staleHours = positiveHours(process.env.COFFRE_WARP_STALE_AFTER_HOURS);
  const cutoff = Date.now() - staleHours * 60 * 60 * 1000;
  const identity = `non_identity@${organization}.cloudflareaccess.com`;
  const dryRun = process.argv.includes('--dry-run');

  const registrations = await listRegistrations(accountId);
  const stale = registrations.filter((registration) => isStaleCoffreRegistration(
    registration,
    { cutoff, identity, policyId },
  ));

  for (const registration of stale) {
    const description = `${registration.id} (${registration.device?.name ?? 'unknown device'})`;
    if (dryRun) {
      console.log(`would delete stale Coffre WARP registration ${description}`);
      continue;
    }
    await cloudflareRequest(
      `/accounts/${encodeURIComponent(accountId)}/devices/registrations/${encodeURIComponent(registration.id)}`,
      { method: 'DELETE' },
    );
    console.log(`deleted stale Coffre WARP registration ${description}`);
  }

  console.log(`${dryRun ? 'found' : 'deleted'} ${stale.length} stale Coffre WARP registration(s)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
