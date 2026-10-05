// coffre at an address whose DNS is not on the Cloudflare account. A Worker
// answers only where Cloudflare ends TLS, and a CNAME to workers.dev is not
// that; so setup makes the address a custom hostname of one of the
// account's zones, with Cloudflare for SaaS. The address's DNS provider
// gets a CNAME to the zone's fallback origin, and the TXT records
// Cloudflare asks for; the app Worker's route on the zone serves it.
// Cloudflare is the record: a second run finds the custom hostname, and
// waits for what is left.
import { type CloudflareApi, CloudflareError, type CustomHostname, denied, type Zone } from './cloudflare.ts';
import { listed } from './tty.ts';

/** The fallback origin setup makes on a zone that has none: `coffre-fallback.<zone>`, a record that points nowhere, for the Worker to stand behind. */
export const FALLBACK = 'coffre-fallback';

/** How often setup asks Cloudflare whether it has seen the records. */
const EVERY_MS = 10_000;

/** The zone an address is under, the longest one when zones nest. */
export function zoneOf(address: string, zones: readonly Zone[]): Zone | undefined {
  return zones
    .filter(({ name }) => address === name || address.endsWith(`.${name}`))
    .sort((a, b) => b.name.length - a.name.length)[0];
}

/**
 * Cloudflare refused this login what an address whose DNS is elsewhere
 * needs, on `zones`: setup asks for a token that may, and does it again.
 */
export class Refused extends Error {
  readonly zones: string[];
  constructor(zones: string[]) {
    super(`Cloudflare refused this login the custom hostnames of ${listed(zones, 'and')}`);
    this.zones = zones;
  }
}

/** What a token needs, for setup to go on under it: wrangler's login has no scope for DNS records, and may have none for custom hostnames. */
export function tokenNeeded(zones: readonly string[]): string {
  return (
    `Cloudflare refused this login the custom hostnames of ${listed(zones, 'and')}: wrangler's login may not manage them, and has no scope for DNS records. ` +
    'Make a token at https://dash.cloudflare.com/profile/api-tokens with Account: Workers Scripts Edit, Hyperdrive Edit and Account Settings Read; ' +
    `and Zone, for ${zones.length === 1 ? zones[0] : 'the domain coffre goes through'}: Zone Read, Workers Routes Edit, SSL and Certificates Edit and DNS Edit. ` +
    'Setup goes on under it, and so does each wrangler it runs.'
  );
}

/** Cloudflare for SaaS, off on a zone: the dashboard turns it on, and asks for a payment method, even on the Free plan. */
export function saasNeeded(account: string, zone: string): string {
  return (
    `Cloudflare for SaaS isn't enabled on ${zone}. Enable it at https://dash.cloudflare.com/${account}/${zone}/ssl-tls/custom-hostnames: ` +
    'Cloudflare asks for a payment method, and the first 100 custom hostnames are free. Then run setup again.'
  );
}

/** Cloudflare's answer for a zone without Cloudflare for SaaS: "No quota has been allocated for this zone". */
const NO_SAAS = 1404;

/**
 * The zone that serves `address`: the one whose custom hostname it is
 * already, when a run before made it; else the account's only domain, or
 * the one chosen, which must have Cloudflare for SaaS on. Throws Refused
 * when the login may read no zone's custom hostnames.
 */
export async function saasZone(
  api: CloudflareApi,
  account: string,
  zones: readonly Zone[],
  address: string,
  choose: (question: string, options: readonly string[]) => Promise<number>,
): Promise<Zone> {
  const off = new Set<string>();
  let refused = 0;
  for (const zone of zones) {
    try {
      if ((await api.customHostname(zone.id, address)) !== null) return zone;
    } catch (error) {
      if (error instanceof CloudflareError && error.codes.includes(NO_SAAS)) off.add(zone.id);
      else if (denied(error)) refused += 1;
      else throw error;
    }
  }
  if (refused === zones.length) throw new Refused(zones.map(({ name }) => name));
  const zone = zones.length === 1 ? zones[0]! : zones[await choose(`Which of your domains serves ${address}?`, zones.map(({ name }) => name))]!;
  if (off.has(zone.id)) throw new Error(saasNeeded(account, zone.name));
  return zone;
}

/** Where `address` stands on `zone`: its custom hostname, and the CNAME's target, the zone's fallback origin. */
export type Served = { zone: Zone; target: string; hostname: CustomHostname };

/** Whether Cloudflare gave up on a custom hostname's records, which a request to validate again starts over. */
const gaveUp = ({ status, ssl }: CustomHostname) => status === 'moved' || ssl?.status?.endsWith('_timed_out') === true;

/**
 * Serve `address` through `zone`: its fallback origin, kept when it has
 * one, which other custom hostnames may use; and the custom hostname, made,
 * kept, or asked to validate again when Cloudflare gave up waiting for its
 * records. A new one is read again after `settle` milliseconds: its
 * certificate's record is seldom in the answer to its creation. Throws
 * Refused when the login may not.
 */
export async function serveThrough(api: CloudflareApi, zone: Zone, address: string, settle = 1_000): Promise<Served & { details: string[] }> {
  try {
    const details: string[] = [];
    let target = (await api.fallbackOrigin(zone.id))?.origin;
    if (target === undefined) {
      target = `${FALLBACK}.${zone.name}`;
      // A run stopped between the two finds the record, and only sets the origin.
      if (!(await api.hasDnsRecord(zone.id, target))) await api.createOriginlessRecord(zone.id, target, "coffre's fallback origin: its Worker answers there");
      await api.setFallbackOrigin(zone.id, target);
      details.push(`fallback origin  ${target}, made`);
    } else {
      details.push(`fallback origin  ${target}, kept`);
    }
    let hostname = await api.customHostname(zone.id, address);
    if (hostname === null) {
      const made = await api.createCustomHostname(zone.id, address);
      await new Promise((resolve) => setTimeout(resolve, settle));
      hostname = await api.customHostnameById(zone.id, made.id);
      details.push(`custom hostname  ${address}, made`);
    } else if (gaveUp(hostname)) {
      hostname = await api.revalidate(zone.id, hostname.id);
      details.push(`custom hostname  ${address}, kept, asked to validate again`);
    } else {
      details.push(`custom hostname  ${address}, kept`);
    }
    return { zone, target, hostname, details };
  } catch (error) {
    if (denied(error)) throw new Refused([zone.name]);
    throw error;
  }
}

export type DnsRecord = { type: 'CNAME' | 'TXT'; name: string; value: string };

/**
 * What to add at the address's DNS provider: the CNAME, always, which
 * nothing on Cloudflare's side proves is there; and each TXT record
 * Cloudflare has yet to see, the hostname's and its certificate's.
 */
export function recordsToAdd({ hostname, status, ownership_verification: owner, ssl }: CustomHostname, target: string): DnsRecord[] {
  const records: DnsRecord[] = [{ type: 'CNAME', name: hostname, value: target }];
  if (status !== 'active' && owner?.name && owner.value) records.push({ type: 'TXT', name: owner.name, value: owner.value });
  if (ssl?.status !== 'active') {
    for (const { txt_name, txt_value } of ssl?.validation_records ?? []) {
      if (txt_name && txt_value) records.push({ type: 'TXT', name: txt_name, value: txt_value });
    }
  }
  return records;
}

/** Records one to a line, in columns, to copy: `CNAME  secrets.example.com  →  coffre-fallback.acme.com`, `TXT  _cf-custom-hostname.…  "…"`. */
export function recordLines(records: readonly DnsRecord[]): string[] {
  const width = Math.max(...records.map(({ name }) => name.length));
  return records.map(({ type, name, value }) => `${type.padEnd(5)}  ${name.padEnd(width)}  ${type === 'CNAME' ? `→  ${value}` : JSON.stringify(value)}`);
}

/** Where a custom hostname stands: done once both halves are active; stopped where Cloudflare gave up; and why it waits, when it says. */
export function standing({ hostname, status, ssl, verification_errors }: CustomHostname): { done: boolean; stopped: string | null; text: string; why: string[] } {
  const certificate = ssl?.status ?? 'initializing';
  const stopped = ['blocked', 'deleted', 'pending_deletion'].includes(status)
    ? `Cloudflare marked ${hostname} ${status.replace(/_/g, ' ')}: see SSL/TLS, Custom Hostnames, on its dashboard`
    : status === 'moved' || certificate.endsWith('_timed_out')
      ? `Cloudflare stopped waiting for ${hostname}'s records. Once they are in, run setup again: it asks Cloudflare to validate again`
      : null;
  return {
    done: status === 'active' && certificate === 'active',
    stopped,
    text: `hostname ${status.replace(/_/g, ' ')}, certificate ${certificate.replace(/_/g, ' ')}`,
    why: [...(verification_errors ?? []), ...(ssl?.validation_errors ?? []).flatMap(({ message }) => (message ? [message] : []))],
  };
}

/** What the wait shows, as it goes. */
export type Watching = {
  /** The records still to add, whenever they change: Cloudflare may give its certificate's a moment after the hostname's. */
  records(lines: string[]): void;
  /** Where it stands now. */
  note(text: string): void;
  /** Why Cloudflare is still waiting, when it says. */
  under(lines: string[]): void;
};

/**
 * Wait until Cloudflare has seen the records, asking every `every`
 * milliseconds; throws where it stopped waiting itself. Ctrl-C leaves
 * nothing half done: a run after waits for what is left.
 */
export async function waitForRecords(api: CloudflareApi, served: Served, watching: Watching, every = EVERY_MS): Promise<void> {
  const start = Date.now();
  let shown = '';
  for (;;) {
    // As Cloudflare has it now: its certificate's records, say, which it gives a moment after the hostname's.
    const hostname = await api.customHostnameById(served.zone.id, served.hostname.id);
    const now = standing(hostname);
    if (now.stopped !== null) throw new Error(now.stopped);
    if (now.done) return;
    const records = recordsToAdd(hostname, served.target);
    if (JSON.stringify(records) !== shown) {
      shown = JSON.stringify(records);
      watching.records(recordLines(records));
    }
    const seconds = Math.round((Date.now() - start) / 1000);
    watching.note(`Wait for the DNS records: ${now.text} (${seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`})`);
    watching.under(now.why);
    await new Promise((resolve) => setTimeout(resolve, every));
  }
}
