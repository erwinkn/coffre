/**
 * Why an instance could not be reached, from what `fetch` threw. Node's
 * `fetch` says only `fetch failed`: what happened is in its `cause`, Node's
 * own error, with a code (`ENOTFOUND`, `ECONNREFUSED`, a certificate's) and
 * often the address it tried. A browser's says nothing more, and has no cause.
 */

/** Node's error under a failed `fetch`; an AggregateError, with no message, when every address failed. */
type Cause = Error & { code?: string; address?: string; port?: number; hostname?: string; errors?: Cause[] };

/** Two colons or more, in hex: an IPv6 address, as `::1` or `2001:db8::1:443` with its port. */
const IPV6 = /[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*/i;

const TIMEOUT_OR_REFUSAL = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT', 'ENETUNREACH', 'EHOSTUNREACH']);

/** What to try for the common causes; null for the others. */
function hint(cause: Cause): string | null {
  const code = cause.code ?? '';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return "the name does not resolve here: check the address, or flush this machine's DNS cache";
  }
  const tried = [cause, ...(cause.errors ?? [])].flatMap((each) => [each.address ?? '', each.message]);
  if (TIMEOUT_OR_REFUSAL.has(code) && tried.some((each) => IPV6.test(each))) {
    return "it was tried over IPv6, which this network may not carry: try NODE_OPTIONS=--dns-result-order=ipv4first";
  }
  if (/CERT|UNABLE_TO_VERIFY|SELF_SIGNED/.test(code)) {
    return 'something between you and the instance, such as a proxy or a network filter, presents its own certificate';
  }
  return null;
}

/** The cause's own words, with its code and address when they don't already say them. */
function described(cause: Cause): string {
  const said = cause.message || (cause.errors ?? []).map((each) => each.message).join(', ');
  const address = cause.address === undefined ? undefined : cause.port === undefined ? cause.address : `${cause.address}:${cause.port}`;
  const more = [cause.code, address].filter((each): each is string => each !== undefined && !said.includes(each));
  if (said === '') return more.join(' ') || cause.name;
  return more.length === 0 ? said : `${said} (${more.join(', ')})`;
}

/**
 * `could not reach <origin>: <why>`, and what to try when the cause is a
 * common one: `could not reach https://x: getaddrinfo ENOTFOUND x; the name
 * does not resolve here: …`.
 */
export function unreachable(origin: string, error: unknown): string {
  const cause = error instanceof Error && error.cause instanceof Error ? (error.cause as Cause) : null;
  if (cause === null) return `could not reach ${origin}: ${error instanceof Error ? error.message : String(error)}`;
  const then = hint(cause);
  return `could not reach ${origin}: ${described(cause)}${then === null ? '' : `; ${then}`}`;
}

/** A request that never reached the instance: its message says why, `cause` is what `fetch` threw. */
export class Unreachable extends Error {
  readonly origin: string;

  constructor(origin: string, error: unknown) {
    super(unreachable(origin, error), { cause: error });
    this.name = 'Unreachable';
    this.origin = origin;
  }
}
