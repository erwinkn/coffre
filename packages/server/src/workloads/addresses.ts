import { BlockList, isIP } from 'node:net';

/**
 * Whether an address is globally routable unicast, by IANA's special-purpose
 * registries for IPv4 and IPv6: what a binding's issuer may resolve to on
 * Node. Loopback, private, shared (`100.64.0.0/10`, a carrier's or an
 * overlay's), link-local (the cloud metadata address among them),
 * documentation, benchmarking, multicast and reserved space are refused.
 * For IPv6, only global unicast (`2000::/3`), less its special blocks;
 * IPv4-mapped, NAT64, unique-local and link-local fall outside it.
 */
const SPECIAL_V4 = new BlockList();
for (const [prefix, length] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  SPECIAL_V4.addSubnet(prefix, length, 'ipv4');
}

const GLOBAL_V6 = new BlockList();
GLOBAL_V6.addSubnet('2000::', 3, 'ipv6');

const SPECIAL_V6 = new BlockList();
for (const [prefix, length] of [
  // IETF protocol assignments, Teredo among them.
  ['2001::', 23],
  ['2001:db8::', 32],
  // 6to4.
  ['2002::', 16],
  ['3fff::', 20],
] as const) {
  SPECIAL_V6.addSubnet(prefix, length, 'ipv6');
}

export function isPublicAddress(address: string): boolean {
  switch (isIP(address)) {
    case 4:
      return !SPECIAL_V4.check(address, 'ipv4');
    case 6:
      return GLOBAL_V6.check(address, 'ipv6') && !SPECIAL_V6.check(address, 'ipv6');
    default:
      return false;
  }
}
