import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';

/**
 * What a read decides on, and the keys it uses: a cut-down coffre with the
 * same shape of work. A member row sealed with the vault's row key over its
 * grants; the newest access entry it names; an environment that may be
 * deleted. Synthetic keys, derived from one test seed, for synthetic data.
 */
export type Keys = { log: Buffer; row: Buffer; kek: Buffer };

export function keysFrom(seed: string): Keys {
  const derive = (label: string) => createHash('sha256').update(`lanes.${label}`).update(seed).digest();
  return { log: derive('log'), row: derive('row'), kek: derive('kek') };
}

export type Member = { principal: string; status: string; role: string | null; access_seq: string; mac: string };
export type Grant = { principal: string; environment_id: string; role: string };

export function memberMac(key: Buffer, member: Omit<Member, 'mac'>, grants: readonly Grant[]): Buffer {
  const held = [...grants].map((g) => `${g.environment_id}:${g.role}`).sort();
  return createHmac('sha256', key).update(JSON.stringify([member.principal, member.status, member.role, String(member.access_seq), held])).digest();
}

export function wrap(kek: Buffer, dek: Buffer): { wrapped: Buffer; iv: Buffer } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', kek, iv);
  const wrapped = Buffer.concat([cipher.update(dek), cipher.final(), cipher.getAuthTag()]);
  return { wrapped, iv };
}

export function unwrap(kek: Buffer, wrapped: Buffer, iv: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(wrapped.subarray(wrapped.length - 16));
  return Buffer.concat([decipher.update(wrapped.subarray(0, wrapped.length - 16)), decipher.final()]);
}

/** What one read statement brings back: everything a decision about one principal at one environment reads. */
export type Snapshot = {
  at: number;
  member: Member | null;
  grants: Grant[];
  access: { seq: string; mac: string } | null;
  policy: { seq: string } | null;
  environment: { id: string; deleted: boolean } | null;
  secret: { id: string; nature: string; wrapped: string; iv: string } | null;
  /** The control lane's head, in the lanes world. */
  control: string | null;
};

/** Why a read is refused, or null to allow it. The checks a vault read makes, in kind. */
export function refusal(keys: Keys, s: Snapshot, environmentId: string): string | null {
  if (s.member === null || s.member.status !== 'active') return 'not_member';
  const mac = memberMac(keys.row, s.member, s.grants);
  if (!mac.equals(Buffer.from(s.member.mac, 'hex'))) return 'tampered';
  if (s.access === null || s.access.seq !== String(s.member.access_seq)) return 'stale';
  if (s.environment === null || s.environment.deleted) return 'deleted';
  if (!s.grants.some((g) => g.environment_id === environmentId)) return 'forbidden';
  if (s.secret === null) return 'missing';
  return null;
}
