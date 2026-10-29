// A CI platform's issuer for the vault's tests (T149, PR 3b): its key, which a binding names by `KEYS` or carries
// uploaded, and the ID tokens it signs for a run.
import { generateKeyPairSync, randomBytes, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';

import { thumbprint, type PublicJwk } from '@coffre/core/identity';

export const ISSUER = 'https://token.actions.githubusercontent.com';
export const KEYS = `${ISSUER}/.well-known/jwks`;
/** This instance's public URL, which a binding is made on: its base audience. */
export const ORIGIN = 'https://secrets.acme.example';

export type TestIssuer = {
  /** A run's ID token: `claims` over a CI run's own, the header's `kid` the issuer's unless `kid` says otherwise. */
  token: (claims?: Record<string, unknown>, options?: { kid?: string; key?: KeyObject }) => string;
  jwk: Record<string, unknown>;
};

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** An issuer of one RSA key, `rs-1`. */
export function testIssuer(): TestIssuer {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' };
  return {
    jwk,
    token: (claims = {}, options = {}) => {
      const now = Math.floor(Date.now() / 1000);
      const input = `${part({ alg: 'RS256', kid: options.kid ?? 'rs-1', typ: 'JWT' })}.${part({
        iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/market:ref:refs/heads/dev', iat: now - 5, exp: now + 295, jti: randomUUID(),
        run_id: '7001', repository_id: '1', ...claims,
      })}`;
      return `${input}.${signWith('sha256', Buffer.from(input), options.key ?? privateKey).toString('base64url')}`;
    },
  };
}

/** A workload's key, P-256, as its process holds one: its thumbprint, and DPoP proofs it signs for a sign-in at `url`. */
export type ProofKey = { jkt: string; proof: (url: string, options?: { iat?: number }) => Promise<string> };

export async function proofKey(): Promise<ProofKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kty, crv, x, y } as PublicJwk;
  return {
    jkt: await thumbprint(jwk),
    proof: async (url, options = {}) => {
      const input = `${part({ typ: 'dpop+jwt', alg: 'ES256', jwk })}.${part({ jti: randomBytes(16).toString('base64url'), htm: 'POST', htu: url, iat: options.iat ?? Math.floor(Date.now() / 1000) })}`;
      const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(input));
      return `${input}.${Buffer.from(signature).toString('base64url')}`;
    },
  };
}
