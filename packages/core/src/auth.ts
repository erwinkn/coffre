import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { sha256 } from '../../crypto/src/index';
import { VaultError, type Authenticator, type Credentials, type Identity } from '../../contracts/src/index';

export class AccessAuthenticator implements Authenticator {
  private readonly keys: JWTVerifyGetKey;
  constructor(private readonly issuer: string, private readonly audience: string, keyResolver?: JWTVerifyGetKey, allowLocal = false) {
    const u = new URL(issuer);
    if (u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) throw new Error('Invalid Access issuer');
    if (!(u.protocol === 'https:' && u.hostname.endsWith('.cloudflareaccess.com')) && !(allowLocal && u.protocol === 'http:' && u.hostname === '127.0.0.1')) throw new Error('Untrusted issuer configuration');
    if (!audience) throw new Error('Missing Access audience');
    this.keys = keyResolver ?? createRemoteJWKSet(new URL('/cdn-cgi/access/certs', issuer), { timeoutDuration: 5000, cooldownDuration: 10000 });
  }
  async verify(credentials: Credentials): Promise<Identity> {
    if (credentials.bearer && credentials.accessJwt) throw new VaultError('UNAUTHENTICATED', 'Ambiguous credentials');
    if (credentials.bearer) {
      const match = credentials.bearer.match(/^coffre_([a-f0-9-]{36})\.([A-Za-z0-9_-]{43})$/);
      if (!match) throw new VaultError('UNAUTHENTICATED', 'Invalid credentials');
      return { kind: 'token', id: match[1]!, digest: await sha256(credentials.bearer) };
    }
    if (!credentials.accessJwt || credentials.accessJwt.length > 16384) throw new VaultError('UNAUTHENTICATED', 'Authentication required');
    try {
      const { payload } = await jwtVerify(credentials.accessJwt, this.keys, { issuer: this.issuer, audience: this.audience, algorithms: ['RS256'], requiredClaims: ['exp', 'iat'], clockTolerance: 5 });
      if (typeof payload.sub === 'string' && payload.sub) return { kind: 'human', subject: payload.sub };
      if (typeof payload.common_name === 'string' && payload.common_name) return { kind: 'access-service', subject: payload.common_name };
      throw new Error('Missing principal');
    } catch { throw new VaultError('UNAUTHENTICATED', 'Invalid or expired credentials'); }
  }
}
// Token material has high entropy. The comparison still avoids early exits on the hash contents.
export function sameDigest(a: string, b: string): boolean { let difference = a.length ^ b.length; for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ (b.charCodeAt(i) || 0); return difference === 0; }
