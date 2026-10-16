import type { Minted, Minter } from './mint.ts';

/**
 * Cloudflare R2's temporary credentials, signed here, with no call to
 * Cloudflare: an HS256 JWT over the bucket and scope, keyed by a parent R2
 * API token's secret access key. R2 checks it against the parent, which
 * caps it; revoking the parent ends every one at once.
 * https://developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/
 *
 *   const assets = r2({ accountId, accessKeyId: env.R2_PARENT_ID, secretAccessKey: env.R2_PARENT_SECRET });
 *   { at: 'web/prod', from: assets.credentials({ bucket: 'web-assets', scope: 'object-read-write', prefixes: ['releases/'], ttlSeconds: 900 }),
 *     keys: { accessKeyId: 'R2_ACCESS_KEY_ID', secretAccessKey: 'R2_SECRET_ACCESS_KEY', sessionToken: 'R2_SESSION_TOKEN' } }
 *
 * The parent is an R2 API token made once in the dashboard, Object Read &
 * Write on the buckets it may delegate: no permission to make tokens,
 * which Cloudflare's error 9109 is about. Its secret stays in the vault's
 * configuration; the fields minted are what an S3 client takes.
 *
 * Prototype (W108): checked against Cloudflare's published derivation,
 * never against R2 itself.
 */
export type R2Options = {
  accountId: string;
  /** The parent token's access key ID, its `id`. */
  accessKeyId: string;
  /** The parent token's secret access key: the SHA-256, hex, of its value, as the dashboard shows it. */
  secretAccessKey: string;
  /** `eu` or `fedramp` for a bucket in that jurisdiction. */
  jurisdiction?: 'eu' | 'fedramp';
};

export type R2Scope = {
  bucket: string;
  scope: 'object-read-only' | 'object-read-write' | 'admin-read-only' | 'admin-read-write';
  /** Keys starting with one of these, alone. */
  prefixes?: readonly string[];
  /** These keys, exactly, alone. */
  objects?: readonly string[];
  /** How long each lasts: a job's length, not a day. */
  ttlSeconds: number;
};

const SCOPES = new Set(['object-read-only', 'object-read-write', 'admin-read-only', 'admin-read-write']);

export function r2(options: R2Options): { credentials(scope: R2Scope): Minter } {
  const { accountId, accessKeyId, secretAccessKey, jurisdiction } = options;
  if (!/^[0-9a-f]{32}$/.test(accountId)) throw new Error('r2(…).accountId must be the 32 hex digits of a Cloudflare account ID');
  if (typeof accessKeyId !== 'string' || accessKeyId.length === 0) throw new Error('r2(…).accessKeyId must be the parent R2 token\'s access key ID');
  if (!/^[0-9a-f]{64}$/.test(secretAccessKey)) throw new Error('r2(…).secretAccessKey must be the parent R2 token\'s secret access key, 64 hex digits');
  const host = `${accountId}${jurisdiction === undefined ? '' : `.${jurisdiction}`}.r2.cloudflarestorage.com`;
  return {
    credentials(scope: R2Scope): Minter {
      const { bucket, prefixes = [], objects = [], ttlSeconds } = scope;
      if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket)) throw new Error(`credentials(…).bucket must be an R2 bucket's name; got "${bucket}"`);
      if (!SCOPES.has(scope.scope)) throw new Error(`credentials(…).scope must be one of ${[...SCOPES].join(', ')}`);
      if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 7 * 24 * 3600) throw new Error('credentials(…).ttlSeconds must be a whole number of seconds, from a minute to a week');
      const fixed = { bucket, scope: scope.scope, prefixes: [...prefixes], objects: [...objects], ttlSeconds };
      return {
        provider: 'r2',
        fields: ['accessKeyId', 'secretAccessKey', 'sessionToken'],
        scope: { account: accountId, parent: accessKeyId, ...fixed },
        mint: async (): Promise<Minted> => {
          const now = Math.floor(Date.now() / 1000);
          const exp = now + ttlSeconds;
          const payload = {
            bucket, scope: fixed.scope, paths: { prefixPaths: fixed.prefixes, objectPaths: fixed.objects },
            sub: accountId, iss: accessKeyId, aud: host, iat: now, exp,
          };
          const input = `${base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${base64url(JSON.stringify(payload))}`;
          const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secretAccessKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
          const jwt = `${input}.${base64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(input))))}`;
          const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(jwt)));
          return {
            values: {
              accessKeyId,
              secretAccessKey: [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join(''),
              sessionToken: btoa(`jwt/${jwt}`),
            },
            expiresAt: new Date(exp * 1000).toISOString(),
          };
        },
      };
    },
  };
}

function base64url(value: string | Uint8Array): string {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
