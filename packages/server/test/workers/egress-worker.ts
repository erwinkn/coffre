// The credential proxy in workerd, its credentials leaving through a binding
// as a VPC Service's do: here a service binding to this Worker, which plays
// the upstream behind it and says what reached it. A VPC Service binding is
// no more than such a `Fetcher`, and local workerd has none of its own.
import type { PluginContext } from '../../src/plugins.ts';
import { credentialProxy, header, sigv4, type Egress } from '../../src/plugins/credential-proxy.ts';

type Env = { EGRESS: Egress; MISSING?: Egress };

const KEY = 'sk_schumann_real_0123456789abcdef';
const AWS = { AWS_ACCESS_KEY_ID: 'AKIAREAL0123456789AB', AWS_SECRET_ACCESS_KEY: 'real/secret/0123456789abcdefghijklmnopqr' };

/** coffre as the proxy calls it: every handle stands, for market/dev, and opens these values. */
const coffre = {
  publicUrl: 'https://secrets.acme.example',
  // A handle's request is no workload's.
  workload: async () => null,
  handle: async () => ({ expiresAt: new Date(Date.now() + 3_600_000).toISOString(), paths: ['market/dev'] }),
  use: async () => ({
    values: { SCHUMANN_API_KEY: KEY, ...AWS },
    plain: [],
    keys: ['SCHUMANN_API_KEY', ...Object.keys(AWS)],
    environment: { path: 'market/dev', personal: false },
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  }),
} as unknown as PluginContext;

const proxy = (egress: Egress | undefined) =>
  credentialProxy({
    credentials: {
      schumann: { upstream: 'https://dev.api.europ.schuman.io', inject: header('x-api-key', '{SCHUMANN_API_KEY}'), egress: egress! },
      s3: { upstream: 'https://s3.eu-west-3.amazonaws.com', inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }), egress: egress! },
    },
  });

/** The upstream behind the binding: what it was sent, never the key itself, which the proxy would redact. */
async function upstream(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/moved') return new Response(null, { status: 302, headers: { location: `${url.origin}/companies?page=2` } });
  const length = (await request.arrayBuffer()).byteLength;
  return Response.json({
    url: request.url,
    method: request.method,
    key: request.headers.get('x-api-key') === KEY,
    signed: (request.headers.get('authorization') ?? '').startsWith(`AWS4-HMAC-SHA256 Credential=${AWS.AWS_ACCESS_KEY_ID}/`),
    contentLength: request.headers.get('content-length'),
    length,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/use')) return upstream(request);
    try {
      const routes = proxy(url.searchParams.has('missing') ? env.MISSING : env.EGRESS).routes!;
      return await routes.fetch(request, coffre);
    } catch (error) {
      return new Response(error instanceof Error ? error.message : String(error), { status: 500 });
    }
  },
};
