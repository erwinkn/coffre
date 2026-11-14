// The credential proxy in workerd (`credential-proxy-egress-workers.test.ts`), its
// credentials leaving through a binding as a VPC Service's do: here a service binding to
// this Worker, which plays the upstream behind it and says what reached it. A VPC Service
// binding is no more than such a `Fetcher`, and local workerd has none of its own.
// `yousign` leaves through the Worker's own fetch, for the suite's upstream at `UPSTREAM`,
// and takes a workload's request too: any session token stands, its proof (checked on
// Node, `proxy-workload.test.ts`) signing `content-type` and `content-digest`. coffre's
// side is a stand-in on 0.16's contract: every handle stands for market/dev, and every
// use opens these values.
import type { PluginContext, Used, WorkloadUse } from '../../src/plugins.ts';
import { credentialProxy, header, sigv4, type Egress } from '../../src/plugins/credential-proxy.ts';

type Env = { EGRESS: Egress; MISSING?: Egress; UPSTREAM: string };

const KEY = 'sk_schumann_real_0123456789abcdef';
const AWS = { AWS_ACCESS_KEY_ID: 'AKIAREAL0123456789AB', AWS_SECRET_ACCESS_KEY: 'real/secret/0123456789abcdefghijklmnopqr' };

const session: WorkloadUse = { principal: 'token:api-prod', hdr: ['content-type', 'content-digest'], nonce: 'nonce-1', path: 'market/dev' };

const coffre = {
  publicUrl: 'https://secrets.acme.example',
  // A handle's request is no workload's; a session's stands.
  workload: async (request: Request) => (/^DPoP coffre_wl_/.test(request.headers.get('authorization') ?? '') ? session : null),
  handle: async () => ({ expiresAt: new Date(Date.now() + 3_600_000).toISOString(), paths: ['market/dev'] }),
  use: async (caller: string | WorkloadUse): Promise<Used> => ({
    values: { SCHUMANN_API_KEY: KEY, ...AWS },
    plain: [],
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    environment: { path: 'market/dev', personal: false },
    workload: typeof caller === 'string' ? null : { policy: {} as never, constraints: null },
  }),
} as unknown as PluginContext;

const proxy = (egress: Egress | undefined, upstream: string) =>
  credentialProxy({
    insecureUpstreams: true,
    credentials: {
      yousign: { upstream, inject: header('authorization', 'Bearer {SCHUMANN_API_KEY}') },
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
      const routes = proxy(url.searchParams.has('missing') ? env.MISSING : env.EGRESS, env.UPSTREAM).routes!;
      return await routes.fetch(request, coffre);
    } catch (error) {
      return new Response(error instanceof Error ? error.message : String(error), { status: 500 });
    }
  },
};
