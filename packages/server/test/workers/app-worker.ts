// coffre on Workers as a deployment runs it on the 0.16 contract: the app's
// `createCoffre(…)`, and the vault as an entrypoint of the same Worker
// behind the app's `VAULT` service binding, with its signer, each over a
// Hyperdrive binding of its own to the suite's database. Its fetch answers
// as a deployment's Start app does: coffre's middleware around every
// request, coffre's routes for coffre's paths, and a page for `/page`. Each
// service's workload gate is its Durable Object, `GATES`. Its credential
// proxy has one credential, `echo`, whose upstream is a fake inside the
// Worker (its `egress`): it answers what it was sent, the key reversed so
// that the proxy's redaction leaves it, so a request through the proxy goes
// all the way but for the network; and one tunnel, `db`, to the suite's
// database, whose WebSockets go to their Durable Object, `SOCKETS`. Its
// `CoffreWorkload` entrypoint is what another Worker binds with `props`: the
// Worker binds it itself, under several props (`COFFRE_*`), and `/as/<binding>/…`
// asks through one, as a bound Worker's fetch would; `/rpc/<binding>` calls one of
// its methods, as a bound Worker's `env.COFFRE.sign(…)` would, for the signers,
// the verifier and the AWS-signed credential `keys`' environment holds. The
// vault's key is a key service's stand-in, which `/key-service` makes give
// out partway through a call.
import type { CoffreBinding } from '@coffre/client/workload';
import { github, signin } from '@coffre/core/identity';
import { derivedSigningKey, KekUnavailableError, LocalKekProvider, type KekProvider } from '@coffre/core/kek';
import { postgres as vaultDatabase, vault } from '@coffre/vault/cloudflare';

import { createCoffre, postgres, type GatesNamespace, type SocketsNamespace, type Vault as VaultBinding, type WaitUntil } from '../../src/cloudflare.ts';
import { allow, credentialProxy, header, hmac, postgres as tunnel, privateKey, sigv4 } from '../../src/plugins/credential-proxy.ts';
import { vaultKv } from '../../src/plugins/vault-kv.ts';
import { processLimits } from '../../src/workloads/limits.ts';

export { CoffreSigner } from '@coffre/vault/cloudflare';

type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT_HYPERDRIVE: { connectionString: string };
  APP_KEY: string;
  VAULT_KEY: string;
  VAULT: VaultBinding;
  GATES: GatesNamespace;
  SOCKETS: SocketsNamespace;
  /** `CoffreWorkload`, bound with props naming `edge`, `token:edge`, `keys`, `ghost` (a service with no binding), and none. */
  COFFRE_EDGE: CoffreBinding;
  COFFRE_TOKEN_EDGE: CoffreBinding;
  COFFRE_KEYS: CoffreBinding;
  COFFRE_GHOST: CoffreBinding;
  COFFRE_NO_PROPS: CoffreBinding;
};

/** The upstream `echo` and its kin answer from: what it was sent, the key reversed so that the proxy's redaction leaves it. */
const echoed = { fetch: async (url: URL, init: RequestInit) => Response.json({ path: url.pathname, reversed: [...(new Headers(init.headers).get('authorization') ?? '')].reverse().join('') }) };

/**
 * How many more calls the key service answers before one fails, and how many
 * it was asked since `/key-service` said: every one until then, and every
 * one again after the one it fails. Both Workers are this one, in one isolate.
 */
const outage = { answers: Infinity, calls: 0 };

/** The vault's own key, wrapping and opening as a key service would, until `outage` says it gives out. */
function keyService(key: string): KekProvider {
  const local = LocalKekProvider.fromBase64(key, 'app-workers-test');
  const call = <T>(run: () => Promise<T>): Promise<T> => {
    outage.calls += 1;
    if (outage.answers-- > 0) return run();
    outage.answers = Infinity;
    return Promise.reject(new KekUnavailableError('KMS Decrypt failed 3 times: KMSInternalException'));
  };
  return {
    provider: local.provider, keyId: local.keyId, keyVersion: local.keyVersion,
    wrap: (...args) => call(() => local.wrap(...args)),
    unwrap: (...args) => call(() => local.unwrap(...args)),
  };
}

export const Vault = vault((env: Env) => ({
  database: vaultDatabase(env.VAULT_HYPERDRIVE as never),
  kek: keyService(env.VAULT_KEY),
  // What the vault derives from a key it holds, which a key service's it does not.
  signingKey: derivedSigningKey(Buffer.from(env.VAULT_KEY, 'base64')).toString('base64'),
  owners: ['root@acme.example'],
  workloads: {},
}));

const coffre = createCoffre((env: Env) => ({
  publicUrl: 'https://secrets.acme.example',
  database: postgres(env.HYPERDRIVE as never),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } }),
  auditChainKey: env.APP_KEY,
  gates: env.GATES,
  sockets: env.SOCKETS,
  plugins: [
    credentialProxy({
      credentials: {
        echo: {
          upstream: 'https://api.echo.example/v1',
          inject: header('authorization', 'Bearer {API_KEY}'),
          egress: echoed,
        },
        // The same key, held to one path by its rules, and to one request a minute by its limit.
        ruled: { upstream: 'https://api.echo.example/v1', inject: header('authorization', 'Bearer {API_KEY}'), egress: echoed, rules: [allow('GET', '/ping')] },
        once: { upstream: 'https://api.echo.example/v1', inject: header('authorization', 'Bearer {API_KEY}'), egress: echoed, limit: { perMinute: 1 } },
        // What `presign` signs a URL with; nothing is ever sent to it here.
        s3: { upstream: 'https://bucket.s3.eu-west-3.amazonaws.com', inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
      },
      // An HMAC secret that takes a raw message past JSON's 1 MiB, the same held to one signature a minute, and a private key.
      signers: { mac: hmac('MAC_KEY', { encoding: 'hex', maxBytes: 2 * 1024 * 1024 }), 'mac-once': hmac('MAC_KEY', { encoding: 'hex', limit: { perMinute: 1 } }), ed25519: privateKey('SIGNING_KEY') },
      verifiers: { hook: hmac('HOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) },
      // The suite's database is on loopback, which only insecureUpstreams dials; its checks every second.
      tunnels: { db: tunnel('TUNNEL_URL') },
      insecureUpstreams: true,
      recheckSeconds: 1,
    }),
    vaultKv(),
  ],
}));

export const CoffreGates = coffre.Gates;
export const CoffreSockets = coffre.Sockets;
export const CoffreWorkload = coffre.Workload;

export default {
  async fetch(request: Request, env: Env, ctx: WaitUntil): Promise<Response> {
    if (new URL(request.url).pathname === '/key-service') {
      // POST: how many calls it answers before it gives out; GET: how many it was asked since.
      if (request.method === 'POST') Object.assign(outage, { answers: Number(await request.text()), calls: 0 });
      return Response.json({ calls: outage.calls });
    }
    // As a Worker that binds coffre: its request, sent over the binding the path names, to a host the binding ignores.
    const through = /^\/as\/([A-Z_]+)(\/.*)$/.exec(new URL(request.url).pathname);
    if (through !== null) {
      const binding = env[through[1] as keyof Env] as CoffreBinding;
      return binding.fetch(new Request(`https://coffre${through[2]}${new URL(request.url).search}`, request));
    }
    // As a Worker that calls coffre's methods over the binding: `{ method, args }`, each `{ bytes }` among them a
    // Uint8Array of its base64. What it threw, as the caller sees it: RPC carries an error's fields, not its class.
    const rpc = /^\/rpc\/([A-Z_]+)$/.exec(new URL(request.url).pathname);
    if (rpc !== null) {
      const { method, args } = (await request.json()) as { method: 'sign' | 'verify' | 'presign'; args: unknown[] };
      const binding = env[rpc[1] as keyof Env] as CoffreBinding;
      const given = args.map((arg) => (typeof arg === 'object' && arg !== null && 'bytes' in arg ? new Uint8Array(Buffer.from(arg.bytes as string, 'base64')) : arg));
      try {
        return Response.json({ value: await (binding[method] as (...args: unknown[]) => Promise<unknown>)(...given) });
      } catch (error) {
        const { name, message, status, code, reason } = error as Error & { status?: number; code?: string; reason?: string };
        return Response.json({ thrown: { name, message, status, code, reason } });
      }
    }
    const socket = coffre.upgrade(request, env);
    if (socket !== null) return socket;
    const scope = coffre.request(env, ctx).coffre;
    return scope.respond(request, async (page) => {
      if (new URL(request.url).pathname !== '/page') return scope.route(request);
      // A page's render: two loaders ask who the visitor is, side by side.
      const [first, second] = await Promise.all([page.client.me(), page.client.me()]);
      return Response.json({ who: first.principal.id, same: JSON.stringify(first) === JSON.stringify(second) });
    });
  },
};
