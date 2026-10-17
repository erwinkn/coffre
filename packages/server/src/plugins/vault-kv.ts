/**
 * Reading coffre as a HashiCorp Vault KV v2 store, for the tools that speak
 * Vault: External Secrets Operator first, and `vault kv get`, vals, Terraform's
 * `vault_kv_secret_v2` (docs/design/plugins.md, "The Vault KV adapter"). In
 * the deployment's configuration:
 *
 *   import { vaultKv } from '@coffre/server/plugins/vault-kv';
 *   plugins: [vaultKv()],
 *
 * and its app's route, `routes/v1.$.ts`, `createFileRoute('/v1/$')({ ...plugin })`.
 * Then `VAULT_ADDR=https://secrets.acme.example` and a coffre service token as
 * the Vault token:
 *
 *   GET /v1/secret/data/market/prod         every value of market/prod
 *   GET /v1/secret/data/market/prod/KEY     one: { KEY: value }
 *   GET /v1/auth/token/lookup-self          who the token is
 *   GET /v1/sys/internal/ui/mounts/secret   that `secret` is KV v2, for `vault kv get`
 *
 * Read only: anything else is refused. The token comes from `X-Vault-Token`
 * alone, never a cookie, and no CORS answer lets another site's page send
 * one, so these GETs can reveal what coffre's own API reveals only to a POST.
 * Each read is the API's reveal, as the token's holder: the same checks, the
 * same vault, one `secret.read` entry per value.
 */
import { CoffreError, type Me } from '@coffre/client';

import type { CoffrePlugin, PluginContext } from '../plugins.ts';

export type VaultKvOptions = {
  /** The mount clients name, `secret` as Vault's own default: `secret/data/market/prod`. */
  mount?: string;
};

const MOUNT = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** coffre's environments as a Vault KV v2 mount, read only. */
export function vaultKv(options: VaultKvOptions = {}): CoffrePlugin {
  const mount = options.mount ?? 'secret';
  if (!MOUNT.test(mount)) throw new Error(`vaultKv: a mount is one path segment, such as secret; got ${JSON.stringify(mount)}`);
  return {
    name: 'vault-kv',
    routes: { prefix: '/v1', fetch: (request, coffre) => serve(request, coffre, mount) },
  };
}

async function serve(request: Request, coffre: PluginContext, mount: string): Promise<Response> {
  const url = new URL(request.url);
  let path: string;
  try {
    // After `/v1/`, each segment decoded, as Vault reads it.
    path = url.pathname.slice('/v1/'.length).split('/').filter(Boolean).map(decodeURIComponent).join('/');
  } catch {
    return failure(400, 'the path is not valid percent-encoding');
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') return failure(405, "coffre's Vault API is read only");
  // Vault Enterprise's namespaces: an empty header is what some clients always send.
  if ((request.headers.get('x-vault-namespace') ?? '') !== '') return failure(400, 'coffre has no Vault namespaces');
  // Response wrapping (`vault kv get -wrap-ttl=5m`): the client expects a single-use token, not the values. Refused before anything is read.
  if ((request.headers.get('x-vault-wrap-ttl') ?? '') !== '') return failure(400, 'coffre does not wrap responses: leave out -wrap-ttl');

  // What `vault kv get` and vals ask first, to learn the mount's KV version. It holds no secret: Vault's UI asks it too.
  const mounts = 'sys/internal/ui/mounts/';
  if (path.startsWith(mounts)) {
    const asked = path.slice(mounts.length);
    return asked === mount || asked.startsWith(`${mount}/`) ? success(mountInfo(mount)) : failure(403, 'permission denied');
  }

  const token = request.headers.get('x-vault-token') ?? '';
  if (token === '') return failure(403, 'permission denied: send a coffre token as X-Vault-Token');
  const api = coffre.api(token);
  try {
    if (path === 'auth/token/lookup-self') return success(lookupSelf(await api.me()));
    const data = `${mount}/data/`;
    if (path.startsWith(data)) {
      if (url.searchParams.has('list')) return failure(405, 'coffre does not list environments through its Vault API');
      if (url.searchParams.has('version')) return failure(400, 'coffre serves current values only: leave out version');
      const place = path.slice(data.length);
      // A path that names no environment is a mistake in the client's configuration: 400, which ESO does not read as the secret gone.
      const depth = place.split('/').length;
      if (depth < 2 || depth > 3) return failure(400, `name ${data}<project>/<environment>, or ${data}<project>/<environment>/<KEY> for one value`);
      const { values } = await api.secrets.reveal(place);
      return success({ data: values, metadata: METADATA });
    }
    return failure(404);
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    return refused(error);
  }
}

/**
 * A KV v2 read's metadata. An environment has no version of its own, and
 * a value's history stays in coffre: 0 says there is none here, as
 * `?version=` is refused.
 */
const METADATA = { created_time: '1970-01-01T00:00:00Z', custom_metadata: null, deletion_time: '', destroyed: false, version: 0 };

/** The mount as `sys/internal/ui/mounts/<path>` describes it: `options.version`, a string, is what clients read. */
function mountInfo(mount: string) {
  return {
    path: `${mount}/`,
    type: 'kv',
    description: 'coffre',
    options: { version: '2' },
    accessor: '',
    local: false,
    seal_wrap: false,
    external_entropy_access: false,
    uuid: '',
    plugin_version: '',
    running_plugin_version: '',
    running_sha256: '',
    config: { default_lease_ttl: 0, max_lease_ttl: 0, force_no_cache: false },
  };
}

/**
 * `auth/token/lookup-self`, which ESO asks to check its store, and
 * Terraform before every plan. ESO reads `type`, a string, `ttl`, a number,
 * and `expire_time`, which may be null; Terraform needs no `namespace_path`.
 * The token's expiry is not in `me`: a ttl of 0 and no expire time say it
 * does not expire, as Vault's own non-expiring tokens do, and coffre refuses
 * it once it has.
 */
function lookupSelf(me: Me) {
  if (!me.registered) throw new CoffreError(403, 'registration_required', 'you are signed in, but not a member here');
  return {
    accessor: '',
    creation_time: 0,
    creation_ttl: 0,
    display_name: `${me.principal.type === 'service' ? 'token' : 'user'}:${me.principal.id}`,
    entity_id: '',
    expire_time: null,
    explicit_max_ttl: 0,
    id: '',
    meta: null,
    num_uses: 0,
    orphan: true,
    path: 'auth/token/create',
    policies: ['default'],
    renewable: false,
    ttl: 0,
    type: 'service',
  };
}

/** Vault's envelope around `data`: no lease, nothing to renew. */
function success(data: unknown): Response {
  return Response.json(
    { request_id: crypto.randomUUID(), lease_id: '', renewable: false, lease_duration: 0, data, wrap_info: null, warnings: null, auth: null, mount_type: 'kv' },
    { headers: { 'cache-control': 'no-store' } },
  );
}

/** Vault's error shape. A 404's list is empty, as Vault's is: ESO reads it as "no such secret". */
function failure(status: number, message = ''): Response {
  return Response.json({ errors: status === 404 ? [] : [message] }, { status, headers: { 'cache-control': 'no-store' } });
}

/**
 * The API's refusal, as Vault says it. A token coffre does not know is
 * Vault's 403, not 401; a place that does not exist is 404, which ESO
 * reads as the secret gone. Anything else keeps its status and message:
 * a 503 stays one, so that an outage is never read as a deletion.
 */
function refused(error: CoffreError): Response {
  if (error.status === 401 || error.status === 403) return failure(403, `permission denied: ${error.message}`);
  return failure(error.status, error.message);
}
