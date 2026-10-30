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
 * or, for a workload that holds no coffre token, its platform's ID token,
 * through the service account's trust bindings:
 *
 *   PUT /v1/auth/kubernetes/login { role, jwt }   a token for service account `role`, five minutes
 *   PUT /v1/auth/token/revoke-self                that token, ended
 *
 * Read only, and current values only: anything else is refused, never with
 * 404, which only says that the place a read names is not there. The token
 * comes from `X-Vault-Token` alone, never a cookie, and no CORS answer lets
 * another site's page send one, so these GETs can reveal what coffre's own
 * API reveals only to a POST. Each read is the API's reveal, as the token's
 * holder: the same checks, the same vault, the same `secret.read` entry.
 */
import { CoffreError, type Me } from '@coffre/client';

import type { CoffrePlugin, PluginContext } from '../plugins.ts';
import { UNAVAILABLE_RETRY_AFTER } from '../api/errors.ts';

export type VaultKvOptions = {
  /** The mount clients name, `secret` as Vault's own default: `secret/data/market/prod`. */
  mount?: string;
};

const MOUNT = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** coffre's environments as a Vault KV v2 mount, read only. */
export function vaultKv(options: VaultKvOptions = {}): CoffrePlugin {
  const mount = options.mount ?? 'secret';
  if (!MOUNT.test(mount)) throw new Error(`vaultKv: a mount is one path segment, such as secret; got ${JSON.stringify(mount)}`);
  // Vault's own roots, where no secrets engine mounts: `auth/<mount>/login` and `sys/…` are paths of their own here too.
  if (mount === 'auth' || mount === 'sys') throw new Error(`vaultKv: ${mount} is Vault's own path, where no secrets mount; name another, such as secret`);
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
  // The writes it takes: signing in, at any auth mount's `login` (`kubernetes`, `jwt` or the deployment's own name), and out.
  const writes = request.method === 'PUT' || request.method === 'POST';
  // A mount may be several segments deep, `kubernetes/cluster-a`; Vault's token auth has no login.
  const signing = (/^auth\/.+\/login$/.test(path) && path !== 'auth/token/login') || path === 'auth/token/revoke-self';
  if (signing && !writes) return failure(405, 'sign in and out with PUT or POST');
  if (request.method !== 'GET' && request.method !== 'HEAD' && !signing) return failure(405, "coffre's Vault API is read only");
  const login = signing && path !== 'auth/token/revoke-self';
  const revoke = signing && !login;
  // HashiCorp's client sends LIST as `GET …?list=true`, on any path: ESO's `dataFrom.find` asks it of `<mount>/metadata/`.
  if (url.searchParams.has('list')) return failure(405, 'coffre does not list environments through its Vault API');
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

  if (login) return logIn(coffre);
  const token = request.headers.get('x-vault-token') ?? '';
  if (token === '') return failure(403, 'permission denied: send a coffre token as X-Vault-Token');
  const api = coffre.api(token);
  try {
    if (revoke) {
      await coffre.signOut(token);
      return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
    }
    if (path === 'auth/token/lookup-self') return success(lookupSelf(await api.me()));
    const data = `${mount}/data/`;
    if (path.startsWith(data)) {
      // `version`, `read_snapshot_id` and whatever Vault adds next each ask for other values than the current ones: none is taken.
      if (url.search !== '') return failure(400, 'coffre serves current values only, and takes no query: leave out version and the like');
      const place = path.slice(data.length);
      // A path that names no environment is a mistake in the client's configuration: 400, which ESO does not read as the secret gone.
      const depth = place.split('/').length;
      if (depth < 2 || depth > 3) return failure(400, `name ${data}<project>/<environment>, or ${data}<project>/<environment>/<KEY> for one value`);
      // A person's read of an environment leaves its sensitive keys out: Vault's warnings name them, never their values.
      const { values, sensitive, version } = await api.secrets.reveal(place);
      const warnings = sensitive.length === 0 ? null : [`left out, sensitive, which no person is handed: ${sensitive.join(', ')}`];
      return success({ data: values, metadata: metadata(version) }, null, warnings);
    }
    // Only a read of a place that is not there is 404, which ESO reads as the secret gone: anything else coffre does not serve is 400.
    return failure(400, `coffre's Vault API serves ${data}<project>/<environment>[/<KEY>], auth/token/lookup-self, auth/<mount>/login and auth/token/revoke-self`);
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    return refused(error);
  }
}

/**
 * `auth/<mount>/login`, as ESO's Kubernetes and JWT auth send it, `{ role,
 * jwt }`: the role names a coffre service account, and the JWT is a
 * workload's ID token, which the exchange takes through that account's
 * trust bindings: a Kubernetes service account's projected token, a GitHub
 * run's. The exchange admits the request, reads its body, checks the token,
 * spends it and issues a credential of five minutes, never this plugin: it
 * holds no key of any issuer's, and only says what the body names. The
 * answer is Vault's `auth` block, not renewable: ESO signs in again for its
 * next read.
 */
async function logIn(coffre: PluginContext): Promise<Response> {
  let role: unknown;
  try {
    const issued = await coffre.exchange((body) => {
      const login = (body ?? {}) as { role?: unknown; jwt?: unknown };
      role = login.role;
      return { service: typeof role === 'string' ? `token:${role}` : role, token: login.jwt };
    });
    const left = Math.max(0, Math.floor((Date.parse(issued.expiresAt) - Date.now()) / 1000));
    return success(null, {
      client_token: issued.token,
      accessor: '',
      policies: ['default'],
      token_policies: ['default'],
      metadata: { role },
      lease_duration: left,
      renewable: false,
      entity_id: '',
      token_type: 'service',
      orphan: true,
      num_uses: 0,
    });
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    if (error.status === 400) return failure(400, `a login's body is JSON, { "role", "jwt" }: ${error.message}`);
    // An instance that trusts no workloads says 404: no place a read names, so not Vault's 404 either.
    return error.status === 404 ? failure(400, error.message) : refused(error);
  }
}

/**
 * A KV v2 read's metadata. Vault's `version` is a number, which no version
 * of coffre's is: 0 says there is none here, as `?version=` is refused. An
 * environment's own version, a hash of what the read opened, is in
 * `custom_metadata`, Vault's map of strings, where `vault kv get` shows it.
 */
function metadata(version: string | null) {
  return {
    created_time: '1970-01-01T00:00:00Z',
    custom_metadata: version === null ? null : { coffre_version: version },
    deletion_time: '',
    destroyed: false,
    version: 0,
  };
}

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
 * The ttl is the seconds the token has left, which ESO takes for expired
 * under 60. A credential that is not coffre's, Access's assertion, says
 * none: a ttl of 0 and no expire time, as Vault's tokens that never expire.
 */
function lookupSelf(me: Me, now = Date.now()) {
  if (!me.registered) throw new CoffreError(403, 'registration_required', 'you are signed in, but not a member here');
  return {
    accessor: '',
    creation_time: 0,
    creation_ttl: 0,
    display_name: `${me.principal.type === 'service' ? 'token' : 'user'}:${me.principal.id}`,
    entity_id: '',
    expire_time: me.credentialExpiresAt,
    explicit_max_ttl: 0,
    id: '',
    meta: null,
    num_uses: 0,
    orphan: true,
    path: 'auth/token/create',
    policies: ['default'],
    renewable: false,
    ttl: me.credentialExpiresAt === null ? 0 : Math.max(0, Math.floor((Date.parse(me.credentialExpiresAt) - now) / 1000)),
    type: 'service',
  };
}

/** Vault's envelope around `data`, a login's `auth`, and what the answer leaves out: no lease, nothing to renew. */
function success(data: unknown, auth: Record<string, unknown> | null = null, warnings: string[] | null = null): Response {
  return Response.json(
    { request_id: crypto.randomUUID(), lease_id: '', renewable: false, lease_duration: 0, data, wrap_info: null, warnings, auth, mount_type: 'kv' },
    { headers: { 'cache-control': 'no-store' } },
  );
}

/** Vault's error shape. A 404's list is empty, as Vault's is: ESO reads it as "no such secret". */
function failure(status: number, message = '', retryAfter?: string): Response {
  return Response.json({ errors: status === 404 ? [] : [message] }, { status, headers: { 'cache-control': 'no-store', ...(retryAfter === undefined ? {} : { 'retry-after': retryAfter }) } });
}

/**
 * The API's refusal, as Vault says it. A token coffre does not know is
 * Vault's 403, not 401; a place that does not exist is 404, which ESO
 * reads as the secret gone. A key's one refusal (`not_available`, D153),
 * whether the key is missing or the caller may not have it, is 403: as
 * the two are one answer, a 404 would have ESO delete a secret it syncs
 * whenever its reader lost the key, a grant revoked or the key made
 * sensitive. Anything else keeps its status and message: a 503 stays
 * one, so that an outage is never read as a deletion.
 */
function refused(error: CoffreError): Response {
  if (error.status === 401 || error.status === 403 || error.code === 'not_available') return failure(403, `permission denied: ${error.message}`);
  // coffre not answering for a moment says when to ask again, as the API does.
  return failure(error.status, error.message, error.status === 503 && error.code === 'unavailable' && error.reason === undefined ? UNAVAILABLE_RETRY_AFTER : undefined);
}
