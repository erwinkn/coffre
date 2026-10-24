/**
 * A CI run signing in as a service, with the ID token its platform signs
 * for it (docs/design/oidc.md), and no bearer token: `coffre --service
 * api-deploy …` for one command, or `coffre login <url> --service
 * api-deploy` for the commands after it. The CLI takes the run's ID token,
 * trades it at `POST /api/auth/oidc` for a credential that lasts five
 * minutes, and keeps that credential in memory, or, after a login, in the
 * session it saves, which lasts as long. A token is spent once used, so on
 * GitHub each exchange asks the runner for a fresh one.
 */
import { createHash } from 'node:crypto';
import { chmodSync } from 'node:fs';
import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import { contentDigest, declaredDigest, MAX_DIGESTED_BODY, UNSIGNED_HEADERS } from '@coffre/client/dpop';
import { askedNonce, aws, azure, CoffreError, enrollment, fly, gcp, github, kubernetes, oidc, vercel, workload, type Proof, type Workload } from '@coffre/client/workload';

import { clash, environmentPaths, listOf } from './environments.ts';
import { UsageError } from './manage.ts';
import { readSecret } from './secret.ts';
import { listen, type Tunnel } from './tunnels.ts';

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

/** What GitHub's runner hands a job with `permissions: id-token: write`: where to ask for an ID token, and with what. */
export type Runner = {
  ACTIONS_ID_TOKEN_REQUEST_URL?: string;
  ACTIONS_ID_TOKEN_REQUEST_TOKEN?: string;
};

/**
 * The run's ID token, for `audience`, this instance's URL: the one
 * `coffre login --service <name> --id-token` asked for (GitLab's
 * `id_tokens`, or any issuer's), or GitHub's runner's, asked for a fresh
 * one, when the job has `permissions: id-token: write`.
 */
export async function idToken(given: string | undefined, runner: Runner, audience: string, fetchImpl: Fetch): Promise<string> {
  if (given) return given;
  const [url, bearer] = [runner.ACTIONS_ID_TOKEN_REQUEST_URL?.trim(), runner.ACTIONS_ID_TOKEN_REQUEST_TOKEN?.trim()];
  if (url && bearer) {
    const request = new URL(url);
    request.searchParams.set('audience', audience);
    const response = await fetchImpl(request.href, { headers: { authorization: `bearer ${bearer}`, accept: 'application/json' } });
    const body = (await response.json().catch(() => null)) as { value?: unknown } | null;
    if (!response.ok || typeof body?.value !== 'string') throw new Error(`GitHub did not give this job an ID token (status ${response.status})`);
    return body.value;
  }
  throw new Error(
    '--service signs in with the run\'s ID token, and there is none: on GitHub Actions, give the job ' +
      '`permissions: id-token: write`; elsewhere, pipe it to `coffre login <url> --service <name> --id-token` (GitLab: an `id_tokens` entry whose aud is ' +
      `${audience})`,
  );
}

/** Trade an ID token for a credential of `service`, or throw saying why the instance refused. */
export async function exchange(origin: string, service: string, token: string, fetchImpl: Fetch): Promise<{ token: string; expiresAt: string }> {
  const response = await fetchImpl(`${origin}/api/auth/oidc`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ service, token }),
  });
  const body = (await response.json().catch(() => null)) as { token?: unknown; expiresAt?: unknown; reason?: unknown; message?: unknown } | null;
  if (response.ok && typeof body?.token === 'string' && typeof body.expiresAt === 'string') {
    return { token: body.token, expiresAt: body.expiresAt };
  }
  const why = typeof body?.message === 'string' ? body.message : `status ${response.status}`;
  const reason = typeof body?.reason === 'string' ? ` (${body.reason})` : '';
  throw new Error(`${origin} would not sign this run in as ${service}${reason}: ${why}`);
}

/**
 * Key-bound, the same CLI (docs/design/workload-access.md, sections 6.3 and
 * 9.3): `coffre serve` and `coffre --service <name> run` sign in at
 * `POST /api/auth/workload` with a platform's proof, and hold a session bound
 * to a key that lives in the CLI's memory alone. The app reaches its
 * credentials through a local listener, which forwards what it sends,
 * signed, and its databases through tunnels that sign their upgrades.
 */

/** The proofs `--proof` names. Each secret one (an enrollment code, an ID token) is read from stdin, never an argument. */
export const PROOFS = 'kubernetes[:<file>], aws, gcp, azure:<audience>, fly, vercel, github, enrollment or oidc';

/** A `--proof`, as `@coffre/client/workload` proves it; none, in a GitHub Actions job, is the job's ID token. */
export async function proofOf(spec: string | undefined, runner: Runner): Promise<Proof> {
  if (spec === undefined) {
    if (runner.ACTIONS_ID_TOKEN_REQUEST_URL && runner.ACTIONS_ID_TOKEN_REQUEST_TOKEN) return github();
    throw new UsageError(`name the platform's proof: --proof ${PROOFS}`);
  }
  const [kind, rest] = spec.split(/:(.*)/s) as [string, string | undefined];
  switch (kind) {
    case 'kubernetes':
      return kubernetes(rest || undefined);
    case 'aws':
      return aws();
    case 'gcp':
      return gcp();
    case 'azure':
      if (!rest) throw new UsageError("--proof azure:<audience> names coffre's Entra application: azure:api://coffre-acme");
      return azure({ audience: rest });
    case 'fly':
      return fly();
    case 'vercel':
      return vercel();
    case 'github':
      return github();
    case 'enrollment':
      return enrollment(await readSecret({ label: 'Enrollment code', hint: 'coffre_enr_…, from `coffre enroll <service>`; piped in, as printf %s "$COFFRE_ENROLL" | coffre …' }));
    case 'oidc': {
      const token = await readSecret({ label: 'ID token', hint: "the platform's ID token for this instance: GitLab's id_tokens entry, or a custom issuer's" });
      return oidc(token);
    }
  }
  throw new UsageError(`--proof ${spec}: a proof is one of ${PROOFS}`);
}

/** Where a listener listens: `127.0.0.1:7300`, `[::1]:7300`, or a Unix socket, `unix:/run/coffre/api.sock`. */
export type Address = { host: string; port: number } | { path: string };

export function addressOf(text: string, flag: string): Address {
  if (text.startsWith('unix:') && text.length > 5) return { path: text.slice(5) };
  const match = /^(?:\[([0-9a-fA-F:.]+)\]|([^:[\]]+)):(\d{1,5})$/.exec(text);
  const port = Number(match?.[3]);
  if (match === null || port > 65535) throw new UsageError(`${flag} ${text}: an address is <host>:<port>, [<ipv6>]:<port> or unix:<path>`);
  return { host: match[1] ?? match[2]!, port };
}

/**
 * Headers no request carries on to coffre: the transport's, the app's
 * credentials for the listener, which the session's replace, and a
 * person's handle header, which `credential(name)` sends empty here.
 */
const DROPPED = new Set([...UNSIGNED_HEADERS, 'expect', 'x-coffre-handle']);
/** Headers no answer carries back: the transport's, and what fetch undid (a body it decompressed is no longer its encoding). */
const UNANSWERED = new Set(['connection', 'content-encoding', 'content-length', 'keep-alive', 'transfer-encoding', 'dpop-nonce']);

/**
 * A local listener that forwards each request under `/use/` to coffre,
 * signed by the session, as the app sent it: its method, path, query, headers
 * and body. The app's config names it (`OPENAI_BASE_URL=http://127.0.0.1:7300/use/openai`),
 * and coffre writes no URL into the app's environment (R14). On a Unix
 * socket, only the socket's owner may connect.
 */
export async function forwarder(coffre: Workload, origin: string, address: Address): Promise<{ url: string; close: () => void }> {
  const server = createServer((req, res) => {
    const answer = (status: number, error: string, message: string) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ error, message }));
    let target: URL;
    try {
      target = new URL(req.url ?? '/', origin);
    } catch {
      return answer(400, 'bad_request', 'this request names no URL');
    }
    if (target.origin !== origin || !target.pathname.startsWith('/use/')) return answer(404, 'not_found', 'this listener forwards /use/… to coffre, and nothing else');
    // An app that goes away ends the request to coffre, and its answer's body.
    const gone = new AbortController();
    res.on('close', () => gone.abort());
    void (async () => {
      const headers = new Headers();
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        if (!DROPPED.has(req.rawHeaders[i]!.toLowerCase())) headers.append(req.rawHeaders[i]!, req.rawHeaders[i + 1]!);
      }
      const method = req.method ?? 'GET';
      // What the request carries, as a stream: the app's own, sent once, or the chunks read, as often as it is sent.
      let body: (() => ReadableStream<Uint8Array>) | undefined;
      let again = false;
      if (method !== 'GET' && method !== 'HEAD') {
        const length = req.headers['content-length'];
        if (headers.has('x-amz-content-sha256')) {
          // An upload to an AWS-signed credential is bound by the digest it declares: it streams, of any size, with the
          // length it says, which coffre streams it by.
          if (length !== undefined) headers.set('content-length', length);
          const stream = Readable.toWeb(req) as ReadableStream<Uint8Array>;
          body = () => stream;
        } else {
          // Any other body is signed whole, so it is read whole, hashed as it comes: the chunks as they came, one copy and in
          // memory, never on disk, then its digest and length declared, which coffre streams it on by, checking the bytes.
          const tooLarge = () => answer(413, 'too_large', `a request's body through coffre is at most ${MAX_DIGESTED_BODY / 1024 / 1024} MiB, under the 100 MB a Cloudflare zone takes`);
          // A length said past it is refused before a byte is read.
          if (Number(length ?? 0) > MAX_DIGESTED_BODY) return tooLarge();
          const own = headers.get('content-digest');
          let declared: string | null;
          try {
            declared = own === null ? null : declaredDigest(own);
          } catch (error) {
            return answer(400, 'bad_request', (error as Error).message);
          }
          const chunks: Buffer[] = [];
          const hash = createHash('sha256');
          let size = 0;
          for await (const chunk of req as AsyncIterable<Buffer>) {
            size += chunk.length;
            if (size > MAX_DIGESTED_BODY) return tooLarge();
            hash.update(chunk);
            chunks.push(chunk);
          }
          // Its own, beside an app's digest of another algorithm, which declares nothing to coffre: the body streams all the same.
          // The app's own SHA-256 is held to the bytes here, before any of them go.
          const sha256 = hash.digest('hex');
          if (declared !== null && declared !== sha256) return answer(400, 'bad_request', 'the body is not what its Content-Digest says');
          const ours = contentDigest(sha256);
          if (own === null) headers.set('content-digest', ours);
          else if (declared === null) headers.set('content-digest', `${own}, ${ours}`);
          headers.set('content-length', String(size));
          again = true;
          body = () => {
            let next = 0;
            return new ReadableStream<Uint8Array>({ pull: (out) => (next < chunks.length ? out.enqueue(chunks[next++]!) : out.close()) });
          };
        }
      }
      const send = () => coffre.fetch(target.href, { method, headers, body: body?.(), redirect: 'manual', signal: gone.signal, ...(body === undefined ? {} : { duplex: 'half' }) } as RequestInit);
      let response = await send();
      // A stream goes once, with a fresh nonce: one coffre would take only with its newest goes again, from the chunks.
      if (again && askedNonce(response)) {
        await response.body?.cancel();
        response = await send();
      }
      const back: [string, string][] = [...response.headers].filter(([name]) => !UNANSWERED.has(name) && name !== 'set-cookie');
      // A redirect to coffre's own /use/ comes back through this listener, which signs it: a path, which the app resolves against the listener.
      const location = back.find(([name]) => name === 'location');
      if (location !== undefined) {
        const to = URL.canParse(location[1], target.href) ? new URL(location[1], target.href) : null;
        if (to !== null && to.origin === origin && to.pathname.startsWith('/use/')) location[1] = `${to.pathname}${to.search}${to.hash}`;
      }
      for (const cookie of response.headers.getSetCookie()) back.push(['set-cookie', cookie]);
      res.writeHead(response.status, back);
      // Read only as fast as the app takes it.
      if (response.body === null) res.end();
      else await pipeline(Readable.fromWeb(response.body as import('node:stream/web').ReadableStream<Uint8Array>), res);
    })().catch((error: unknown) => {
      if (gone.signal.aborted) return;
      if (res.headersSent) return res.destroy();
      answer(502, 'bad_gateway', `coffre did not answer: ${error instanceof Error ? error.message : String(error)}`);
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    if ('path' in address) {
      // The socket is made its owner's alone from the start, never open to others before its chmod.
      const umask = process.umask(0o177);
      server.listen(address.path, () => resolve());
      process.umask(umask);
    }
    else server.listen(address.port, address.host, () => resolve());
  });
  if ('path' in address) chmodSync(address.path, 0o600);
  const bound = server.address();
  const url = 'path' in address ? `unix:${address.path}` : `http://${address.host.includes(':') ? `[${address.host}]` : address.host}:${(bound as { port: number }).port}`;
  return { url, close: () => (server.closeAllConnections(), server.close()) };
}

/** A tunnel as a workload's plan names it: the key the app reads its URL from, and coffre's end. */
type Planned = { values?: Record<string, unknown>; credentials?: unknown; tunnels?: Record<string, { key?: unknown; url?: unknown }>; left?: unknown; useOnly?: unknown };

/** What `coffre --service <name> run` gives its command, key-bound: the plan's values, the credentials' local URLs, and the tunnels'. */
export type KeyBound = { places: string[]; env: Record<string, string>; close: () => Promise<void> };

/**
 * Sign `service` in key-bound, and make what its command gets: each place's
 * plan, values the session may read (plain ones, and those its binding
 * lists in `reads`), `COFFRE_CREDENTIALS` naming each credential at a local
 * listener, and a tunnel listener for each database. Null where the
 * instance has no key-bound sessions yet, which the bearer exchange serves.
 */
export async function keyBound(origin: string, service: string, proof: Proof, positionals: readonly string[], log: (line: string) => void): Promise<KeyBound | null> {
  // The run ends its session when its command ends, a SIGTERM passed on to the command included.
  const coffre = await workload({ url: origin, service, proof, log, sigterm: false }).catch((error: unknown) => {
    if (error instanceof CoffreError && (error.status === 404 || error.status === 501)) return null;
    throw error;
  });
  if (coffre === null) return null;
  const opened: { close: () => void }[] = [];
  const close = async () => {
    for (const each of opened) each.close();
    await coffre.close();
  };
  // Stopped while the command is not yet started: the session ends first, then the run, by the same signal. The run's own
  // handlers, which pass a signal on to its command, take over once it starts.
  const signals = ['SIGTERM', 'SIGINT', 'SIGHUP'] as const;
  const stopped = (signal: NodeJS.Signals) => {
    for (const each of signals) process.off(each, stopped);
    void close()
      .catch(() => undefined)
      .finally(() => process.kill(process.pid, signal));
  };
  for (const each of signals) process.on(each, stopped);
  try {
    const places = positionals.length === 0 ? [...coffre.places] : environmentPaths(positionals);
    const outside = places.filter((place) => !coffre.places.includes(place));
    if (outside.length > 0) throw new Error(`${service}'s session reaches ${listOf(coffre.places)}, not ${listOf(outside)}`);
    const local = await forwarder(coffre, origin, { host: '127.0.0.1', port: 0 });
    opened.push(local);
    const plans: [string, Planned][] = [];
    for (const place of places) {
      const response = await coffre.fetch(`${origin}/use/${place.split('/').map(encodeURIComponent).join('/')}`, { headers: { accept: 'application/json' } });
      const plan = (await response.json().catch(() => null)) as (Planned & { message?: unknown }) | null;
      if (!response.ok || plan === null) throw new Error(`${origin} gave ${service} no plan for ${place} (${response.status})${typeof plan?.message === 'string' ? `: ${plan.message}` : ''}`);
      plans.push([place, plan]);
    }
    // A tunnel's URL goes into the key the plan names for it: a plan that names none (`tunnels: ["db"]`) gives `run` nowhere to put it.
    for (const [place, plan] of plans) {
      if (plan.tunnels !== undefined && (typeof plan.tunnels !== 'object' || Array.isArray(plan.tunnels))) {
        throw new Error(`${origin}'s plan for ${place} names its tunnels without the key each URL goes in: coffre run needs { <name>: { key, url } }; coffre serve --tunnel <name>=<address> needs none`);
      }
    }
    const values = (plan: Planned) => Object.entries(plan.values ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === 'string');
    const tunnels = (plan: Planned) => Object.entries(plan.tunnels ?? {}).filter((entry): entry is [string, Tunnel] => typeof entry[1].key === 'string' && typeof entry[1].url === 'string');
    const names = (list: unknown) => (Array.isArray(list) ? list.filter((name): name is string => typeof name === 'string') : []);
    const shared = clash(plans.map(([place, plan]) => [place, [...values(plan).map(([key]) => key), ...tunnels(plan).map(([, tunnel]) => tunnel.key)]]));
    if (shared !== null) throw new Error(`${shared}: a key comes from one environment only`);
    // A credential is named once in COFFRE_CREDENTIALS: one named in two environments would quietly be the last one's.
    const twice = clash(plans.map(([place, plan]) => [place, names(plan.credentials)]));
    if (twice !== null) throw new Error(`${twice}: a credential comes from one environment only; run with the one it should be`);
    const env: Record<string, string> = {};
    const credentials: Record<string, string> = {};
    for (const [place, plan] of plans) {
      for (const [key, value] of values(plan)) Object.defineProperty(env, key, { value, enumerable: true, writable: true, configurable: true });
      for (const name of names(plan.credentials)) credentials[name] = `${local.url}/use/${place}/${name}`;
      for (const [, tunnel] of tunnels(plan)) {
        const listener = await listen(tunnel, coffre);
        opened.push(listener);
        Object.defineProperty(env, tunnel.key, { value: listener.url, enumerable: true, writable: true, configurable: true });
      }
      // What the session uses and may not hold: the plan's `left`, or the reveal's `useOnly`, as the server names them.
      const left = [...new Set([...names(plan.left), ...names(plan.useOnly)])];
      if (left.length > 0) log(`coffre: ${place}: ${listOf(left)} ${left.length === 1 ? 'is' : 'are'} used through coffre now; list ${left.length === 1 ? 'it' : 'them'} in the binding's reads if this job must hold ${left.length === 1 ? 'it' : 'them'}`);
    }
    // What `credential(name)` (`@coffre/client/credential`) reads: each credential at the local listener, which signs, and no handle.
    env.COFFRE_CREDENTIALS = JSON.stringify(credentials);
    env.COFFRE_HANDLE = '';
    log(`coffre: ${service}, key-bound, in ${listOf(places)}: ${Object.keys(credentials).length === 0 ? 'no credential' : `${listOf(Object.keys(credentials).sort())} through ${local.url}/use`}`);
    return { places, env, close };
  } catch (error) {
    await close();
    throw error;
  } finally {
    for (const each of signals) process.off(each, stopped);
  }
}
