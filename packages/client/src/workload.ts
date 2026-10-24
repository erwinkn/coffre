/**
 * A workload's session with coffre (docs/design/workload-access.md, section
 * 9.1): it proves who it is once, gets a session bound to a key that never
 * leaves this process, and from then on uses its credentials through coffre,
 * every request signed. The app holds no secret that works anywhere else.
 *
 *   import { workload, enrollment } from '@coffre/client/workload';
 *
 *   const coffre = await workload({ url: 'https://secrets.acme.example', service: 'api-prod', proof: enrollment(process.env.COFFRE_ENROLL) });
 *   const openai = new OpenAI({ apiKey: 'coffre', baseURL: coffre.url('openai'), fetch: coffre.fetch });
 *   const charge = await coffre.credential('stripe').fetch('/v1/charges', { method: 'POST', body: new URLSearchParams({ amount: '2000' }) });
 *
 * What it does for the app, so the app does nothing:
 *
 *   - a P-256 key made here, non-extractable; the key, the session's token
 *     and the gate's nonce live in this closure only, never on disk or in
 *     the environment;
 *   - the exchange, retried while an enrollment code is `full` (5 minutes)
 *     or its session awaits approval (10), and after a spent projected token,
 *     once the kubelet writes the next;
 *   - renewal at half-life, every 30 seconds for an enrollment session, whose
 *     expiry is its liveness; a fresh proof, with the same key, before the
 *     session's hard end, `notAfter`; and a new session whenever the old one
 *     is lost (revoked, frozen, expired while the process slept);
 *   - each request under `<url>/use/` signed whole (method, URL, query, the
 *     headers it was given, the body), with the newest nonce, and sent again
 *     once if the gate asks for a fresh one;
 *   - logout on `close()`, and on SIGTERM.
 */
import { base64url, bodyDigest, createProof, generateProofKey, thumbprint, UNSIGNED_BODY, type ProofKey, type PublicJwk } from './dpop.ts';
import { CoffreError } from './index.ts';
import type { Proof, ProofContext } from './workload-proofs.ts';

export { aws, azure, enrollment, fly, gcp, github, keyAudience, kubernetes, KUBERNETES_TOKEN, oidc, vercel } from './workload-proofs.ts';
export type { AwsCredentials, PlatformProof, Proof, ProofContext } from './workload-proofs.ts';
export { CoffreError } from './index.ts';

type Fetch = typeof fetch;

export type WorkloadOptions = {
  /** The instance: `https://secrets.acme.example`. */
  url: string;
  /** The service account the workload signs in as: `api-prod`, or `token:api-prod`. */
  service: string;
  /** How it proves who it is: `kubernetes()`, `aws()`, `gcp()`, `enrollment(code)`… (`./workload-proofs.ts`). */
  proof: Proof;
  /** Which of the binding's environments `url`, `credential` and `read` mean, when it has several: `market/prod`. */
  place?: string;
  fetch?: Fetch;
  /** Where it says what it waits for (a full code, an approval, a spent token): stderr unless set. */
  log?: (line: string) => void;
  /** `false` for a process that ends its own way, and calls `close()` itself: no logout on SIGTERM. */
  sigterm?: boolean;
};

export type NarrowOptions = {
  places?: string[];
  credentials?: string[];
  methods?: string[];
  /** Path prefixes of the upstream, matched by whole segments: `/v1/refunds`. */
  paths?: string[];
  /** Seconds; never past the parent's end. */
  expiresIn?: number;
  /** What the service's page calls it: `refund-agent`. */
  label?: string;
};

export interface Workload {
  readonly service: string;
  /** The environments the session reaches. */
  readonly places: readonly string[];
  /**
   * A `fetch` that signs every request under `<url>/use/` and passes anything
   * else through untouched: give it to any SDK that takes one.
   */
  readonly fetch: Fetch;
  /** A credential's URL on coffre's proxy, an SDK's base URL: `<url>/use/<name>`, or `<url>/use/<project>/<env>/<name>` with several places. */
  url(name: string): string;
  credential(name: string): UsedCredential;
  /** The escape hatch: a plain value, or one the binding lists in `reads`. Anything else rejects with `use_only`. */
  read(key: string): Promise<string>;
  /**
   * A session with less authority (section 8.4), for a part of the app that
   * needs less: in this process, a `Workload` of its own key; for another
   * process, which made the key and sends only its public half, the child's
   * token, which that process uses with its own key.
   */
  narrow(options: NarrowOptions & { key: PublicJwk }): Promise<{ token: string; expiresAt: string }>;
  narrow(options: NarrowOptions): Promise<Workload>;
  /** Logs out: the session ends now, and its children with it. */
  close(): Promise<void>;
}

export interface UsedCredential {
  /** `<credential's URL>/<path>`, signed: the proxy forwards it to the upstream with the real key. */
  fetch(path: string, init?: RequestInit): Promise<Response>;
  /** A signature by a signer's private key, which stays in coffre: base64url, as `credential.sign` gives. */
  sign(message: string | Uint8Array): Promise<string>;
  /** Whether `signature` is a verifier's over `message`: an inbound webhook's, checked without reading its secret. */
  verify(message: string | Uint8Array, signature: string): Promise<boolean>;
  /** A presigned GET or HEAD of `path` under an AWS-signed credential's upstream: the upstream's own URL, for anyone until `expiresAt`. */
  presign(path: string, options?: { expiresIn?: number; method?: 'GET' | 'HEAD'; query?: Record<string, string> }): Promise<{ url: string; expiresAt: string }>;
  /** A short-lived child of a minter (an AWS session, a GitHub installation token), where the binding lists it. */
  mint<T = Record<string, string>>(): Promise<T & { expiresAt: string }>;
}

/** A session as the exchange answers it. */
type Session = { token: string; expiresAt: number; notAfter: number; places: string[]; issuedAt: number };

/**
 * The gate's newest nonce, and when the request that brought it went out: a
 * nonce is good for at least the 2 minutes from then until the gate's next
 * rotation. Each request is numbered as it goes out, and an answer to an
 * earlier one than the request that set the nonce never replaces it, so a
 * late answer cannot bring an old nonce back, nor make it look new.
 */
type Nonces = { value: string | undefined; at: number; seq: number; sent: number };
/** A request's place in that order, and its time, taken as it goes out. */
type Sent = { seq: number; at: number };
const dispatch = (nonces: Nonces): Sent => ({ seq: ++nonces.sent, at: Date.now() });

/** How long a nonce is taken as fresh, for a request that cannot be sent again (a stream, a WebSocket's upgrade): under the 2 minutes it lasts. */
const FRESH_NONCE_MS = 100_000;
/** How long the exchange waits out a full enrollment code, and a session awaiting approval. */
const FULL_MS = 5 * 60_000;
const PENDING_MS = 10 * 60_000;
/** An enrollment session renews every 30 seconds: its expiry, 90 seconds past its last renewal, is its liveness. */
const ENROLLMENT_RENEW_MS = 30_000;
/** Refusals no new proof can change: the code was superseded by a newer deploy's. */
const FINAL = new Set(['superseded']);

const SHA256_HEX = /^[0-9a-f]{64}$/;
/** How long a logout may take: a process stopping waits no longer for it. */
const LOGOUT_MS = 3000;
/** The redirects fetch follows, and how many it follows at most. */
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MOST_REDIRECTS = 20;

/** Each session's SIGTERM handler: a process whose every handler is one of these ends on SIGTERM once they have logged out. */
const TERMINATING = new WeakSet<object>();

/** What `upgradeHeaders` and `upgradeRefused` reach, for each workload: its own, never on the object. */
const UPGRADES = new WeakMap<Workload, { sign: (url: string) => Promise<Record<string, string>>; refused: () => void }>();

/**
 * Sign in as `service`, with `proof`, and hold the session for as long as
 * the process runs. Rejects if the first exchange is refused.
 */
export async function workload(options: WorkloadOptions): Promise<Workload> {
  const url = new URL(options.url);
  // A proof, a code above all, crosses only TLS, or stays on this machine.
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && /^(localhost|127(\.\d{1,3}){3}|\[::1\])$/.test(url.hostname))) {
    throw new TypeError(`workload() talks to coffre over https, or http on this machine: not ${url.origin}`);
  }
  const origin = url.origin;
  const base: Fetch = options.fetch ?? ((input, init) => fetch(input, init));
  const log = options.log ?? ((line: string) => console.error(line));
  const key = await generateProofKey();
  /** Aborted by `close()`: an exchange, its waits and its proof's stop with it. */
  const lifetime = new AbortController();
  // A proof's own requests (a metadata server's) end with the session too.
  const proofFetch: ProofContext['fetch'] = (input, init = {}) => base(input, { ...init, signal: init.signal ? anySignal([init.signal, lifetime.signal]) : lifetime.signal });
  const context: ProofContext = { audience: origin, jkt: await thumbprint(key.jwk), fetch: proofFetch, log, signal: lifetime.signal };
  const nonces: Nonces = { value: undefined, at: 0, seq: 0, sent: 0 };
  const enrolled = options.proof.kind === 'enrollment';
  const api = apiOf({ origin, base, key, nonces });

  /** Trade a fresh proof for a session, waiting out what the design says to wait out; throws a refusal, with the server's words. */
  const exchange = async (): Promise<Session> => {
    const start = Date.now();
    const said = new Set<string>();
    const say = (line: string) => void (said.has(line) || (said.add(line), log(line)));
    for (;;) {
      lifetime.signal.throwIfAborted();
      const proof = await options.proof.prove(context);
      const url = `${origin}/api/auth/workload`;
      const sent = dispatch(nonces);
      const response = await base(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json', dpop: await createProof(key, { method: 'POST', url }) },
        body: JSON.stringify({ service: options.service, proof }),
        signal: lifetime.signal,
        // A proof, a code above all, goes to this URL alone: never where a redirect points.
        redirect: 'error',
      });
      note(nonces, response, sent);
      const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
      const [expiresAt, notAfter] = [Date.parse(String(body?.expiresAt)), Date.parse(String(body?.notAfter))];
      if (response.status === 200 && typeof body?.token === 'string' && Number.isFinite(expiresAt) && Number.isFinite(notAfter)) {
        const places = Array.isArray(body.places) ? body.places.filter((place): place is string => typeof place === 'string') : [];
        return { token: body.token, expiresAt, notAfter, places, issuedAt: Date.now() };
      }
      const reason = typeof body?.reason === 'string' ? body.reason : undefined;
      if (response.status === 202 && Date.now() - start < PENDING_MS) {
        say(`coffre: ${options.service}'s session waits for a person to approve it${typeof body?.approve === 'string' ? `, at ${body.approve}` : ''}`);
        await sleep(5000, lifetime.signal);
        continue;
      }
      if (response.status === 429 && reason === 'full' && Date.now() - start < FULL_MS) {
        say(`coffre: ${options.service}'s enrollment code holds all the sessions it admits; waiting for one to end, up to 5 minutes`);
        await sleep(retryAfter(response, 30_000), lifetime.signal);
        continue;
      }
      if (reason === 'replayed' && options.proof.spent !== undefined && (await options.proof.spent(context))) continue;
      throw refusal(response.status, body, `${origin} would not sign ${options.service} in with its ${options.proof.name} proof`);
    }
  };

  let session: Session | null = await exchange();
  if (options.place !== undefined && !session.places.includes(options.place)) {
    throw new Error(`${options.service} reaches ${session.places.join(', ') || 'no environment'}, not ${options.place}`);
  }
  /** The environments of the newest session, kept while a lost one is proved again. */
  let places = session.places;
  /**
   * Every session proved and not past its hard end: a new proof leaves the
   * old one to finish its requests, and close() ends them all, their
   * children with them. Not pruned by their expiry, which a renewal answered
   * late may have pushed on: a session already ended answers 401, which is
   * an end too.
   */
  let roots: Session[] = [session];
  let closed = false;
  /** The exchange in flight, which requests without a session wait for; and why the last one failed, while none holds. */
  let attempt: Promise<Session> | null = null;
  let failure: unknown = null;
  /** A refusal no new proof can change (a superseded code, a proof given once and spent), once seen. */
  let final: unknown = null;
  let tries = 0;
  /** The renewal in flight for each session: one each, so that an old session's renewal answered late takes no new session's turn. */
  const renewals = new WeakMap<Session, Promise<void>>();
  const timers = { renew: undefined as Timer | undefined, prove: undefined as Timer | undefined, retry: undefined as Timer | undefined };
  const at = (which: keyof typeof timers, when: number, run: () => unknown) => {
    clearTimeout(timers[which]);
    if (closed) return;
    timers[which] = setTimeout(() => void run(), Math.max(0, when - Date.now()));
    (timers[which] as { unref?: () => void }).unref?.();
  };

  /** Renew at half-life, or every 30 seconds for an enrollment; prove again at 90% of the way to `notAfter`. */
  const plan = (held: Session) => {
    const now = Date.now();
    at('renew', enrolled ? now + ENROLLMENT_RENEW_MS : now + Math.max(1000, (held.expiresAt - now) / 2), renew);
    // An enrollment's `notAfter` is its code's end, which no new proof passes. A projected token's next is written at 80% of its life.
    if (!enrolled) at('prove', held.notAfter - (held.notAfter - held.issuedAt) / 10, () => prove().catch(() => undefined));
  };

  /** A new session, with a fresh proof and the same key: requests in flight finish on the old one. Retried with backoff while it fails, unless it cannot change. */
  const prove = (): Promise<Session> => {
    // A refusal no new proof changes stands: no later renewal or request asks again.
    if (final !== null) return Promise.reject(final);
    attempt ??= exchange()
      .then((next) => {
        // Closed while it was asked for: it ends now, as the one it replaced did.
        if (closed) {
          void logout(api, next.token).catch(() => undefined);
          throw new Error(`${options.service}'s session with coffre is closed`);
        }
        session = next;
        places = next.places;
        roots = [...roots.filter((root) => root.notAfter > Date.now()), next];
        failure = null;
        tries = 0;
        plan(next);
        return next;
      })
      .catch((error: unknown) => {
        failure = error;
        // A proof spent, from a platform that gives no fresh one (a token given once), is as final as a superseded code.
        const spent = error instanceof CoffreError && error.reason === 'replayed' && options.proof.spent === undefined;
        if (spent) log(`coffre: ${options.service}'s ${options.proof.name} proof was spent, and it gives no fresh one: the session ends at its expiry`);
        if (spent || (error instanceof CoffreError && FINAL.has(error.reason ?? ''))) final = error;
        else if (!closed) at('retry', Date.now() + backoff(tries++), () => prove().catch(() => undefined));
        throw error;
      })
      .finally(() => (attempt = null));
    return attempt;
  };

  /** Push the session's expiry on; a session coffre no longer renews is lost, and proved again. */
  const renew = (): Promise<void> => {
    const held = session;
    if (held === null || closed) return Promise.resolve();
    const running = renewals.get(held);
    if (running !== undefined) return running;
    const renewal = (async () => {
      try {
        const { response, body } = await api('/api/auth/workload/renew', held.token);
        if (response.ok && typeof body?.expiresAt === 'string') {
          held.expiresAt = Date.parse(body.expiresAt);
          if (session === held) at('renew', enrolled ? Date.now() + ENROLLMENT_RENEW_MS : Date.now() + Math.max(1000, (held.expiresAt - Date.now()) / 2), renew);
          return;
        }
        // Asked for a nonce once more, it says nothing of the session: tried again soon, as when coffre is out of reach.
        if ((response.status !== 401 && response.status !== 403) || askedNonce(response)) throw new Error(`renewal answered ${response.status}`);
        if (session === held) lose();
      } catch {
        // coffre unreachable for now: try again soon, and once the session is gone, prove again.
        if (session !== held) return;
        if (Date.now() >= held.expiresAt) return lose();
        at('renew', Math.min(Date.now() + (enrolled ? 5000 : 30_000), held.expiresAt), renew);
      }
    })().finally(() => renewals.delete(held));
    renewals.set(held, renewal);
    return renewal;
  };

  const lose = () => {
    if (closed) return;
    session = null;
    clearTimeout(timers.renew);
    clearTimeout(timers.prove);
    prove().catch(() => undefined);
  };

  /** The session to sign with: the one held, the exchange in flight, or, while exchanges fail, why. */
  const current = async (): Promise<Session> => {
    if (closed) throw new Error(`${options.service}'s session with coffre is closed`);
    // A process frozen past its session's expiry (Lambda between invocations) proves again before its request.
    if (session !== null && Date.now() < session.expiresAt - 5000) return session;
    if (attempt !== null) return attempt;
    if (failure !== null) throw failure;
    return prove();
  };

  plan(session);

  const signals = (globalThis as { process?: NodeJS.Process }).process;
  let closing: Promise<void> | null = null;
  // One logout, however many ask for it (the app, and SIGTERM): each waits for it.
  // Rejects if coffre did not confirm every session's end, each asked for at most 3 seconds.
  const close = () =>
    (closing ??= (async () => {
      closed = true;
      lifetime.abort();
      for (const timer of Object.values(timers)) clearTimeout(timer);
      session = null;
      try {
        const ended = await Promise.allSettled(roots.filter((root) => root.notAfter > Date.now()).map((root) => logout(api, root.token)));
        const failed = ended.find((each): each is PromiseRejectedResult => each.status === 'rejected');
        if (failed !== undefined) throw failed.reason;
      } finally {
        // Its handler goes once it has logged out: until then, SIGTERM waits for it.
        signals?.off?.('SIGTERM', onTerm);
        TERMINATING.delete(onTerm);
      }
    })());
  // A graceful stop logs out at once. Where every handler is a session's, the last to log out ends the process with SIGTERM, as it would have ended without them.
  const onTerm = () => {
    const alone = signals!.listeners('SIGTERM').every((listener) => TERMINATING.has(listener));
    void close()
      .catch(() => undefined)
      .finally(() => alone && signals!.listenerCount('SIGTERM') === 0 && signals!.kill(signals!.pid, 'SIGTERM'));
  };
  if (options.sigterm !== false) {
    TERMINATING.add(onTerm);
    signals?.on?.('SIGTERM', onTerm);
  }

  return surface({
    origin,
    base,
    key,
    nonces,
    api,
    service: options.service,
    place: options.place,
    current,
    places: () => places,
    // A renewal answers the gate's newest nonce, and keeps the session besides.
    refresh: renew,
    close,
  });
}

type Timer = ReturnType<typeof setTimeout>;

/** What a session's requests need, a root's or a child's. */
type Core = {
  origin: string;
  base: Fetch;
  key: ProofKey;
  nonces: Nonces;
  api: Api;
  service: string;
  place: string | undefined;
  current: () => Promise<Session>;
  places: () => string[];
  /** Fetch the gate's newest nonce, for a request that cannot be sent again. */
  refresh: () => Promise<void>;
  close: () => Promise<void>;
};

function surface(core: Core): Workload {
  const { origin, key, nonces } = core;
  const under = (url: string) => {
    try {
      const parsed = new URL(url);
      return parsed.origin === origin && parsed.pathname.startsWith('/use/');
    } catch {
      return false;
    }
  };
  const fresh = async () => {
    if (Date.now() - nonces.at > FRESH_NONCE_MS) await core.refresh().catch(() => undefined);
  };

  /** A request under `/use/`, signed; or any other, as given. Redirects come back through here, so each hop is signed for itself. */
  const go = async (input: RequestInfo | URL, init: RequestInit | undefined, hops: number): Promise<Response> => {
    const url = input instanceof Request ? input.url : input instanceof URL ? input.href : String(input);
    if (!under(url)) return core.base(input, init);
    // As fetch would send it: the headers fetch adds for its body (a form's content-type) are the app's, and signed.
    const request = new Request(input, init);
    // A request to an AWS-signed credential declares its body's digest, which coffre takes as the body's line, and which S3 checks
    // against the bytes; any other declared value leaves the body unsigned. Only such a request streams; any other body is read whole.
    const declared = request.headers.get('x-amz-content-sha256');
    const streamed = init?.body instanceof ReadableStream || (input instanceof Request && init?.body === undefined);
    const stream = declared !== null && request.body !== null && streamed ? request.body : null;
    const bytes = stream === null && request.body !== null ? new Uint8Array(await request.arrayBuffer()) : null;
    // A request with no body signs the empty body's digest, whatever it declares, as coffre recomputes it.
    const line = declared === null || (stream === null && (bytes === null || bytes.length === 0)) ? await bodyDigest(bytes ?? new Uint8Array()) : SHA256_HEX.test(declared) ? declared : UNSIGNED_BODY;
    const send = async () => {
      const { token } = await core.current();
      const headers = new Headers(request.headers);
      headers.set('authorization', `DPoP ${token}`);
      headers.set('dpop', await createProof(key, { method: request.method, url: request.url, token, nonce: nonces.value, content: { headers: request.headers, body: line } }));
      const sent = dispatch(nonces);
      const response = await core.base(request.url, {
        method: request.method,
        headers,
        body: stream ?? (bytes as Uint8Array<ArrayBuffer> | null),
        signal: request.signal,
        // A proof signs one URL: fetch following a redirect itself would send it to another.
        redirect: 'manual',
        ...(stream === null ? {} : { duplex: 'half' }),
      } as RequestInit);
      note(nonces, response, sent);
      return response;
    };
    let response: Response;
    if (stream !== null) {
      // A stream is sent once: it goes with a nonce fresh enough that the gate takes it.
      await fresh();
      response = await send();
    } else {
      response = await send();
      if (askedNonce(response)) {
        await response.body?.cancel();
        response = await send();
      }
    }
    const location = response.headers.get('location');
    if (request.redirect === 'manual' || !REDIRECTS.has(response.status) || location === null) return response;
    await response.body?.cancel();
    if (request.redirect === 'error') throw new TypeError(`fetch failed: ${request.url} redirects, and redirect is "error"`);
    if (hops >= MOST_REDIRECTS) throw new TypeError(`fetch failed: more than ${MOST_REDIRECTS} redirects`);
    // As fetch follows one: a 303, or a POST's 301 or 302, becomes a GET without its body; a stream cannot be sent again.
    const asGet = (response.status === 303 && request.method !== 'HEAD') || ((response.status === 301 || response.status === 302) && request.method === 'POST');
    if (!asGet && stream !== null) throw new TypeError(`fetch failed: ${request.url} redirects a streamed body, which cannot be sent again`);
    const next = new URL(location, request.url);
    const headers = new Headers(request.headers);
    if (asGet) for (const name of ['content-type', 'content-length', 'content-encoding', 'content-language', 'content-location']) headers.delete(name);
    // As fetch does: credentials the app set go to no other origin.
    if (next.origin !== new URL(request.url).origin) for (const name of ['authorization', 'cookie', 'proxy-authorization']) headers.delete(name);
    // The next hop, signed afresh if it is coffre's, and sent with the app's own headers alone if it is not.
    return go(next, { method: asGet ? 'GET' : request.method, headers, body: asGet ? null : (bytes as Uint8Array<ArrayBuffer> | null), signal: request.signal, redirect: 'follow' }, hops + 1);
  };
  const signed: Fetch = (input, init) => go(input, init, 0);

  const placeOf = (): string => {
    const places = core.places();
    const place = core.place ?? (places.length === 1 ? places[0] : undefined);
    if (place === undefined) throw new Error(`${core.service} reaches ${places.join(', ') || 'no environment'}: name the one to use, workload({ place })`);
    return place;
  };
  const placeUrl = () => `${origin}/use/${placeOf().split('/').map(encodeURIComponent).join('/')}`;
  const url = (name: string) => (core.places().length === 1 ? `${origin}/use/${encodeURIComponent(name)}` : `${placeUrl()}/${encodeURIComponent(name)}`);

  /** What coffre makes with the environment's values, at the environment's URL: a signature, a verdict, a presigned URL, a minted child. */
  const compute = async (asked: Record<string, unknown>, what: string): Promise<Record<string, unknown>> => {
    const response = await signed(placeUrl(), { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(asked) });
    const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    if (!response.ok || body === null) throw refusal(response.status, body, `coffre ${what} nothing`);
    return body;
  };

  const workload: Workload = {
    service: core.service,
    get places() {
      return core.places();
    },
    fetch: signed,
    url,
    credential: (name) => ({
      fetch: (path, init) => {
        // A path stays under its credential: `/../stripe/…`, from an object key or a file name, would otherwise spend another.
        const base = url(name);
        const target = new URL(`${base}${path.startsWith('/') ? '' : '/'}${path}`);
        const under = new URL(base).pathname;
        if (target.pathname !== under && !target.pathname.startsWith(`${under}/`)) throw new TypeError(`${JSON.stringify(path)} leaves ${name}'s URL: a credential's fetch reaches its own upstream only`);
        return signed(target.href, init);
      },
      sign: async (message) => {
        const body = await compute({ sign: { credential: name, message: bytesOf(message) } }, 'signed');
        if (typeof body.signature !== 'string') throw new Error('coffre signed nothing');
        return body.signature;
      },
      verify: async (message, signature) => (await compute({ verify: { credential: name, message: bytesOf(message), signature } }, 'verified')).valid === true,
      presign: async (path, options = {}) => {
        const body = await compute({ presign: { credential: name, path, ...options } }, 'presigned');
        if (typeof body.url !== 'string' || typeof body.expiresAt !== 'string') throw new Error('coffre presigned nothing');
        return { url: body.url, expiresAt: body.expiresAt };
      },
      mint: async <T>() => (await compute({ mint: { credential: name } }, 'minted')) as T & { expiresAt: string },
    }),
    read: async (name) => {
      const response = await signed(placeUrl(), { headers: { accept: 'application/json' } });
      const body = (await response.json().catch(() => null)) as { values?: Record<string, unknown> } | null;
      if (!response.ok) throw refusal(response.status, body as Record<string, unknown> | null, `coffre answered no plan for ${placeOf()}`);
      const value = body?.values?.[name];
      if (typeof value === 'string') return value;
      throw new CoffreError(403, 'forbidden', `${core.service} reads no ${name} in ${placeOf()}: it reads plain values and those its binding lists in reads, and uses every other through coffre`, 'use_only');
    },
    narrow: (async (options: NarrowOptions & { key?: PublicJwk }) => {
      const own = options.key === undefined ? await generateProofKey() : null;
      const { token } = await core.current();
      const { key: given, expiresIn, label, ...constraints } = options;
      const { response, body } = await core.api('/api/auth/workload/narrow', token, { key: given ?? own!.jwk, label, constraints, expiresIn });
      if (!response.ok || typeof body?.token !== 'string' || typeof body.expiresAt !== 'string') throw refusal(response.status, body, `coffre narrowed ${core.service} to nothing`);
      if (own === null) return { token: body.token, expiresAt: body.expiresAt };
      return child(core, own, body.token, Date.parse(body.expiresAt), options.places ?? core.places());
    }) as Workload['narrow'],
    close: core.close,
  };
  UPGRADES.set(workload, {
    sign: async (target) => {
      await fresh();
      const { token } = await core.current();
      const url = target.replace(/^ws/, 'http');
      return { authorization: `DPoP ${token}`, dpop: await createProof(key, { method: 'GET', url, token, nonce: nonces.value }) };
    },
    // When a refusal's nonce came cannot be told against the answers since: the next upgrade asks the gate's newest first.
    refused: () => (nonces.at = 0),
  });
  return workload;
}

/** A narrowed session in this process: its own key, no renewal, and its end its parent's or its own. */
function child(parent: Core, key: ProofKey, token: string, expiresAt: number, places: string[]): Workload {
  let closed = false;
  let closing: Promise<void> | null = null;
  const held: Session = { token, expiresAt, notAfter: expiresAt, places, issuedAt: Date.now() };
  // Its own proofs, with its own key, at the gate it shares with its parent.
  const api = apiOf({ origin: parent.origin, base: parent.base, key, nonces: parent.nonces });
  return surface({
    ...parent,
    key,
    api,
    places: () => places,
    place: parent.place !== undefined && places.includes(parent.place) ? parent.place : undefined,
    current: async () => {
      if (closed || Date.now() >= held.expiresAt) throw new Error(`this narrowed session of ${parent.service} has ended`);
      return held;
    },
    // A child renews nothing: its parent's renewal brings the gate's newest nonce, which they share. A parent that ended ended it too.
    refresh: parent.refresh,
    close: () =>
      (closing ??= (async () => {
        closed = true;
        await logout(api, token);
      })()),
  });
}

/**
 * The headers that sign a WebSocket's upgrade to `url` (a tunnel's), made
 * outside `coffre.fetch`: the session, and a proof of a GET at its `https`
 * form with a nonce fresh enough that the gate takes it, since an upgrade
 * refused cannot be told why and sent again.
 */
export function upgradeHeaders(coffre: Workload, url: string): Promise<Record<string, string>> {
  const upgrade = UPGRADES.get(coffre);
  if (upgrade === undefined) throw new TypeError('upgradeHeaders takes a workload() session');
  return upgrade.sign(url);
}

/**
 * Say that coffre refused an upgrade, or that it never opened: its nonce may
 * be the gate's no longer, so the next upgrade, which cannot be sent again
 * either, first asks for the newest.
 */
export function upgradeRefused(coffre: Workload): void {
  UPGRADES.get(coffre)?.refused();
}

/**
 * An AWS SDK credential provider over delivered minting (section 7.2): a
 * minter's short-lived children, where the binding lists it, each kept
 * until a minute before it expires.
 *
 *   const s3 = new S3Client({ region: 'eu-west-3', credentials: fromCoffre(coffre, 'aws') });
 */
export function fromCoffre(coffre: Workload, minter: string): () => Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken?: string; expiration: Date }> {
  let held: { value: { accessKeyId: string; secretAccessKey: string; sessionToken?: string; expiration: Date }; until: number } | null = null;
  return async () => {
    if (held !== null && Date.now() < held.until) return held.value;
    const minted = await coffre.credential(minter).mint<{ accessKeyId: string; secretAccessKey: string; sessionToken?: string }>();
    if (typeof minted.accessKeyId !== 'string' || typeof minted.secretAccessKey !== 'string') throw new Error(`${minter} minted no AWS credentials`);
    const expiration = new Date(minted.expiresAt);
    held = { value: { accessKeyId: minted.accessKeyId, secretAccessKey: minted.secretAccessKey, sessionToken: minted.sessionToken, expiration }, until: expiration.getTime() - 60_000 };
    return held.value;
  };
}

/** Keep the gate's newest nonce: every answer from coffre carries it, and the newest is the one to a request sent last. */
function note(nonces: Nonces, response: { headers: { get(name: string): string | null } }, sent: Sent): void {
  const nonce = response.headers.get('dpop-nonce');
  if (nonce !== null && nonce !== '' && sent.seq > nonces.seq) {
    nonces.value = nonce;
    nonces.at = sent.at;
    nonces.seq = sent.seq;
  }
}

/** A POST to coffre's own API with a session (renew, narrow, logout), signed by its key. */
type Api = (path: string, token: string, body?: unknown, signal?: AbortSignal) => Promise<{ response: Response; body: Record<string, unknown> | null }>;

/**
 * Its proof signs the token and the newest nonce, and a body where there is
 * one (`hdr` and `req`: narrow's, the key and the limits it gives a child),
 * so no one who sees the request can make it say anything else; sent again
 * once if the gate asks for a fresh nonce.
 */
function apiOf({ origin, base, key, nonces }: { origin: string; base: Fetch; key: ProofKey; nonces: Nonces }): Api {
  return async (path, token, body, signal) => {
    const url = `${origin}${path}`;
    const json = body === undefined ? undefined : JSON.stringify(body);
    const headers = { accept: 'application/json', ...(json === undefined ? {} : { 'content-type': 'application/json' }) };
    const content = json === undefined ? undefined : { headers, body: await bodyDigest(json) };
    const send = async () => {
      const sent = dispatch(nonces);
      const response = await base(url, {
        method: 'POST',
        headers: { ...headers, authorization: `DPoP ${token}`, dpop: await createProof(key, { method: 'POST', url, token, nonce: nonces.value, content }) },
        body: json,
        signal,
        redirect: 'error',
      });
      note(nonces, response, sent);
      return response;
    };
    let response = await send();
    if (askedNonce(response)) {
      await response.body?.cancel();
      response = await send();
    }
    return { response, body: (await response.json().catch(() => null)) as Record<string, unknown> | null };
  };
}

/** End a session, waiting 3 seconds at most; rejects unless coffre says it ended, or had already (401). */
async function logout(api: Api, token: string): Promise<void> {
  const { response, body } = await api('/api/auth/logout', token, undefined, AbortSignal.timeout(LOGOUT_MS));
  // A 401 says the session is over, unless it asks for a nonce yet again: then nothing ended.
  if (!response.ok && (response.status !== 401 || askedNonce(response))) throw refusal(response.status, body, 'coffre did not end the session');
}

/** Whether coffre refused a proof for its nonce alone (RFC 9449, section 8): sent again once, with the nonce it gave. */
function askedNonce(response: Response): boolean {
  return response.status === 401 && /error="?use_dpop_nonce/.test(response.headers.get('www-authenticate') ?? '') && response.headers.has('dpop-nonce');
}

function refusal(status: number, body: Record<string, unknown> | null, what: string): CoffreError {
  const reason = typeof body?.reason === 'string' ? body.reason : undefined;
  const message = typeof body?.message === 'string' ? body.message : `status ${status}`;
  return new CoffreError(status, typeof body?.error === 'string' ? body.error : 'refused', `${what}${reason === undefined ? '' : ` (${reason})`}: ${message}`, reason);
}

/** `Retry-After`, in milliseconds, or `fallback`. */
function retryAfter(response: Response, fallback: number): number {
  const seconds = Number(response.headers.get('retry-after'));
  return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 300) * 1000 : fallback;
}

/** 1, 2, 4… seconds, at most a minute, a little jittered so that a fleet's replicas spread out. */
function backoff(tries: number): number {
  return Math.min(60_000, 1000 * 2 ** tries) * (0.75 + Math.random() / 2);
}

/** A message as coffre's `sign` and `verify` take it: a string's UTF-8, base64url. */
const bytesOf = (message: string | Uint8Array) => base64url(typeof message === 'string' ? new TextEncoder().encode(message) : message);

/** A signal that aborts with the first of `signals`: `AbortSignal.any`, where the runtime has it (Node 20.3 and later). */
function anySignal(signals: AbortSignal[]): AbortSignal {
  if (typeof AbortSignal.any === 'function') return AbortSignal.any(signals);
  const controller = new AbortController();
  for (const signal of signals) {
    if (signal.aborted) controller.abort(signal.reason);
    else signal.addEventListener('abort', () => controller.abort(signal.reason), { once: true });
  }
  return controller.signal;
}

/** A wait that `signal` ends early, rejecting. */
const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => (signal.removeEventListener('abort', stop), resolve()), ms);
    const stop = () => (clearTimeout(timer), reject(signal.reason as Error));
    signal.addEventListener('abort', stop, { once: true });
  });
