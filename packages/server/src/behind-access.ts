import { ACCESS_JWT_HEADER, AccessKeysUnavailable, generateToken, hashToken, seal, unseal, type Principal } from '@coffre/core/identity';
import type { Me } from '@coffre/client';
import { emailAddress } from '@coffre/core/schemas';

import { ApiError, noteTampered, refusal } from './api/errors.ts';
import { bearerToken, readCookie } from './auth.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';
import { dpopToken } from './sessions.ts';
import { describeUserAgent } from './signin.ts';

/**
 * Signing in behind Cloudflare Access (docs/design/0.16.md, "Behind
 * Cloudflare Access"). Access authenticates a person before any request
 * reaches coffre, and sends its signed assertion with each one. The vault
 * finds a caller only by a credential's hash, so a browser holds a session
 * of coffre's as with any provider: Access is the provider, and the first
 * request signs in.
 *
 * Every request but health's and `GET /api/auth` comes here first, and
 * leaves with the session it may use, or none:
 *
 * 1. Its assertion is verified: the team's keys, RS256 or ES256, issuer,
 *    audience, expiry. None, or one that fails, is no session: whatever
 *    cookie came with it counts for nothing, so Access's own revocation
 *    shuts the door on the next request.
 * 2. Its session cookie counts when the companion cookie, sealed under the
 *    app's key, says it was signed in for this assertion's subject and this
 *    token. Nothing is asked of anyone.
 * 3. Otherwise (no session, someone else's assertion on a shared browser,
 *    a companion that does not open) the person signs in: one `signin`
 *    change, the account being Access's subject, which ends the session the
 *    browser showed. Both cookies are set on the response.
 *
 * Only a browser signs in: a request that carries Access's own cookie,
 * `CF_Authorization`, as a browser's does, and no bearer token. The CLI
 * through cloudflared and an Access service token carry none, and get no
 * session: signing them in would make a session row a command. They are served once they show a
 * credential of coffre's beside the assertion.
 */

/** Access's own cookie, which a browser it signed in carries and nothing else does. */
const ACCESS_COOKIE = 'CF_Authorization';
/** Behind Access every request is HTTPS, so both cookies carry the `__Host-` prefix: Secure, host-only, path-wide. */
export const ACCESS_SESSION_COOKIE = '__Host-coffre_session';
export const ACCESS_SUBJECT_COOKIE = '__Host-coffre_access';
/** How sign-ins through Access are known to the vault: one provider among the others (`identities_provider_check`). */
export const ACCESS_PROVIDER = 'cloudflare-access';
/** What a caller with no session behind Access is told. */
export const BROWSERS_ONLY = "behind Cloudflare Access coffre signs in browsers only: open it in a browser through Access; the CLI and service tokens are not served behind Access yet";

/**
 * What the check made of a request. `session`: the token it may use, or
 * null. `cookies`: what to set on the response. `unregistered`: the email
 * of someone Access vouches for and coffre has no member for, whom `GET /me`
 * tells so. `why`: what a request with no session is told.
 */
export type Admission = {
  session: string | null;
  cookies: string[];
  unregistered: string | null;
  why: string;
  /**
   * The session is gone in the vault (ended, expired, its member removed,
   * signed out): the response clears both cookies, in place of any the
   * check set, and the next request signs in again.
   */
  ended(): void;
};

/** What the companion cookie holds, sealed: whose sign-in the session is, and which session, by its token's SHA-256. */
type Companion = { subject: string; session: string };

const hashed = (token: string) => hashToken(token).toString('hex');

function cookie(name: string, value: string, maxAgeSeconds: number): string {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}; Secure`;
}

const CLEARED = [cookie(ACCESS_SESSION_COOKIE, '', 0), cookie(ACCESS_SUBJECT_COOKIE, '', 0)];

function admission(session: string | null, why: string, cookies: string[] = [], unregistered: string | null = null): Admission {
  const result: Admission = {
    session,
    cookies,
    unregistered,
    why,
    ended() {
      // A session this request signed in for and its own end revoked would otherwise be set after its clearing.
      result.cookies = [...CLEARED];
    },
  };
  return result;
}

/** What a request behind Access with no session it may use is told: `browsers_only`, which the CLI reads, when it came as a machine. */
export const unadmitted = (access: Admission | undefined): ApiError =>
  new ApiError('unauthenticated', access?.why ?? 'sign in first', access?.why === BROWSERS_ONLY ? 'browsers_only' : undefined);

/** A machine's credential, in `Authorization`: a bearer token, or a workload's session with its proof (DPoP). A browser sends neither. */
export const machineCredential = (request: Request): string | null => bearerToken(request) ?? dpopToken(request);

/** A request whose session counts for nothing: health's, and before the check runs. */
export const NO_SESSION = (): Admission => admission(null, BROWSERS_ONLY);

/** The session a request may use behind Access, and the cookies its response sets (above). */
export async function admit(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Admission> {
  const { auth, access } = runtime;
  if (auth.mode !== 'cloudflare' || access === null) throw new Error('only a deployment behind Cloudflare Access admits requests through it');
  const assertion = (request.headers.get(ACCESS_JWT_HEADER) ?? '').trim();
  if (assertion === '') return admission(null, 'open coffre through Cloudflare Access: this request carries no Access assertion');
  let principal: Principal;
  try {
    principal = await access.verifier.verify(assertion);
  } catch (error) {
    if (error instanceof AccessKeysUnavailable) {
      console.error('Cloudflare Access keys could not be fetched', logged(error));
      throw new ApiError('unavailable', "coffre could not fetch Cloudflare Access's keys to check this request; try again");
    }
    return admission(null, "Cloudflare Access's assertion did not verify: your Access session may have expired, open coffre through Access again");
  }
  // A browser carries Access's cookie, and sends no token of its own.
  if (principal.type !== 'user' || readCookie(request, ACCESS_COOKIE) === null || machineCredential(request) !== null) return admission(null, BROWSERS_ONLY);

  const session = readCookie(request, ACCESS_SESSION_COOKIE);
  const companion = unseal<Companion>(access.key, readCookie(request, ACCESS_SUBJECT_COOKIE));
  if (session !== null && companion !== null && companion.subject === principal.subject && companion.session === hashed(session)) {
    return admission(session, BROWSERS_ONLY);
  }

  // Signing in. The account is Access's subject, under the team's issuer; its email, as Access verified it.
  const token = generateToken('browser');
  const trace = { request: crypto.randomUUID(), ip: sourceIp };
  const email = emailAddress.safeParse(principal.email).success ? [principal.email] : [];
  const signedIn = await runtime.vault.change<'signin'>({
    ...trace,
    op: 'signin',
    account: { provider: ACCESS_PROVIDER, issuer: hashed(auth.access.issuer), subject: principal.subject, emails: email },
    session: { token: hashed(token), minutes: Math.max(1, Math.round(auth.browserSessionHours * 60)), label: describeUserAgent(request.headers.get('user-agent')) },
    // The session this browser had, its person's or someone else's before them: it ends with this one's start.
    replaces: session === null ? null : hashed(session),
  });
  if ('refused' in signedIn) {
    const code = signedIn.refused;
    // Removed, or never added: either way not a member, which their pages say.
    if (code === 'not_registered' || code === 'deactivated') return admission(null, 'you are signed in to Cloudflare Access, but not a member of this coffre', session === null ? [] : [...CLEARED], principal.email);
    if (code === 'account_mismatch') {
      return admission(null, 'your Cloudflare Access account is not the one your membership is bound to: ask an admin to remove you and add you again', session === null ? [] : [...CLEARED]);
    }
    const error = refusal(code);
    noteTampered(error, 'signing in through Cloudflare Access', trace.request);
    throw error;
  }
  const seconds = (Date.parse(signedIn.answer.expiresAt) - Date.now()) / 1000;
  const sealed = seal(access.key, { subject: principal.subject, session: hashed(token) } satisfies Companion, seconds);
  return admission(token, BROWSERS_ONLY, [cookie(ACCESS_SESSION_COOKIE, token, seconds), cookie(ACCESS_SUBJECT_COOKIE, sealed, seconds)]);
}

/**
 * `GET /me` for someone Access vouches for whom coffre has no member for:
 * who they are, and that they are not registered, which their pages say
 * (0.14.7's answer). Every other route refuses them `registration_required`.
 */
export function unregisteredMe(email: string): Me {
  const none = { only: [] };
  return {
    principal: { type: 'user', id: email },
    registered: false,
    tampered: false,
    instanceRole: 'member',
    scope: { projects: none, environments: none },
    runsInstance: false,
    canReadAudit: false,
    setsUpServices: false,
    serviceSetup: null,
    features: { mcp: null, workloads: false },
    personalToken: null,
    credentialExpiresAt: null,
    environments: [],
  };
}
