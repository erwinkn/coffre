/**
 * What went wrong with a sign-in, in words. The callback redirects with a
 * code rather than a sentence so the URL stays short and nothing the provider
 * said is reflected into the page.
 */
const MESSAGES: Record<string, string> = {
  provider_denied: 'The sign-in was cancelled, or the provider refused it.',
  state_mismatch:
    'This sign-in expired or was started in another tab. Start again from this page.',
  invalid_response:
    'The provider answered in a way coffre could not verify. Try again; if it keeps happening, tell whoever runs coffre.',
  provider_unavailable: 'The provider could not be reached. Try again in a moment.',
  no_verified_email:
    'That account has no verified email address, so coffre cannot match it to an invitation.',
  wrong_domain: 'That account is outside the organization this instance belongs to.',
  not_in_organization:
    'That GitHub account is not a member of the required organization. If it is, grant coffre access to the organization when GitHub asks.',
  not_registered:
    'Nobody has invited that account’s email address. Ask an owner to add you under Users, then sign in again.',
  deactivated: 'Your access to this coffre was removed. Ask an owner if that is a mistake.',
  account_mismatch:
    'Your email already signs in with a different account. Use that one, then link this account from your account page.',
  already_linked: 'That account is already linked to someone else.',
  tampered:
    'Your access record failed coffre’s integrity check: it was changed outside coffre. An owner must remove you and add you again.',
  unknown_provider: 'That sign-in option is not configured here.',
  link_session: 'Your session changed while linking. Sign in again, then retry.',
};

/**
 * Where an email already signs in, for `account_mismatch`: the providers by
 * the label the sign-in page shows them under, and the one just tried. What
 * the visitor may know: the provider has just verified the email is theirs.
 */
export type Already = { providers: readonly string[]; via?: string };

export function signinErrorMessage(code: string | undefined, already?: Already): string | null {
  if (code === undefined) return null;
  if (code === 'account_mismatch' && already !== undefined && already.providers.length > 0) return mismatch(already);
  return MESSAGES[code] ?? 'The sign-in did not complete. Try again.';
}

/** "Your email already signs in with GitHub. Sign in with GitHub, then link this account from your account page." */
function mismatch({ providers, via }: Already): string {
  const link = 'then link this account from your account page.';
  // The same provider, another account of it: a second GitHub account, say.
  if (providers.length === 1 && providers[0] === via) {
    return `Your email already signs in with another ${via} account. Sign in with that one, ${link}`;
  }
  const named = providers.map((provider) => (provider === via ? `another ${provider} account` : provider));
  const list = named.length < 3 ? named.join(' and ') : `${named.slice(0, -1).join(', ')} and ${named.at(-1)}`;
  return named.length === 1
    ? `Your email already signs in with ${list}. Sign in with ${list}, ${link}`
    : `Your email already signs in with ${list}. Sign in with one of them, ${link}`;
}

export type LoginSearch = { next?: string; error?: string; with?: string; via?: string };

/** A sign-in provider's id, as the instance configures it. */
const PROVIDER_ID = /^[a-z0-9_-]{1,40}$/;

/**
 * `/login`'s search: where to resume after signing in, same-origin paths
 * only, since an absolute URL accepted here would make the sign-in page an
 * open redirect; and the sign-in's `error`, with account_mismatch's `with`
 * and `via`, provider ids, shown once, then taken out of the URL.
 */
export function loginSearch(search: Record<string, unknown>): LoginSearch {
  const out: LoginSearch = {};
  const { next, error, via } = search;
  if (typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')) out.next = next;
  if (typeof error === 'string' && /^[a-z_]{1,40}$/.test(error)) out.error = error;
  const providers = typeof search.with === 'string' ? search.with.split(',').filter((id) => PROVIDER_ID.test(id)).slice(0, 8) : [];
  if (providers.length > 0) out.with = providers.join(',');
  if (typeof via === 'string' && PROVIDER_ID.test(via)) out.via = via;
  return out;
}
