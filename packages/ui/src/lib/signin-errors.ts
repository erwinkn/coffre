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

export function signinErrorMessage(code: string | undefined): string | null {
  if (code === undefined) return null;
  return MESSAGES[code] ?? 'The sign-in did not complete. Try again.';
}
