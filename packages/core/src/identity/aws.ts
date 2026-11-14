import { oldestMatching, policyOf, type ExchangeRefused, type ProofBinding } from './proofs.ts';
import { PROFILE_URNS } from './workloads.ts';

/**
 * The `aws` proof's answer, held to a service's bindings
 * (docs/design/workload-access.md, section 4.3; docs/design/0.16.md, "A
 * workload signing in"). The app checks the request the workload signed,
 * a `GetCallerIdentity` naming this instance and the session's key, sends
 * it to STS, and hands the vault STS's answer, on its word: which account,
 * and whose credentials. The vault says which binding that is.
 */

/** What STS says signed the request: `GetCallerIdentityResult`'s three fields. */
export type CallerIdentity = { account: string; arn: string; userId: string };

/** An assumed role's session, as a binding names its role: by account and the role's unique ID, which a role made again under the same name does not keep. */
export type AwsIdentity = { account: string; roleId: string; arn: string; role: string; session: string };

const ACCOUNT = /^\d{12}$/;
const ASSUMED_ROLE = /^arn:aws:sts::(\d{12}):assumed-role\/([\w+=,.@-]{1,64})\/([\w+=,.@-]{2,64})$/;
const ROLE_SESSION = /^(AROA[A-Z0-9]{8,124}):([\w+=,.@-]{2,64})$/;

/**
 * The role a caller's identity is a session of, or why none: an account's
 * root, a federated user and an IAM user are `no_match`, since each means a
 * long-lived key on disk, which a workload does not hold, and so is any
 * other partition than `aws`. An answer whose account, ARN and user ID
 * disagree is no answer STS gives: `malformed` (0.14's server took it as
 * STS unavailable).
 */
export function assumedRole(identity: CallerIdentity): AwsIdentity | ExchangeRefused {
  if (!ACCOUNT.test(identity.account)) return { refused: 'malformed' };
  // Only an assumed role's session is one: a root's `arn:aws:iam::<account>:root`, a federated user's, an IAM user's (`AIDA…`) are not.
  const role = ASSUMED_ROLE.exec(identity.arn);
  const session = ROLE_SESSION.exec(identity.userId);
  if (role === null || session === null) return { refused: 'no_match' };
  if (role[1] !== identity.account || session[2] !== role[3]) return { refused: 'malformed' };
  return { account: identity.account, roleId: session[1]!, arn: identity.arn, role: role[2]!, session: role[3]! };
}

/** The claims an `aws` binding matches, as the proof makes them. */
export function awsClaims(identity: AwsIdentity): { account: string; role_id: string } {
  return { account: identity.account, role_id: identity.roleId };
}

/**
 * STS's answer held to a service's bindings: the oldest `aws` binding with
 * a policy that names its role's account and unique ID, and the claims the
 * session's entry gives, the role's ARN and session name with them. The
 * request named the session's key and this instance under its signature,
 * so nothing is spent, and nothing but its binding's hours ends the
 * session early.
 */
export function matchAwsAnswer<B extends ProofBinding>(answer: CallerIdentity, bindings: readonly B[]): { binding: B; claims: Record<string, string> } | ExchangeRefused {
  const candidates = bindings.filter((binding) => binding.profile === 'aws' && binding.issuer === PROFILE_URNS.aws && policyOf(binding) != null);
  if (candidates.length === 0) return { refused: 'no_match' };
  const identity = assumedRole(answer);
  if ('refused' in identity) return identity;
  const binding = oldestMatching(candidates, awsClaims(identity));
  if (binding === null) return { refused: 'no_match' };
  return { binding, claims: { ...awsClaims(identity), arn: identity.arn, session: identity.session } };
}
