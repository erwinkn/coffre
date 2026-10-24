import {
  BindingInvalid,
  claimAt,
  KEY_NAMING_PROFILES,
  type BindingClaims,
  type BindingPolicy,
  type CheckedBinding,
  type WorkloadProfile,
} from '@coffre/core/identity';

/**
 * What each platform's binding and tokens must say beyond the claims a
 * binding names (docs/design/workload-access.md, section 4.2). Core holds
 * the rules every profile shares: the required claims, the issuers that
 * force a profile, the policy's fields. These are each platform's own:
 * the shape of the IDs it issues, which issuer goes with which, and what a
 * token of it says that its binding cannot.
 *
 * A binding names IDs the platform never reuses, so each is checked for
 * the shape the platform gives it: a name in its place is refused, since a
 * name can be taken again after its owner is gone.
 */
export type ProfileRules = {
  /** At binding time, after `checkBinding` and `checkPolicy`. Throws `BindingInvalid`. */
  binding(binding: CheckedBinding, policy: BindingPolicy): void;
  /** At the exchange, once the token verified and matched its binding's claims: why it is still refused, or null. */
  token(claims: Record<string, unknown>, binding: { issuer: string; claims: BindingClaims; policy: BindingPolicy }): string | null;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** A Kubernetes namespace (a DNS label) and service account (a DNS subdomain), as its tokens' `sub` names them. */
const SERVICE_ACCOUNT_SUB = /^system:serviceaccount:([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?):([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?)$/;
/** A Google service account's unique ID: digits, 21 of them today. */
const GOOGLE_ID = /^[1-9]\d{0,31}$/;
const AZURE_V1 = /^https:\/\/sts\.windows\.net\/([0-9a-f-]{36})\/$/;
const AZURE_V2 = /^https:\/\/login\.microsoftonline\.com\/([0-9a-f-]{36})\/v2\.0$/;
const FLY_ISSUER = /^https:\/\/oidc\.fly\.io\/[a-z0-9][a-z0-9-]{0,62}$/;
/**
 * Fly's IDs are digits in its documentation's tokens, unchecked live: kept
 * loose, which fails closed, since a token's `org_id` and `app_id` are IDs
 * and a binding naming a name matches none.
 */
const FLY_ID = /^[A-Za-z0-9_-]{1,64}$/;
const VERCEL_ISSUER = /^https:\/\/oidc\.vercel\.com(\/[a-z0-9][a-z0-9-]{0,62})?$/;
const VERCEL_OWNER = /^(team_)?[A-Za-z0-9]{8,64}$/;
const VERCEL_PROJECT = /^prj_[A-Za-z0-9]{8,64}$/;
/** `production`, `preview`, `development`, or a custom environment's slug. */
const VERCEL_ENVIRONMENT = /^[a-z0-9][a-z0-9-]{0,63}$/;
const AWS_ACCOUNT = /^\d{12}$/;
/** A role's unique ID: `AROA`, then its own characters. */
const AWS_ROLE_ID = /^AROA[A-Z0-9]{8,124}$/;

function shaped(claims: BindingClaims, name: string, pattern: RegExp, what: string): void {
  if (!pattern.test(claims[name] as string)) throw new BindingInvalid(`${name} is ${what}`);
}

const none = () => null;

export const PROFILE_RULES: { readonly [P in WorkloadProfile]?: ProfileRules } = {
  kubernetes: {
    binding({ claims }) {
      const sub = SERVICE_ACCOUNT_SUB.exec(claims.sub as string);
      if (sub === null) throw new BindingInvalid('sub is the service account\'s, system:serviceaccount:<namespace>:<name>');
      shaped(claims, 'kubernetes.io.serviceaccount.uid', UUID, "the service account's UID, which a service account made again under the same name does not keep: kubectl get serviceaccount <name> -o jsonpath='{.metadata.uid}'");
      // Narrowing claims that name the same account again must agree with sub, or the binding would match nothing.
      for (const [name, value] of [['kubernetes.io.namespace', sub[1]], ['kubernetes.io.serviceaccount.name', sub[3]]] as const) {
        if (claims[name] !== undefined && claims[name] !== value) throw new BindingInvalid(`${name} is ${value}, as its sub says`);
      }
    },
    // The cluster says the same account twice, in sub and under kubernetes.io; a token where they differ is no cluster's.
    token(claims) {
      const sub = SERVICE_ACCOUNT_SUB.exec(String(claims.sub));
      if (sub === null) return 'the token\'s sub is no service account\'s';
      const namespace = claimAt(claims, 'kubernetes.io.namespace');
      const name = claimAt(claims, 'kubernetes.io.serviceaccount.name');
      return namespace === sub[1] && name === sub[3] ? null : 'the token names another service account under kubernetes.io than its sub';
    },
  },
  gcp: {
    binding({ claims }) {
      shaped(claims, 'sub', GOOGLE_ID, "the service account's unique ID, its digits, which a service account made again under the same email does not keep: gcloud iam service-accounts describe <email> --format='value(uniqueId)'");
    },
    token: none,
  },
  azure: {
    binding({ issuer, claims }, policy) {
      const tenant = AZURE_V1.exec(issuer)?.[1] ?? AZURE_V2.exec(issuer)?.[1];
      if (tenant === undefined || !UUID.test(tenant)) {
        throw new BindingInvalid('an azure binding\'s issuer is https://sts.windows.net/<tenant>/ (v1 tokens) or https://login.microsoftonline.com/<tenant>/v2.0 (v2), by the tenant\'s ID');
      }
      shaped(claims, 'tid', UUID, "the tenant's ID");
      if (claims.tid !== tenant) throw new BindingInvalid('tid is the tenant its issuer names');
      shaped(claims, 'oid', UUID, "the managed identity's object ID (its principal ID): az identity show --query principalId");
      // A v1 token's aud is the resource as asked for, its App ID URI or client ID; a v2 token's is always the API's client ID.
      if (AZURE_V2.test(issuer) && !UUID.test(policy.audience ?? '')) {
        throw new BindingInvalid("a v2 token's audience is the API's application (client) ID, a GUID, never its App ID URI: Entra puts no other in a v2 token");
      }
    },
    // The issuer says which token version Entra issues, and each version names its own issuer: a token that disagrees is not what was bound.
    token(claims, binding) {
      const version = AZURE_V1.test(binding.issuer) ? '1.0' : '2.0';
      return claims.ver === version ? null : `the token is of version ${JSON.stringify(claims.ver ?? null)}, and its binding's issuer issues ${version}`;
    },
  },
  fly: {
    binding({ issuer, claims }) {
      if (!FLY_ISSUER.test(issuer)) throw new BindingInvalid('a fly binding\'s issuer is https://oidc.fly.io/<organization>, by its slug');
      shaped(claims, 'org_id', FLY_ID, "the organization's ID, as its tokens' org_id says it");
      shaped(claims, 'app_id', FLY_ID, "the app's ID, as its tokens' app_id says it");
    },
    token: none,
  },
  vercel: {
    binding({ issuer, claims }) {
      if (!VERCEL_ISSUER.test(issuer)) throw new BindingInvalid('a vercel binding\'s issuer is https://oidc.vercel.com/<team> (team mode) or https://oidc.vercel.com (global mode)');
      shaped(claims, 'owner_id', VERCEL_OWNER, "the team's ID, team_…, as .vercel/project.json's orgId says it");
      shaped(claims, 'project_id', VERCEL_PROJECT, "the project's ID, prj_…, as .vercel/project.json's projectId says it");
      shaped(claims, 'environment', VERCEL_ENVIRONMENT, 'production, preview, development or a custom environment\'s slug');
    },
    token: none,
  },
  aws: {
    binding({ claims }) {
      // Its proof says the account and the role, and nothing else a binding could narrow by.
      const extra = Object.keys(claims).filter((name) => name !== 'account' && name !== 'role_id');
      if (extra.length > 0) throw new BindingInvalid(`an aws binding names its role's account and role_id alone, not ${extra.join(', ')}`);
      shaped(claims, 'account', AWS_ACCOUNT, 'the account\'s 12 digits');
      shaped(claims, 'role_id', AWS_ROLE_ID, "the role's unique ID, AROA…, which a role made again under the same name does not keep: aws iam get-role --role-name <name> --query Role.RoleId");
    },
    // Its proof is no token: workloads/aws.ts checks it.
    token: none,
  },
};

/**
 * The audiences a token of a binding may name, the first the one its SDK
 * asks for: the session's key, `<publicUrl>#jkt=<thumbprint>`, for the
 * platforms whose caller picks the audience, and `?jkt=` for one that
 * refuses a `#` in it (section 4.2); the exact audience of a platform that
 * fixes it; this instance's URL for every other.
 */
export function expectedAudiences(profile: WorkloadProfile, policy: BindingPolicy, expected: { publicUrl: string; jkt: string }): string[] {
  if (KEY_NAMING_PROFILES.includes(profile) || policy.keyAudience === true) {
    return [`${expected.publicUrl}#jkt=${expected.jkt}`, `${expected.publicUrl}?jkt=${expected.jkt}`];
  }
  return [policy.audience ?? expected.publicUrl];
}
