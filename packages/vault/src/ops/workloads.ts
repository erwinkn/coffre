import { randomUUID } from 'node:crypto';

import { isCredentialScope, type CredentialScope } from '@coffre/core/access';
import {
  CARRIED, hardEnd, matchAwsAnswer, matchIdToken, MAX_BINDINGS, OIDC_PROFILES, PROFILE_URNS, readIdToken, runClaims, sessionRefusal, signatureRefusal,
  type BindingPolicy, type CallerIdentity, type DecodedToken, type ExchangeRefused,
} from '@coffre/core/identity';
import type { Answers, Asked, Presented, WorkloadChanges, WorkloadRenew } from '@coffre/core/vault';
import { bindings, credentials, environments, policy, principals, projects } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { callerFrom, callerParts, ID, live as standing, refusedTo } from '../caller.ts';
import { amended, part, put, WRITE_MS, type Operation, type Parts, type Seen, type Unsealed } from '../change.ts';
import type { Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { HASH, presented, text, traced } from './input.ts';

/** How long a CI run's token lasts: 0.14's `EXCHANGED_CREDENTIAL_MS`. */
const RUN_MS = 5 * 60_000;
/** How long a workload's session lives past its sign-in and each renewal, unless its hard end is sooner: 0.14's `SESSION_MS`. */
const SESSION_MS = 60 * 60_000;
/**
 * How close to its expiry a session may still be renewed, 0.14's `RENEW_MARGIN_MS` (5 s): a session is renewed only while
 * it has longer left than a write's statement may run, so a renewal lands before the session ends and revives nothing.
 */
const RENEW_MARGIN_MS = WRITE_MS;
/** A key's thumbprint (RFC 7638): the SHA-256 of its JWK, in base64url. */
const THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;
/** No project: a change about none, where only the caller's own rows weigh. */
const NO_PROJECT = sql`(SELECT NULL::uuid WHERE false)`;
/** The longest issuer, keys' address or public URL the contract carries. */
const MOST_URL = 2048;

/** Text as `text` takes it, of `most` characters at most: what a URL may be. */
const long = (value: unknown, most: number): value is string => typeof value === 'string' && value.length <= most && !value.includes('\0') && Buffer.from(value).toString() === value;

/** A binding's scope, as the credentials it issues carry it on their row: always one, and one that does not read as a scope reaches nothing. */
function scopeOf(stored: string | null): string {
  if (stored === null) return '[]';
  try {
    return isCredentialScope(JSON.parse(stored)) ? stored : '[]';
  } catch {
    return '[]';
  }
}

/**
 * A CI run trades its platform's ID token for a service token of five
 * minutes (docs/design/0.16.md, "A workload signing in"): nobody asks it,
 * and the vault takes the token's signature on the app's word, under the
 * keys the app names, but for keys a binding carries, which it verifies
 * itself (`check`). Everything else is held to its own rows: the service,
 * its live bindings on the token's issuer and the policy row, one read.
 *
 * One statement spends the proof and writes the credential, issued by the
 * oldest binding with no policy whose claims match (`created_by:
 * binding:<id>`, its scope the binding's), with an entry that ages out. A
 * refusal writes nothing and is not logged: nobody who stands asked it.
 *
 * Rows hidden from the read. A binding or the service's row written
 * behind the vault refuses the exchange (`tampered`): the oldest match
 * wins, and one passed over would let a later one answer. A binding taken
 * out of the read altogether (deleted, or marked revoked, for the one
 * exchange) is the gap the design accepts for a row taken away for one
 * decision: the binding that answers in its place is one the service's
 * manager made, with the scope they gave it.
 */
function tokenExchange(input: Asked<'token.exchange'>, vault: Deciding): Operation<Parts, Answers['token.exchange'], Map<string, 'unknown_signer' | 'malformed' | null>> {
  const from = traced(input);
  const { service, token, under, publicUrl, credential } = input;
  if (!text(service) || typeof token !== 'string' || typeof under !== 'object' || under === null || !long(under.issuer, MOST_URL) || !long(under.jwksUri, MOST_URL) || !long(publicUrl, MOST_URL) || !text(credential) || !HASH.test(credential)) {
    throw new TypeError("an exchange names the service, the ID token, the issuer and keys' address it was verified under, the app's public URL, and the new token by its SHA-256");
  }
  const issuer = under.issuer;
  const jwksUri = under.jwksUri;
  const decoded = readIdToken(token);
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  const read = {
    service: part(principals, sql`${principals.id} = ${service}`),
    // Its live bindings on the issuer, in its generation, oldest first, one more than a service may hold: each in `bindings_live_idx`'s order.
    // Those with a policy too, which the decision leaves out: one written behind the vault to say it has one is still read.
    bindings: part(bindings, sql`${bindings.id} IN (SELECT b.id FROM bindings b WHERE b.principal = ${service} AND b.issuer = ${issuer} AND b.revoked_at IS NULL
      AND b.generation = (SELECT p.generation FROM principals p WHERE p.id = ${service}) ORDER BY b.created_at, b.id LIMIT ${MAX_BINDINGS + 1})`),
    // The instance's one row, which the vault's adoption writes: nothing is made of a database it has not adopted.
    instance: part(policy, sql`${policy.onlyRow}`),
  };
  type Read = typeof read;
  /** The keys a binding carries that the token is held to: those of the bindings the app's word names. */
  const carried = (seen: Seen<Read>) => (jwksUri.startsWith(CARRIED) ? seen.bindings.filter((row) => row.jwksUri === jwksUri) : []);
  return {
    read,
    // Under the keys on the sealed rows, each set once: the app has not verified a token whose keys a binding carries.
    async check(seen: Seen<Read>) {
      const sets = new Set(carried(seen).flatMap((row) => (row.jwks === null ? [] : [row.jwks])));
      return new Map(await Promise.all([...sets].map(async (jwks) => [jwks, await signatureRefusal(token, jwks)] as const)));
    },
    decide(seen: Seen<Read>, at: number, unsealed: Unsealed<Read>, signed: Map<string, 'unknown_signer' | 'malformed' | null>) {
      if (seen.instance.length === 0) return { refused: unsealed.instance > 0 ? 'tampered' : 'adopting' };
      // A row written behind the vault is not a row that is absent: a service whose row is not the vault's is not one with none, nor a binding passed over one that does not match.
      if (unsealed.service + unsealed.bindings > 0) return { refused: 'tampered' };
      if ('refused' in decoded) return decoded;
      const [account] = seen.service;
      // A deployment that takes no workloads, or makes a service a key-bound session or nothing (`useOnly`), issues no CI run a token: the app answers 404 and 410 first, as 0.14's route did.
      if (vault.workloads === null || vault.workloads.useOnly || account === undefined || account.status !== 'active') return { refused: 'no_match' };
      const live = seen.bindings.filter((row) => row.principal === account.id && row.generation === account.generation && row.revokedAt === null);
      // More than a service may hold: none of them answers, as in 0.14.
      if (live.length > MAX_BINDINGS) return { refused: 'no_match' };
      // Keys a binding carries: the token is verified under them before any claim is, as 0.14 verified it first. Every binding
      // the app's word names carries the same keys, those its address is the hash of: a row that carries others refuses it.
      if (jwksUri.startsWith(CARRIED)) {
        for (const row of carried({ ...seen, bindings: live })) {
          const refused = row.jwks === null ? 'malformed' : signed.get(row.jwks);
          if (refused !== null) return { refused: refused ?? 'malformed' };
        }
      }
      const found = matchIdToken(decoded, live, { under: { issuer, jwksUri }, publicUrl, wanted: { kind: 'run' }, now: at });
      if ('refused' in found) return found;
      const { binding } = found;
      const now = new Date(at);
      const expiresAt = new Date(at + RUN_MS);
      const run = runClaims(found.claims);
      const spent = found.spends!;
      return {
        writes: [put(credentials, {
          id, kind: 'service', tokenHash: Buffer.from(credential, 'hex'), tokenHint: null, previousTokenHash: null, generation: binding.generation, principal: account.id, identityId: null,
          // Its binding's, on its own row: what it reaches is the binding's as it is now, and never more than that row says.
          scope: scopeOf(binding.scope), places: null, label: binding.label, createdAt: now, createdBy: `binding:${binding.id}`, expiresAt, lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null,
          jkt: null, notAfter: null, ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: JSON.stringify(run), client: null, challenge: null,
        })],
        once: spent,
        // Its last use, moved on to the entry's date with the rest, or not at all.
        used: binding,
        entry: {
          // A run's coming ages out with the uses, as a session's does.
          kept: false,
          action: 'token.exchange', actor: account.id, credential: id, request: from.request, ip: from.ip,
          objects: [`principal:${account.id}`, `credential:${id}`, `binding:${binding.id}`],
          detail: { kind: 'service', credential: id, binding: binding.id, generation: binding.generation, issuer: binding.issuer, expiresAt: expiresAt.toISOString(), run, proof: spent.toString('hex') },
        },
        answer: { principal: account.id, credential: id, expiresAt: expiresAt.toISOString(), binding: binding.id },
      };
    },
  };
}

/** A proof as the contract carries it, checked: an ID token and the keys it was verified under, or STS's answer. */
type Proof = { kind: 'oidc'; token: string; under: { issuer: string; jwksUri: string }; decoded: DecodedToken | ExchangeRefused } | { kind: 'aws'; answer: CallerIdentity };

function proofOf(input: unknown): Proof | null {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return null;
  const kinds = Object.keys(input);
  if (kinds.length !== 1) return null;
  if (kinds[0] === 'oidc') {
    const { token, under } = (input as { oidc: { token: unknown; under: { issuer: unknown; jwksUri: unknown } | null } }).oidc ?? {};
    if (typeof token !== 'string' || typeof under !== 'object' || under === null || !long(under.issuer, MOST_URL) || !long(under.jwksUri, MOST_URL)) return null;
    return { kind: 'oidc', token, under: { issuer: under.issuer, jwksUri: under.jwksUri }, decoded: readIdToken(token) };
  }
  if (kinds[0] === 'aws') {
    const answer = (input as { aws: Partial<CallerIdentity> | null }).aws;
    if (typeof answer !== 'object' || answer === null || !text(answer.account) || !long(answer.arn, MOST_URL) || !long(answer.userId, MOST_URL)) return null;
    return { kind: 'aws', answer: { account: answer.account, arn: answer.arn, userId: answer.userId } };
  }
  return null;
}

/**
 * The ids of the projects these bindings' scopes name, as SQL for an array:
 * read as text, so that a row not the vault's casts nothing it does not
 * hold. An array, so that each is found by its index, one by one.
 */
const projectsNamed = (ids: SQL) => sql`ARRAY(SELECT m.found[1]::uuid FROM bindings b, regexp_matches(b.scope, '"projectId":"(${ID})"', 'g') AS m(found) WHERE b.id IN ${ids})`;

/**
 * The environments a scope reaches, as a session's row lists them: each it
 * names, and each of a project it names but personal configs, which no
 * service reads; each live, in a live project, once, by path. 0.14's
 * `environmentsOf`.
 */
function reachedBy(scope: CredentialScope, found: { places: readonly Row<typeof environments>[]; projects: readonly Row<typeof projects>[] }): string[] {
  const reached = new Map<string, string>();
  for (const grant of scope) {
    const project = found.projects.find((row) => row.id === grant.projectId);
    if (project === undefined || !standing(project)) continue;
    for (const environment of found.places) {
      if (environment.projectId !== project.id || environment.owner !== null || !standing(environment) || (grant.environmentId != null && environment.id !== grant.environmentId)) continue;
      reached.set(environment.id, `${project.slug}/${environment.slug}`);
    }
  }
  return [...reached].sort(([, a], [, b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([id]) => id);
}

/**
 * A workload trades a proof for a session bound to a key it holds
 * (docs/design/0.16.md, "A workload signing in"): nobody asks it. The proof
 * is a platform's ID token, whose signature the vault takes on the app's
 * word but where a binding carries its keys, or STS's answer to the request
 * the workload signed, on the app's word too. One read: the service, its
 * live bindings of that proof's profiles with a policy, on the proof's
 * issuer, the instance's row, and the places those bindings' scopes name.
 *
 * Held to the oldest binding that takes it as `token.exchange` is, then to
 * that binding's policy: its sources against the request's address, and
 * reads it lists where the deployment lets none, both `no_match`; then a
 * freeze of the instance's workloads, the service or the binding, `frozen`,
 * as 0.14 refused it. The session ends at its hard end (`hardEnd`), and
 * expires an hour on or then. One statement spends the proof where its
 * kind is spent, writes the session, bound to the key, with the binding's
 * scope and the places it reaches as of now on its own row, and moves the
 * binding's last use on, with an entry that ages out.
 *
 * A place row not the vault's refuses (`tampered`): the places a session
 * lists choose where `/use/<credential>` goes when it names none.
 */
function workloadSignin(input: Asked<'workload.signin'>, vault: Deciding): Operation<Parts, Answers['workload.signin'], Map<string, 'unknown_signer' | 'malformed' | null>> {
  const from = traced(input);
  const { service, key, publicUrl, credential } = input;
  const proof = proofOf(input.proof);
  if (!text(service) || proof === null || !text(key) || !THUMBPRINT.test(key) || !long(publicUrl, MOST_URL) || !text(credential) || !HASH.test(credential)) {
    throw new TypeError("a workload signs in with the service, one proof by its kind (an ID token with the issuer and keys' address it was verified under, or STS's answer), the thumbprint of its key, the app's public URL, and the session's token by its SHA-256");
  }
  const issuer = proof.kind === 'oidc' ? proof.under.issuer : PROFILE_URNS.aws;
  const profiles: readonly string[] = proof.kind === 'oidc' ? OIDC_PROFILES : ['aws'];
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  // Its live bindings of the proof's profiles with a policy, on the issuer, in its generation, oldest first, one more than a service may hold.
  const candidates = sql`(SELECT b.id FROM bindings b WHERE b.principal = ${service} AND b.issuer = ${issuer} AND b.revoked_at IS NULL AND b.policy IS NOT NULL
    AND b.profile = ANY(${sql.param(profiles)}::text[]) AND b.generation = (SELECT p.generation FROM principals p WHERE p.id = ${service}) ORDER BY b.created_at, b.id LIMIT ${MAX_BINDINGS + 1})`;
  const read = {
    service: part(principals, sql`${principals.id} = ${service}`),
    bindings: part(bindings, sql`${bindings.id} IN ${candidates}`),
    // The instance's one row: nothing is made of a database the vault has not adopted, and it says whether every workload is frozen.
    instance: part(policy, sql`${policy.onlyRow}`),
    // What those bindings' scopes name, for the places a session lists.
    projects: part(projects, sql`${projects.id} = ANY(${projectsNamed(candidates)})`),
    places: part(environments, sql`${environments.projectId} = ANY(${projectsNamed(candidates)})`),
  };
  type Read = typeof read;
  const carried = (seen: Seen<Read>) => (proof.kind === 'oidc' && proof.under.jwksUri.startsWith(CARRIED) ? seen.bindings.filter((row) => row.jwksUri === proof.under.jwksUri) : []);
  return {
    read,
    async check(seen: Seen<Read>) {
      if (proof.kind !== 'oidc') return new Map();
      const sets = new Set(carried(seen).flatMap((row) => (row.jwks === null ? [] : [row.jwks])));
      return new Map(await Promise.all([...sets].map(async (jwks) => [jwks, await signatureRefusal(proof.token, jwks)] as const)));
    },
    decide(seen: Seen<Read>, at: number, unsealed: Unsealed<Read>, signed: Map<string, 'unknown_signer' | 'malformed' | null>) {
      if (seen.instance.length === 0) return { refused: unsealed.instance > 0 ? 'tampered' : 'adopting' };
      if (unsealed.service + unsealed.bindings + unsealed.projects + unsealed.places > 0) return { refused: 'tampered' };
      if (proof.kind === 'oidc' && 'refused' in proof.decoded) return proof.decoded;
      const [account] = seen.service;
      // A deployment that takes no workloads makes no session; `useOnly` makes them, and only them.
      if (vault.workloads === null || account === undefined || account.status !== 'active') return { refused: 'no_match' };
      const live = seen.bindings.filter((row) => row.principal === account.id && row.generation === account.generation && row.revokedAt === null && row.policy !== null && profiles.includes(row.profile));
      if (live.length > MAX_BINDINGS) return { refused: 'no_match' };
      let found: { binding: Row<typeof bindings>; claims: Record<string, unknown>; spends: Buffer | null; exp: number | null };
      if (proof.kind === 'oidc') {
        if (proof.under.jwksUri.startsWith(CARRIED)) {
          for (const row of carried({ ...seen, bindings: live })) {
            const refused = row.jwks === null ? 'malformed' : signed.get(row.jwks);
            if (refused !== null) return { refused: refused ?? 'malformed' };
          }
        }
        const decoded = proof.decoded as DecodedToken;
        const matched = matchIdToken(decoded, live, { under: proof.under, publicUrl, wanted: { kind: 'session', jkt: key }, now: at });
        if ('refused' in matched) return matched;
        found = { binding: matched.binding, claims: matched.claims, spends: matched.spends, exp: decoded.claims.exp };
      } else {
        const matched = matchAwsAnswer(proof.answer, live);
        if ('refused' in matched) return matched;
        // The request named the session's key and this instance under its signature: nothing is spent, and nothing but the binding's hours ends it.
        found = { binding: matched.binding, claims: matched.claims, spends: null, exp: null };
      }
      const { binding } = found;
      const says = JSON.parse(binding.policy!) as BindingPolicy;
      const refused = sessionRefusal(says, from.ip, { noReads: vault.workloads.noReads });
      if (refused !== null) return { refused };
      const [instance] = seen.instance;
      if (instance!.workloadsFrozenAt !== null || account.frozenAt !== null || binding.frozenAt !== null) return { refused: 'frozen' };
      const notAfter = hardEnd(binding, says, at, found.exp);
      if (notAfter <= at) return { refused: 'expired' };
      const expiresAt = new Date(Math.min(at + SESSION_MS, notAfter));
      const scope = scopeOf(binding.scope);
      const places = reachedBy(JSON.parse(scope) as CredentialScope, seen);
      const run = runClaims(found.claims);
      const now = new Date(at);
      return {
        writes: [put(credentials, {
          id, kind: 'workload', tokenHash: Buffer.from(credential, 'hex'), tokenHint: null, previousTokenHash: null, generation: binding.generation, principal: account.id, identityId: null,
          // Its binding's scope on its own row, and the places it reaches as of now, where `/use/<credential>` goes when it names none.
          scope, places: JSON.stringify(places.map((environmentId) => ({ environmentId, personal: false }))), label: binding.label, createdAt: now, createdBy: `binding:${binding.id}`,
          expiresAt, lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null,
          jkt: key, notAfter: new Date(notAfter), ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: null, client: null, challenge: null,
        })],
        ...(found.spends === null ? {} : { once: found.spends }),
        used: binding,
        entry: {
          kept: false,
          action: 'token.exchange', actor: account.id, credential: id, request: from.request, ip: from.ip,
          objects: [`principal:${account.id}`, `credential:${id}`, `binding:${binding.id}`],
          detail: {
            kind: 'workload', credential: id, binding: binding.id, generation: binding.generation, issuer: binding.issuer, proved: proof.kind, key,
            expiresAt: expiresAt.toISOString(), notAfter: new Date(notAfter).toISOString(), run, proof: found.spends?.toString('hex') ?? null,
          },
        },
        answer: { principal: account.id, credential: id, expiresAt: expiresAt.toISOString(), notAfter: new Date(notAfter).toISOString(), places, binding: binding.id },
      };
    },
  };
}

/**
 * A workload's session moves its own expiry on, with its key's proof: an
 * hour from the vault's clock, never past its hard end. Its caller's rows
 * are the read. A frozen session renews, as in 0.14, so that lifting the
 * freeze restores it; one stopped for anything else is told why, and a
 * narrowed one renews nothing, as it ends with its parent. Within five
 * seconds of its expiry it is refused `expired`, and its decision holds
 * until then (`until`): a write that starts later writes nothing, and the
 * change, decided again, is refused, so a renewal revives nothing. At its
 * hard end already, nothing moves. Its entry ages out; 0.14 logged none,
 * and moved no binding's last use, nor does this.
 */
function workloadRenew(input: Presented & WorkloadRenew, vault: Deciding): Operation<Parts, Answers['workload.renew']> {
  const shown = presented(input);
  const read = callerParts(shown.token, NO_PROJECT);
  return {
    read,
    denied: refusedTo('workload.renew', shown, vault.workloads),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = callerFrom(seen, shown, vault.workloads, at);
      if (caller === null || caller.workload === null) return { refused: 'unauthenticated' };
      const { stop, narrowed, binding } = caller.workload;
      if (stop !== null && stop !== 'frozen') return { refused: stop };
      if (narrowed) return { refused: 'narrowed' };
      const session = caller.credential;
      if (session.expiresAt.getTime() <= at + RENEW_MARGIN_MS) return { refused: 'expired' };
      const next = Math.min(at + SESSION_MS, session.notAfter!.getTime());
      const moved = next > session.expiresAt.getTime();
      const expiresAt = new Date(moved ? next : session.expiresAt.getTime());
      return {
        writes: moved ? [amended(credentials, session, { expiresAt })] : [],
        until: session.expiresAt.getTime() - RENEW_MARGIN_MS,
        entry: {
          kept: false,
          action: 'workload.renew', actor: caller.principal, credential: session.id, request: shown.request, ip: shown.ip,
          objects: [`principal:${caller.principal}`, `credential:${session.id}`, `binding:${binding.id}`],
          detail: { credential: session.id, binding: binding.id, expiresAt: expiresAt.toISOString(), notAfter: session.notAfter!.toISOString(), ...(moved ? {} : { unchanged: true }) },
        },
        answer: { expiresAt: expiresAt.toISOString() },
      };
    },
  };
}

/** The changes of workloads signing in (docs/design/0.16.md, "A workload signing in"). */
export const workloadOperations: Operations<WorkloadChanges> = { 'token.exchange': tokenExchange, 'workload.signin': workloadSignin, 'workload.renew': workloadRenew };
