import { randomUUID } from 'node:crypto';

import { isCredentialScope } from '@coffre/core/access';
import { CARRIED, matchIdToken, MAX_BINDINGS, readIdToken, runClaims, signatureRefusal } from '@coffre/core/identity';
import type { Answers, Asked, WorkloadChanges } from '@coffre/core/vault';
import { bindings, credentials, policy, principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { part, put, type Operation, type Parts, type Seen, type Unsealed } from '../change.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { HASH, text, traced } from './input.ts';

/** How long a CI run's token lasts: 0.14's `EXCHANGED_CREDENTIAL_MS`. */
const RUN_MS = 5 * 60_000;
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

/** The changes of workloads signing in (docs/design/0.16.md, "A workload signing in"). */
export const workloadOperations: Operations<WorkloadChanges> = { 'token.exchange': tokenExchange };
