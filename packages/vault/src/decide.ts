import {
  allows, EVERYWHERE, INSTANCE_ROLES, NOTHING, ROLES, ownsProject, readsSensitive, sessionScope, useOnly, withinCredential,
  type HeldKey, type Holdings, type Permission, type Place, type Policy,
} from '@coffre/core/access';
import { handsBack, live, PRINCIPAL, type Access, type Purpose, type RefusalCode, type UseCode, type UseWay } from '@coffre/core/vault';

import { overCap, type BulkRead } from './bulk.ts';
import {
  noEdits, objectKey, sealed, type BindingInput, type ConnectionInput, type CredentialInput, type EnvironmentInput, type Input, type PolicyInput, type PrincipalInput, type Ref,
  type RolesInput, type SealKeys, type SecretInput,
} from './inputs.ts';
import type { EnvironmentRow } from './store.ts';

/**
 * How the vault decides each key of one call, and each reference one makes,
 * as functions of what the decision read and nothing else: the rest of
 * `#keys` and `reference` reads, locks and logs around them. Pure, so that `formal/lean` holds them to its model
 * case by case (`pnpm formal:lean`, docs/formal.md).
 */

/** What a decision reads of someone: whether they are a member, what they hold now, and what they would with their lapsed grants. */
export type Reader = { status: Access['status']; live: Holdings; all: Holdings };

/** An environment a secret is in, or that holds a reference to one. */
export type SecretPlace = { projectId: string; environmentId: string };

/**
 * Where a decision checks a permission: an environment, with its slug as
 * the store has it when it was read and is in the project claimed;
 * otherwise none, which no grant on a slug matches.
 */
export function placeIn(place: SecretPlace, environments: ReadonlyMap<string, { projectId: string; slug: string }>): Place {
  const environment = environments.get(place.environmentId);
  const slug = environment?.projectId === place.projectId ? environment.slug : null;
  return { projectId: place.projectId, environmentId: place.environmentId, environmentSlug: slug };
}

/**
 * A key of a personal config is its owner's alone (docs/design/forking.md,
 * section 4): no grant or role opens or wraps it, an Owner's included,
 * only its owner, while they read the environment it is a config of,
 * whatever the call is. Nor does any reference reach into or out of one.
 * Undefined for a key of any other environment, decided as ever.
 */
export function personalRefusal(
  reader: Reader,
  principal: string,
  permission: Permission,
  secret: SecretPlace,
  at: SecretPlace,
  environments: ReadonlyMap<string, EnvironmentRow>,
): RefusalCode | null | undefined {
  const own = environments.get(secret.environmentId);
  const elsewhere = at.environmentId !== secret.environmentId;
  const held = elsewhere ? environments.get(at.environmentId) : own;
  if (own?.owner == null && held?.owner == null) return undefined;
  // Held elsewhere, a reference into or out of one; or not its owner's.
  if (elsewhere || own === undefined || principal !== own.owner || own.parentId === null) return 'personal';
  const parent = placeIn({ projectId: secret.projectId, environmentId: own.parentId }, environments);
  // Its owner reads what they wrote while they read or use the environment it configures (R8).
  const gone = own.deleted || (environments.get(own.parentId)?.deleted ?? true);
  const refused = refuses(reader, 'secret.use', parent, gone) === null ? null : refuses(reader, 'secret.read', parent, gone);
  if (refused !== null) return refused;
  // The credential's scope caps the owner still: their viewer token on the parent reads, and wraps no key. Reading their
  // own values takes use there: a Contributor's handle reads what its owner wrote, and nothing of the parent's.
  return withinCredential(reader.live, permission === 'secret.read' ? 'secret.use' : permission, parent) ? null : 'no_grant';
}

/**
 * Why `reader` may not do `permission` at `where`, or null if they may. A
 * deleted place is refused before any grant is asked, so no kind of grant,
 * on the project, the environment or every project, can reach into one.
 */
export function refuses(reader: Reader, permission: Permission, where: Place, deleted: boolean): RefusalCode | null {
  if (reader.status === 'tampered') return 'tampered';
  if (reader.status === 'removed') return 'removed';
  if (reader.status === 'unknown') return 'not_a_member';
  if (deleted) return 'deleted';
  if (allows(reader.live, permission, where)) return null;
  // Would a grant that has lapsed have covered it?
  return allows(reader.all, permission, where) ? 'expired' : 'no_grant';
}

/**
 * What refuses each key of a call by where it is, before any `vet`: its
 * personal config's owner, any one of the permissions it `needs` besides,
 * `permission` itself, at `at`, its reference's holder or where it is; and
 * a key it `owns` that its reader does not own the project of.
 */
export function keyRefusals(
  reader: Reader,
  call: {
    principal: string;
    permission: Permission;
    secrets: readonly SecretPlace[];
    at: readonly SecretPlace[];
    environments: ReadonlyMap<string, EnvironmentRow>;
    needs: readonly (readonly Permission[] | null)[];
    owns?: readonly boolean[];
  },
): (RefusalCode | null)[] {
  const { principal, permission, secrets, at, environments, needs } = call;
  const gone = (place: SecretPlace) => environments.get(place.environmentId)?.deleted ?? false;
  const refusalOf = (secret: SecretPlace, i: number): RefusalCode | null => {
    const personal = personalRefusal(reader, principal, permission, secret, at[i]!, environments);
    if (personal !== undefined) return personal;
    const also = needs[i];
    if (also != null) {
      const place = placeIn(at[i]!, environments);
      const refused = also.map((need) => refuses(reader, need, place, gone(secret) || gone(at[i]!)));
      // Any one of none is none held: refused.
      if (refused.every((code) => code !== null)) return refused[0] ?? 'no_grant';
    }
    // Through a reference, the holder's grants decide, its source's never: a reference takes its value and nature
    // (a sensitive one stays use-only) from its source, and its permissions from where it lives. Its maker held what
    // the source's nature asks when it was made (`reference`).
    return refuses(reader, permission, placeIn(at[i]!, environments), gone(secret) || gone(at[i]!));
  };
  // A loosening takes its reader owning the project besides, a personal config's owner too, there.
  return secrets.map((secret, i) => {
    const code = refusalOf(secret, i);
    return code === null && call.owns?.[i] === true && !ownsProject(reader.live, secret.projectId) ? 'not_allowed' : code;
  });
}

/**
 * Each key's refusal once its sensitivity is weighed too, after `vet`. A
 * sensitive value is only ever used for a person, never handed back, by
 * whatever credential of theirs asks; and handed back to a service account
 * only on a credential an Owner of its own project issued, a reference's
 * source's too, whose value it is (`readsSensitive`, R32). And a fork
 * copies one, for anyone, a service account too, only where its app says
 * it keeps it sensitive (an app of 0.9, mid-deploy, would write the copy as
 * a secret its people read), and never one read through a reference.
 */
export function sensitiveRefusals(
  codes: readonly (RefusalCode | null)[],
  reader: Reader,
  call: {
    action: 'secret.read' | 'key.wrap' | 'key.rewrap';
    principal: string;
    purpose?: string;
    keepsSensitive?: boolean;
    secrets: readonly { projectId: string; sensitive?: boolean }[];
    /** Each secret read through a reference. */
    viaReference?: readonly boolean[];
  },
): (RefusalCode | null)[] {
  const copying = call.action === 'secret.read' && call.purpose === 'copy';
  const handedBack = call.action === 'secret.read' && handsBack({ purpose: call.purpose ?? '', keepsSensitive: call.keepsSensitive === true });
  const person = call.principal.startsWith('user:');
  return call.secrets.map((secret, i) => {
    const code = codes[i] ?? null;
    if (code !== null || secret.sensitive !== true) return code;
    // A sensitive value read through a reference is never copied: a fork keeps it a reference to its source, so the
    // value stays in its own project, where R16/R32 decide who reads it. Copying it would move it to the fork's.
    if ((copying && call.keepsSensitive !== true) || (copying && call.viaReference?.[i] === true) || (handedBack && person)) return 'sensitive';
    if (handedBack && !readsSensitive(reader.live, secret.projectId)) return 'not_owner_issued';
    return null;
  });
}

/**
 * Each key's refusal once a workload's listing is weighed too, after `vet`
 * and before its sensitivity (docs/design/workload-access.md, section 6.1).
 * A workload is handed back, for any purpose but the proxy's use, only a
 * value its credential lists where the value is held (`useOnly`): each
 * secret is that place, a reference's source, a fork's parent, whatever
 * place the call checked its permission at. A copy too, kept sensitive or
 * not: it would land where the workload may read it. The vault opens no
 * plain value, so every key here is a secret or a sensitive one.
 */
export function useOnlyRefusals(
  codes: readonly (RefusalCode | null)[],
  reader: Reader,
  call: { action: 'secret.read' | 'key.wrap' | 'key.rewrap'; purpose?: string; secrets: readonly HeldKey[] },
): (RefusalCode | null)[] {
  const handedBack = call.action === 'secret.read' && call.purpose !== 'use';
  return call.secrets.map((secret, i) => codes[i] ?? (handedBack && useOnly(reader.live, secret) ? 'use_only' : null));
}

/**
 * Why `reader` may not make a reference at `holder` to `source`, or null, past
 * what only the database settles (a source of another claim, a reference to
 * itself). A personal config's values are bound to its owner: no reference
 * holds one, nor reads one. Making one hands its source's value to whoever
 * reads the holder, whatever its nature becomes: its maker writes the holder,
 * reads the source there, as any direct access, and, for a sensitive one,
 * which nobody reads, uses it there too (R24). A workload refers only to a
 * value it is handed back, a plain one or one it lists (`useOnly`): it
 * would otherwise move a value it uses to a place whose keys it reads.
 */
export function referenceRefusal(
  reader: Reader,
  holder: SecretPlace,
  source: HeldKey,
  environments: ReadonlyMap<string, EnvironmentRow>,
  nature: 'plain' | 'secret' | 'sensitive',
): RefusalCode | null {
  if (environments.get(holder.environmentId)?.owner != null || environments.get(source.environmentId)?.owner != null) return 'personal';
  const gone = (place: SecretPlace) => environments.get(place.environmentId)?.deleted ?? false;
  const at = placeIn(source, environments);
  return refuses(reader, 'secret.write', placeIn(holder, environments), gone(holder))
    ?? refuses(reader, 'secret.read', at, gone(source))
    ?? (nature === 'sensitive' ? refuses(reader, 'secret.use', at, gone(source)) : null)
    ?? (nature !== 'plain' && useOnly(reader.live, source) ? 'use_only' : null);
}

// --- a use, on sealed inputs (0.15) ---------------------------------------------

/**
 * A use as its log entry records it (plan, PR 3; the request, not the
 * outcome): on which credential, which key, through which environment,
 * why, and when. `place` is 0.14's `through`: a fork an inherited value is
 * read in, which decides nothing but names the read; null when the key is
 * read in its own environment (a reference's holder's), where it is
 * decided either way.
 */
export type UseRequest = {
  /**
   * Its way in, by id: a credential's, or, with `way`, an MCP connection's or a Cloudflare binding's; behind Cloudflare
   * Access, the person's object's key (`objectKey`), the only id a person has (T147).
   */
  credential: string;
  /** What `credential` is the id of (`Way`): a credential, absent. */
  way?: Way;
  secretId: string;
  place: string | null;
  purpose: Purpose;
  keepsSensitive: boolean;
  /** Its time, ms since the epoch: what expiry is decided at, live and replayed. */
  at: number;
  /**
   * A named use, which hands a plain value back as its text and logs no entry of it (T145). Any other use, by ids and
   * so any one the log records, opens a wrapped key or nothing: a plain value is `bad_claim` to it, live and replayed
   * alike (review r1 of D153).
   */
  plain?: true;
};

export type { UseCode };

/**
 * What a use came in on (T147; formal/WaysIn.tla): a credential; an MCP connection; a Cloudflare service binding; or,
 * behind Cloudflare Access, which signs a browser in with no row of coffre's, the person alone.
 */
export type Way = 'credential' | UseWay;

/** The object a use's way in is: a credential's, a connection's or a binding's. Behind Access, none: the account alone. */
export type WayInput = CredentialInput | ConnectionInput | BindingInput;

/** One input as a use read it: its row (null: none), the seal on it, and the seal its object's newest change left (null: none, or gone). */
export type Read<T extends Input> = { row: T | null; seal: Buffer | null; newest: Buffer | null };

/**
 * Everything a use reads, in one snapshot: what the use's statement returns
 * (PR 5), or what a replay built from the log; its seals checked once
 * `checked` (`checkSeals`). `principal` and `bulk` are read for the
 * credential's principal, and null with no credential row; `source` for a
 * reference, null otherwise; `environments`, by id, every one
 * `useEnvironments` names. Read, `credential` is the way in's object, of
 * its own kind (`WayInput`; none behind Access, whose `principal` is read by
 * the request's key); checked, the credential it stands for (`wayChecked`).
 */
export type UseView<checked extends boolean = false> = {
  credential: checked extends true ? Checked<CredentialInput> : Read<WayInput>;
  principal: In<PrincipalInput, checked> | null;
  roles: In<RolesInput, checked>;
  policy: In<PolicyInput, checked>;
  secret: In<SecretInput, checked>;
  source: In<SecretInput, checked> | null;
  environments: ReadonlyMap<string, In<EnvironmentInput, checked>>;
  bulk: BulkRead | null;
};
export type CheckedView = UseView<true>;

/** An input once its seal is checked: whether the seal is the vault's over its row, and whether it is its object's newest. */
export type Checked<T extends Input> = { row: T | null; valid: boolean; current: boolean };

type In<T extends Input, checked extends boolean> = checked extends true ? Checked<T> : Read<T>;

/**
 * Each input's seal checked, against the object it was read as: a row
 * filed under another object's key carries no seal of the vault's for it.
 * A row with none (none read) is valid, and current while its object has
 * no newest seal either: never made, or gone.
 */
export function checkSeals(keys: SealKeys, view: UseView, request: Pick<UseRequest, 'credential' | 'secretId' | 'way'>): CheckedView {
  const check = <T extends Input>(read: Read<T>, ref: Ref): Checked<T> => ({
    row: read.row,
    valid: read.row === null ? read.seal === null : sealed(keys, ref, read.row, read.seal),
    current: read.row === null ? read.newest === null : read.seal !== null && read.newest !== null && read.seal.equals(read.newest),
  });
  const credential = wayChecked(check, view, request);
  const secret = view.secret.row;
  return {
    credential,
    principal: view.principal === null || credential.row === null ? null : check(view.principal, { kind: 'principal', id: credential.row.principal }),
    roles: check(view.roles, { kind: 'roles', id: 'instance' }),
    policy: check(view.policy, { kind: 'policy', id: 'instance' }),
    secret: check(view.secret, { kind: 'secret', id: request.secretId }),
    source: view.source === null || secret?.source == null ? null : check(view.source, { kind: 'secret', id: secret.source }),
    environments: new Map([...view.environments].map(([id, read]) => [id, check(read, { kind: 'environment', id })])),
    bulk: view.bulk,
  };
}

/**
 * A use's way in, its seal checked against its own object, and read as the credential it stands for (T147;
 * formal/WaysIn.tla, WayReadInUse, AccountReadInUse), so that every rule after weighs it as one:
 *
 *   a credential          itself
 *   an MCP connection     its person's credential, of no scope, as a session is: what its person holds, to its end
 *   a Cloudflare binding  its service's workload credential, of its scope with its policy's reads (`sessionScope`), as
 *                         the session a sign-in through it would make; one no Cloudflare call is taken through (another
 *                         profile, no policy) reaches nothing
 *   Cloudflare Access     the account alone, of its generation, a person's or an Access service token's, which Access
 *                         signs in with no row of coffre's: the account is all there is to end; a service's, a bearer
 *                         of no scope, as a service token of 0.4
 *
 * Behind Access, the account read must be the one the request's key names; none, there is no way in.
 */
function wayChecked(check: <T extends Input>(read: Read<T>, ref: Ref) => Checked<T>, view: UseView, request: Pick<UseRequest, 'credential' | 'way'>): Checked<CredentialInput> {
  const way = request.way ?? 'credential';
  if (way === 'access') {
    const account = view.principal?.row ?? null;
    if (account === null || objectKey({ kind: 'principal', id: account.principal }) !== request.credential) return { row: null, valid: true, current: true };
    const caller = account.principal.startsWith('user:') ? 'person' : 'bearer';
    return { row: { kind: 'credential', id: request.credential, principal: account.principal, caller, scope: null, expiresAt: null, revoked: false, generation: account.generation }, valid: true, current: true };
  }
  const read = view.credential;
  if (read.row !== null && read.row.kind !== way) return { row: null, valid: false, current: false };
  const checked = check(read, { kind: way, id: request.credential });
  return { ...checked, row: checked.row === null ? null : asCredential(checked.row) };
}

/** A way in's object as the credential it stands for (`wayChecked`). */
export function asCredential(object: WayInput): CredentialInput {
  switch (object.kind) {
    case 'credential':
      return object;
    case 'connection':
      return { kind: 'credential', id: object.id, principal: object.principal, caller: 'person', scope: null, expiresAt: object.expiresAt, revoked: object.revoked, generation: object.generation };
    case 'binding': {
      const policy = bindingPolicy(object);
      return {
        kind: 'credential', id: object.id, principal: object.principal, caller: 'workload',
        scope: policy === null ? [] : sessionScope({ scope: null }, { scope: object.scope === null ? null : JSON.stringify(object.scope) }, policy),
        expiresAt: null, revoked: object.revoked || policy === null, generation: object.generation,
      };
    }
  }
}

/**
 * A binding's policy, as a Cloudflare call through it is taken (`bindingWorkload`): of profile `cloudflare`, with one;
 * else null. Its text is under the binding's seal, and the vault made it canonical JSON: one that does not parse is a
 * bug of the vault's, which fails the call (and its replay) rather than read as a binding ended.
 */
function bindingPolicy(binding: BindingInput): { reads?: Parameters<typeof sessionScope>[2]['reads'] } | null {
  if (binding.profile !== 'cloudflare' || binding.policy === null) return null;
  const policy = JSON.parse(binding.policy) as unknown;
  return policy !== null && typeof policy === 'object' && !Array.isArray(policy) ? (policy as { reads?: Parameters<typeof sessionScope>[2]['reads'] }) : null;
}

/**
 * Whether the credential reaches at all: one missing, revoked, ended at the request's time, or of another generation
 * than its active account's. A removal moves the account's on, which ends every credential of it before its sweep
 * revokes each, the account admitted again or not (formal/Credentials.tla, UseDecidesGeneration). One still removed
 * is refused as such, by the rules after.
 */
function credentialRefused(view: CheckedView, request: UseRequest): boolean {
  const credential = view.credential.row;
  return credential === null || credentialEnded(credential, view.principal?.row ?? null, request.at);
}

/** Whether a credential has ended at `at`: revoked, past its end, or of another generation than its active account's. */
export function credentialEnded(credential: CredentialInput, account: PrincipalInput | null, at: number): boolean {
  return credential.revoked || (credential.expiresAt !== null && at >= credential.expiresAt)
    || (account?.status === 'active' && account.generation !== credential.generation);
}

/**
 * Why the caller may not act at `place`, the environment a key is sought or held in, or null: 0.14's rules on the
 * reader its principal, credential and roles make there, for the request's purpose, and nothing of any key's. A
 * place with no row: `missing`.
 */
function standingAt(view: CheckedView, request: UseRequest, place: string): UseCode | null {
  const sought = view.environments.get(place)?.row ?? null;
  if (sought === null) return 'missing';
  // A personal config is weighed with its parent, as its owner reads it while they read the parent (R8).
  const parents = standingParents(view, place).flatMap((read) => (read.row === null ? [] : [read.row]));
  return placeRefusal(view.principal!.row, view.credential.row!, view.roles.row ?? noEdits(), sought, parents, request);
}

/** 0.14's rules for the request's permission at `sought`, on the reader its principal, credential and roles make there. */
function placeRefusal(
  principal: PrincipalInput | null, credential: CredentialInput, roles: RolesInput, sought: EnvironmentInput, parents: readonly EnvironmentInput[],
  request: Pick<UseRequest, 'purpose' | 'at'>,
): UseCode | null {
  const rows = [sought, ...parents];
  const reader = readerOf(principal, credential, roles, rows, request.at);
  const at: SecretPlace = { projectId: sought.projectId, environmentId: sought.id };
  const environments = new Map(rows.map(({ id, projectId, slug, owner, parentId, deleted, archived, projectArchived }) => [id, { projectId, slug, owner, parentId, deleted, archived: archived || projectArchived }]));
  const [code] = keyRefusals(reader, { principal: credential.principal, permission: request.purpose === 'use' ? 'secret.use' : 'secret.read', secrets: [at], at: [at], environments, needs: [null] });
  return code ?? null;
}

/**
 * The roles coffre ships (`ROLES`, `INSTANCE_ROLES`), as the named statement's gate weighs them where the roles' edits
 * name none (`use_stands`, 0045): each column's `secret.read` and `secret.use`, all it asks of them. Passed with every
 * named call, so that the roles have one source and an edit of one ships no migration.
 */
export const GATE_ROLES: string = JSON.stringify({ roles: gateColumns(ROLES), instanceRoles: gateColumns(INSTANCE_ROLES) });

function gateColumns(roles: Readonly<Record<string, { permissions: readonly Permission[]; protected: readonly Permission[] }>>) {
  const weighed = (column: readonly Permission[]) => column.filter((permission) => permission === 'secret.read' || permission === 'secret.use');
  return Object.fromEntries(Object.entries(roles).map(([name, role]) => [name, { permissions: weighed(role.permissions), protected: weighed(role.protected) }]));
}

/**
 * Why the caller of a named use has no standing at the place it names, or null if they have: `standingRefusal` on its
 * rows as read, before their seals are checked, which only the vault can (D150 fallback D, W268; formal/Probing.tla,
 * StandingFirst). The named statement decides this first, from rows no key decides (the credential, its account and
 * grants, the roles, the place), and reads the key only for a caller who stands (`use_stands`, 0045; SQLite's twin
 * asks this). A named place is a live environment of its own, never a fork's or a personal config's (`nowhere`), so no
 * parent weighs. Its seals checked and current, this is `standingRefusal` at that place: `use-stands.test.ts` holds
 * the statement's gate to it.
 */
export function namedStanding(
  principal: PrincipalInput | null, credential: CredentialInput, roles: RolesInput, place: EnvironmentInput, request: Pick<UseRequest, 'purpose' | 'at'>,
): UseCode | null {
  if (credentialEnded(credential, principal, request.at)) return 'credential';
  return placeRefusal(principal, credential, roles, place, [], request);
}

/** The environment a personal config at `place` is of, as the view read it: the standing weighs it too. */
function standingParents(view: CheckedView, place: string): Checked<EnvironmentInput>[] {
  const sought = view.environments.get(place)?.row ?? null;
  if (sought === null || sought.owner === null || sought.parentId === null) return [];
  const parent = view.environments.get(sought.parentId);
  return parent === undefined ? [] : [parent];
}

/** `decideChecked` on what a use read, its seals checked with the vault's keys. */
export function decideUse(keys: SealKeys, view: UseView, request: UseRequest): UseCode | null {
  return decideChecked(checkSeals(keys, view, request), request);
}

/**
 * The environments a use's decision weighs, in the order it reaches them:
 * the one it is read through, the key's own (where its permission is
 * checked), where its value is, and a personal config's parent. Read from the rows the view has, so the use's statement
 * and the replay read the same ones.
 */
export function useEnvironments(view: Pick<UseView<boolean>, 'secret' | 'source' | 'environments'>, request: Pick<UseRequest, 'place'>): string[] {
  const secret = view.secret.row;
  // A key the place does not hold: the place it was sought in, where the caller's standing decides (T145).
  if (secret === null) return request.place === null ? [] : [request.place];
  const value = secret.source === null ? secret : view.source?.row ?? null;
  const ids = [...(request.place === null ? [] : [request.place]), secret.environmentId];
  if (value !== null) {
    ids.push(value.environmentId);
    const own = view.environments.get(value.environmentId)?.row;
    if (own?.owner != null && own.parentId !== null) ids.push(own.parentId);
  }
  return [...new Set(ids)];
}

function sealRefusal(inputs: readonly Checked<Input>[]): UseCode | null {
  for (const input of inputs) {
    if (input.row !== null && !input.valid) return 'tampered';
    if (!input.current) return 'stale';
  }
  return null;
}

/**
 * Why the caller may not act where a use's key is held, or, for a key the place does not hold, where it was sought
 * (T145; formal/Probing.tla, MissingByStanding), or null: `decideChecked`'s first step (T158, review d5 of #416). The
 * credential first, its row's seal and its account's, then whether it reaches at all, which no place or key decides
 * (the app's 401: review r1 of D153); then the seals of what the standing reads (the roles, the policy, the key's row,
 * which says where it is held, that place and a personal config's parent), then 0.14's rules there.
 */
export function standingRefusal(view: CheckedView, request: UseRequest): UseCode | null {
  const caller = sealRefusal([view.credential, ...(view.principal === null ? [] : [view.principal])]);
  if (caller !== null) return caller;
  if (view.credential.row === null || credentialRefused(view, request)) return 'credential';
  const stand = view.secret.row === null ? request.place : view.secret.row.environmentId;
  const refused = sealRefusal([view.roles, view.policy, view.secret,
    ...(stand === null ? [] : [view.environments.get(stand)!, ...standingParents(view, stand)])]);
  if (refused !== null) return refused;
  return stand === null ? null : standingAt(view, request, stand);
}

/**
 * Why a use is refused, or null to allow it: a function of what it read
 * and of the request alone, so that the replay of the log decides the same
 * (docs/design/sealed-inputs.md).
 *
 * 1. **The caller's standing, before anything of the key's own** (T158;
 *    review d5 of #416; `standingRefusal`): the seals of what it reads (the
 *    credential, the principal, the roles, the policy, the key's row, which
 *    says where it is held, and that environment, or the one it was sought
 *    in), then the credential
 *    (missing, revoked, ended at the request's time, or of an earlier
 *    generation than its account's: a removal's, before its sweep revokes
 *    it), then 0.14's rules there for the request's permission
 *    (`standingAt`). A caller refused there is refused the same for every
 *    key, held, gone or never made; and the app answers every refusal alike
 *    besides (D153).
 * 2. **Seals,** every other input's, before anything its rows say: `tampered`
 *    for a row whose seal is not the vault's, `stale` for one that is not
 *    its object's newest. A row put back from before a change can make a
 *    use refused or allowed that the log's state would decide otherwise;
 *    checked before its rows, every such use is `stale`, never another
 *    refusal (HotPathOne's `StaleFirst`, `TamperVisible`: the standing's
 *    inputs first, then the key's).
 * 3. **The key:** a key that is no more, a reference whose source is
 *    gone or that has ended (`ended`), a reference to a reference, a value with no wrapped
 *    key (a plain one, which the vault never opens), and a place it is read
 *    through that 0.14's `throughOk` refuses (`bad_claim`): one but a live,
 *    unarchived environment of an unarchived project, the key's, other than
 *    the key's own.
 *    Permission is decided at the key's own environment (a reference's
 *    holder's), whatever it is read through.
 * 4. **0.14's rules, unchanged:** `keyRefusals`, then `useOnlyRefusals`,
 *    then `sensitiveRefusals`, on the reader its principal, credential,
 *    roles and environments make (`readerOf`). Nothing is `vet`ted: a
 *    reference's end is its holder's row, sealed (`ended` above).
 * 5. **The bulk cap,** on what the use read of it, with the policy's count.
 *
 * Step 1 refuses only what step 4 would: 0.14's rules decide a key's
 * permission at its holder (`keyRefusals`' `at`), and the reader's policy
 * there is that environment's alone, so a refusal at the holder is one of
 * the key's, perhaps by another code.
 */
export function decideChecked(view: CheckedView, request: UseRequest): UseCode | null {
  const credential = view.credential.row;
  const secret = view.secret.row;
  if ((credential === null) !== (view.principal === null) || (credential === null) !== (view.bulk === null)) {
    throw new Error("a use reads its credential's principal and bulk rows with it, and none without it");
  }
  if ((secret?.source == null) !== (view.source === null)) throw new Error("a use reads a reference's source with it, and none for a key that is no reference");
  const ids = useEnvironments(view, request);
  const environments = ids.map((id) => {
    const read = view.environments.get(id);
    if (read === undefined) throw new Error(`a use weighs environment ${id}, which it did not read`);
    return read;
  });
  const notHere = standingRefusal(view, request);
  if (notHere !== null) return notHere;
  if (credential === null) return 'credential';
  // Then the key's own seals, a key's row put back or hidden around the log `stale` (live never refuses otherwise
  // where the log would allow), and only then what its rows say.
  const keyRefused = sealRefusal([view.secret, ...(view.source === null ? [] : [view.source]), ...environments]);
  if (keyRefused !== null) return keyRefused;
  if (secret === null) return 'missing';
  const value = secret.source === null ? secret : view.source!.row;
  if (value === null) return 'ended';
  // A reference whose end its row says (`ended_at`): no version of its own, no source. 0.14's `reference.end`.
  if (secret.source === null && secret.version === '') return 'ended';
  // A reference reads a key's own value: one to another reference is none the change path makes.
  if (value.source !== null && secret.source !== null) return 'bad_claim';
  // A use opens a wrapped key, or hands back a plain value's text, which its digest binds (T145): any other is no value.
  if (value.key === null && value.digest === null) return 'bad_claim';
  const rows = new Map(ids.flatMap((id) => {
    const row = view.environments.get(id)!.row;
    return row === null ? [] : [[id, row] as const];
  }));
  // Read through a fork (0.14's `throughOk`): a live, unarchived environment of the key's project, unarchived too, not its own. It
  // decides nothing: the key is decided where it is held.
  if (request.place !== null) {
    const fork = rows.get(request.place);
    if (request.place === secret.environmentId || fork === undefined || fork.projectId !== secret.projectId || fork.deleted || fork.archived || fork.projectArchived) return 'bad_claim';
  }
  const policy = view.policy.row;
  if (policy === null) return 'no_policy';
  const reader = readerOf(view.principal!.row, credential, view.roles.row ?? noEdits(), rows.values(), request.at);
  const at: SecretPlace = { projectId: secret.projectId, environmentId: secret.environmentId };
  const place: SecretPlace = { projectId: value.projectId, environmentId: value.environmentId };
  // As 0.14's snapshot has them: archived, the environment or its project.
  const environmentRows = new Map([...rows].map(([id, { projectId, slug, owner, parentId, deleted, archived, projectArchived }]) => [id, { projectId, slug, owner, parentId, deleted, archived: archived || projectArchived }]));
  const permission: Permission = request.purpose === 'use' ? 'secret.use' : 'secret.read';
  const byPlace = keyRefusals(reader, { principal: credential.principal, permission, secrets: [place], at: [at], environments: environmentRows, needs: [null] });
  const listed = useOnlyRefusals(byPlace, reader, { action: 'secret.read', purpose: request.purpose, secrets: [{ ...place, secretId: value.id }] });
  const [code] = sensitiveRefusals(listed, reader, {
    action: 'secret.read', principal: credential.principal, purpose: request.purpose, keepsSensitive: request.keepsSensitive,
    secrets: [{ projectId: value.projectId, sensitive: value.nature === 'sensitive' }], viaReference: [secret.source !== null],
  });
  if (code != null) return code;
  // A plain value counts toward no cap, as when the app handed it back itself; only a named use hands one back.
  if (value.key === null) return request.plain === true ? null : 'bad_claim';
  return overCap(view.bulk!, policy.bulk) ? 'bulk_limit' : null;
}

/**
 * What a use's principal holds through its credential, at `at`, as
 * `#standing` and `through` in vault.ts make it from 0.14's rows: their
 * role and grants, live and lapsed; the credential's scope and kind; and
 * the policy, the release's roles with the log's edits over them and, of the environments the
 * use weighs, those protected and not deleted. `allows` asks the policy
 * only whether the place it checks is protected, and every place a use
 * checks is one of those, so the policy is as good as the whole one there.
 */
export function readerOf(principal: PrincipalInput | null, credential: CredentialInput, roles: RolesInput, environments: Iterable<EnvironmentInput>, at: number): Reader {
  const through = { ...(credential.scope === null ? {} : { credentialScope: credential.scope }), kind: credential.caller };
  const status = principal === null || !PRINCIPAL.test(credential.principal) ? 'unknown' : principal.status;
  if (principal === null || status !== 'active') {
    const none = { ...NOTHING, ...through };
    return { status, live: none, all: none };
  }
  const guarded = [...environments].filter((environment) => environment.protected && !environment.deleted);
  // By project, in a Map: a project id a plain object already holds (`constructor`) is a project like another.
  const byProject = new Map<string, { environmentId: string; slug: string | null }[]>();
  for (const environment of guarded) byProject.set(environment.projectId, [...(byProject.get(environment.projectId) ?? []), { environmentId: environment.id, slug: environment.slug }]);
  const policy: Policy = {
    roles: { ...ROLES, ...roles.roles },
    instanceRoles: { ...INSTANCE_ROLES, ...roles.instanceRoles },
    protected: guarded.map((environment) => environment.id),
    protectedIn: Object.fromEntries(byProject),
  };
  const person = credential.principal.startsWith('user:');
  const standing = person ? { role: principal.role, scope: principal.scope } : { role: 'member' as const, scope: EVERYWHERE };
  const grants = (only: (grant: PrincipalInput['grants'][number]) => boolean) =>
    principal.grants.filter(only).map(({ projectId, environmentId, role }) => ({ projectId, environmentId, role }));
  const holdings = (held: Holdings['grants']): Holdings => ({ ...standing, grants: held, policy, service: !person, ...through });
  return { status: 'active', live: holdings(grants((grant) => live(grant, at))), all: holdings(grants(() => true)) };
}
