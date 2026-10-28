import {
  allows, EVERYWHERE, INSTANCE_ROLES, NOTHING, ROLES, ownsProject, readsSensitive, useOnly, withinCredential,
  type HeldKey, type Holdings, type Permission, type Place, type Policy,
} from '@coffre/core/access';
import { handsBack, live, PRINCIPAL, type Access, type Purpose, type RefusalCode, type UseCode } from '@coffre/core/vault';

import { overCap, type BulkRead } from './bulk.ts';
import { noEdits, sealed, type CredentialInput, type EnvironmentInput, type Input, type PolicyInput, type PrincipalInput, type Ref, type RolesInput, type SealKeys, type SecretInput } from './inputs.ts';
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
  credential: string;
  secretId: string;
  place: string | null;
  purpose: Purpose;
  keepsSensitive: boolean;
  /** Its time, ms since the epoch: what expiry is decided at, live and replayed. */
  at: number;
};

export type { UseCode };

/** One input as a use read it: its row (null: none), the seal on it, and the seal its object's newest change left (null: none, or gone). */
export type Read<T extends Input> = { row: T | null; seal: Buffer | null; newest: Buffer | null };

/**
 * Everything a use reads, in one snapshot: what the use's statement returns
 * (PR 5), or what a replay built from the log; its seals checked once
 * `checked` (`checkSeals`). `principal` and `bulk` are read for the
 * credential's principal, and null with no credential row; `source` for a
 * reference, null otherwise; `environments`, by id, every one
 * `useEnvironments` names.
 */
export type UseView<checked extends boolean = false> = {
  credential: In<CredentialInput, checked>;
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
export function checkSeals(keys: SealKeys, view: UseView, request: Pick<UseRequest, 'credential' | 'secretId'>): CheckedView {
  const check = <T extends Input>(read: Read<T>, ref: Ref): Checked<T> => ({
    row: read.row,
    valid: read.row === null ? read.seal === null : sealed(keys, ref, read.row, read.seal),
    current: read.row === null ? read.newest === null : read.seal !== null && read.newest !== null && read.seal.equals(read.newest),
  });
  const credential = view.credential.row;
  const secret = view.secret.row;
  return {
    credential: check(view.credential, { kind: 'credential', id: request.credential }),
    principal: view.principal === null || credential === null ? null : check(view.principal, { kind: 'principal', id: credential.principal }),
    roles: check(view.roles, { kind: 'roles', id: 'instance' }),
    policy: check(view.policy, { kind: 'policy', id: 'instance' }),
    secret: check(view.secret, { kind: 'secret', id: request.secretId }),
    source: view.source === null || secret?.source == null ? null : check(view.source, { kind: 'secret', id: secret.source }),
    environments: new Map([...view.environments].map(([id, read]) => [id, check(read, { kind: 'environment', id })])),
    bulk: view.bulk,
  };
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
  if (secret === null) return [];
  const value = secret.source === null ? secret : view.source?.row ?? null;
  const ids = [...(request.place === null ? [] : [request.place]), secret.environmentId];
  if (value !== null) {
    ids.push(value.environmentId);
    const own = view.environments.get(value.environmentId)?.row;
    if (own?.owner != null && own.parentId !== null) ids.push(own.parentId);
  }
  return [...new Set(ids)];
}

/**
 * Why a use is refused, or null to allow it: a function of what it read
 * and of the request alone, so that the replay of the log decides the same
 * (docs/design/sealed-inputs.md).
 *
 * 1. **Seals,** every input's, before anything its rows say: `tampered`
 *    for a row whose seal is not the vault's, `stale` for one that is not
 *    its object's newest. A row put back from before a change can make a
 *    use refused or allowed that the log's state would decide otherwise;
 *    checked first, every such use is `stale`, never another refusal
 *    (HotPathOne's `StaleFirst`, `TamperVisible`).
 * 2. **The credential and the key:** missing, revoked or ended at the
 *    request's time; a key that is no more, a reference whose source is
 *    gone or that has ended (`ended`), a reference to a reference, a value with no wrapped
 *    key (a plain one, which the vault never opens), and a place it is read
 *    through that 0.14's `throughOk` refuses (`bad_claim`): one but a live,
 *    unarchived environment of an unarchived project, the key's, other than
 *    the key's own.
 *    Permission is decided at the key's own environment (a reference's
 *    holder's), whatever it is read through.
 * 3. **0.14's rules, unchanged:** `keyRefusals`, then `useOnlyRefusals`,
 *    then `sensitiveRefusals`, on the reader its principal, credential,
 *    roles and environments make (`readerOf`). Nothing is `vet`ted: a
 *    reference's end is its holder's row, sealed (`ended` above).
 * 4. **The bulk cap,** on what the use read of it, with the policy's count.
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
  const inputs: Checked<Input>[] = [view.credential, ...(view.principal === null ? [] : [view.principal]), view.roles, view.policy, view.secret,
    ...(view.source === null ? [] : [view.source]), ...environments];
  for (const input of inputs) {
    if (input.row !== null && !input.valid) return 'tampered';
    if (!input.current) return 'stale';
  }
  if (credential === null || credential.revoked || (credential.expiresAt !== null && request.at >= credential.expiresAt)) return 'credential';
  if (secret === null) return 'missing';
  const value = secret.source === null ? secret : view.source!.row;
  if (value === null) return 'ended';
  // A reference whose end its row says (`ended_at`): no version of its own, no source. 0.14's `reference.end`.
  if (secret.source === null && secret.version === '') return 'ended';
  // A reference reads a key's own value: one to another reference is none the change path makes.
  if (value.source !== null && secret.source !== null) return 'bad_claim';
  // A use opens a wrapped key: a plain value, which 0.14's vault never decides either, is the app's to hand back.
  if (value.key === null) return 'bad_claim';
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
