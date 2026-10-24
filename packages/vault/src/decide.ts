import { allows, ownsProject, readsSensitive, withinCredential, type Holdings, type Permission, type Place } from '@coffre/core/access';
import { handsBack, type Access, type RefusalCode } from '@coffre/core/vault';
import type { EnvironmentRow } from './store.ts';

/**
 * How the vault decides each key of one call, as functions of what the
 * decision read and nothing else: the rest of `#keys` reads, locks and
 * logs around them. Pure, so that `formal/lean` holds them to its model
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
  const held = at.environmentId === secret.environmentId ? own : environments.get(at.environmentId);
  if (own?.owner == null && held?.owner == null) return undefined;
  if (own !== held || principal !== own?.owner || own.parentId === null) return 'personal';
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
 * it keeps it sensitive: an app of 0.9, mid-deploy, would write the copy as
 * a secret its people read.
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
  },
): (RefusalCode | null)[] {
  const copying = call.action === 'secret.read' && call.purpose === 'copy';
  const handedBack = call.action === 'secret.read' && handsBack({ purpose: call.purpose ?? '', keepsSensitive: call.keepsSensitive === true });
  const person = call.principal.startsWith('user:');
  return call.secrets.map((secret, i) => {
    const code = codes[i] ?? null;
    if (code !== null || secret.sensitive !== true) return code;
    if ((copying && call.keepsSensitive !== true) || (handedBack && person)) return 'sensitive';
    if (handedBack && !readsSensitive(reader.live, secret.projectId)) return 'not_owner_issued';
    return null;
  });
}
