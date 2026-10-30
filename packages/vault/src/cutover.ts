import { randomUUID } from 'node:crypto';

import { deletedWithProject, isTombstone, TOMBSTONE } from '@coffre/core/schemas';
import type { CutoverInput, PolicyEdits } from '@coffre/core/vault';
import type { GrantRow } from '@coffre/db/grants';

import { genesisCall, payloadOf, type ChangeKeys } from './changes.ts';
import type { BulkLimit } from './config.ts';
import { canonical, objectKey, sealOf, type Input, type Ref, type RolesInput } from './inputs.ts';
import { CUTOVER_ACTOR, CUTOVER_OBJECT, entryMac } from './log-entry.ts';
import { bindingObject, connectionObject, credentialObject, environmentObject, principalObject, secretObject } from './objects.ts';
import type { BindingRead, ChangeCall, ConnectionRead, CredentialRead, EnvironmentRead, Member, ProjectRow, SecretRead } from './store.ts';

export { CUTOVER_ACTOR, CUTOVER_OBJECT };

/**
 * 0.15's cutover from 0.14 (docs/design/0.15-plan.md, PR 9;
 * formal/Migration015.tla): the rows 0.14 left, read and held to what 0.14
 * accepts, and the log's first changes made of them. The vault does it once,
 * at its first start with 0.15's log, when the app asks (`Vault.cutover`),
 * under every member's row, 0.14's head, the issue lock and the fence; this
 * module is its reads and writes, and its plan, pure, of what to seal.
 *
 * Each object 0.15's log has no change of, and whose row carries no seal:
 * - **a member** (principal), if 0.14's own check holds (`#integrity`: its
 *   MAC, and it names its newest authentic access entry); its genesis names
 *   that entry (`old`), which a use holds 0.14's log to (UsesSeeOldWrites);
 * - **the roles**, from 0.14's newest authentic `policy.change`, and the
 *   **policy**, the deployment's bulk cap;
 * - **an environment**, its protection from that policy; deleted as 0.14's
 *   chain says, never its slugs (DeletedFromChain): a project's
 *   `project.delete`, the environment's own `environment.delete`, each
 *   checked by the app under its key. A tombstone with no entry, or an entry
 *   with no tombstone, refuses the cutover. A deleted project's standing
 *   environments are given `<slug>~deleted` (`deletedWithProject`), as 0.15
 *   deletes a project;
 * - **a key**, as its rows hold it, unless its place was deleted: then it is
 *   archived, if it was not, and has no object, as 0.15's deletion leaves it.
 *   An archived key gets its object and its `secret.delete` (T144), so its
 *   unarchive has something to restore. A reference row no authentic
 *   `reference.create` made is no object; one an authentic `reference.end`
 *   ended has its row's end written first (0029);
 * - **a credential**, **a binding** or **an MCP connection** the app
 *   vouched for under its key (`CutoverInput`), as it read it
 *   (VouchedHeld): its row must still be that, or the cutover asks the app
 *   again (`Moved`).
 *
 * A row 0.14 would not accept gets no genesis: its object stays unsealed,
 * every use of it `stale`, never sealed as a writer left it.
 */

/** Why the cutover asks the app again: a 0.14 write since what it vouched for was read. */
export class Moved extends Error {}

/** Why a cutover is refused: 0.14's chain or rows not as 0.14 accepts them. Nothing is sealed. */
export class CutoverRefused extends Error {}

/** The cutover's change: the head of 0.14's it names (its own `log.cutover` entry), and where its chain was verified from. */
export function cutoverPayload(anchor: { seq: bigint; hash: Buffer }, from: { seq: bigint; hash: Buffer }): string {
  return canonical({
    op: 'cutover',
    anchor: { seq: anchor.seq.toString(), hash: anchor.hash.toString('hex') },
    from: { seq: from.seq.toString(), hash: from.hash.toString('hex') },
  });
}

/** The cutover's change, MAC'd as any entry of the changes tree. */
export function cutoverRow(keys: ChangeKeys, at: number, payload: string): { requestId: string; at: number; actor: string; payload: string; mac: Buffer } {
  const row = { at, requestId: randomUUID(), object: CUTOVER_OBJECT, actor: CUTOVER_ACTOR, payload, seal: null };
  return { requestId: row.requestId, at, actor: CUTOVER_ACTOR, payload, mac: entryMac(keys.mac, { tree: 'changes', row }) };
}

// --- what it seals ------------------------------------------------------------

/** What 0.14 holds that the cutover seals, read under its locks, and what was checked of it. */
export type CutoverFacts = {
  /** The objects the log has a change of: 0.15's already, never sealed again. */
  logged: ReadonlySet<string>;
  /** The rows of `log_config` there are, by name: the roles' and the policy's, which only a change writes. */
  config: ReadonlySet<string>;
  /** Each member, with their grants, their row's seal, and whether 0.14's own check of them holds (`#integrity`). */
  members: readonly { member: Member; grants: readonly GrantRow[]; seal: Buffer | null; genuine: boolean }[];
  /** The roles an Owner edited, and the environments protected, as 0.14's newest authentic `policy.change` says, and its number. */
  edits: PolicyEdits;
  policySeq: bigint | null;
  /** The deployment's bulk cap. */
  bulk: BulkLimit;
  projects: readonly ProjectRow[];
  environments: readonly EnvironmentRead[];
  secrets: readonly SecretRead[];
  /** Each reference row's `reference.create`, by that entry's number: whether it is the vault's, about that row, and whether an authentic `reference.end` ended it. */
  references: ReadonlyMap<string, { authentic: boolean; ended: boolean }>;
  /** What the app vouched for. */
  input: CutoverInput;
  credentials: ReadonlyMap<string, CredentialRead>;
  bindings: ReadonlyMap<string, BindingRead>;
  connections: ReadonlyMap<string, ConnectionRead>;
};

/** One object's genesis: its object, the 0.14 entry it accounts for, and, for an archived key, its delete after. */
export type Genesis = { ref: Ref; object: Input; old?: bigint; deleted?: true };

export type CutoverPlan = {
  /** Each standing environment of a deleted project, to be given `<slug>~deleted`, and each live key under a deleted place, to be archived. */
  rename: string[];
  archive: string[];
  /** Reference rows an authentic `reference.end` ended, to be marked so before their holders' genesis. */
  ends: string[];
  genesis: Genesis[];
  bindings: Genesis[];
  /** Objects left unsealed, and why: 0.14 would not accept them as they are (`stale`), or no one but a writer made them (`tampered`). */
  skipped: { ref: Ref; why: string; fault: 'stale' | 'tampered' }[];
};

/**
 * What the cutover seals, from `facts`: pure. Throws `CutoverRefused` for
 * a place whose deletion its chain and its slugs disagree about, and `Moved`
 * for a row the app vouched for that is not as it read it.
 */
export function planCutover(facts: CutoverFacts): CutoverPlan {
  const plan: CutoverPlan = { rename: [], archive: [], ends: [], genesis: [], bindings: [], skipped: [] };
  const fresh = (ref: Ref, seal: Buffer | null) => seal === null && !facts.logged.has(objectKey(ref));

  for (const { member, grants, seal, genuine } of facts.members) {
    const ref: Ref = { kind: 'principal', id: member.principal };
    if (!fresh(ref, seal)) continue;
    if (!genuine) {
      plan.skipped.push({ ref, why: "0.14's check of their row fails (#integrity)", fault: 'stale' });
      continue;
    }
    plan.genesis.push({ ref, object: principalObject(member, grants), old: member.accessSeq });
  }

  // The roles and the policy, made from 0.14's policy and the deployment's cap: a row of either no change made was planted.
  const policySeq = facts.policySeq ?? undefined;
  const config = (ref: Ref, object: Input, old?: bigint) => {
    if (facts.logged.has(objectKey(ref))) return;
    if (facts.config.has(ref.kind)) plan.skipped.push({ ref, why: 'its row no change made', fault: 'tampered' });
    else plan.genesis.push({ ref, object, ...(old === undefined ? {} : { old }) });
  };
  config({ kind: 'roles', id: 'instance' }, { kind: 'roles', roles: { ...facts.edits.roles }, instanceRoles: { ...facts.edits.instanceRoles } } satisfies RolesInput, policySeq);
  config({ kind: 'policy', id: 'instance' }, { kind: 'policy', bulk: { count: facts.bulk.count, windowMs: facts.bulk.windowMs } });

  // Deleted as 0.14's chain says (DeletedFromChain): each tombstone the chain's, each of the chain's deletions a tombstone.
  const deletedProjects = new Map(facts.input.deleted.filter((place) => place.kind === 'project').map((place) => [place.id, place.tombstone]));
  const deletedAlone = new Map(facts.input.deleted.filter((place) => place.kind === 'environment').map((place) => [place.id, place.tombstone]));
  const projects = new Map(facts.projects.map((project) => [project.id, project]));
  for (const project of facts.projects) {
    const tombstone = deletedProjects.get(project.id);
    if (tombstone === undefined ? isTombstone(project.slug) : project.slug !== tombstone) {
      throw new CutoverRefused(`the project ${project.id}'s slug, ${project.slug}, is ${tombstone === undefined ? 'a tombstone no authentic project.delete gave it' : `not the tombstone its project.delete gave it, ${tombstone}`}`);
    }
  }
  const deletedPlace = new Map<string, boolean>();
  for (const environment of facts.environments) {
    const ownTombstone = deletedAlone.get(environment.id);
    const withProject = deletedProjects.has(environment.projectId);
    if (ownTombstone !== undefined ? environment.slug !== ownTombstone : isTombstone(environment.slug) && !(withProject && environment.slug === deletedWithProject(baseSlug(environment.slug)))) {
      throw new CutoverRefused(`the environment ${environment.id}'s slug, ${environment.slug}, is ${ownTombstone === undefined ? 'a tombstone no authentic deletion gave it' : `not the tombstone its environment.delete gave it, ${ownTombstone}`}`);
    }
    deletedPlace.set(environment.id, ownTombstone !== undefined || withProject);
    const ref: Ref = { kind: 'environment', id: environment.id };
    if (!fresh(ref, environment.seal)) continue;
    let { slug } = environment;
    if (withProject && !isTombstone(slug)) {
      plan.rename.push(environment.id);
      slug = deletedWithProject(slug);
    }
    const object = environmentObject({
      id: environment.id, projectId: environment.projectId, slug, owner: environment.owner, parentId: environment.parentId,
      protected: facts.edits.protected.some((place) => place.environmentId === environment.id), archived: environment.archived,
      projectArchived: projects.get(environment.projectId)?.archived ?? false,
    });
    plan.genesis.push({ ref, object, ...(policySeq === undefined ? {} : { old: policySeq }) });
  }

  for (const secret of facts.secrets) {
    const ref: Ref = { kind: 'secret', id: secret.id };
    if (!fresh(ref, secret.seal)) continue;
    // Under a place deleted: no object, as 0.15's deletion leaves its keys (archived, their versions erased).
    if (deletedPlace.get(secret.environmentId) !== false) {
      if (!secret.archived && deletedPlace.get(secret.environmentId) === true) plan.archive.push(secret.id);
      if (deletedPlace.get(secret.environmentId) === undefined) plan.skipped.push({ ref, why: 'its environment has no row', fault: 'stale' });
      continue;
    }
    let reads: { source: string | null; reference: string | null } = { source: null, reference: null };
    if (secret.version === null && secret.reference !== null) {
      const made = facts.references.get(secret.reference.createdSeq.toString());
      if (made?.authentic !== true) {
        plan.skipped.push({ ref, why: `its reference row ${secret.reference.id} is no authentic reference.create's`, fault: 'tampered' });
        continue;
      }
      // Its row says it ended where 0.14's log has no end of it: 0.14 still reads through it (review r6). Not sealed.
      if (secret.reference.ended && !made.ended) {
        plan.skipped.push({ ref, why: `its reference row ${secret.reference.id} says it ended, which no reference.end does`, fault: 'tampered' });
        continue;
      }
      // Ended by an authentic `reference.end`: its row says so first (0029's `end_reference`), and the key reads nothing.
      if (made.ended && !secret.reference.ended) plan.ends.push(secret.reference.id);
      if (!made.ended && !secret.reference.ended) reads = { source: secret.reference.source, reference: secret.reference.id };
    }
    // Its current version not its newest: rolled back around the app, which 0.14 refuses to read through a reference.
    if (!secret.newest) {
      plan.skipped.push({ ref, why: 'its current version is not its newest', fault: 'stale' });
      continue;
    }
    const object = secretObject({ id: secret.id, projectId: secret.projectId, environmentId: secret.environmentId, ...reads, version: secret.version });
    plan.genesis.push(secret.archived ? { ref, object, deleted: true } : { ref, object });
  }

  // What the app vouched for, held to its rows as it read them (VouchedHeld).
  for (const vouched of facts.input.credentials) {
    const ref: Ref = { kind: 'credential', id: vouched.id };
    const read = facts.credentials.get(vouched.id);
    if (read === undefined) throw new Moved(`the credential ${vouched.id} the app vouched for has no row now`);
    if (read.logged || read.seal !== null || facts.logged.has(objectKey(ref))) continue;
    if (canonical(read.columns) !== canonical(vouched)) throw new Moved(`the credential ${vouched.id}'s row moved since the app vouched for it`);
    plan.genesis.push({ ref, object: credentialObject(read.columns) });
  }
  for (const vouched of facts.input.connections) {
    const ref: Ref = { kind: 'connection', id: vouched.id };
    const read = facts.connections.get(vouched.id);
    if (read === undefined) throw new Moved(`the connection ${vouched.id} the app vouched for has no row now`);
    if (read.logged || read.seal !== null || facts.logged.has(objectKey(ref))) continue;
    if (canonical(read.columns) !== canonical(vouched) || read.columns.revoked) throw new Moved(`the connection ${vouched.id}'s row moved since the app vouched for it`);
    plan.genesis.push({ ref, object: connectionObject(read.columns) });
  }
  for (const vouched of facts.input.bindings) {
    const ref: Ref = { kind: 'binding', id: vouched.id };
    const read = facts.bindings.get(vouched.id);
    if (read === undefined) throw new Moved(`the binding ${vouched.id} the app vouched for has no row now`);
    if (read.logged || read.seal !== null || facts.logged.has(objectKey(ref))) continue;
    // The instance it was made on: the deployment's public URL, as the app vouched for it (T160), which its genesis writes
    // beside its seal. 0.14 writes none, and its MAC covers none: a row with one is not 0.14's.
    const { origin: _, ...columns } = vouched;
    if (read.origin !== null) {
      plan.skipped.push({ ref, why: 'it names an instance, which no binding of 0.14 does', fault: 'tampered' });
      continue;
    }
    if (canonical(read.columns) !== canonical(columns) || read.columns.revoked) throw new Moved(`the binding ${vouched.id}'s row moved since the app vouched for it`);
    plan.bindings.push({ ref, object: bindingObject({ ...read.columns, origin: vouched.origin }) });
  }
  return plan;
}

/** Each genesis as the change path's calls (`change_input`), an archived key's delete after its own, from the seal it leaves. */
export function genesisCalls(keys: ChangeKeys, genesis: readonly Genesis[], at: number): ChangeCall[] {
  return genesis.flatMap(({ ref, object, old, deleted }) => {
    const made = genesisCall(keys, ref, object, at, CUTOVER_ACTOR, old);
    if (deleted !== true) return [made];
    const row = { at, requestId: randomUUID(), object: objectKey(ref), actor: CUTOVER_ACTOR, payload: payloadOf(ref, { op: 'secret.delete' }), seal: null };
    return [made, { ref, ...row, value: null, sealFrom: sealOf(keys.seals[0]!, ref, object), mac: entryMac(keys.mac, { tree: 'changes', row }) }];
  });
}

function baseSlug(slug: string): string {
  const at = slug.indexOf(TOMBSTONE);
  return at < 0 ? slug : slug.slice(0, at);
}
