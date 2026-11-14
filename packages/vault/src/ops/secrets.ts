import { randomUUID } from 'node:crypto';

import { allows, useOnly, type Permission } from '@coffre/core/access';
import type { Answers, KeyWrite, Nature, Presented, ReferenceBreak, SecretPath, SecretRefile, SecretsChanges, SecretWrite } from '@coffre/core/vault';
import { dismissedKeys, environments, projects, secrets, secretVersions } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerFrom, callerParts, live, refusedTo } from '../caller.ts';
import { amended, part, put, type Operation, type Parts, type Seen, type Value, type Write } from '../change.ts';
import type { Fresh, Row } from '../rows.ts';
import { natureOf } from '../value.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { KEY, presented, text } from './input.ts';

/** The app's own bounds (its routes'): a value's length in characters, the keys of one write, and a request's body, which every value of a write came in. */
const VALUE_LENGTH = 64 * 1024;
const MOST_KEYS = 2000;
const WRITE_BYTES = 1024 * 1024;
/** The most a value weighs in UTF-8, 3 bytes a UTF-16 unit: what a version restored counts for, which is read only after the count. */
const VALUE_BYTES = 3 * VALUE_LENGTH;
const NATURES = ['secret', 'sensitive', 'plain'];
/** The most a version's number is, as Postgres keeps it. */
const MOST_VERSION = 2 ** 31 - 1;
/** How many environments a key is inherited through, as a use reads them (use.ts). */
const MAX_PARENTS = 3;

/** Text as Postgres stores it and a reader gets it back: no NUL, no half of a surrogate pair. */
const wellFormed = (value: string) => !value.includes('\0') && Buffer.from(value).toString() === value;
const written = (value: unknown): value is string => typeof value === 'string' && value.length <= VALUE_LENGTH && wellFormed(value);
/** A folder as the app's routes have it (`folderName`), within the table's check: 1 to 64 UTF-16 units, no slash or control character, nothing `trim` takes away. */
const filed = (value: unknown) => value === null || (typeof value === 'string' && wellFormed(value) && value.length >= 1 && value.length <= 64 && !/[/\p{Cc}]/u.test(value) && value === value.trim());

const wrong = () => new TypeError('a write names a place by its slugs and 1 to 2,000 keys, each once, with a value of well-formed text, 64 Ki characters at most and 1 MiB in all, a version restored counted as 192 KiB, the most a value weighs, and its nature if any, a version to restore, or a reference to a key by its slugs and name, an archiving or a folder');

/** A key named where it is held: its project's and environment's slugs, and its name. */
const located = (path: unknown): path is SecretPath =>
  typeof path === 'object' && path !== null && text((path as SecretPath).project) && text((path as SecretPath).environment) && typeof (path as SecretPath).key === 'string' && KEY.test((path as SecretPath).key);

/** One key's item, on its own: what it does, with what it says it with. */
function valid(item: KeyWrite): boolean {
  if (typeof item !== 'object' || item === null || typeof item.key !== 'string' || !KEY.test(item.key)) return false;
  if (!(item.archived === undefined || typeof item.archived === 'boolean') || !(item.folder === undefined || filed(item.folder))) return false;
  // A key is archived with no value written over it or restored, and made no reference.
  if (item.value !== undefined) return written(item.value) && (item.nature === undefined || NATURES.includes(item.nature)) && item.ref === undefined && item.restore === undefined && item.archived !== true;
  if (item.restore !== undefined) return Number.isSafeInteger(item.restore) && item.restore >= 1 && item.restore <= MOST_VERSION && item.nature === undefined && item.ref === undefined && item.archived !== true;
  if (item.ref !== undefined) return located(item.ref) && item.nature === undefined && item.archived !== true;
  return item.nature === undefined && (item.archived !== undefined || item.folder !== undefined);
}

/**
 * Keys written in one environment (docs/design/0.16.md, "A change"), all
 * of them or none, one line each in one entry: a key's next version, the
 * key made where the environment has none by that name; its archiving, or
 * its return; the folder it is listed in. A value or a folder takes
 * `secret.write` there, an archiving or a return `secret.archive`, and a
 * return `secret.read` too: the value serves again, to whoever reads the
 * environment now, granted since it was archived included, so only whoever
 * could read it brings it back. 0.14 asked that of a secret, `secret.use`
 * of a sensitive value and nothing more of a plain one or of none; this
 * asks `secret.read` of each. A key that was a reference holds its own value
 * from a write on.
 *
 * A version restored (0.14's `restoreVersion`) is the key's next one, its
 * value opened and sealed again by the engine (`Value`'s `copy`), which the
 * decision never holds. It takes `secret.write` and `secret.read`: the old
 * value serves again, so whoever brings it back could read it. 0.14 asked
 * `secret.use` of a sensitive one and nothing of a plain one; this asks
 * `secret.read` of each, as a return does. The value comes back as it was
 * kept, as its version's row labels it, which its opening holds that row
 * to; and sensitive while the key is, as a value written with no nature
 * finds it (below), or while its newest version's row says its value was:
 * a key made a reference keeps that, with no MAC, so the engine opens that
 * version as labelled before the write (`vouched`), and one relabelled
 * refuses the restore, `unreadable`. A value written again as sensitive is a new value to
 * the vault: an older version of the same text comes back as it was kept,
 * where 0.14 knew it by its ciphertext. Its first date is its source's.
 * Made by a recipe or in a pair, it comes back as typed: Regenerate would
 * make a value of another kind of what the row says, and a half would pair
 * with a half it no longer matches.
 *
 * A key made a reference (0.14's `referenceTargets` and the vault's
 * `referenceRefusal`) takes `secret.write` here, and `secret.read` where its
 * source is, `secret.use` too for a sensitive one: its maker hands the value
 * to whoever reads here. The source is a key of a live project and
 * environment, no personal config's, as is the key made one; it is no
 * reference, and nor is the key made one read by one: one hop. Each is
 * decided on what the write leaves, its other keys included. A reference
 * held elsewhere whose row the vault does not see reads nothing through a
 * second hop either (use.ts): the check that none would is a courtesy to its
 * readers, as an archive's is.
 *
 * A value written with no nature is never looser than the key's value was,
 * as its sealed row says (0.14.7's `bareLevel`): sensitive stays sensitive,
 * and anything else is a secret, a plain value's included, since plain is
 * kept only where a write says so. A key the environment does not hold
 * yet is what it inherits, as a use finds it (use.ts): the nearest parent's
 * key by that name, unless a fork on the way dismissed it; a key inherited
 * from nowhere is a secret. An archived key the environment brings back
 * with a value read what it inherits until then: it is as sensitive as either
 * its own or that. A reference's is its source's, whose row the
 * reference cannot be without. A row the vault does not see, the key's own, a source or a
 * parent, refuses the write, `unreadable`, rather than guess.
 */
function secretWrite(input: Presented & SecretWrite, vault: Deciding): Operation<Parts, Answers['secret.write']> {
  const shown = presented(input);
  const { project: projectSlug, environment: environmentSlug, keys } = input;
  const items = Array.isArray(keys) ? [...keys] : [];
  if (!text(projectSlug) || !text(environmentSlug) || items.length === 0 || items.length > MOST_KEYS || !items.every(valid) || new Set(items.map((item) => item.key)).size !== items.length
    || items.reduce((sum, item) => sum + (item.restore === undefined ? Buffer.byteLength(item.value ?? '') : VALUE_BYTES), 0) > WRITE_BYTES) {
    throw wrong();
  }
  // A key the environment does not have yet is made under an id drawn here: a decision draws nothing.
  const fresh = new Map(items.map((item) => [item.key, { secret: randomUUID(), version: randomUUID() }]));
  const needs = new Set<Permission>(items.flatMap((item): Permission[] => [
    ...(item.value !== undefined || item.restore !== undefined || item.ref !== undefined || item.folder !== undefined ? ['secret.write' as const] : []),
    ...(item.archived === undefined ? [] : ['secret.archive' as const]),
    ...(item.archived === false || item.restore !== undefined ? ['secret.read' as const] : []),
  ]));
  const archiving = items.flatMap((item) => (item.archived === true ? [item.key] : []));
  // The keys whose value comes with no nature said, typed or restored: what each is now decides it.
  const bare = items.flatMap((item) => ((item.value !== undefined && item.nature === undefined) || item.restore !== undefined ? [item.key] : []));
  const restores = items.flatMap((item) => (item.restore === undefined ? [] : [{ key: item.key, version: item.restore }]));
  const refs = items.flatMap((item) => (item.ref === undefined ? [] : [{ key: item.key, to: item.ref }]));
  // The keys whose readers decide: one archived stops them, and one made a reference would be a second hop for them.
  const stopping = [...archiving, ...refs.map((ref) => ref.key)];
  // A reference's source may be in another project, whose grants and protections the caller is weighed by too.
  const slugs = [...new Set([projectSlug, ...refs.map((ref) => ref.to.project)])];

  const project = sql`(SELECT p.id FROM projects p WHERE p.slug = ${projectSlug})`;
  const here = sql`(SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${environmentSlug})`;
  // The environment and those it inherits from, for a bare value only: what it is written over may be a parent's.
  const chain = sql`(WITH RECURSIVE chain (id, parent_id, depth) AS (
    SELECT e.id, e.parent_id, 0 FROM environments e WHERE ${bare.length > 0 ? sql`true` : sql`false`} AND e.id = ${here}
    UNION SELECT e.id, e.parent_id, chain.depth + 1 FROM environments e JOIN chain ON e.id = chain.parent_id WHERE chain.depth < ${MAX_PARENTS}
  ) SELECT id FROM chain)`;
  // The references that read a key this write archives or makes a reference, from wherever they are held.
  const readers = sql`(SELECT r.id FROM secrets r WHERE r.source_id IN (SELECT s.id FROM secrets s WHERE s.project_id = ${project} AND s.environment_id = ${here} AND s.key = ANY(${sql.param(stopping)}::text[])))`;
  // Where each source is said to be, found by slugs: the decision holds every row found to what it is asked, by its MAC.
  const sourcePlaces = sql`(SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE (p.slug, e.slug) IN (SELECT * FROM unnest(${sql.param(refs.map((ref) => ref.to.project))}::text[], ${sql.param(refs.map((ref) => ref.to.environment))}::text[])))`;
  const read = {
    ...callerParts(shown.token, sql`(SELECT p.id FROM projects p WHERE p.slug = ANY(${sql.param(slugs)}::text[]))`),
    project: part(projects, sql`${projects.slug} = ANY(${sql.param(slugs)}::text[])`),
    environment: part(environments, sql`${environments.projectId} = ${project} AND ${environments.slug} = ${environmentSlug}`),
    secret: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} = ${here} AND ${secrets.key} = ANY(${sql.param(items.map((item) => item.key))}::text[])`),
    parent: part(environments, sql`${environments.id} IN ${chain} AND ${environments.id} <> ${here}`),
    // What a key written with no nature is now where the environment holds none: a parent's, unless dismissed on the way.
    inherited: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} IN ${chain} AND ${secrets.environmentId} <> ${here} AND ${secrets.key} = ANY(${sql.param(bare)}::text[])`),
    dismissed: part(dismissedKeys, sql`${dismissedKeys.environmentId} IN ${chain} AND ${dismissedKeys.key} = ANY(${sql.param(bare)}::text[])`),
    // What a key written with no nature refers to, its own or the one it inherits, if a reference: its value's nature is the source's.
    source: part(secrets, sql`${secrets.id} IN (SELECT s.source_id FROM secrets s WHERE s.project_id = ${project} AND s.environment_id IN ${chain} AND s.key = ANY(${sql.param(bare)}::text[]))`),
    // Each key a reference is made to, and where it is.
    target: part(secrets, sql`${secrets.id} IN (SELECT s.id FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = e.project_id
      WHERE (p.slug, e.slug, s.key) IN (SELECT * FROM unnest(${sql.param(refs.map((ref) => ref.to.project))}::text[], ${sql.param(refs.map((ref) => ref.to.environment))}::text[], ${sql.param(refs.map((ref) => ref.to.key))}::text[])))`),
    targetPlace: part(environments, sql`${environments.id} IN ${sourcePlaces}`),
    reader: part(secrets, sql`${secrets.id} IN ${readers}`),
    readerPlace: part(environments, sql`${environments.id} IN (SELECT r.environment_id FROM secrets r WHERE r.id IN ${readers})`),
    readerProject: part(projects, sql`${projects.id} IN (SELECT r.project_id FROM secrets r WHERE r.id IN ${readers})`),
    // Each version restored, and its key's newest: by number, as the key's sealed row counts them.
    version: part(secretVersions, sql`(${secretVersions.secretId}, ${secretVersions.version}) IN (SELECT s.id, r.version FROM secrets s
      JOIN unnest(${sql.param(restores.map((each) => each.key))}::text[], ${sql.param(restores.map((each) => each.version))}::int[]) AS r (key, version) ON r.key = s.key
      WHERE s.project_id = ${project} AND s.environment_id = ${here}
      UNION SELECT s.id, s.versions FROM secrets s WHERE s.project_id = ${project} AND s.environment_id = ${here} AND s.key = ANY(${sql.param(restores.map((each) => each.key))}::text[]))`),
  };
  /** The place asked about, as far as it is there. */
  const placed = (seen: Seen<typeof read>) => {
    const place = seen.project.find((row) => row.slug === projectSlug && live(row));
    return { place, environment: place && seen.environment.find((row) => row.projectId === place.id && row.slug === environmentSlug && live(row)) };
  };
  return {
    read,
    denied: refusedTo('secret.write', shown, vault.workloads, {
      where: { project: projectSlug, environment: environmentSlug },
      objects: (seen: Seen<typeof read>) => {
        const { place, environment } = placed(seen);
        return [...(place === undefined ? [] : [`project:${place.id}`]), ...(environment === undefined ? [] : [`environment:${environment.id}`])];
      },
    }),
    decide(seen: Seen<typeof read>, at: number, unsealed) {
      const caller = callerFrom(seen, shown, vault.workloads, at);
      if (caller === null) return { refused: 'unauthenticated' };
      if (caller.workload?.stop != null) return { refused: caller.workload.stop };
      // A narrowed session uses values, and changes nothing.
      if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
      const { place, environment } = placed(seen);
      // The same answer whether the place is not there, is someone's personal config, or is not theirs to write in: none says which.
      if (place === undefined || environment === undefined || environment.owner !== null || ![...needs].every((permission) => caller.may(permission, environment))) return { refused: 'no_access' };
      // A key's own row edited behind the vault still holds its name: the key is neither made again nor guessed at.
      if (unsealed.secret > 0) return { refused: 'unreadable' };
      // Each reference's source, as its rows say: a live key of a live place, no personal config's, that the caller reads there.
      const targets = new Map<string, { row: Row<typeof secrets>; where: Row<typeof environments> }>();
      for (const { key, to } of refs) {
        const whose = seen.project.find((row) => row.slug === to.project && live(row));
        const where = whose && seen.targetPlace.find((row) => row.projectId === whose.id && row.slug === to.environment && live(row));
        // As for the place written: not there, someone's personal config, or not theirs to read are one answer.
        if (where === undefined || where.owner !== null || !caller.may('secret.read', where)) return { refused: 'no_access' };
        // Archived or not: whether it is is asked of what the write leaves, which may bring it back.
        const row = seen.target.find((found) => found.projectId === where.projectId && found.environmentId === where.id && found.key === to.key);
        // A source's row edited behind the vault is not guessed at either.
        if (row === undefined) return { refused: unsealed.target > 0 ? 'unreadable' : 'unknown_key' };
        targets.set(key, { row, where });
      }

      const now = new Date(at);
      const held = new Map(seen.secret.map((row) => [row.key, row]));
      const sources = new Map(seen.source.map((row) => [row.id, row]));
      const parents = new Map(seen.parent.map((row) => [row.id, row]));
      const inherited = new Map(seen.inherited.filter((row) => row.archivedAt === null).map((row) => [`${row.environmentId} ${row.key}`, row]));
      const dismissed = new Set(seen.dismissed.filter((row) => row.restoredAt === null).map((row) => `${row.environmentId} ${row.key}`));
      // A parent, a key or a dismissal edited behind the vault may be what decides a nature: none is guessed.
      const blind = unsealed.parent + unsealed.inherited + unsealed.dismissed > 0;
      /** The key a key the environment does not hold reads, as a use finds it: null for none, undefined for one the vault cannot tell. */
      const passedDown = (key: string): Row<typeof secrets> | null | undefined => {
        if (blind) return undefined;
        for (let layer = environment, depth = 0; !dismissed.has(`${layer.id} ${key}`) && layer.parentId !== null; depth += 1) {
          const parent = parents.get(layer.parentId);
          if (parent === undefined || parent.projectId !== place.id || depth >= MAX_PARENTS) return undefined;
          const row = inherited.get(`${parent.id} ${key}`);
          if (row !== undefined) return row;
          layer = parent;
        }
        return null;
      };
      const writes: Write[] = [];
      const sealed: Value[] = [];
      const vouched: Row<typeof secretVersions>[] = [];
      const lines: Record<string, unknown>[] = [];
      const leaves = new Map<string, Fresh<typeof secrets>>();
      const answered: [string, { version: number; nature: Nature }][] = [];
      const referring = new Set<string>();
      const versions = new Map(seen.version.map((row) => [`${row.secretId} ${row.version}`, row]));
      for (const { key, value, nature: asked, restore, ref, archived, folder } of items) {
        const was = held.get(key) ?? null;
        // Only a value or a reference makes a key: there is nothing else to archive, file or restore.
        if (was === null && value === undefined && ref === undefined) return { refused: 'unknown_key' };
        // An archived key keeps its name: it is brought back, not written over.
        if (was?.archivedAt != null && (value !== undefined || restore !== undefined || ref !== undefined) && archived !== false) return { refused: 'archived' };
        const ids = fresh.get(key)!;
        const { mac: _, ...kept } = was ?? { mac: null, id: ids.secret, projectId: place.id, environmentId: environment.id, key, createdAt: now, updatedAt: now, versions: 0, currentVersion: null, archivedAt: null, folder: null, sourceId: null, nature: null, recipe: null, pairId: null, pairHalf: null };
        let secret: Fresh<typeof secrets> = { ...kept, archivedAt: archived === undefined ? kept.archivedAt : archived ? (kept.archivedAt ?? now) : null, folder: folder === undefined ? kept.folder : folder };
        const line: Record<string, unknown> = { key, secret: secret.id };
        if (value !== undefined || restore !== undefined) {
          // The version restored, which the key's sealed row counts, and its newest: a row of either gone behind the vault is not guessed at.
          const from = restore === undefined ? undefined : versions.get(`${kept.id} ${restore}`);
          const newest = restore === undefined ? undefined : versions.get(`${kept.id} ${kept.versions}`);
          if (restore !== undefined && restore > kept.versions) return { refused: 'unknown_version' };
          if (restore !== undefined && (from === undefined || newest === undefined)) return { refused: 'unreadable' };
          // What the key's value is now: its own, or what it inherits, and either one's source's: a source is never deleted while referred to.
          // An archived key read what it inherits, and is brought back as its own: it is as sensitive as either.
          const current = asked !== undefined ? [] : was === null ? [passedDown(key)] : was.archivedAt === null ? [kept] : [kept, passedDown(key)];
          const natures = current.map((row) => (row == null || row.sourceId === null ? row : sources.get(row.sourceId)));
          if (natures.includes(undefined)) return { refused: 'unreadable' };
          // The key's newest value, whose nature its sealed row says while that is its value. Once it holds none of its own (made a
          // reference, or one broken), only the version's row says it, under no MAC: its encryption is held to it (`vouched`).
          const unsaid = restore !== undefined && kept.currentVersion !== kept.versions ? newest : undefined;
          if (unsaid !== undefined && unsaid !== from) vouched.push(unsaid);
          const sticks = natures.some((row) => row?.nature === 'sensitive') || unsaid?.sensitive === true;
          const nature: Nature = asked ?? (sticks ? 'sensitive' : from === undefined ? 'secret' : natureOf(from));
          const version = kept.versions + 1;
          // Typed or restored, not generated: no recipe for Regenerate, and in no pair.
          secret = { ...secret, versions: version, currentVersion: version, updatedAt: now, sourceId: null, nature, recipe: null, pairId: null, pairHalf: null };
          const row = { id: ids.version, secretId: secret.id, version, createdAt: now, createdBy: caller.principal, sensitive: nature === 'sensitive' };
          sealed.push(from === undefined
            ? { version: { ...row, firstWrittenAt: now, plaintext: nature === 'plain' ? value! : null }, text: Buffer.from(value!) }
            // The value is its source's, and so is the date it was first written to the key.
            : { version: { ...row, firstWrittenAt: from.firstWrittenAt, plaintext: nature === 'plain' ? from.plaintext : null }, copy: from });
          answered.push([key, { version, nature }]);
          // `restored`: the version whose value it is; `source`: the secret it referred to until now.
          Object.assign(line, { version, nature }, was === null ? { made: true } : {}, restore === undefined ? {} : { restored: restore }, was?.sourceId == null ? {} : { source: was.sourceId });
        }
        const target = ref === undefined ? undefined : targets.get(key)!.row;
        // A key that reads that source already is left as it is.
        if (target !== undefined && kept.sourceId !== target.id) {
          // Its own value, if any, is history: the key has none now, and reads the source's.
          secret = { ...secret, updatedAt: now, sourceId: target.id, currentVersion: null, nature: null, recipe: null, pairId: null, pairHalf: null };
          // `refers`: the secret it reads from now on; `source`, the one it read until now.
          Object.assign(line, { refers: target.id }, was === null ? { made: true } : {}, was?.sourceId == null ? {} : { source: was.sourceId });
          referring.add(key);
        }
        if ((secret.archivedAt === null) !== (kept.archivedAt === null)) line.archived = secret.archivedAt !== null;
        if (secret.folder !== kept.folder) line.folder = secret.folder;
        // What changes nothing writes nothing: archived already, filed where it is.
        if (Object.keys(line).length === 2) continue;
        writes.push(put(secrets, secret, was));
        leaves.set(secret.id, secret);
        lines.push(line);
      }
      // The keys live references read, as the write leaves them: one held in a key, an environment or a project
      // archived or deleted reads nothing. A place not found is not known to be one.
      const gone = (row: { slug: string; archivedAt: Date | null } | undefined) => row !== undefined && !live(row);
      const reading = new Set<string>();
      for (const row of [...seen.reader, ...leaves.values()]) {
        const reader = leaves.get(row.id) ?? row;
        if (reader.sourceId !== null && reader.archivedAt === null && !gone(seen.readerPlace.find((where) => where.id === reader.environmentId))
          && !gone(seen.readerProject.find((whose) => whose.id === reader.projectId))) reading.add(reader.sourceId);
      }
      // A key archived stops every reference that reads it, so it is not while one does.
      if (lines.some((line) => line.archived === true && reading.has(line.secret as string))) return { refused: 'referenced' };
      const also = new Set<string>();
      for (const { key } of refs) {
        const { row, where } = targets.get(key)!;
        const holder = held.get(key)?.id ?? fresh.get(key)!.secret;
        const source = leaves.get(row.id) ?? row;
        // An archived key is no source, unless the same write brings it back.
        if (source.archivedAt !== null) return { refused: 'unknown_key' };
        if (source.id === holder) return { refused: 'reference_to_itself' };
        // One hop: a reference reads a value, never another reference, nor is one read through.
        if (source.sourceId !== null) return { refused: 'reference_to_reference' };
        if (reading.has(holder)) return { refused: 'referenced' };
        // Its maker hands the source's value to whoever reads here: they read it there, and use it there too if it is
        // sensitive, which nobody reads. A workload refers only to a value it is handed back where it is held: it would
        // otherwise move one it only uses to a place whose keys it reads.
        if (source.nature === 'sensitive' && !caller.may('secret.use', where)) return { refused: 'no_access' };
        if (source.nature !== 'plain' && useOnly(caller.holds, { projectId: source.projectId, environmentId: source.environmentId, secretId: source.id })) return { refused: 'use_only' };
        // Its source's pages find the entry of a reference made too.
        if (referring.has(key)) for (const object of [`project:${where.projectId}`, `environment:${where.id}`, `secret:${source.id}`]) also.add(object);
      }
      return {
        writes,
        values: sealed,
        vouched,
        entry: {
          kept: true,
          action: 'secret.write',
          actor: caller.principal,
          credential: caller.credential.id,
          request: shown.request,
          ip: shown.ip,
          objects: [...new Set([`project:${place.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...lines.map((line) => `secret:${line.secret as string}`), ...also])],
          detail: { keys: lines },
        },
        // As entries: a key named `__proto__` is a key like any other.
        answer: { keys: Object.fromEntries(answered) },
      };
    },
  };
}

/**
 * A folder of one environment's keys renamed, or emptied (0.14's
 * `refileSecrets`): every key filed there, archived ones too, in one
 * change, by whoever writes keys there, as filing one key takes. Half a
 * folder renamed would be two folders, and a row's folder is only known
 * once its MAC holds: a row edited behind the vault may have been filed
 * there, or moved out, so the environment's keys are read whole, and one
 * row that does not hold refuses the refile, `unreadable`, rather than
 * leave a key behind. A folder with no
 * key in it is `no_folder`, to whoever may write there; to anyone else, as
 * for a place that is not there, `no_access`.
 */
function secretRefile(input: Presented & SecretRefile, vault: Deciding): Operation<Parts, Answers['secret.refile']> {
  const shown = presented(input);
  const { project: projectSlug, environment: environmentSlug, folder: from, to } = input;
  if (!text(projectSlug) || !text(environmentSlug) || from === null || !filed(from) || to === undefined || !filed(to)) {
    throw new TypeError('a folder of keys is named by its place\'s slugs and its name, and renamed to one of 1 to 64 characters, with no "/", no control character and no space at either end, or emptied');
  }
  const project = sql`(SELECT p.id FROM projects p WHERE p.slug = ${projectSlug})`;
  const here = sql`(SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${environmentSlug})`;
  const read = {
    ...callerParts(shown.token, project),
    project: part(projects, sql`${projects.slug} = ${projectSlug}`),
    environment: part(environments, sql`${environments.projectId} = ${project} AND ${environments.slug} = ${environmentSlug}`),
    // Every key of the environment, not those its rows say are in the folder: a row moved out behind the vault says it is not.
    keys: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} = ${here}`),
  };
  const placed = (seen: Seen<typeof read>) => {
    const place = seen.project.find((row) => row.slug === projectSlug && live(row));
    return { place, environment: place && seen.environment.find((row) => row.projectId === place.id && row.slug === environmentSlug && live(row)) };
  };
  return {
    read,
    denied: refusedTo('secret.refile', shown, vault.workloads, {
      where: { project: projectSlug, environment: environmentSlug },
      objects: (seen: Seen<typeof read>) => {
        const { place, environment } = placed(seen);
        return [...(place === undefined ? [] : [`project:${place.id}`]), ...(environment === undefined ? [] : [`environment:${environment.id}`])];
      },
    }),
    decide(seen: Seen<typeof read>, at: number, unsealed) {
      const caller = callerFrom(seen, shown, vault.workloads, at);
      if (caller === null) return { refused: 'unauthenticated' };
      if (caller.workload?.stop != null) return { refused: caller.workload.stop };
      if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
      const { place, environment } = placed(seen);
      // As for a write: a personal config holds keys only its owner files, which no route serves yet.
      if (place === undefined || environment === undefined || environment.owner !== null || !caller.may('secret.write', environment)) return { refused: 'no_access' };
      if (unsealed.keys > 0) return { refused: 'unreadable' };
      const there = seen.keys.filter((row) => row.environmentId === environment.id && row.folder === from);
      if (there.length === 0) return { refused: 'no_folder' };
      const moved = there.map((row) => row.key).sort();
      return {
        // Renamed onto itself, nothing moves: the entry says it was asked, as for projects (`folder.refile`).
        writes: to === from ? [] : there.map((row) => amended(secrets, row, { folder: to })),
        entry: {
          kept: true,
          action: 'secret.refile',
          actor: caller.principal,
          credential: caller.credential.id,
          request: shown.request,
          ip: shown.ip,
          objects: [`project:${place.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...there.map((row) => `secret:${row.id}`)],
          detail: { folder: from, to, keys: moved },
        },
        answer: { moved },
      };
    },
  };
}

/**
 * End the reference a key is (0.14's `breakReference`): its readers read
 * nothing there until it is given a value, or made a reference again, and
 * its value before the reference stays history. Whoever writes the key
 * may, and whoever manages access in its source's project
 * (`grant.manage`), who decides who reads the source and need not see the
 * key's environment. To anyone else, as to the place that is not there,
 * `no_access`; to its writer, a key that is no reference is `no_reference`.
 */
function referenceBreak(input: Presented & ReferenceBreak, vault: Deciding): Operation<Parts, Answers['reference.break']> {
  const shown = presented(input);
  const { project: projectSlug, environment: environmentSlug, key } = input;
  if (!text(projectSlug) || !text(environmentSlug) || typeof key !== 'string' || !KEY.test(key)) throw new TypeError('a reference is broken by its key, named by its place\'s slugs and its name');
  const project = sql`(SELECT p.id FROM projects p WHERE p.slug = ${projectSlug})`;
  const here = sql`(SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${environmentSlug})`;
  const source = sql`(SELECT s.source_id FROM secrets s WHERE s.project_id = ${project} AND s.environment_id = ${here} AND s.key = ${key})`;
  // The source's project, whose access managers may break it too: weighed by their grants there.
  const sourceProject = sql`(SELECT s.project_id FROM secrets s WHERE s.id IN ${source})`;
  const read = {
    ...callerParts(shown.token, sql`(SELECT ${project} UNION SELECT * FROM ${sourceProject} AS source (project_id))`),
    project: part(projects, sql`${projects.slug} = ${projectSlug} OR ${projects.id} IN ${sourceProject}`),
    environment: part(environments, sql`${environments.projectId} = ${project} AND ${environments.slug} = ${environmentSlug}`),
    secret: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} = ${here} AND ${secrets.key} = ${key}`),
    source: part(secrets, sql`${secrets.id} IN ${source}`),
    sourcePlace: part(environments, sql`${environments.id} IN (SELECT s.environment_id FROM secrets s WHERE s.id IN ${source})`),
  };
  const placed = (seen: Seen<typeof read>) => {
    const place = seen.project.find((row) => row.slug === projectSlug && live(row));
    return { place, environment: place && seen.environment.find((row) => row.projectId === place.id && row.slug === environmentSlug && live(row)) };
  };
  return {
    read,
    denied: refusedTo('reference.break', shown, vault.workloads, {
      where: { project: projectSlug, environment: environmentSlug },
      objects: (seen: Seen<typeof read>) => {
        const { place, environment } = placed(seen);
        return [...(place === undefined ? [] : [`project:${place.id}`]), ...(environment === undefined ? [] : [`environment:${environment.id}`])];
      },
    }),
    decide(seen: Seen<typeof read>, at: number, unsealed) {
      const caller = callerFrom(seen, shown, vault.workloads, at);
      if (caller === null) return { refused: 'unauthenticated' };
      if (caller.workload?.stop != null) return { refused: caller.workload.stop };
      if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
      const { place, environment } = placed(seen);
      // A personal config holds no reference.
      if (place === undefined || environment === undefined || environment.owner !== null) return { refused: 'no_access' };
      const writes = caller.may('secret.write', environment);
      const holder = seen.secret.find((row) => row.environmentId === environment.id && row.key === key);
      const from = holder?.sourceId == null ? undefined : seen.source.find((row) => row.id === holder.sourceId);
      // By the source's own row: a project's id the holder's names, unseen, manages nothing.
      const whose = from && seen.project.find((row) => row.id === from.projectId);
      const manages = whose !== undefined && allows(caller.holds, 'grant.manage', { projectId: whose.id });
      if (!writes && !manages) return { refused: 'no_access' };
      // Only its writer gets here without the key's row: one edited behind the vault is not guessed at.
      if (holder === undefined) return { refused: unsealed.secret > 0 ? 'unreadable' : 'unknown_key' };
      if (holder.sourceId === null) return { refused: 'no_reference' };
      const where = from && seen.sourcePlace.find((row) => row.id === from.environmentId);
      return {
        writes: [amended(secrets, holder, { sourceId: null, updatedAt: new Date(at) })],
        entry: {
          kept: true,
          action: 'reference.break',
          actor: caller.principal,
          credential: caller.credential.id,
          request: shown.request,
          ip: shown.ip,
          objects: [...new Set([`project:${place.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, `secret:${holder.id}`,
            `secret:${holder.sourceId}`, ...(from === undefined ? [] : [`project:${from.projectId}`, `environment:${from.environmentId}`])])],
          // `source`: the secret it read.
          detail: { key, secret: holder.id, source: holder.sourceId },
        },
        answer: { source: whose === undefined || where === undefined ? null : { project: whose.slug, environment: where.slug, key: from!.key } },
      };
    },
  };
}

/** The changes of keys and their values. */
export const secretOperations: Operations<SecretsChanges> = { 'secret.write': secretWrite, 'secret.refile': secretRefile, 'reference.break': referenceBreak };
