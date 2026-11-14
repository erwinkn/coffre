import { randomUUID } from 'node:crypto';

import type { Permission } from '@coffre/core/access';
import type { Answers, KeyWrite, Nature, Presented, SecretsChanges, SecretWrite } from '@coffre/core/vault';
import { dismissedKeys, environments, projects, secrets } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerFrom, callerParts, live, refusedTo } from '../caller.ts';
import { part, put, type Operation, type Parts, type Seen, type Value, type Write } from '../change.ts';
import type { Fresh, Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { KEY, presented, text } from './input.ts';

/** The app's own bounds (its routes'): a value's length in characters, the keys of one write, and a request's body, which every value of a write came in. */
const VALUE_LENGTH = 64 * 1024;
const MOST_KEYS = 2000;
const WRITE_BYTES = 1024 * 1024;
const NATURES = ['secret', 'sensitive', 'plain'];
/** How many environments a key is inherited through, as a use reads them (use.ts). */
const MAX_PARENTS = 3;

/** Text as Postgres stores it and a reader gets it back: no NUL, no half of a surrogate pair. */
const wellFormed = (value: string) => !value.includes('\0') && Buffer.from(value).toString() === value;
const written = (value: unknown): value is string => typeof value === 'string' && value.length <= VALUE_LENGTH && wellFormed(value);
/** A folder as the app's routes have it (`folderName`), within the table's check: 1 to 64 UTF-16 units, no slash or control character, nothing `trim` takes away. */
const filed = (value: unknown) => value === null || (typeof value === 'string' && wellFormed(value) && value.length >= 1 && value.length <= 64 && !/[/\p{Cc}]/u.test(value) && value === value.trim());

const wrong = () => new TypeError('a write names a place by its slugs and 1 to 2,000 keys, each once, with a value of well-formed text, 64 Ki characters at most and 1 MiB in all, and its nature if any, an archiving or a folder');

/** One key's item, on its own: what it does, with what it says it with. */
function valid(item: KeyWrite): boolean {
  if (typeof item !== 'object' || item === null || typeof item.key !== 'string' || !KEY.test(item.key)) return false;
  if (!(item.archived === undefined || typeof item.archived === 'boolean') || !(item.folder === undefined || filed(item.folder))) return false;
  // A key is archived with no value written over it.
  if (item.value !== undefined) return written(item.value) && (item.nature === undefined || NATURES.includes(item.nature)) && item.archived !== true;
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
    || items.reduce((sum, item) => sum + Buffer.byteLength(item.value ?? ''), 0) > WRITE_BYTES) {
    throw wrong();
  }
  // A key the environment does not have yet is made under an id drawn here: a decision draws nothing.
  const fresh = new Map(items.map((item) => [item.key, { secret: randomUUID(), version: randomUUID() }]));
  const needs = new Set<Permission>(items.flatMap((item): Permission[] => [
    ...(item.value !== undefined || item.folder !== undefined ? ['secret.write' as const] : []),
    ...(item.archived === undefined ? [] : ['secret.archive' as const]),
    ...(item.archived === false ? ['secret.read' as const] : []),
  ]));
  const archiving = items.flatMap((item) => (item.archived === true ? [item.key] : []));
  const bare = items.flatMap((item) => (item.value !== undefined && item.nature === undefined ? [item.key] : []));

  const project = sql`(SELECT p.id FROM projects p WHERE p.slug = ${projectSlug})`;
  const here = sql`(SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${environmentSlug})`;
  // The environment and those it inherits from, for a bare value only: what it is written over may be a parent's.
  const chain = sql`(WITH RECURSIVE chain (id, parent_id, depth) AS (
    SELECT e.id, e.parent_id, 0 FROM environments e WHERE ${bare.length > 0 ? sql`true` : sql`false`} AND e.id = ${here}
    UNION SELECT e.id, e.parent_id, chain.depth + 1 FROM environments e JOIN chain ON e.id = chain.parent_id WHERE chain.depth < ${MAX_PARENTS}
  ) SELECT id FROM chain)`;
  // The references that read a key this write archives, from wherever they are held.
  const readers = sql`(SELECT r.id FROM secrets r WHERE r.source_id IN (SELECT s.id FROM secrets s WHERE s.project_id = ${project} AND s.environment_id = ${here} AND s.key = ANY(${sql.param(archiving)}::text[])))`;
  const read = {
    ...callerParts(shown.token, project),
    project: part(projects, sql`${projects.slug} = ${projectSlug}`),
    environment: part(environments, sql`${environments.projectId} = ${project} AND ${environments.slug} = ${environmentSlug}`),
    secret: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} = ${here} AND ${secrets.key} = ANY(${sql.param(items.map((item) => item.key))}::text[])`),
    parent: part(environments, sql`${environments.id} IN ${chain} AND ${environments.id} <> ${here}`),
    // What a key written with no nature is now where the environment holds none: a parent's, unless dismissed on the way.
    inherited: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} IN ${chain} AND ${secrets.environmentId} <> ${here} AND ${secrets.key} = ANY(${sql.param(bare)}::text[])`),
    dismissed: part(dismissedKeys, sql`${dismissedKeys.environmentId} IN ${chain} AND ${dismissedKeys.key} = ANY(${sql.param(bare)}::text[])`),
    // What a key written with no nature refers to, its own or the one it inherits, if a reference: its value's nature is the source's.
    source: part(secrets, sql`${secrets.id} IN (SELECT s.source_id FROM secrets s WHERE s.project_id = ${project} AND s.environment_id IN ${chain} AND s.key = ANY(${sql.param(bare)}::text[]))`),
    reader: part(secrets, sql`${secrets.id} IN ${readers}`),
    readerPlace: part(environments, sql`${environments.id} IN (SELECT r.environment_id FROM secrets r WHERE r.id IN ${readers})`),
    readerProject: part(projects, sql`${projects.id} IN (SELECT r.project_id FROM secrets r WHERE r.id IN ${readers})`),
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
      const lines: Record<string, unknown>[] = [];
      const leaves = new Map<string, Fresh<typeof secrets>>();
      const answered: [string, { version: number; nature: Nature }][] = [];
      for (const { key, value, nature: asked, archived, folder } of items) {
        const was = held.get(key) ?? null;
        // Only a value makes a key: there is nothing else to archive or file.
        if (was === null && value === undefined) return { refused: 'unknown_key' };
        // An archived key keeps its name: it is brought back, not written over.
        if (was?.archivedAt != null && value !== undefined && archived !== false) return { refused: 'archived' };
        const ids = fresh.get(key)!;
        const { mac: _, ...kept } = was ?? { mac: null, id: ids.secret, projectId: place.id, environmentId: environment.id, key, createdAt: now, updatedAt: now, versions: 0, currentVersion: null, archivedAt: null, folder: null, sourceId: null, nature: null, recipe: null, pairId: null, pairHalf: null };
        let secret: Fresh<typeof secrets> = { ...kept, archivedAt: archived === undefined ? kept.archivedAt : archived ? (kept.archivedAt ?? now) : null, folder: folder === undefined ? kept.folder : folder };
        const line: Record<string, unknown> = { key, secret: secret.id };
        if (value !== undefined) {
          // What the key's value is now: its own, or what it inherits, and either one's source's: a source is never deleted while referred to.
          // An archived key read what it inherits, and is brought back as its own: it is as sensitive as either.
          const current = asked !== undefined ? [] : was === null ? [passedDown(key)] : was.archivedAt === null ? [kept] : [kept, passedDown(key)];
          const natures = current.map((row) => (row == null || row.sourceId === null ? row : sources.get(row.sourceId)));
          if (natures.includes(undefined)) return { refused: 'unreadable' };
          const nature = asked ?? (natures.some((row) => row?.nature === 'sensitive') ? 'sensitive' : 'secret');
          const version = kept.versions + 1;
          // Typed, not generated: no recipe for Regenerate, and in no pair.
          secret = { ...secret, versions: version, currentVersion: version, updatedAt: now, sourceId: null, nature, recipe: null, pairId: null, pairHalf: null };
          sealed.push({
            version: { id: ids.version, secretId: secret.id, version, createdAt: now, createdBy: caller.principal, plaintext: nature === 'plain' ? value : null, sensitive: nature === 'sensitive' },
            text: Buffer.from(value),
          });
          answered.push([key, { version, nature }]);
          // `source`: the secret it referred to until now.
          Object.assign(line, { version, nature }, was === null ? { made: true } : {}, was?.sourceId == null ? {} : { source: was.sourceId });
        }
        if ((secret.archivedAt === null) !== (kept.archivedAt === null)) line.archived = secret.archivedAt !== null;
        if (secret.folder !== kept.folder) line.folder = secret.folder;
        // What changes nothing writes nothing: archived already, filed where it is.
        if (Object.keys(line).length === 2) continue;
        writes.push(put(secrets, secret, was));
        leaves.set(secret.id, secret);
        lines.push(line);
      }
      // A key archived stops every reference that reads it, so it is not while one does: one held in a key, an
      // environment or a project archived or deleted reads nothing. A place not found is not known to be one.
      const gone = (row: { slug: string; archivedAt: Date | null } | undefined) => row !== undefined && !live(row);
      const stopped = new Set(lines.filter((line) => line.archived === true).map((line) => line.secret));
      const reads = seen.reader.some((row) => {
        const reader = leaves.get(row.id) ?? row;
        return reader.sourceId !== null && stopped.has(reader.sourceId) && reader.archivedAt === null
          && !gone(seen.readerPlace.find((where) => where.id === reader.environmentId)) && !gone(seen.readerProject.find((whose) => whose.id === reader.projectId));
      });
      if (reads) return { refused: 'referenced' };
      return {
        writes,
        values: sealed,
        entry: {
          kept: true,
          action: 'secret.write',
          actor: caller.principal,
          credential: caller.credential.id,
          request: shown.request,
          ip: shown.ip,
          objects: [`project:${place.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...lines.map((line) => `secret:${line.secret as string}`)],
          detail: { keys: lines },
        },
        // As entries: a key named `__proto__` is a key like any other.
        answer: { keys: Object.fromEntries(answered) },
      };
    },
  };
}

/** The changes of keys and their values. */
export const secretOperations: Operations<SecretsChanges> = { 'secret.write': secretWrite };
