import { randomUUID } from 'node:crypto';

import { allows } from '@coffre/core/access';
import type { Answers, Presented, SecretWrite } from '@coffre/core/vault';
import { environments, projects, secrets } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerFrom, callerParts } from '../caller.ts';
import { part, put, type Operation, type Parts, type Seen, type Value, type Write } from '../change.ts';
import type { Fresh } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import { presented, text } from './input.ts';

/** A value's size at most, in bytes of UTF-8: a certificate chain or a service account's key file fits many times over. */
const VALUE_BYTES = 64 * 1024;
const NATURES = ['secret', 'sensitive', 'plain'];

/** A place that is there: not archived, and not the tombstone a deletion leaves. */
const live = (row: { slug: string; archivedAt: Date | null }) => row.archivedAt === null && !row.slug.includes('~');

/**
 * Values written in one environment (docs/design/0.16.md, "A change"):
 * each key's next version, and the key itself where the environment has
 * none by that name. Whoever holds `secret.write` there, on a credential
 * that reaches it. A key that was a reference holds its own value from
 * here on. All of them, or none.
 */
export function secretWrite(input: Presented & SecretWrite, vault: Deciding): Operation<Parts, Answers['secret.write']> {
  const shown = presented(input);
  const { project: projectSlug, environment: environmentSlug, values } = input;
  const items = Array.isArray(values) ? [...values] : [];
  const valid = items.every((item) => typeof item === 'object' && item !== null && text(item.key) && typeof item.value === 'string' && Buffer.byteLength(item.value) <= VALUE_BYTES && NATURES.includes(item.nature));
  if (!text(projectSlug) || !text(environmentSlug) || items.length === 0 || items.length > 1000 || !valid || new Set(items.map((item) => item.key)).size !== items.length) {
    throw new TypeError('a write names a place by its slugs and 1 to 1,000 keys, each once, with a value of 64 KiB at most and its nature');
  }
  // A key the environment does not have yet is made under an id drawn here: a decision draws nothing.
  const fresh = new Map(items.map((item) => [item.key, { secret: randomUUID(), version: randomUUID() }]));

  const project = sql`(SELECT p.id FROM projects p WHERE p.slug = ${projectSlug})`;
  const read = {
    ...callerParts(shown.token, project),
    project: part(projects, sql`${projects.slug} = ${projectSlug}`),
    environment: part(environments, sql`${environments.projectId} = ${project} AND ${environments.slug} = ${environmentSlug}`),
    secret: part(secrets, sql`${secrets.projectId} = ${project} AND ${secrets.environmentId} = (SELECT e.id FROM environments e WHERE e.project_id = ${project} AND e.slug = ${environmentSlug}) AND ${secrets.key} = ANY(${sql.param(items.map((item) => item.key))}::text[])`),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number) {
      const caller = callerFrom(seen, seen.environment, shown, vault.workloads, at);
      if (caller === null) return { refused: 'unauthenticated' };
      if (caller.workload?.stop != null) return { refused: caller.workload.stop };
      // A narrowed session uses values, and changes nothing.
      if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
      const [place] = seen.project;
      const [environment] = seen.environment;
      // The same answer whether the place is not there or not theirs to write in: none says which.
      if (place === undefined || environment === undefined || !live(place) || !live(environment) || environment.owner !== null) return { refused: 'no_access' };
      if (!allows(caller.holds, 'secret.write', { projectId: place.id, environmentId: environment.id, environmentSlug: environment.slug })) return { refused: 'no_access' };

      const now = new Date(at);
      const held = new Map(seen.secret.map((row) => [row.key, row]));
      // An archived key keeps its name: it is brought back, not written over.
      if (items.some((item) => held.get(item.key)?.archivedAt != null)) return { refused: 'archived' };
      const writes: Write[] = [];
      const written: Value[] = [];
      const keys = items.map(({ key, value, nature }) => {
        const was = held.get(key) ?? null;
        const ids = fresh.get(key)!;
        const { mac: _, ...kept } = was ?? { mac: null, id: ids.secret, projectId: place.id, environmentId: environment.id, key, createdAt: now, versions: 0, archivedAt: null, folder: null };
        const version = kept.versions + 1;
        const secret: Fresh<typeof secrets> = { ...kept, versions: version, currentVersion: version, updatedAt: now, sourceId: null };
        writes.push(put(secrets, secret, was));
        written.push({
          secret,
          owner: null,
          version: { id: ids.version, secretId: secret.id, version, createdAt: now, createdBy: caller.principal, recipe: null, pairId: null, pairHalf: null, plaintext: nature === 'plain' ? value : null, sensitive: nature === 'sensitive' },
          text: Buffer.from(value),
        });
        return { key, secret: secret.id, version, nature, ...(was === null ? { made: true } : {}), ...(was?.sourceId == null ? {} : { was: was.sourceId }) };
      });
      return {
        writes,
        values: written,
        entry: {
          kept: true,
          action: 'secret.write',
          actor: caller.principal,
          credential: caller.credential.id,
          request: shown.request,
          ip: shown.ip,
          objects: [`project:${place.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...keys.map((item) => `secret:${item.secret}`)],
          detail: { keys },
        },
        answer: { versions: Object.fromEntries(keys.map((item) => [item.key, item.version])) },
      };
    },
  };
}
