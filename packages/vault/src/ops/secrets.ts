import { randomUUID } from 'node:crypto';

import type { Answers, Presented, SecretsChanges, SecretWrite } from '@coffre/core/vault';
import { environments, projects, secrets } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerFrom, callerParts, live, refusedTo } from '../caller.ts';
import { part, put, type Operation, type Parts, type Seen, type Value, type Write } from '../change.ts';
import type { Fresh } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { KEY, presented, text } from './input.ts';

/** The app's own bounds (its routes'): a value's length in characters, the keys of one write, and a request's body, which every value of a write came in. */
const VALUE_LENGTH = 64 * 1024;
const MOST_KEYS = 2000;
const WRITE_BYTES = 1024 * 1024;
const NATURES = ['secret', 'sensitive', 'plain'];

/** A value as text Postgres stores and a reader gets back as written: no NUL, no half of a surrogate pair. */
const written = (value: unknown): value is string => typeof value === 'string' && value.length <= VALUE_LENGTH && !value.includes('\0') && Buffer.from(value).toString() === value;

/**
 * Values written in one environment (docs/design/0.16.md, "A change"):
 * each key's next version, and the key itself where the environment has
 * none by that name. Whoever holds `secret.write` there, on a credential
 * that reaches it. A key that was a reference holds its own value from
 * here on. All of them, or none.
 */
function secretWrite(input: Presented & SecretWrite, vault: Deciding): Operation<Parts, Answers['secret.write']> {
  const shown = presented(input);
  const { project: projectSlug, environment: environmentSlug, values } = input;
  const items = Array.isArray(values) ? [...values] : [];
  const valid = items.every((item) => typeof item === 'object' && item !== null && typeof item.key === 'string' && KEY.test(item.key) && written(item.value) && NATURES.includes(item.nature));
  if (!text(projectSlug) || !text(environmentSlug) || items.length === 0 || items.length > MOST_KEYS || !valid || new Set(items.map((item) => item.key)).size !== items.length || items.reduce((sum, item) => sum + Buffer.byteLength(item.value), 0) > WRITE_BYTES) {
    throw new TypeError('a write names a place by its slugs and 1 to 2,000 keys, each once, with its nature and a value of well-formed text, 64 Ki characters at most, and 1 MiB in all');
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
    denied: refusedTo('secret.write', shown, vault.workloads, { project: projectSlug, environment: environmentSlug }),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = callerFrom(seen, shown, vault.workloads, at);
      if (caller === null) return { refused: 'unauthenticated' };
      if (caller.workload?.stop != null) return { refused: caller.workload.stop };
      // A narrowed session uses values, and changes nothing.
      if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
      const place = seen.project.find((row) => row.slug === projectSlug && live(row));
      const environment = place && seen.environment.find((row) => row.projectId === place.id && row.slug === environmentSlug && live(row));
      // The same answer whether the place is not there, is someone's personal config, or is not theirs to write in: none says which.
      if (place === undefined || environment === undefined || environment.owner !== null || !caller.may('secret.write', environment)) return { refused: 'no_access' };

      const now = new Date(at);
      const held = new Map(seen.secret.map((row) => [row.key, row]));
      // An archived key keeps its name: it is brought back, not written over.
      if (items.some((item) => held.get(item.key)?.archivedAt != null)) return { refused: 'archived' };
      const writes: Write[] = [];
      const sealed: Value[] = [];
      const keys = items.map(({ key, value, nature }) => {
        const was = held.get(key) ?? null;
        const ids = fresh.get(key)!;
        const { mac: _, ...kept } = was ?? { mac: null, id: ids.secret, projectId: place.id, environmentId: environment.id, key, createdAt: now, versions: 0, archivedAt: null, folder: null };
        const version = kept.versions + 1;
        const secret: Fresh<typeof secrets> = { ...kept, versions: version, currentVersion: version, updatedAt: now, sourceId: null };
        writes.push(put(secrets, secret, was));
        sealed.push({
          version: { id: ids.version, secretId: secret.id, version, createdAt: now, createdBy: caller.principal, recipe: null, pairId: null, pairHalf: null, plaintext: nature === 'plain' ? value : null, sensitive: nature === 'sensitive' },
          text: Buffer.from(value),
        });
        // `source`: the secret it referred to until now.
        return { key, secret: secret.id, version, nature, ...(was === null ? { made: true } : {}), ...(was?.sourceId == null ? {} : { source: was.sourceId }) };
      });
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
          objects: [`project:${place.id}`, `environment:${environment.id}`, `principal:${caller.principal}`, `credential:${caller.credential.id}`, ...keys.map((item) => `secret:${item.secret}`)],
          detail: { keys },
        },
        answer: { versions: Object.fromEntries(keys.map((item) => [item.key, item.version])) },
      };
    },
  };
}

/** The changes of keys and their values. */
export const secretOperations: Operations<SecretsChanges> = { 'secret.write': secretWrite };
