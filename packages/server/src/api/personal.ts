import { randomBytes, randomUUID } from 'node:crypto';

import { isUniqueViolation } from '@coffre/db/dialect';
import { environments } from '@coffre/db/schema';

import { environmentsCreatedAt, insert, liveEnvironment, liveKeysIn, MAX_PARENTS, parentsOf, personalConfig, places, resolvePath, type ResolvedPath } from '../db/queries.ts';
import { can, lists, placeOf } from './caller.ts';
import { AppChanges, environmentChange, madeEnvironment, madeProtection } from './changes.ts';
import { allowed, audited, denied, Refusal, withRefusals, type ApiContext } from './context.ts';
import { conflict, forbidden, notFound } from './errors.ts';
import { formatMember, formatPath, type Path } from './paths.ts';

/**
 * Personal configs (docs/design/forking.md): `market/dev@me` is your own
 * fork of `market/dev`, whose values only you read, and only while you
 * read dev. It is chosen explicitly, by `@me`, never in place of dev; a
 * read of it falls back to dev while you have none, and a write makes one.
 */

/** Who `@me` is: a person. A service account owns no personal config, so its `@me` is always dev. */
export function ownerOf(ctx: ApiContext): string | null {
  return ctx.caller.principal.type === 'user' ? formatMember(ctx.caller.principal) : null;
}

/**
 * A path as a read resolves it: `market/dev@me` is your personal config of
 * dev, or dev itself while you have none, marked `fallback`, so one
 * committed `coffre run market/dev@me` serves everyone, CI included.
 */
export async function resolveRead(ctx: ApiContext, path: Path): Promise<ResolvedPath | null> {
  const place = await resolvePath(ctx.db, path, { owner: ownerOf(ctx) });
  if (place?.personal === undefined || place.environment !== null) return place;
  const fallback = await resolvePath(ctx.db, { ...path, environment: place.personal.of.slug });
  return fallback === null ? null : { ...fallback, personal: { of: place.personal.of, fallback: true } };
}

/** `dev@me`, as a personal config is named to its owner: its generated slug is never shown. */
export function personalName(place: { personal?: ResolvedPath['personal']; environment: { slug: string; owner: string | null; parentSlug: string | null } | null }): string | null {
  if (place.environment?.owner == null) return null;
  return `${place.environment.parentSlug ?? place.personal?.of.slug ?? '?'}@me`;
}

/**
 * Make the caller's personal config of `place.personal.of`, or find the one
 * a concurrent call made: a person who reads the environment, of an
 * environment that is live, no personal config itself, and not so deep in
 * a chain that one more level runs past `MAX_PARENTS`. It takes nothing
 * but read there: a Viewer may keep a local `DATABASE_URL`. Its slug is
 * generated, and only an API that lists it for deletion shows it.
 */
export async function makePersonal(ctx: ApiContext, place: ResolvedPath, action: string): Promise<{ place: ResolvedPath; created: boolean }> {
  const of = place.personal!.of;
  const path = `${place.project.slug}/${of.slug}`;
  const owner = ownerOf(ctx);
  return withRefusals(ctx, async () => {
    const fields = { projectId: place.project.id, environmentId: of.id, metadata: { path } };
    if (owner === null) {
      throw new Refusal(forbidden('a service account keeps no personal config: name the environment itself'), denied(ctx, action, 'not_a_person', fields));
    }
    const parent = await resolvePath(ctx.db, { project: place.project.slug, environment: of.slug });
    if (parent?.environment == null || parent.project.archivedAt !== null || parent.environment.archivedAt !== null) throw notFound(`no live environment ${path}`);
    if (!lists(ctx.caller, placeOf(parent.project, parent.environment))) {
      throw new Refusal(forbidden(`a personal config of ${path} takes read or use on it`), denied(ctx, action, 'missing_secret_read', fields));
    }
    const above = await parentsOf(ctx.db, of.id);
    if (above === null || above.length >= MAX_PARENTS) {
      throw new Refusal(conflict(`${path} already inherits from ${MAX_PARENTS} environments: it takes no personal config`), denied(ctx, action, 'too_deep', fields));
    }
    const id = randomUUID();
    const slug = `${of.slug.slice(0, 48)}-p-${randomBytes(4).toString('hex')}`;
    const config = madeEnvironment(ctx.caller, { id, projectId: place.project.id, slug, owner, parentId: of.id });
    const changes = await AppChanges.prepare(ctx.vault, formatMember(ctx.caller.principal), [environmentChange(undefined, config)]);
    const made = await audited(ctx, async (tx, log) => {
      // One made meanwhile holds its place: that one is it, and this one is not made.
      if (await personalConfig(tx, of.id, owner)) return (changes?.drop(), false);
      // Archived or deleted since it was checked, it takes no personal config.
      if (!(await liveEnvironment(tx, of.id))) throw notFound(`no live environment ${path}`);
      try {
        await insert(tx, environments, { id, projectId: place.project.id, slug, name: slug, parentId: of.id, owner, ...madeProtection(config, changes) });
      } catch (error) {
        if (isUniqueViolation(error)) return (changes?.drop(), false);
        throw error;
      }
      log.push(allowed(ctx, 'environment.create', { projectId: place.project.id, environmentId: id, metadata: { slug, personal: of.slug } }));
      return true;
    }, changes);
    const mine = await resolvePath(ctx.db, { project: place.project.slug, environment: `${of.slug}@me` }, { owner });
    if (mine?.environment == null) throw notFound(`${formatPath({ project: place.project.slug, environment: `${of.slug}@me` })} went away as it was made`);
    return { place: mine, created: made };
  });
}

/** A personal config as its project's maintainers see it: whose, of what, and its keys' names. */
export type PersonalConfig = {
  owner: string;
  /** The environment it is a config of, by slug. */
  of: string;
  /** Its own slug, which deleting it names: `DELETE /projects/market/dev-p-3f9c2a1b`. */
  slug: string;
  /** The keys it holds a value of, by name; never a value. */
  keys: string[];
  archived: boolean;
  createdAt: string;
};

/**
 * A project's personal configs, for whoever manages its environments: that
 * they exist, whose they are, and the names of their keys, which within a
 * project are no secret (R6). Their values stay their owners' alone.
 */
export async function listPersonal(ctx: ApiContext, place: ResolvedPath): Promise<{ configs: PersonalConfig[] }> {
  const project = (await places(ctx.db)).find((each) => each.id === place.project.id);
  const configs = project?.environments.filter((environment) => environment.owner !== null) ?? [];
  const keys = await liveKeysIn(ctx.db, configs.map((config) => config.id));
  const created = await environmentsCreatedAt(ctx.db, configs.map((config) => config.id));
  return {
    configs: configs
      .map((config) => ({
        owner: config.owner!,
        of: config.parentSlug ?? '?',
        slug: config.slug,
        keys: keys.filter((key) => key.environmentId === config.id).map((key) => key.key).sort(),
        archived: config.archivedAt !== null,
        createdAt: (created.get(config.id) ?? new Date(0)).toISOString(),
      }))
      .sort((a, b) => (a.of < b.of ? -1 : a.of > b.of ? 1 : a.owner < b.owner ? -1 : 1)),
  };
}
