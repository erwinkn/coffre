'use server';

import { revalidatePath } from 'next/cache';
import { coffreFetch } from '../lib/api';

type Result<T> = ({ ok: true } & T) | { ok: false; error: string };

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

function badSlug(value: string): string | null {
  return SLUG.test(value)
    ? null
    : 'must be lowercase letters, digits and hyphens, starting with a letter or digit';
}

/**
 * Every function here is a thin wrapper over the API. None of them touch
 * Postgres: the API is what authorises the change and writes the audit row, so
 * routing structural edits around it would leave them unrecorded.
 *
 * Note there is no delete. The audit log holds ON DELETE RESTRICT references
 * to projects, environments and secrets, so archiving is the real operation.
 */

export async function createProject(slug: string, name: string): Promise<Result<object>> {
  const invalid = badSlug(slug);
  if (invalid) return { ok: false, error: `slug ${invalid}` };
  if (name.trim() === '') return { ok: false, error: 'name is required' };

  const result = await coffreFetch('/v1/admin/projects', {
    method: 'POST',
    body: JSON.stringify({ slug, name }),
  });
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath('/');
  return { ok: true };
}

export async function updateProject(
  project: string,
  changes: { slug?: string; name?: string },
): Promise<Result<object>> {
  if (changes.slug) {
    const invalid = badSlug(changes.slug);
    if (invalid) return { ok: false, error: `slug ${invalid}` };
  }

  const result = await coffreFetch(`/v1/admin/projects/${project}`, {
    method: 'PATCH',
    body: JSON.stringify(changes),
  });
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath('/');
  revalidatePath(`/${project}`);
  return { ok: true };
}

export async function setProjectArchived(
  project: string,
  archived: boolean,
): Promise<Result<object>> {
  const result = await coffreFetch(`/v1/admin/projects/${project}/archive`, {
    method: 'POST',
    body: JSON.stringify({ archived }),
  });
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath('/');
  revalidatePath(`/${project}`);
  return { ok: true };
}

export async function createEnvironment(
  project: string,
  slug: string,
  name: string,
): Promise<Result<object>> {
  const invalid = badSlug(slug);
  if (invalid) return { ok: false, error: `slug ${invalid}` };
  if (name.trim() === '') return { ok: false, error: 'name is required' };

  const result = await coffreFetch(`/v1/admin/projects/${project}/environments`, {
    method: 'POST',
    body: JSON.stringify({ slug, name }),
  });
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}`);
  return { ok: true };
}

export async function updateEnvironment(
  project: string,
  environment: string,
  changes: { slug?: string; name?: string },
): Promise<Result<object>> {
  if (changes.slug) {
    const invalid = badSlug(changes.slug);
    if (invalid) return { ok: false, error: `slug ${invalid}` };
  }

  const result = await coffreFetch(
    `/v1/admin/projects/${project}/environments/${environment}`,
    { method: 'PATCH', body: JSON.stringify(changes) },
  );
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}`);
  return { ok: true };
}

export async function setEnvironmentArchived(
  project: string,
  environment: string,
  archived: boolean,
): Promise<Result<object>> {
  const result = await coffreFetch(
    `/v1/admin/projects/${project}/environments/${environment}/archive`,
    { method: 'POST', body: JSON.stringify({ archived }) },
  );
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}`);
  return { ok: true };
}

export async function createGrant(
  project: string,
  input: {
    principalType: 'user' | 'service';
    principalId: string;
    role: string;
    environmentSlug: string | null;
    expiresAt: string | null;
  },
): Promise<Result<object>> {
  if (input.principalId.trim() === '') return { ok: false, error: 'principal is required' };

  const result = await coffreFetch(`/v1/admin/projects/${project}/grants`, {
    method: 'POST',
    body: JSON.stringify(input),
  });
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}`);
  return { ok: true };
}

export async function revokeGrant(project: string, grantId: string): Promise<Result<object>> {
  const result = await coffreFetch(`/v1/admin/projects/${project}/grants/${grantId}`, {
    method: 'DELETE',
  });
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}`);
  return { ok: true };
}
