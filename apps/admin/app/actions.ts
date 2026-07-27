'use server';

import { revalidatePath } from 'next/cache';
import { coffreFetch } from '../lib/api';

/**
 * Reveal a secret value.
 *
 * This goes through the API like everything else, so it authorises the user
 * and writes an audit row. Revealing a secret in the UI is a read, and is
 * recorded as one -- that is the property that makes the UI safe to have.
 */
export async function revealSecret(
  project: string,
  environment: string,
  key: string,
): Promise<{ ok: true; value: string } | { ok: false; error: string }> {
  const result = await coffreFetch<{ value: string }>(
    `/v1/projects/${project}/environments/${environment}/secrets/${key}`,
  );
  return result.ok ? { ok: true, value: result.data.value } : { ok: false, error: result.error };
}

export async function saveSecret(
  project: string,
  environment: string,
  key: string,
  value: string,
): Promise<{ ok: true; version: number } | { ok: false; error: string }> {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key)) {
    return { ok: false, error: 'key must look like AN_ENV_VAR' };
  }

  const result = await coffreFetch<{ version: number }>(
    `/v1/projects/${project}/environments/${environment}/secrets/${key}`,
    { method: 'PUT', body: JSON.stringify({ value }) },
  );

  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}/${environment}`);
  return { ok: true, version: result.data.version };
}

export async function verifyAuditChain(): Promise<
  { ok: true; rows: number; head: string } | { ok: false; error: string }
> {
  const result = await coffreFetch<
    { ok: true; rows: number; head: string } | { ok: false; failedAtSeq: number; reason: string }
  >('/v1/audit/verify');

  if (!result.ok) return { ok: false, error: result.error };
  if (!result.data.ok) {
    return {
      ok: false,
      error: `chain broken at seq ${result.data.failedAtSeq}: ${result.data.reason}`,
    };
  }
  return { ok: true, rows: result.data.rows, head: result.data.head };
}

/**
 * Retire or restore a secret.
 *
 * Not a delete: audit_log references secrets with ON DELETE RESTRICT, so a
 * secret that has ever been read or written cannot be removed. Archiving stops
 * it being served and drops it from bulk fetch, so a rotated-out credential
 * stops being injected into processes -- while its history stays intact.
 */
export async function setSecretArchived(
  project: string,
  environment: string,
  key: string,
  archived: boolean,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const result = await coffreFetch(
    `/v1/projects/${project}/environments/${environment}/secrets/${key}/archive`,
    { method: 'POST', body: JSON.stringify({ archived }) },
  );
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}/${environment}`);
  return { ok: true };
}

export type SecretVersion = {
  version: number;
  createdAt: string;
  createdBy: string;
  current: boolean;
  kek: string;
};

/** Version history. Metadata only -- no values are returned or logged as read. */
export async function listVersions(
  project: string,
  environment: string,
  key: string,
): Promise<{ ok: true; versions: SecretVersion[] } | { ok: false; error: string }> {
  const result = await coffreFetch<{ versions: SecretVersion[] }>(
    `/v1/projects/${project}/environments/${environment}/secrets/${key}/versions`,
  );
  return result.ok
    ? { ok: true, versions: result.data.versions }
    : { ok: false, error: result.error };
}

/**
 * Roll back to an earlier version.
 *
 * Repoints the current pointer; nothing is copied or rewritten, because
 * versions are append-only. Audited with both the old and new version.
 */
export async function rollbackSecret(
  project: string,
  environment: string,
  key: string,
  version: number,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const result = await coffreFetch(
    `/v1/projects/${project}/environments/${environment}/secrets/${key}/rollback`,
    { method: 'POST', body: JSON.stringify({ version }) },
  );
  if (!result.ok) return { ok: false, error: result.error };

  revalidatePath(`/${project}/${environment}`);
  return { ok: true };
}

export type ImportPlanEntry = {
  key: string;
  action: 'create' | 'update' | 'unchanged';
  version: number | null;
};
export type ImportProblem = { line: number; text: string; reason: string };

/**
 * Bulk import a .env file. `dryRun` returns the plan without writing.
 *
 * Parsing happens server-side so the UI and CLI cannot disagree about what a
 * .env file means.
 */
export async function importEnv(
  project: string,
  environment: string,
  content: string,
  dryRun: boolean,
): Promise<
  | { ok: true; plan: ImportPlanEntry[]; problems: ImportProblem[] }
  | { ok: false; error: string }
> {
  const result = await coffreFetch<{ plan: ImportPlanEntry[]; problems: ImportProblem[] }>(
    `/v1/projects/${project}/environments/${environment}/import`,
    { method: 'POST', body: JSON.stringify({ content, dryRun }) },
  );
  if (!result.ok) return { ok: false, error: result.error };

  if (!dryRun) revalidatePath(`/${project}/${environment}`);
  return { ok: true, plan: result.data.plan, problems: result.data.problems ?? [] };
}
