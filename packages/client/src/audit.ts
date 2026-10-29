/** How the audit log's entries are said, to people: by the pages and the CLI alike. */

/**
 * The CI run an entry was written for, as its issuer stated it at the
 * exchange: `acme/api run 7001 at 3f2a9c1`, a GitLab pipeline, or the
 * token's subject. Null for an entry no trust binding's credential wrote.
 */
export function runLabel(run: { claims: Record<string, string | number> } | null): string | null {
  if (run === null) return null;
  const { claims } = run;
  const text = (name: string) => (typeof claims[name] === 'string' || typeof claims[name] === 'number' ? String(claims[name]) : null);
  const at = text('sha') === null ? '' : ` at ${text('sha')!.slice(0, 7)}`;
  if (text('repository') !== null && text('run_id') !== null) return `${text('repository')} run ${text('run_id')}${at}`;
  if (text('project_path') !== null && text('pipeline_id') !== null) return `${text('project_path')} pipeline ${text('pipeline_id')}${at}`;
  return text('sub') === null ? 'a CI run' : `CI run ${text('sub')}`;
}
