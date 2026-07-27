'use client';

import { useState, useTransition } from 'react';
import {
  importEnv,
  listVersions,
  revealSecret,
  rollbackSecret,
  saveSecret,
  setSecretArchived,
  type ImportPlanEntry,
  type ImportProblem,
  type SecretVersion,
} from '../../actions';
import type { Permission, SecretKey } from '../../../lib/api';

type Props = {
  project: string;
  environment: string;
  permissions: Permission[];
  keys: SecretKey[];
};

export function SecretsClient({ project, environment, permissions, keys }: Props) {
  const canWrite = permissions.includes('secret.write');
  const canArchive = permissions.includes('secret.archive');
  const canReveal = permissions.includes('secret.read');

  const active = keys.filter((entry) => !entry.archived);
  const archived = keys.filter((entry) => entry.archived);

  return (
    <>
      <div className="card">
        {active.length === 0 ? (
          <div className="empty">No secrets in this environment yet.</div>
        ) : (
          active.map((entry) => (
            <SecretRow
              key={entry.key}
              project={project}
              environment={environment}
              entry={entry}
              canWrite={canWrite}
              canArchive={canArchive}
              canReveal={canReveal}
            />
          ))
        )}
      </div>

      {canWrite && <NewSecret project={project} environment={environment} />}
      {canWrite && canReveal && <ImportEnv project={project} environment={environment} />}

      {archived.length > 0 && (
        <>
          <h2>Archived</h2>
          <p className="sub">
            Retired, so no longer served or injected by <code>coffre run</code>. History and
            audit references are intact, and restoring is one click.
          </p>
          <div className="card">
            {archived.map((entry) => (
              <SecretRow
                key={entry.key}
                project={project}
                environment={environment}
                entry={entry}
                canWrite={canWrite}
                canArchive={canArchive}
                canReveal={canReveal}
              />
            ))}
          </div>
        </>
      )}
    </>
  );
}

function SecretRow({
  project,
  environment,
  entry,
  canWrite,
  canArchive,
  canReveal,
}: {
  project: string;
  environment: string;
  entry: SecretKey;
  canWrite: boolean;
  canArchive: boolean;
  canReveal: boolean;
}) {
  const [value, setValue] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [versions, setVersions] = useState<SecretVersion[] | null>(null);
  const [pending, startTransition] = useTransition();

  function onHistory() {
    if (versions !== null) {
      setVersions(null);
      return;
    }
    startTransition(async () => {
      const result = await listVersions(project, environment, entry.key);
      if (result.ok) {
        setVersions(result.versions);
        setError(null);
      } else {
        setError(result.error);
      }
    });
  }

  function onReveal() {
    if (value !== null) {
      setValue(null);
      return;
    }
    startTransition(async () => {
      const result = await revealSecret(project, environment, entry.key);
      if (result.ok) {
        setValue(result.value);
        setError(null);
      } else {
        setError(result.error);
      }
    });
  }

  function onSave() {
    startTransition(async () => {
      const result = await saveSecret(project, environment, entry.key, draft);
      if (result.ok) {
        setEditing(false);
        setValue(null);
        setDraft('');
        setError(null);
      } else {
        setError(result.error);
      }
    });
  }

  return (
    <div>
      <div className="row">
        <div className="key">{entry.key}</div>
        <span className="meta">
          v{entry.version} · {entry.updatedBy}
        </span>
        {canReveal && (
          <button onClick={onReveal} disabled={pending}>
            {value !== null ? 'Hide' : pending ? '...' : 'Reveal'}
          </button>
        )}
        {canArchive && (
          <button
            disabled={pending}
            onClick={() =>
              startTransition(async () => {
                const result = await setSecretArchived(
                  project,
                  environment,
                  entry.key,
                  !entry.archived,
                );
                if (!result.ok) setError(result.error);
              })
            }
          >
            {entry.archived ? 'Restore' : 'Archive'}
          </button>
        )}
        {canReveal && (
          <button onClick={onHistory} disabled={pending}>
            {versions === null ? 'History' : 'Hide history'}
          </button>
        )}
        {canWrite && !entry.archived && (
          <button
            onClick={() => {
              setEditing(!editing);
              setDraft('');
            }}
          >
            {editing ? 'Cancel' : 'Edit'}
          </button>
        )}
      </div>

      {versions !== null && (
        <div style={{ padding: '0 14px 12px' }}>
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Written</th>
                <th>By</th>
                <th>KEK</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {versions.map((version) => (
                <tr key={version.version}>
                  <td>
                    v{version.version}
                    {version.current && (
                      <span className="pill admin" style={{ marginLeft: 8 }}>
                        current
                      </span>
                    )}
                  </td>
                  <td>{version.createdAt.replace('T', ' ').slice(0, 19)}</td>
                  <td className="wrap">{version.createdBy}</td>
                  <td>{version.kek}</td>
                  <td>
                    {canWrite && !version.current && (
                      <button
                        disabled={pending}
                        onClick={() =>
                          startTransition(async () => {
                            const result = await rollbackSecret(
                              project,
                              environment,
                              entry.key,
                              version.version,
                            );
                            if (result.ok) {
                              setVersions(null);
                              setValue(null);
                            } else {
                              setError(result.error);
                            }
                          })
                        }
                      >
                        Roll back to this
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="meta" style={{ marginTop: 8 }}>
            Rolling back repoints the current version. Nothing is copied or deleted, and a
            later write continues the numbering forward.
          </div>
        </div>
      )}

      {value !== null && <div className="value">{value}</div>}
      {error !== null && (
        <div className="value" style={{ color: 'var(--deny)' }}>
          {error}
        </div>
      )}

      {editing && (
        <div className="form-row">
          <input
            className="grow"
            autoFocus
            placeholder={`New value for ${entry.key}`}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
          <button className="primary" onClick={onSave} disabled={pending || draft === ''}>
            Save new version
          </button>
        </div>
      )}
    </div>
  );
}

function NewSecret({ project, environment }: { project: string; environment: string }) {
  const [key, setKey] = useState('');
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function onCreate() {
    startTransition(async () => {
      const result = await saveSecret(project, environment, key, value);
      if (result.ok) {
        setKey('');
        setValue('');
        setError(null);
      } else {
        setError(result.error);
      }
    });
  }

  return (
    <>
      <h2>Add a secret</h2>
      <div className="card">
        <div className="form-row">
          <input
            placeholder="SECRET_KEY"
            style={{ maxWidth: 260 }}
            value={key}
            onChange={(event) => setKey(event.target.value)}
          />
          <input
            className="grow"
            placeholder="value"
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
          <button
            className="primary"
            onClick={onCreate}
            disabled={pending || key === '' || value === ''}
          >
            Create
          </button>
        </div>
        {error !== null && (
          <div className="value" style={{ color: 'var(--deny)' }}>
            {error}
          </div>
        )}
      </div>
    </>
  );
}

/**
 * Bulk import from a .env file.
 *
 * Always previews first. The preview compares against current values, which
 * means it reads them -- so it needs secret.read as well as secret.write, and
 * both the preview and the import are audited.
 */
function ImportEnv({ project, environment }: { project: string; environment: string }) {
  const [content, setContent] = useState('');
  const [plan, setPlan] = useState<ImportPlanEntry[] | null>(null);
  const [problems, setProblems] = useState<ImportProblem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();

  function run(dryRun: boolean) {
    startTransition(async () => {
      const result = await importEnv(project, environment, content, dryRun);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setError(null);
      setProblems(result.problems);
      if (dryRun) {
        setPlan(result.plan);
      } else {
        setPlan(null);
        setContent('');
        setOpen(false);
      }
    });
  }

  if (!open) {
    return (
      <div style={{ marginTop: 20 }}>
        <button onClick={() => setOpen(true)}>Import .env</button>
      </div>
    );
  }

  const changes = plan?.filter((entry) => entry.action !== 'unchanged') ?? [];

  return (
    <>
      <h2>Import .env</h2>
      <div className="card">
        <div style={{ padding: 14 }}>
          <textarea
            rows={8}
            autoFocus
            placeholder={'DATABASE_URL=postgres://...\nSTRIPE_KEY="sk_live_..."'}
            value={content}
            onChange={(event) => {
              setContent(event.target.value);
              setPlan(null);
            }}
          />
        </div>
        <div className="form-row" style={{ paddingTop: 0 }}>
          <button disabled={pending || content === ''} onClick={() => run(true)}>
            Preview
          </button>
          <button
            className="primary"
            disabled={pending || plan === null || changes.length === 0}
            onClick={() => run(false)}
          >
            {plan === null
              ? 'Preview first'
              : `Apply ${changes.length} change${changes.length === 1 ? '' : 's'}`}
          </button>
          <button
            onClick={() => {
              setOpen(false);
              setPlan(null);
              setContent('');
            }}
          >
            Cancel
          </button>
        </div>

        {plan !== null && (
          <div style={{ padding: '0 14px 14px' }}>
            <table>
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Action</th>
                  <th>Current version</th>
                </tr>
              </thead>
              <tbody>
                {plan.map((entry) => (
                  <tr key={entry.key}>
                    <td>{entry.key}</td>
                    <td>
                      <span
                        className={`pill ${entry.action === 'unchanged' ? '' : 'allow'}`}
                      >
                        {entry.action}
                      </span>
                    </td>
                    <td>{entry.version === null ? '-' : `v${entry.version}`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {problems.length > 0 && (
          <div className="value" style={{ color: 'var(--deny)' }}>
            {problems.map((problem) => (
              <div key={problem.line}>
                line {problem.line}: {problem.reason} ({problem.text})
              </div>
            ))}
          </div>
        )}

        {error !== null && (
          <div className="value" style={{ color: 'var(--deny)' }}>
            {error}
          </div>
        )}
      </div>
    </>
  );
}
