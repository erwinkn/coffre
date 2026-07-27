'use client';

import { useState, useTransition } from 'react';
import { revealSecret, saveSecret, setSecretArchived } from '../../actions';
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
  const [pending, startTransition] = useTransition();

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
