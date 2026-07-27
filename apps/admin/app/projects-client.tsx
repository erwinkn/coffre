'use client';

import { useState, useTransition } from 'react';
import { createProject } from './admin-actions';

export function NewProject() {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();

  if (!open) {
    return (
      <div style={{ marginTop: 20 }}>
        <button onClick={() => setOpen(true)}>New project</button>
      </div>
    );
  }

  return (
    <>
      <h2>New project</h2>
      <div className="card">
        <div className="form-row">
          <input
            autoFocus
            placeholder="slug (e.g. market)"
            style={{ maxWidth: 240 }}
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
          />
          <input
            className="grow"
            placeholder="Display name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <button
            className="primary"
            disabled={pending || slug === '' || name === ''}
            onClick={() =>
              startTransition(async () => {
                const result = await createProject(slug, name);
                if (result.ok) {
                  setSlug('');
                  setName('');
                  setOpen(false);
                  setError(null);
                } else {
                  setError(result.error);
                }
              })
            }
          >
            Create
          </button>
          <button onClick={() => setOpen(false)}>Cancel</button>
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
