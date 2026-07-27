'use client';

import { useState, useTransition } from 'react';
import {
  createEnvironment,
  createGrant,
  revokeGrant,
  setEnvironmentArchived,
  setProjectArchived,
  updateEnvironment,
  updateProject,
} from '../admin-actions';
import type { GrantRow, ProjectSummary } from '../../lib/api';

type Env = ProjectSummary['environments'][number];

export function ProjectClient({
  project,
  grants,
  grantsError,
}: {
  project: ProjectSummary;
  grants: GrantRow[];
  grantsError: string | null;
}) {
  const isAdmin = project.capability === 'admin';
  const active = project.environments.filter((e) => e.archivedAt === null);
  const archived = project.environments.filter((e) => e.archivedAt !== null);

  return (
    <>
      {isAdmin && <ProjectSettings project={project} />}

      <h2>Environments</h2>
      <div className="card">
        {active.length === 0 ? (
          <div className="empty">No environments yet.</div>
        ) : (
          active.map((environment) => (
            <EnvironmentRow
              key={environment.slug}
              project={project.slug}
              environment={environment}
              isAdmin={isAdmin}
            />
          ))
        )}
      </div>

      {isAdmin && <NewEnvironment project={project.slug} />}

      {archived.length > 0 && (
        <>
          <h2>Archived environments</h2>
          <div className="card">
            {archived.map((environment) => (
              <EnvironmentRow
                key={environment.slug}
                project={project.slug}
                environment={environment}
                isAdmin={isAdmin}
              />
            ))}
          </div>
        </>
      )}

      {isAdmin && (
        <Grants
          project={project.slug}
          environments={project.environments}
          grants={grants}
          error={grantsError}
        />
      )}
    </>
  );
}

function useAction() {
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function run(fn: () => Promise<{ ok: boolean; error?: string }>, onSuccess?: () => void) {
    startTransition(async () => {
      const result = await fn();
      if (result.ok) {
        setError(null);
        onSuccess?.();
      } else {
        setError(result.error ?? 'failed');
      }
    });
  }

  return { error, pending, run };
}

function ErrorLine({ error }: { error: string | null }) {
  if (error === null) return null;
  return (
    <div className="value" style={{ color: 'var(--deny)' }}>
      {error}
    </div>
  );
}

function ProjectSettings({ project }: { project: ProjectSummary }) {
  const [editing, setEditing] = useState(false);
  const [slug, setSlug] = useState(project.slug);
  const [name, setName] = useState(project.name);
  const { error, pending, run } = useAction();
  const isArchived = project.archivedAt !== null;

  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <div className="row">
        <div className="key">
          Project settings
          {isArchived && (
            <span className="pill deny" style={{ marginLeft: 10 }}>
              archived
            </span>
          )}
        </div>
        <button onClick={() => setEditing(!editing)}>{editing ? 'Cancel' : 'Rename'}</button>
        <button
          disabled={pending}
          onClick={() => run(() => setProjectArchived(project.slug, !isArchived))}
        >
          {isArchived ? 'Restore' : 'Archive'}
        </button>
      </div>

      {editing && (
        <div className="form-row">
          <input
            style={{ maxWidth: 240 }}
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
          />
          <input
            className="grow"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <button
            className="primary"
            disabled={pending}
            onClick={() =>
              run(
                () => updateProject(project.slug, { slug, name }),
                () => {
                  setEditing(false);
                  // The slug is part of the URL, so a rename has to navigate.
                  if (slug !== project.slug) window.location.href = `/${slug}`;
                },
              )
            }
          >
            Save
          </button>
        </div>
      )}

      {editing && (
        <div className="meta" style={{ padding: '0 14px 12px' }}>
          Renaming the slug is safe: ciphertext is bound to immutable ids, not to names.
        </div>
      )}
      <ErrorLine error={error} />
    </div>
  );
}

function EnvironmentRow({
  project,
  environment,
  isAdmin,
}: {
  project: string;
  environment: Env;
  isAdmin: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [slug, setSlug] = useState(environment.slug);
  const [name, setName] = useState(environment.name);
  const { error, pending, run } = useAction();
  const isArchived = environment.archivedAt !== null;

  return (
    <div>
      <div className="row">
        <div className="key">
          {isArchived ? (
            environment.slug
          ) : (
            <a href={`/${project}/${environment.slug}`}>{environment.slug}</a>
          )}
          <span className="meta" style={{ marginLeft: 10 }}>
            {environment.name}
          </span>
        </div>
        <span className="meta">
          {environment.secretCount} secret{environment.secretCount === 1 ? '' : 's'}
        </span>
        {isAdmin && (
          <>
            <button onClick={() => setEditing(!editing)}>
              {editing ? 'Cancel' : 'Rename'}
            </button>
            <button
              disabled={pending}
              onClick={() =>
                run(() => setEnvironmentArchived(project, environment.slug, !isArchived))
              }
            >
              {isArchived ? 'Restore' : 'Archive'}
            </button>
          </>
        )}
      </div>

      {editing && (
        <div className="form-row">
          <input
            style={{ maxWidth: 240 }}
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
          />
          <input
            className="grow"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <button
            className="primary"
            disabled={pending}
            onClick={() =>
              run(
                () => updateEnvironment(project, environment.slug, { slug, name }),
                () => setEditing(false),
              )
            }
          >
            Save
          </button>
        </div>
      )}
      <ErrorLine error={error} />
    </div>
  );
}

function NewEnvironment({ project }: { project: string }) {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const { error, pending, run } = useAction();

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="form-row">
        <input
          placeholder="slug (e.g. staging)"
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
            run(
              () => createEnvironment(project, slug, name),
              () => {
                setSlug('');
                setName('');
              },
            )
          }
        >
          Add environment
        </button>
      </div>
      <ErrorLine error={error} />
    </div>
  );
}

function Grants({
  project,
  environments,
  grants,
  error: loadError,
}: {
  project: string;
  environments: Env[];
  grants: GrantRow[];
  error: string | null;
}) {
  const [principalType, setPrincipalType] = useState<'user' | 'service'>('user');
  const [principalId, setPrincipalId] = useState('');
  const [capability, setCapability] = useState<'read' | 'write' | 'admin'>('read');
  const [scope, setScope] = useState('');
  const { error, pending, run } = useAction();

  return (
    <>
      <h2>Access</h2>
      <p className="sub">
        A project-scoped grant applies to every environment in it. Where both exist, the
        stronger capability wins. Machine callers are matched on their Access service-token
        common name, not an email.
      </p>

      {loadError !== null ? (
        <div className="notice bad">{loadError}</div>
      ) : (
        <div className="card">
          {grants.length === 0 ? (
            <div className="empty">No grants yet.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Principal</th>
                  <th>Type</th>
                  <th>Scope</th>
                  <th>Capability</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {grants.map((grant) => (
                  <GrantRowView key={grant.id} project={project} grant={grant} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <div className="card" style={{ marginTop: 12 }}>
        <div className="form-row">
          <select
            value={principalType}
            onChange={(event) => setPrincipalType(event.target.value as 'user' | 'service')}
          >
            <option value="user">user</option>
            <option value="service">service</option>
          </select>
          <input
            className="grow"
            placeholder={
              principalType === 'user' ? 'someone@equisafe.io' : 'ci-deploy.access'
            }
            value={principalId}
            onChange={(event) => setPrincipalId(event.target.value)}
          />
          <select value={scope} onChange={(event) => setScope(event.target.value)}>
            <option value="">whole project</option>
            {environments
              .filter((environment) => environment.archivedAt === null)
              .map((environment) => (
                <option key={environment.slug} value={environment.slug}>
                  {environment.slug}
                </option>
              ))}
          </select>
          <select
            value={capability}
            onChange={(event) =>
              setCapability(event.target.value as 'read' | 'write' | 'admin')
            }
          >
            <option value="read">read</option>
            <option value="write">write</option>
            <option value="admin">admin</option>
          </select>
          <button
            className="primary"
            disabled={pending || principalId === ''}
            onClick={() =>
              run(
                () =>
                  createGrant(project, {
                    principalType,
                    principalId,
                    capability,
                    environmentSlug: scope === '' ? null : scope,
                  }),
                () => setPrincipalId(''),
              )
            }
          >
            Grant
          </button>
        </div>
        <ErrorLine error={error} />
      </div>
    </>
  );
}

function GrantRowView({ project, grant }: { project: string; grant: GrantRow }) {
  const { error, pending, run } = useAction();

  return (
    <tr>
      <td className="wrap">{grant.principalId}</td>
      <td>
        <span className="pill">{grant.principalType}</span>
      </td>
      <td>{grant.scope === 'project' ? 'whole project' : grant.environmentSlug}</td>
      <td>
        <span className={`pill ${grant.capability === 'admin' ? 'admin' : ''}`}>
          {grant.capability}
        </span>
      </td>
      <td>
        <button disabled={pending} onClick={() => run(() => revokeGrant(project, grant.id))}>
          Revoke
        </button>
        {error !== null && <span style={{ color: 'var(--deny)' }}> {error}</span>}
      </td>
    </tr>
  );
}
