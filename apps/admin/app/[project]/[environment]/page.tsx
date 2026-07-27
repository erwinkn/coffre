import { coffreFetch, type Permission, type SecretKey } from '../../../lib/api';
import { SecretsClient } from './secrets-client';

export const dynamic = 'force-dynamic';

type Params = Promise<{ project: string; environment: string }>;

export default async function EnvironmentPage({ params }: { params: Params }) {
  const { project, environment } = await params;

  const result = await coffreFetch<{ permissions: Permission[]; keys: SecretKey[] }>(
    `/v1/projects/${project}/environments/${environment}/keys`,
  );

  if (!result.ok) {
    return (
      <>
        <h1>
          {project} / {environment}
        </h1>
        <div className="notice bad">{result.error}</div>
        <a href="/">Back to projects</a>
      </>
    );
  }

  return (
    <>
      <div className="spread">
        <div>
          <h1>
            {project} / {environment}
          </h1>
          <p className="sub">
            {result.data.keys.filter((entry) => !entry.archived).length} secret
            {result.data.keys.filter((entry) => !entry.archived).length === 1 ? '' : 's'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {result.data.permissions.map((permission) => (
            <span className="pill" key={permission}>
              {permission}
            </span>
          ))}
        </div>
      </div>

      <div className="notice">
        Revealing a value writes an audit entry attributed to you. Listing keys does not.
      </div>

      <SecretsClient
        project={project}
        environment={environment}
        permissions={result.data.permissions}
        keys={result.data.keys}
      />
    </>
  );
}
