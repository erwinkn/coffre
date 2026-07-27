import { coffreFetch, type SecretKey } from '../../../lib/api';
import { SecretsClient } from './secrets-client';

export const dynamic = 'force-dynamic';

type Params = Promise<{ project: string; environment: string }>;

export default async function EnvironmentPage({ params }: { params: Params }) {
  const { project, environment } = await params;

  const result = await coffreFetch<{ capability: string; keys: SecretKey[] }>(
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
            {result.data.keys.length} secret{result.data.keys.length === 1 ? '' : 's'}
          </p>
        </div>
        <span className={`pill ${result.data.capability === 'admin' ? 'admin' : ''}`}>
          {result.data.capability}
        </span>
      </div>

      <div className="notice">
        Revealing a value writes an audit entry attributed to you. Listing keys does not.
      </div>

      <SecretsClient
        project={project}
        environment={environment}
        capability={result.data.capability}
        keys={result.data.keys}
      />
    </>
  );
}
