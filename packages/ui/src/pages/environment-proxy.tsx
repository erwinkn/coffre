import { useState } from 'react';
import { useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';

import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { proxyQuery, type ProxyConfig, type ProxyPlace, type ProxyStore } from '../lib/proxy-prototype';
import type { SecretKey } from '../shared/models';
import { ClosedDoor, PageHeader } from '../components/page';
import { EnvironmentTabs } from '../components/environment-tabs';
import { Protection } from '../components/protected';
import { Lock } from '../components/icons';
import { AddCredential, CopyFromEnvironment, PendingBar, ReviewDialog, useProxyEdits } from '../components/proxy-parts';
import { ProxyLedger } from '../components/proxy-ledger';
import { ProxySheet } from '../components/proxy-sheet';
import { ProxyDocument } from '../components/proxy-document';
import { pageRoute } from '../lib/page-route';
import type { environmentProxy } from '../options';

const Route = pageRoute<ReturnType<typeof environmentProxy>>();

/**
 * An environment's Proxy tab, a prototype (W260, DO NOT MERGE): the
 * credentials `/use/<name>` serves here, the code's and the environment's
 * own, in three shapes to compare (`?variant=`): a ledger, a list and a
 * sheet, a document. Each edits the same pending changes, which one Save
 * stores. The deployment passes the store (`lib/proxy-prototype.ts` says
 * what it mocks).
 */
export function EnvironmentProxyPage({ store }: { store: ProxyStore }) {
  const { project, environment } = Route.useParams();
  const place = { project, environment };
  const { data: secrets } = useSuspenseQuery(queries.secrets(useCoffre(), place));
  const { data: config } = useSuspenseQuery(proxyQuery(store, place));

  if (!secrets.ok) {
    return (
      <ClosedDoor
        icon={<Lock size={18} />}
        label={<span className="mono">{project}/{environment}</span>}
        title="This environment is closed to you"
        actions={
          <Link className="btn" to="/projects/$project" params={{ project }}>
            Back to {project}
          </Link>
        }
      >
        {secrets.error}
      </ClosedDoor>
    );
  }
  return (
    <ProxyPage
      key={`${project}/${environment}`}
      store={store}
      place={place}
      config={config}
      keys={secrets.keys.filter((entry) => !entry.archived)}
      // `proxy.edit`, mocked: an Owner covering the place, whom the API tells apart as one who loosens a sensitive value.
      canEdit={secrets.loosenable === true}
    />
  );
}

const VARIANTS = [
  { id: undefined, label: 'Ledger' },
  { id: 'b', label: 'List' },
  { id: 'c', label: 'Document' },
] as const;

function ProxyPage({ store, place, config, keys, canEdit }: { store: ProxyStore; place: ProxyPlace; config: ProxyConfig; keys: SecretKey[]; canEdit: boolean }) {
  const { project, environment } = place;
  const { variant } = Route.useSearch();
  const { projects } = useShell();
  const inProject = projects.find((entry) => entry.slug === project)?.environments.find((entry) => entry.slug === environment);
  const edits = useProxyEdits({ store, place, config, keys, canEdit });
  const [copying, setCopying] = useState(false);
  // The list and sheet's pick, kept across variants with the edits.
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <>
      <PageHeader tile={project} title={environment} aside={inProject !== undefined && <Protection project={project} environment={inProject} />} />
      <div className="proxy-tabs">
        <EnvironmentTabs project={project} environment={environment} />
        <nav className="segmented segmented-sm proxy-variants" aria-label="Prototype variant">
          {VARIANTS.map((one) => (
            <Link
              key={one.label}
              to="/projects/$project/$environment/proxy"
              params={{ project, environment }}
              search={{ variant: one.id }}
              aria-current={variant === one.id ? 'page' : undefined}
            >
              {one.label}
            </Link>
          ))}
        </nav>
      </div>

      {variant === 'b' ? (
        <ProxySheet edits={edits} config={config} keys={keys} selected={selected} onSelect={setSelected} />
      ) : variant === 'c' ? (
        <ProxyDocument edits={edits} config={config} keys={keys} />
      ) : (
        <ProxyLedger edits={edits} config={config} keys={keys} />
      )}

      <PendingBar edits={edits} />
      <div className="table-actions">
        <AddCredential canEdit={canEdit} project={project} onAdd={() => setSelected(edits.add()[0]!)} onCopy={() => setCopying(true)} />
      </div>

      <ReviewDialog edits={edits} place={place} />
      {copying && <CopyFromEnvironment store={store} place={place} config={config} keys={keys} edits={edits} onClose={() => setCopying(false)} />}
    </>
  );
}
