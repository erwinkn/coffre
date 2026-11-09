import { useState } from 'react';
import { useSuspenseQueries, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { ProxyPage as ProxyView, SecretKey } from '@coffre/client';

import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { inheritanceOf, parentsOf, type ParentPage, type Place } from '../lib/proxy';
import { ClosedDoor, PageHeader } from '../components/page';
import { EnvironmentTabs } from '../components/environment-tabs';
import { Protection } from '../components/protected';
import { Lock } from '../components/icons';
import { Notice } from '../components/ui';
import { AddItem, CopyFromEnvironment, PendingBar, ReservedNames, ReviewDialog, useProxyEdits } from '../components/proxy-parts';
import { ProxySheet } from '../components/proxy-sheet';
import { pageRoute } from '../lib/page-route';
import type { environmentProxy } from '../options';

const Route = pageRoute<typeof environmentProxy>();

/**
 * An environment's Proxy tab (0.16, T186; docs/design/proxy-ui.md): what
 * its credential proxy holds, routes, signers, verifiers and databases, as
 * a list and a panel. The deployment's code's items show locked, with
 * code's values (R66); the environment's own, and those it inherits from
 * its fork's parents, take edits from whoever holds `proxy.edit` here.
 * Edits wait on the page for one Save, which the vault decides.
 */
export function EnvironmentProxyPage() {
  const { project, environment } = Route.useParams();
  const place = { project, environment };
  const coffre = useCoffre();
  const { projects } = useShell();
  const environments = projects.find((entry) => entry.slug === project)?.environments ?? [];
  const parents = parentsOf(environments, place);
  const [{ data: secrets }, { data: page }] = useSuspenseQueries({ queries: [queries.secrets(coffre, place), queries.proxy(coffre, place)] });
  const inherited = useSuspenseQueries({
    queries: parents.map((path) => {
      const [parentProject, parentEnvironment] = path.split('/') as [string, string];
      return queries.proxy(coffre, { project: parentProject, environment: parentEnvironment });
    }),
  });

  if (!page.ok) {
    return (
      <ClosedDoor
        icon={<Lock size={18} />}
        label={<span className="mono">{project}/{environment}</span>}
        title="This environment's proxy is closed to you"
        actions={
          <Link className="btn" to="/projects/$project" params={{ project }}>
            Back to {project}
          </Link>
        }
      >
        {page.error}
      </ClosedDoor>
    );
  }
  return (
    <ProxyTab
      key={`${project}/${environment}`}
      place={place}
      page={page}
      parents={parents.map((path, index): ParentPage => {
        const read = inherited[index]?.data;
        return { path, page: read?.ok === true ? read : null };
      })}
      keys={secrets.ok ? secrets.keys : []}
    />
  );
}

function ProxyTab({ place, page, parents, keys }: { place: Place; page: ProxyView; parents: ParentPage[]; keys: SecretKey[] }) {
  const { project, environment } = place;
  const { projects } = useShell();
  const inProject = projects.find((entry) => entry.slug === project)?.environments.find((entry) => entry.slug === environment);
  const edits = useProxyEdits({ place, page, parents, keys });
  const [copying, setCopying] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const { stop } = inheritanceOf(parents);

  return (
    <>
      <PageHeader tile={project} title={environment} aside={inProject !== undefined && <Protection environment={inProject} />} />
      <EnvironmentTabs project={project} environment={environment} />

      {page.state !== 'ok' && (
        <Notice tone="bad">
          {project}/{environment}&apos;s proxy definitions {page.state === 'stale' ? 'are not their newest saved version' : "failed the vault's integrity check"}: none of
          them is shown, and none serves. {page.routesSensitive && page.editable ? 'Save new ones to replace them whole; the log names what is dropped.' : `An Owner of ${project} replaces them whole.`}
        </Notice>
      )}
      {page.readOnly?.reason === 'not_editable' && (
        <p className="hint proxy-readonly">This deployment&apos;s code keeps its proxy definitions. Set <span className="mono">proxy: {'{'} editable: true {'}'}</span> in its <span className="mono">deployment.ts</span> to write them here.</p>
      )}
      {stop !== null && (
        <p className="hint proxy-readonly">
          <span className="mono">{stop.path}</span> {stop.why === 'closed' ? 'is closed to you' : stop.why === 'stale' ? "holds proxy definitions that are not their newest saved version" : "holds proxy definitions that failed the vault's integrity check"}: what {environment} inherits from it, and through it, is not shown.
        </p>
      )}

      <ProxySheet
        edits={edits}
        selected={selected}
        onSelect={setSelected}
        footer={<AddItem edits={edits} onAdded={setSelected} onCopy={() => setCopying(true)} />}
      />
      <ReservedNames edits={edits} />

      <PendingBar edits={edits} />

      <ReviewDialog edits={edits} />
      {copying && <CopyFromEnvironment edits={edits} onClose={() => setCopying(false)} />}
    </>
  );
}
