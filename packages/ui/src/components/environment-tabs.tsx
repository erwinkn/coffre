import { Link } from '@tanstack/react-router';

import { useMounted } from '../lib/mounted';
import { Key, Relay } from './icons';
import { PageTabs } from './tabs';

/**
 * An environment's tabs: its secrets, and its proxy definitions where the
 * deployment mounted that page (a prototype, W260). Each is a page of its
 * own beside the other, which draws the same header above them: the real
 * build makes the environment a layout, as a project is.
 */
export function EnvironmentTabs({ project, environment }: { project: string; environment: string }) {
  const mounted = useMounted();
  const params = { project, environment };
  return (
    <PageTabs label="Environment sections">
      {[
        <Link key="secrets" to="/projects/$project/$environment" params={params} activeOptions={{ exact: true, includeSearch: false }}>
          <Key size={15} />
          Secrets
        </Link>,
        mounted('/projects/$project/$environment/proxy') && (
          <Link key="proxy" to="/projects/$project/$environment/proxy" params={params}>
            <Relay size={15} />
            Proxy
          </Link>
        ),
      ]}
    </PageTabs>
  );
}
