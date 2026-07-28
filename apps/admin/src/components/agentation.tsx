import { lazy, Suspense } from 'react';
import { ClientOnly } from '@tanstack/react-router';

// Point-and-click UI feedback overlay (agentation.com): you annotate the page,
// the agent reads the annotations over MCP at localhost:4747. Dev-only.
//
// The ternary is what keeps it out of production: import.meta.env.DEV is
// replaced with a literal at build time, so the dynamic import is unreachable
// in the prod build and Rollup drops the chunk entirely.
const Toolbar = import.meta.env.DEV
  ? lazy(() => import('agentation').then((m) => ({ default: m.Agentation })))
  : () => null;

export function Agentation() {
  if (!import.meta.env.DEV) return null;

  return (
    // The toolbar reads the DOM and portals into document.body, so it must not
    // run during SSR or the hydration pass.
    <ClientOnly>
      <Suspense fallback={null}>
        <Toolbar endpoint="http://localhost:4747" />
      </Suspense>
    </ClientOnly>
  );
}
