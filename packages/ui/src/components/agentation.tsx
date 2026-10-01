import { lazy, Suspense } from 'react';
import { ClientOnly } from '@tanstack/react-router';

// Point-and-click UI feedback overlay (agentation.com): you annotate the page,
// the agent reads the annotations over MCP from the annotation server on
// 127.0.0.1:4747. Dev-only. The toolbar reaches that server through the dev
// server's `/_agentation` proxy (dev/vite.config.ts) rather than at localhost
// directly, so annotating through a tunnel lands on this machine too.
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
        <SameOriginToolbar />
      </Suspense>
    </ClientOnly>
  );
}

/** Reads the page's origin, so it renders only inside ClientOnly, never on the server. */
function SameOriginToolbar() {
  return <Toolbar endpoint={`${window.location.origin}/_agentation`} />;
}
