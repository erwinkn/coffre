// What the server renders into a coffre page's head so the browser fetches
// the page's code with the HTML, rather than once its entry has run: each
// page's chunk and the chunks it imports, as the deployment's build named
// them. coffre's Vite plugin (`@coffre/ui/vite`) finds them in the client's
// build and hands them to the server's, as this virtual module. In the
// browser, and under `vite dev`, there are none: the router preloads.
import known from 'virtual:coffre/preloads';

/** A page's `head`: `<link rel="modulepreload">` for each of its files. */
export function preloads(page: string) {
  return { links: (known[page] ?? []).map((href) => ({ rel: 'modulepreload', href })) };
}
