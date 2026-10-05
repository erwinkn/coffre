// coffre's pages in a real browser, signed in: each renders its heading,
// and its scripts run without an error. What a bundler does to the code a
// page receives shows only there: wrangler's keep_names once wrapped the
// functions seroval writes into a page in an `__name` that only the Worker
// had, and a signed-in page rendered, then went blank.
import { Chrome, findChrome } from '../chrome.ts';
import type { Deployment } from '../harness.ts';
import { expect, Skip } from '../report.ts';
import { type Person, PROJECT } from './people.ts';

/** Each page, and the heading it shows. */
const PAGES = [
  ['/projects', 'Projects'],
  [`/projects/${PROJECT}`, 'Conformance'],
  ['/audit', 'Audit'],
] as const;

/** A service account of the pages' own, whose page shows how it signs in. */
const SERVICE = 'token:conformance-pages';

export async function pagesInBrowser(deployment: Deployment, admin: Person, browser: string | null): Promise<string> {
  const executable = browser ?? findChrome();
  if (executable === null) throw new Skip('no Chrome or Chromium here: --browser <path> names one');
  await admin.api.members.add(SERVICE);
  const name = SERVICE.slice('token:'.length);
  // A service account is service:<name> to people; the API and the log keep token:<name>.
  const pages = [...PAGES, ['/tokens', 'Service accounts'], [`/tokens/${name}`, `service:${name}`]] as const;
  const chrome = await Chrome.open(executable);
  try {
    for (const [path, heading] of pages) {
      const loaded = await chrome.load(new URL(path, deployment.origin).href, admin.browser.cookies());
      expect(loaded.errors.length === 0, `${path}, signed in, reported errors in the browser`, loaded.errors.join('\n'));
      // The heading, then what may follow it in the h1, such as a project's slug.
      expect(loaded.heading?.startsWith(heading), `${path}, signed in, shows ${JSON.stringify(loaded.heading)}, not the heading ${JSON.stringify(heading)}`);
      if (path.startsWith('/tokens')) expect(!/(?<![\w-])token:[A-Za-z0-9]/.test(loaded.text), `${path} shows a service account as token:<name>`, loaded.text);
      if (path === `/tokens/${name}`) {
        const ways = loaded.cards.filter((title) => title === 'Sign in with OIDC' || title === 'Bearer tokens');
        expect(ways.join(' then ') === 'Sign in with OIDC then Bearer tokens', `${path} does not show OIDC, then bearer tokens`, loaded.cards);
      }
    }
  } finally {
    await chrome.close();
  }
  return `${pages.map(([path]) => path).join(', ')}, signed in, in Chrome: each rendered, no error from their scripts; a service account shown as service:${name}, OIDC then bearer tokens`;
}
