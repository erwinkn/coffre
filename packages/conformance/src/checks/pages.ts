// coffre's pages in a real browser, signed in: each renders its heading,
// and its scripts run without an error. What a bundler does to the code a
// page receives shows only there: wrangler's keep_names once wrapped the
// functions seroval writes into a page in an `__name` that only the Worker
// had, and a signed-in page rendered, then went blank.
import { Browser } from '../browser.ts';
import { Chrome, findChrome } from '../chrome.ts';
import type { Deployment } from '../harness.ts';
import { expect, Skip } from '../report.ts';
import { type Person, PROJECT, signIn } from './people.ts';

/** Each page, and the heading it shows. */
const PAGES = [
  ['/projects', 'Projects'],
  [`/projects/${PROJECT}`, 'Conformance'],
  ['/audit', 'Audit'],
] as const;

/** A service account of the pages' own, whose page shows how it signs in. */
const SERVICE = 'token:conformance-pages';

/** The Chrome to run, the one given or the one found; skips the check when there is none. */
function chromeOrSkip(browser: string | null): string {
  const executable = browser ?? findChrome();
  if (executable === null) throw new Skip('no Chrome or Chromium here: --browser <path> names one');
  return executable;
}

export async function pagesInBrowser(deployment: Deployment, admin: Person, browser: string | null): Promise<string> {
  const executable = chromeOrSkip(browser);
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

/**
 * A refused sign-in, said once: the page coffre sends the browser back to
 * shows why, rendered by the server, then takes it out of the address, so a
 * reload is a clean retry. The refusal is a real one: a member's address
 * that GitHub now gives another account, which names the provider the
 * address already signs in with.
 */
export async function signinErrorOnce(deployment: Deployment, admin: Person, browser: string | null): Promise<string> {
  const executable = chromeOrSkip(browser);
  const email = 'recycled@conformance.example';
  await admin.api.members.add(`user:${email}`);
  const first = await signIn(deployment, new Browser(deployment.origin), email);
  expect(first.ok, `${email} was refused before anything changed: ${'error' in first ? first.error : ''}`);
  deployment.idp.setGitHubUser(email, { id: deployment.idp.gitHubUserFor(email).id + 1_000_000 });
  const visitor = new Browser(deployment.origin);
  const refused = await signIn(deployment, visitor, email);
  expect(!refused.ok && refused.error === 'account_mismatch', 'another GitHub account with a member\'s address was not refused as account_mismatch', refused);
  const back = new URL(refused.location, deployment.origin);
  expect(back.searchParams.get('with') === 'github', `the refusal does not name the provider the address signs in with: ${refused.location}`);

  const said = 'already signs in with another GitHub account';
  const html = await visitor.fetch(refused.location);
  expect(html.status === 200 && (await html.text()).includes(said), `${refused.location}, without scripts, does not say the address ${said}`, html.status);
  const chrome = await Chrome.open(executable);
  let clean: string;
  try {
    const shown = await chrome.load(back.href, visitor.cookies());
    expect(shown.errors.length === 0, `${refused.location} reported errors in the browser`, shown.errors.join('\n'));
    expect(shown.text.includes(said), `${refused.location} does not say the address ${said}`, shown.text);
    const after = new URL(shown.href);
    clean = `${after.pathname}${after.search}`;
    expect(['error', 'with', 'via'].every((name) => !after.searchParams.has(name)), `${refused.location} kept the refusal in its address`, shown.href);
    const reloaded = await chrome.load(shown.href, visitor.cookies());
    expect(!reloaded.text.includes(said), `${clean}, reloaded, still says the address ${said}`, reloaded.text);
    expect(reloaded.heading !== null, `${clean}, reloaded, rendered no heading`);
  } finally {
    await chrome.close();
  }
  return `${refused.location}: said by the server, once: Chrome then shows ${clean}, and a reload shows no error`;
}
