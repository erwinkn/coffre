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

/**
 * A menu item's dialog opened as a person would: the menu by its button,
 * then the item, by its words. Base UI's menu opens on a pointer press, not
 * a bare click.
 */
const openFromMenu = (menu: string, item: string) => `(async () => {
  const press = { bubbles: true, cancelable: true, pointerType: 'mouse', button: 0 };
  const trigger = document.querySelector(${JSON.stringify(menu)});
  for (const [Kind, type] of [[PointerEvent, 'pointerdown'], [MouseEvent, 'mousedown'], [PointerEvent, 'pointerup'], [MouseEvent, 'mouseup'], [MouseEvent, 'click']]) {
    trigger?.dispatchEvent(new Kind(type, press));
  }
  await new Promise((resolve) => setTimeout(resolve, 300));
  [...document.querySelectorAll('[role=menuitem]')].find((entry) => entry.textContent.includes(${JSON.stringify(item)}))?.click();
})()`;

/** A service account of the pages' own, whose page shows how it signs in. */
const SERVICE = 'token:conformance-pages';

const CONSENT_CLIENT = 'Conformance pages client';

/** A registered client's authorization request, as the consent page receives it. */
async function consentUrl(deployment: Deployment): Promise<string> {
  const redirect = 'http://127.0.0.1:33419/callback';
  const registered = await fetch(`${deployment.origin}/api/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: CONSENT_CLIENT, redirect_uris: [redirect] }),
  });
  const { client_id: clientId } = (await registered.json()) as { client_id?: string };
  expect(registered.status === 201 && clientId !== undefined, `registering an MCP client answered ${registered.status}`);
  const request = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirect,
    response_type: 'code',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
    state: 'pages',
    scope: 'browse write',
  });
  return `${deployment.origin}/oauth/authorize?${request}`;
}

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
  const pages = [...PAGES, ['/settings', 'Settings'], ['/tokens', 'Service accounts'], [`/tokens/${name}`, `service:${name}`]] as const;
  const chrome = await Chrome.open(executable);
  try {
    for (const [path, heading] of pages) {
      // On the service account's page, its removal is opened, and not confirmed: the dialog says first what it would revoke.
      const then = path === `/tokens/${name}` ? openFromMenu('button[aria-label^="Actions for"]', 'Remove') : undefined;
      const loaded = await chrome.load(new URL(path, deployment.origin).href, admin.browser.cookies(), undefined, then);
      expect(loaded.errors.length === 0, `${path}, signed in, reported errors in the browser`, loaded.errors.join('\n'));
      // The heading, then what may follow it in the h1, such as a project's slug.
      expect(loaded.heading?.startsWith(heading), `${path}, signed in, shows ${JSON.stringify(loaded.heading)}, not the heading ${JSON.stringify(heading)}`);
      if (path.startsWith('/tokens')) expect(!/(?<![\w-])token:[A-Za-z0-9]/.test(loaded.text), `${path} shows a service account as token:<name>`, loaded.text);
      if (path === `/tokens/${name}`) {
        const ways = loaded.cards.filter((title) => title === 'Sign in with OIDC' || title === 'Bearer tokens');
        expect(ways.join(' then ') === 'Sign in with OIDC then Bearer tokens', `${path} does not show OIDC, then bearer tokens`, loaded.cards);
        expect(loaded.dialog?.includes('Removing revokes 0 grants, 0 bearer tokens') === true, `${path}: Remove… does not preview what it would revoke`, loaded.dialog);
      }
      if (path === '/settings') expect(loaded.cards.includes('Keys'), '/settings does not show what the keys are checked against', loaded.cards);
    }
    // Its access on every project, which an owner grants and revokes on its Access tab.
    const access = `/tokens/${name}?tab=access`;
    await admin.api.access.set(SERVICE, { '*/dev': 'viewer' });
    try {
      const loaded = await chrome.load(new URL(access, deployment.origin).href, admin.browser.cookies());
      expect(loaded.errors.length === 0, `${access} reported errors in the browser`, loaded.errors.join('\n'));
      for (const shown of ['dev in every project', 'Grant on every project']) {
        expect(loaded.text.includes(shown), `${access}, to an owner, does not show "${shown}"`, loaded.text);
      }
    } finally {
      await admin.api.access.set(SERVICE, { '*/dev': null });
    }
    // The page an MCP client sends a person to: who asks, where the answer goes, and what it may do.
    const consent = await consentUrl(deployment);
    const loaded = await chrome.load(consent, admin.browser.cookies());
    expect(loaded.errors.length === 0, '/oauth/authorize reported errors in the browser', loaded.errors.join('\n'));
    expect(loaded.heading === `Connect ${CONSENT_CLIENT} to coffre?`, `/oauth/authorize shows ${JSON.stringify(loaded.heading)}`);
    for (const shown of ['Unverified', 'localhost', admin.email, 'Browse', 'Approve', 'Deny']) {
      expect(loaded.text.includes(shown), `/oauth/authorize does not show "${shown}"`, loaded.text);
    }
  } finally {
    await chrome.close();
  }
  return `${pages.map(([path]) => path).join(', ')}, signed in, in Chrome: each rendered, no error from their scripts; a service account shown as service:${name}, OIDC then bearer tokens, its removal previewed; the keys' checks in Settings; its grant on dev in every project with an owner's grant button; the MCP consent page, a registered client shown as unverified`;
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
