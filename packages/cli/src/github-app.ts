// GitHub sign-in, for `coffre setup` on Workers: a GitHub App made from a
// manifest. Setup serves a page that posts the manifest to GitHub; GitHub
// shows its own page to create the app, then sends the browser back here
// with a code, which setup turns into the app's client ID and secret. The
// app's private key and webhook secret come with them, and are dropped:
// sign-in needs neither.
//
// On a machine the browser is not on, the page is a data: address to paste
// into the browser instead, and GitHub's way back, the address the browser
// then fails to load, is pasted here. Both land in the same handler.
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { localCallback, openBrowser } from './browser.ts';
import type { Link } from './cloudflare.ts';
import type { Step } from './steps.ts';

/** GitHub's addresses: github.com's, or a GitHub Enterprise Server's. */
export type GitHub = { web: string; api: string };

export const GITHUB: GitHub = { web: 'https://github.com', api: 'https://api.github.com' };

/** An app as made: `url` its public page, `settings` its settings page, where its logo goes. */
export type GitHubApp = { clientId: string; clientSecret: string; slug: string; url: string; settings: string };

/**
 * coffre's mark as an app's logo, as GitHub takes one: a square PNG, 512px,
 * on its black tile, which reads in GitHub's light and dark themes alike.
 * Neither the manifest nor GitHub's API sets a logo: it is uploaded on the
 * app's settings page, by hand.
 */
const LOGO = fileURLToPath(new URL('../assets/github-app-logo.png', import.meta.url));

/** Where the logo is, for someone in a deployment's directory: its own CLI's copy when it has one, else this CLI's. */
export function logoPath(dir: string): string {
  const pinned = join('node_modules', '@coffre', 'cli', 'assets', 'github-app-logo.png');
  return existsSync(join(dir, pinned)) ? pinned : LOGO;
}

/** An app's settings page: under its owner's, a person's or an organization's. */
export function appSettings(github: GitHub, slug: string, owner?: { login?: string; type?: string }): string {
  const under = owner?.type === 'Organization' && owner.login !== undefined ? `organizations/${owner.login}/` : '';
  return `${github.web}/${under}settings/apps/${slug}`;
}

/** GitHub's limit on an app's name. */
const NAME_LIMIT = 34;

/** `coffre-` and the address, its dots as dashes, as long as GitHub allows: unique, as GitHub needs, and editable on its page. */
export function appName(address: string): string {
  return `coffre-${address.replace(/\./g, '-')}`.slice(0, NAME_LIMIT).replace(/-+$/, '');
}

/**
 * The app coffre's sign-in needs: private, its callback coffre's, the one
 * permission to read a person's email addresses, and no webhook. A
 * manifest names that permission `emails`, as GitHub's form does, not
 * `email_addresses`, as its API does: GitHub refuses the latter here.
 */
export function appManifest(publicUrl: string, redirect: string) {
  return {
    name: appName(new URL(publicUrl).host),
    url: publicUrl,
    redirect_url: redirect,
    callback_urls: [`${publicUrl}/auth/callback/github`],
    public: false,
    default_permissions: { emails: 'read' },
    hook_attributes: { url: publicUrl, active: false },
  };
}

const escape = (text: string) => text.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

/** A page of a few words, in the browser's own type. */
function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:20vh auto;padding:0 1.5rem;color:#1f2328}h1{font-size:1.25rem;font-weight:600}p{color:#59636e}button{font:inherit;padding:.4rem 1rem}</style>
${body}`;
}

/** The page that posts the manifest to GitHub, at once. */
export function manifestPage(github: GitHub, manifest: object, state: string): string {
  const action = `${github.web}/settings/apps/new?state=${encodeURIComponent(state)}`;
  return page(
    'coffre: to GitHub',
    `<h1>Taking you to GitHub</h1><p>to create coffre's GitHub App.</p>
<form method="post" action="${escape(action)}"><input type="hidden" name="manifest" value="${escape(JSON.stringify(manifest))}"><noscript><button>Continue to GitHub</button></noscript></form>
<script>document.forms[0].submit()</script>`,
  );
}

/**
 * The same form as an address, for a browser on another machine: as short
 * as it can be, and readable, so that it plainly goes to GitHub and nowhere
 * else. A browser takes it typed or pasted, never from a link.
 */
export function manifestAddress(github: GitHub, manifest: object, state: string): string {
  const action = `${github.web}/settings/apps/new?state=${encodeURIComponent(state)}`;
  const value = JSON.stringify(manifest).replace(/&/g, '&amp;').replace(/'/g, '&#39;');
  const html = `<form method=post action="${escape(action)}"><input type=hidden name=manifest value='${value}'></form><script>document.forms[0].submit()</script>`;
  return `data:text/html,${html.replace(/[%#\s]/g, (c) => encodeURIComponent(c))}`;
}

/** GitHub's code for the app it made, as the app's client ID and secret. The code lasts an hour, and works once. */
export async function convert(github: GitHub, code: string): Promise<GitHubApp> {
  const response = await fetch(`${github.api}/app-manifests/${encodeURIComponent(code)}/conversions`, {
    method: 'POST',
    headers: { accept: 'application/vnd.github+json', 'user-agent': 'coffre-setup', 'x-github-api-version': '2022-11-28' },
  });
  const made = (await response.json().catch(() => ({}))) as {
    client_id?: string;
    client_secret?: string;
    slug?: string;
    html_url?: string;
    owner?: { login?: string; type?: string };
    message?: string;
  };
  if (!response.ok || made.client_id === undefined || made.client_secret === undefined) {
    throw new Error(`GitHub answered ${response.status}${made.message === undefined ? '' : `: ${made.message}`}`);
  }
  const slug = made.slug ?? '';
  return { clientId: made.client_id, clientSecret: made.client_secret, slug, url: made.html_url ?? '', settings: appSettings(github, slug, made.owner) };
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port));
  });
}

/**
 * coffre's GitHub App, made in the browser: on this machine, through
 * setup's page and its callback; on another, through the data: address,
 * and the callback's address pasted back. Whichever comes first.
 */
export async function createGitHubApp(step: Step, say: { aside: (text: string) => void; link: Link }, github: GitHub, publicUrl: string): Promise<GitHubApp> {
  const state = randomBytes(16).toString('base64url');
  const done = new AbortController();
  let app: GitHubApp | null = null;
  let manifest: object = {};
  /** The way back from GitHub, by either road: the app, or why not. */
  const take = async (url: URL): Promise<string | null> => {
    if (app !== null) return null;
    if (url.searchParams.get('state') !== state) return 'that address is from another run of setup: create the app from this one';
    try {
      app = await convert(github, url.searchParams.get('code')!);
    } catch (error) {
      return `GitHub did not take its code: ${(error as Error).message}`;
    }
    done.abort();
    return null;
  };
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    const send = (status: number, html: string) => response.writeHead(status, { 'content-type': 'text/html; charset=utf-8' }).end(html);
    if (url.pathname === '/') return send(200, manifestPage(github, manifest, state));
    if (url.pathname !== '/created') return send(404, page('coffre', '<h1>Not here</h1>'));
    void take(url).then((error) =>
      error === null
        ? send(200, page("coffre's GitHub App", "<h1>coffre's GitHub App is made</h1><p>Back to your terminal: setup carries on there.</p>"))
        : send(400, page('coffre', `<h1>Not made</h1><p>${escape(error)}</p>`)),
    );
  });
  const port = await listen(server);
  try {
    const here = `http://127.0.0.1:${port}/`;
    manifest = appManifest(publicUrl, `${here}created`);
    // GitHub's page shows the name alone: what the app may do is said here, first.
    say.aside("coffre's GitHub App may read the email addresses of whoever signs in with it, and nothing else.");
    say.link("If no browser opened, create it at", here);
    say.link('From a browser on another machine, open this address instead:', manifestAddress(github, manifest, state));
    openBrowser(here);
    step.note("GitHub: create coffre's app in your browser; its name is yours to change");
    await step.paste(
      'If your browser shows an error at a localhost address, paste that address here:',
      async (text) => {
        const url = localCallback(text, port, '/created', ['code', 'state']);
        return typeof url === 'string' ? url : take(url);
      },
      done.signal,
    );
    return app!;
  } finally {
    server.closeAllConnections();
    server.close();
  }
}
