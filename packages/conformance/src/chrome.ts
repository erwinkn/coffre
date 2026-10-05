// A real browser, for what only one shows: coffre's pages as they render
// and hydrate, their scripts run. Headless Chrome, driven over the DevTools
// protocol with Node's own WebSocket, so that conformance depends on no
// browser package; the machine's Chrome or Chromium does.
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

/** What a page did, loaded: the heading it shows, and every error its scripts and console reported. */
export type Loaded = {
  heading: string | null;
  /** The titles of the page's cards, in order. */
  cards: string[];
  /** What a person reads on it. */
  text: string;
  /** The address it ends at, once its scripts have run: a notice read once is taken out of it. */
  href: string;
  /** The text of the dialog open at the end, as after `then` opened one; null for none. */
  dialog: string | null;
  errors: string[];
};

const NAMES = ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'chrome'];
const MAC = ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium'];

/** A Chrome or Chromium on this machine: on PATH, where macOS keeps it, or Playwright's. */
export function findChrome(): string | null {
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    for (const name of NAMES) if (dir !== '' && existsSync(join(dir, name))) return join(dir, name);
  }
  for (const path of MAC) if (existsSync(path)) return path;
  const playwright = join(homedir(), '.cache', 'ms-playwright');
  if (existsSync(playwright)) {
    for (const dir of readdirSync(playwright).filter((name) => name.startsWith('chromium-')).sort().reverse()) {
      for (const build of ['chrome-linux64', 'chrome-linux']) {
        const path = join(playwright, dir, build, 'chrome');
        if (existsSync(path)) return path;
      }
    }
  }
  return null;
}

type Message = { id?: number; method?: string; params?: Record<string, unknown>; result?: Record<string, unknown>; error?: { message: string }; sessionId?: string };

export class Chrome {
  readonly #process: ChildProcess;
  readonly #socket: WebSocket;
  readonly #profile: string;
  #next = 0;
  readonly #pending = new Map<number, { resolve: (result: Record<string, unknown>) => void; reject: (error: Error) => void }>();
  readonly #listeners = new Set<(message: Message) => void>();

  private constructor(process: ChildProcess, socket: WebSocket, profile: string) {
    this.#process = process;
    this.#socket = socket;
    this.#profile = profile;
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data)) as Message;
      if (message.id !== undefined) {
        const pending = this.#pending.get(message.id);
        this.#pending.delete(message.id);
        if (message.error !== undefined) pending?.reject(new Error(message.error.message));
        else pending?.resolve(message.result ?? {});
      } else {
        for (const listener of this.#listeners) listener(message);
      }
    });
  }

  /** Chrome at `executable`, headless, with a profile of its own, gone when closed. */
  static async open(executable: string): Promise<Chrome> {
    const profile = mkdtempSync(join(tmpdir(), 'coffre-chrome-'));
    const child = spawn(
      executable,
      [
        '--headless=new',
        '--remote-debugging-port=0',
        `--user-data-dir=${profile}`,
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-gpu',
        // Only coffre's own pages are loaded; CI's runners have no user namespaces for Chrome's sandbox.
        '--no-sandbox',
        'about:blank',
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    const url = await new Promise<string>((resolve, reject) => {
      let output = '';
      const timer = setTimeout(() => reject(new Error(`Chrome did not start: ${output.trim().split('\n').slice(-3).join(' ')}`)), 30_000);
      child.stderr!.setEncoding('utf8').on('data', (chunk: string) => {
        output += chunk;
        const found = /DevTools listening on (ws:\/\/\S+)/.exec(output);
        if (found !== null) {
          clearTimeout(timer);
          resolve(found[1]!);
        }
      });
      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`Chrome exited with ${code}: ${output.trim().split('\n').slice(-3).join(' ')}`));
      });
    });
    const socket = new WebSocket(url);
    await new Promise<void>((resolve, reject) => {
      socket.addEventListener('open', () => resolve(), { once: true });
      socket.addEventListener('error', () => reject(new Error(`could not reach Chrome at ${url}`)), { once: true });
    });
    return new Chrome(child, socket, profile);
  }

  #send(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<Record<string, unknown>> {
    const id = ++this.#next;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }

  /**
   * `url` in a tab of its own, with `cookies` for its origin: the heading it
   * shows once its scripts have run and settled, and every uncaught error,
   * console error and failed load along the way. `then`, a script run once
   * the page settles, does what a person would next, such as open a dialog,
   * whose text is read with the rest.
   */
  async load(url: string, cookies: [string, string][], settle = 2_000, then?: string): Promise<Loaded> {
    const { targetId } = (await this.#send('Target.createTarget', { url: 'about:blank' })) as { targetId: string };
    const { sessionId } = (await this.#send('Target.attachToTarget', { targetId, flatten: true })) as { sessionId: string };
    const errors: string[] = [];
    let loaded!: () => void;
    const load = new Promise<void>((resolve) => (loaded = resolve));
    const listener = (message: Message) => {
      if (message.sessionId !== sessionId) return;
      const params = message.params ?? {};
      if (message.method === 'Runtime.exceptionThrown') {
        const details = params.exceptionDetails as { text: string; exception?: { description?: string }; url?: string; lineNumber?: number };
        errors.push(`${details.exception?.description?.split('\n')[0] ?? details.text}${details.url ? ` (${details.url}:${(details.lineNumber ?? 0) + 1})` : ''}`);
      } else if (message.method === 'Runtime.consoleAPICalled' && params.type === 'error') {
        const args = params.args as { value?: unknown; description?: string }[];
        errors.push(`console.error: ${args.map((arg) => arg.description ?? String(arg.value)).join(' ')}`);
      } else if (message.method === 'Log.entryAdded') {
        const entry = params.entry as { level: string; text: string; url?: string };
        if (entry.level === 'error') errors.push(`${entry.text}${entry.url ? ` (${entry.url})` : ''}`);
      } else if (message.method === 'Page.loadEventFired') {
        loaded();
      }
    };
    this.#listeners.add(listener);
    try {
      for (const domain of ['Runtime', 'Log', 'Page', 'Network']) await this.#send(`${domain}.enable`, {}, sessionId);
      for (const [name, value] of cookies) await this.#send('Network.setCookie', { name, value, url }, sessionId);
      await this.#send('Page.navigate', { url }, sessionId);
      await Promise.race([load, new Promise((resolve) => setTimeout(resolve, 30_000))]);
      // What streams in after the load, and hydration, have their time: the page may render, then fail.
      await new Promise((resolve) => setTimeout(resolve, settle));
      if (then !== undefined) {
        await this.#send('Runtime.evaluate', { expression: then, awaitPromise: true }, sessionId);
        // What it asked of the server has its time to come back.
        await new Promise((resolve) => setTimeout(resolve, settle));
      }
      // The heading, the cards' titles in order, all the text a person reads, and where the page ended.
      const expression = `({
        heading: document.querySelector('h1')?.textContent?.trim() || null,
        cards: [...document.querySelectorAll('h2.card-title')].map((title) => title.textContent.trim()),
        text: document.body.innerText,
        href: location.href,
        dialog: document.querySelector('[role=alertdialog], [role=dialog]')?.innerText ?? null,
      })`;
      const { result } = (await this.#send('Runtime.evaluate', { expression, returnByValue: true }, sessionId)) as {
        result: { value: { heading: string | null; cards: string[]; text: string; href: string; dialog: string | null } };
      };
      return { ...result.value, errors };
    } finally {
      this.#listeners.delete(listener);
      await this.#send('Target.closeTarget', { targetId }).catch(() => {});
    }
  }

  async close(): Promise<void> {
    await this.#send('Browser.close').catch(() => {});
    this.#socket.close();
    if (this.#process.exitCode === null) {
      await Promise.race([new Promise((resolve) => this.#process.once('exit', resolve)), new Promise((resolve) => setTimeout(resolve, 5_000))]);
      this.#process.kill('SIGKILL');
    }
    rmSync(this.#profile, { recursive: true, force: true });
  }
}
