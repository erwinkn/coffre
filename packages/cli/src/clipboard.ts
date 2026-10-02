// Copying a secret, as a password manager does. The system's clipboard
// tool gets the value on its stdin, never in its arguments, which other
// users can read in the process list; without one, the terminal copies it
// (OSC 52). A value copied through the system is cleared again when the
// clipboard still holds it: after `CLEAR_AFTER_MS`, or when the screen
// closes, whichever comes first.
import { spawn } from 'node:child_process';

export const CLEAR_AFTER_MS = 30_000;

type Tool = { copy: [string, ...string[]]; clear: [string, ...string[]]; paste: [string, ...string[]] };

/** The system's clipboard tool, by platform and display server; null for none known. */
export function systemTool(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): Tool | null {
  const windows: Tool = { copy: ['clip.exe'], clear: ['clip.exe'], paste: ['powershell.exe', '-NoProfile', '-Command', 'Get-Clipboard'] };
  if (platform === 'darwin') return { copy: ['pbcopy'], clear: ['pbcopy'], paste: ['pbpaste'] };
  if (platform === 'win32') return windows;
  if (platform !== 'linux') return null;
  if (env.WSL_DISTRO_NAME) return windows;
  if (env.WAYLAND_DISPLAY) return { copy: ['wl-copy'], clear: ['wl-copy', '--clear'], paste: ['wl-paste', '--no-newline'] };
  if (env.DISPLAY) {
    const xclip = ['xclip', '-selection', 'clipboard'] as const;
    return { copy: [...xclip], clear: [...xclip], paste: [...xclip, '-o'] };
  }
  return null;
}

/** Where a copy went: the system's clipboard, or the terminal's. */
export type Copied = 'system' | 'terminal';

export class Clipboard {
  #tool: Tool | null;
  readonly #terminal: (sequence: string) => void;
  #pending: { text: string; timer: NodeJS.Timeout } | null = null;
  readonly #onCleared: () => void;

  /** `terminal` writes an escape sequence to the screen, for OSC 52; `onCleared` hears of a clear. */
  constructor(terminal: (sequence: string) => void, onCleared: () => void = () => {}, tool = systemTool()) {
    this.#tool = tool;
    this.#terminal = terminal;
    this.#onCleared = onCleared;
  }

  async copy(text: string): Promise<Copied> {
    if (this.#tool !== null) {
      try {
        await feed(this.#tool.copy, text);
        this.#schedule(text);
        return 'system';
      } catch {
        // No such tool here after all, or no display: the terminal, from now on.
        this.#tool = null;
      }
    }
    this.#terminal(`\x1b]52;c;${Buffer.from(text).toString('base64')}\x07`);
    return 'terminal';
  }

  /** Clear a copy still pending now, as the screen closes. */
  async settle(): Promise<void> {
    const pending = this.#pending;
    if (pending === null) return;
    clearTimeout(pending.timer);
    this.#pending = null;
    await this.#clearIfHolds(pending.text);
  }

  #schedule(text: string): void {
    if (this.#pending !== null) clearTimeout(this.#pending.timer);
    const timer = setTimeout(() => {
      this.#pending = null;
      void this.#clearIfHolds(text).then(this.#onCleared, () => {});
    }, CLEAR_AFTER_MS);
    this.#pending = { text, timer };
  }

  /** Clear the clipboard if it still holds `text`: whatever was copied since stays. */
  async #clearIfHolds(text: string): Promise<void> {
    const tool = this.#tool;
    if (tool === null) return;
    try {
      if ((await read(tool.paste)) === text) await feed(tool.clear, '');
    } catch {
      // A clipboard that cannot be read back is left as it is.
    }
  }
}

const TOOL_TIMEOUT_MS = 3_000;

/** Run `command` with `input` on its stdin; its output is not waited for, since xclip and wl-copy stay to serve it. */
function feed([command, ...args]: string[], input: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command!, args, { stdio: ['pipe', 'ignore', 'ignore'], timeout: TOOL_TIMEOUT_MS });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`${command} exited with ${code}`))));
    // A tool that reads nothing, as wl-copy --clear, may be gone before its stdin closes: its exit code is the answer.
    child.stdin.on('error', () => {});
    if (input === '') child.stdin.end();
    else child.stdin.end(input);
  });
}

function read([command, ...args]: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command!, args, { stdio: ['ignore', 'pipe', 'ignore'], timeout: TOOL_TIMEOUT_MS });
    let out = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (out += chunk));
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve(out.replace(/\r?\n$/, '')) : reject(new Error(`${command} exited with ${code}`))));
  });
}
