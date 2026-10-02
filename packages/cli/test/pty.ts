// The CLI in a pseudo-terminal, as an operator runs it, through util-linux's
// `script`: what it writes, byte for byte, and keys sent once it shows what
// a step waits for. Linux only; elsewhere the tests that need it skip.
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

export const ptySkip =
  process.platform !== 'linux' || spawnSync('script', ['--version']).status !== 0 ? 'needs util-linux script, on Linux' : false;

export const ENTER_ALT = '\x1b[?1049h';
export const LEAVE_ALT = '\x1b[?1049l';

export type Session = {
  /** Resolve once the output holds `text`, after what the last wait matched. */
  waitFor(text: string, timeoutMs?: number): Promise<void>;
  send(keys: string): void;
};

const quote = (arg: string) => `'${arg.replace(/'/g, `'\\''`)}'`;

/** Run `coffre <args>` in a terminal of `columns` by `rows`, play `session`, and return everything it wrote. */
export async function inTerminal(
  args: string[],
  env: NodeJS.ProcessEnv,
  play: (session: Session) => Promise<void>,
  size = { columns: 160, rows: 48 },
): Promise<{ output: string; code: number | null }> {
  const command = `stty cols ${size.columns} rows ${size.rows}; exec ${[process.execPath, '--conditions=coffre:source', main, ...args].map(quote).join(' ')}`;
  const child = spawn('script', ['-qfec', command, '/dev/null'], { env: { TERM: 'xterm-256color', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  let seen = 0;
  const waiters: { text: string; resolve: () => void }[] = [];
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => {
    output += chunk;
    for (const waiter of [...waiters]) {
      const at = output.indexOf(waiter.text, seen);
      if (at !== -1) {
        seen = at + waiter.text.length;
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.resolve();
      }
    }
  });
  const exited = new Promise<number | null>((resolve) => child.on('close', resolve));
  const session: Session = {
    waitFor: (text, timeoutMs = 20_000) =>
      new Promise((resolve, reject) => {
        const at = output.indexOf(text, seen);
        if (at !== -1) {
          seen = at + text.length;
          return resolve();
        }
        const timer = setTimeout(() => reject(new Error(`never saw ${JSON.stringify(text)} in:\n${visible(output)}`)), timeoutMs);
        waiters.push({ text, resolve: () => (clearTimeout(timer), resolve()) });
      }),
    send: (keys) => child.stdin.write(keys),
  };
  try {
    await play(session);
  } catch (error) {
    child.kill();
    throw error;
  }
  return { output, code: await exited };
}

/** The output outside the alternate screen, and inside it. */
export function screens(output: string): { main: string; alternate: string } {
  let main = '';
  let alternate = '';
  let rest = output;
  for (;;) {
    const enter = rest.indexOf(ENTER_ALT);
    if (enter === -1) return { main: main + rest, alternate };
    main += rest.slice(0, enter);
    rest = rest.slice(enter + ENTER_ALT.length);
    const leave = rest.indexOf(LEAVE_ALT);
    if (leave === -1) return { main, alternate: alternate + rest };
    alternate += rest.slice(0, leave);
    rest = rest.slice(leave + LEAVE_ALT.length);
  }
}

/** Output without its escape codes, to read. */
export function visible(output: string): string {
  return output.replace(/\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07/g, '');
}
