// The screen a new deployment's secrets are shown on, once. It is the
// terminal's alternate screen, as `less` and `vim` use: leaving it puts back
// what was there, and nothing it showed stays in the scrollback. Values are
// masked until revealed, copied with a key, and a second view says where
// each goes. Leaving asks first, since they will not be shown again.
import { Clipboard, CLEAR_AFTER_MS } from './clipboard.ts';
import { type Key, type Keyboard, type Output, readKeys, type Style, style, truncate, width, wrap } from './tty.ts';

/** A value to save, how much of it to hide, and one line on what it is for and where it goes. */
export type Value = { label: string; value: string; mask: 'all' | 'password' | 'none'; about: string };

export type Section = { title: string; values: Value[] };

/** A command to copy, in the guide. It holds no secret: one it needs, it asks for. */
export type Command = { command: string };

export type GuideBlock = { title: string; lines: (string | Command)[] };

export type Screen = {
  title: string;
  sections: Section[];
  /** The 'where these go' view. */
  guide: GuideBlock[];
};

type View = 'values' | 'guide';

export type ScreenState = {
  view: View;
  selected: Record<View, number>;
  scroll: Record<View, number>;
  /** By item: a value's label, or a command's text. */
  revealed: Set<string>;
  revealAll: boolean;
  copied: Set<string>;
  status: string;
  confirming: boolean;
};

export function initialState(): ScreenState {
  return {
    view: 'values',
    selected: { values: 0, guide: 0 },
    scroll: { values: 0, guide: 0 },
    revealed: new Set(),
    revealAll: false,
    copied: new Set(),
    status: '',
    confirming: false,
  };
}

type Item = { id: string; text: string; secret: boolean; name: string };

/** What the arrows move between: a view's values, or its commands. */
export function items(screen: Screen, view: View): Item[] {
  if (view === 'values') {
    return screen.sections.flatMap(({ values }) =>
      values.map(({ label, value, mask }) => ({ id: label, text: value, secret: mask !== 'none', name: `the ${lower(label)}` })),
    );
  }
  return screen.guide.flatMap(({ lines }) =>
    lines.flatMap((line) => (typeof line === 'string' ? [] : [{ id: line.command, text: line.command, secret: false, name: 'the command' }])),
  );
}

const DOTS = '•'.repeat(32);
const URL_PASSWORD = /(:\/\/[^:@/\s']*:)([^@\s']+)(@)/g;

function masked(value: string, mask: Value['mask']): string {
  if (mask === 'all') return DOTS;
  if (mask === 'password') return value.replace(URL_PASSWORD, '$1••••••••$3');
  return value;
}

/** The values' count in words, for the question before leaving. */
function saved(count: number): string {
  return count === 1 ? 'the value' : count === 2 ? 'both values' : `all ${['three', 'four', 'five', 'six'][count - 3] ?? count} values`;
}

/**
 * The screen as `rows` lines of at most `columns`: a header, the view's
 * lines, scrolled to keep the selected item in sight, and the keys. Sets
 * the view's scroll in `state`.
 */
export function render(screen: Screen, state: ScreenState, columns: number, rows: number, s: Style): string[] {
  // Two columns of margin, and two more for the selection's bar.
  const inner = Math.max(20, columns - 6);
  const rule = `  ${s.dim('─'.repeat(Math.max(10, columns - 4)))}`;
  const count = screen.sections.reduce((n, { values }) => n + values.length, 0);
  const right = s.dim(`${count} value${count === 1 ? '' : 's'} · shown once`);
  const title = `  ${s.bold(screen.title)}`;
  const header = [
    '',
    `${title}${' '.repeat(Math.max(1, columns - width(title) - width(right) - 2))}${right}`,
    rule,
    ...(state.view === 'values'
      ? wrap("Save each one in your password manager now. They aren't stored anywhere, and won't be shown again.", columns - 4).map((line) => `  ${line}`)
      : [`  ${s.bold('Where these go')}`]),
    '',
  ];

  const body: string[] = [];
  const spans: [number, number][] = [];
  const list = items(screen, state.view);
  const selected = Math.min(state.selected[state.view], list.length - 1);
  const shown = (item: Item) => state.revealAll || state.revealed.has(item.id);
  const bar = (on: boolean) => (on ? `  ${s.accent('▎')} ` : '    ');
  if (state.view === 'values') {
    let index = 0;
    for (const section of screen.sections) {
      body.push(`  ${s.dim(s.bold(section.title.toUpperCase()))}`);
      for (const value of section.values) {
        const on = index === selected;
        const item = list[index]!;
        const start = body.length;
        const copied = state.copied.has(item.id) ? `  ${s.green('✓ copied')}` : '';
        body.push(`${bar(on)}${on ? s.accent(s.bold(value.label)) : s.bold(value.label)}${copied}`);
        if (shown(item) || value.mask === 'none') for (const line of wrap(value.value, inner)) body.push(`${bar(on)}${line}`);
        else body.push(`${bar(on)}${truncate(dimDots(masked(value.value, value.mask), s), inner)}`);
        for (const line of wrap(value.about, inner)) body.push(`${bar(on)}${s.dim(line)}`);
        spans.push([start, body.length]);
        body.push('');
        index += 1;
      }
    }
  } else {
    let index = 0;
    for (const block of screen.guide) {
      body.push(`  ${s.dim(s.bold(block.title.toUpperCase()))}`);
      let after = false;
      for (const line of block.lines) {
        if (typeof line === 'string') {
          // Prose after commands starts a paragraph of its own.
          if (after) body.push('');
          for (const part of wrap(line, inner)) body.push(`    ${part}`);
          after = false;
          continue;
        }
        after = true;
        const on = index === selected;
        const item = list[index]!;
        const start = body.length;
        const text = line.command;
        const copied = state.copied.has(item.id) ? ` ${s.green('✓')}` : '';
        wrap(text, inner - 2).forEach((part, i) => {
          const prompt = i === 0 ? s.dim('$ ') : '  ';
          body.push(`${bar(on)}${prompt}${on ? s.accent(part) : part}${i === 0 ? copied : ''}`);
        });
        spans.push([start, body.length]);
        index += 1;
      }
      body.push('');
    }
  }

  // The keys, on as many lines as the width takes: a narrow terminal still shows how to leave.
  const keys = (pairs: [string, string][]) => {
    const lines: string[] = [];
    let line = '';
    for (const [key, what] of pairs) {
      const hint = `${s.accent(key)} ${s.dim(what)}`;
      if (line !== '' && width(line) + 3 + width(hint) > columns - 4) {
        lines.push(`  ${line}`);
        line = hint;
      } else line = line === '' ? hint : `${line}   ${hint}`;
    }
    return [...lines, `  ${line}`];
  };
  const footer = state.confirming
    ? [
        rule,
        ...wrap(`Have you saved ${saved(count)}? They won't be shown again. (y/N)`, columns - 6).map(
          (line, i) => `  ${i === 0 ? s.accent('?') : ' '} ${s.bold(line)}`,
        ),
        ...keys([['y', 'yes, leave'], ['n', 'stay']]),
      ]
    : [
        rule,
        ...keys([
          ['↑↓', 'move'],
          ['c', 'copy'],
          ...(state.view === 'values' ? ([['r', 'reveal'], ['R', 'reveal all']] as [string, string][]) : []),
          ['w', state.view === 'values' ? 'where these go' : 'back to the values'],
          ['q', 'done'],
        ]),
        state.status === '' ? '' : `  ${state.status}`,
      ];

  while (body.at(-1) === '') body.pop();
  const height = Math.max(1, rows - header.length - footer.length - 1);
  const [start, end] = spans[selected] ?? [0, 0];
  let scroll = state.scroll[state.view];
  if (start < scroll) scroll = start;
  if (end > scroll + height) scroll = end - height;
  scroll = Math.max(0, Math.min(scroll, Math.max(0, body.length - height)));
  state.scroll[state.view] = scroll;
  const visible = body.slice(scroll, scroll + height);
  const more = [scroll > 0 ? '↑' : '', scroll + height < body.length ? '↓' : ''].join('');
  const filler = Array.from({ length: height - visible.length }, () => '');
  const scrolled = more === '' ? '' : `  ${s.dim(`${more} more`)}`;
  return [...header, ...visible, ...filler, scrolled, ...footer].slice(0, rows).map((line) => truncate(line, columns));
}

/** Where a screen is drawn and read from. */
export type Terminal = { keys: Keyboard; out: Output };

/**
 * Show `screen` on the alternate screen until the operator leaves it,
 * having said the values are saved. Nothing it shows reaches the main
 * screen, on any way out: q, Ctrl-C, a signal or an error.
 */
export async function showSecrets(terminal: Terminal, screen: Screen, clipboard?: Clipboard): Promise<void> {
  const { keys, out } = terminal;
  const s = style(out);
  const state = initialState();
  const draw = () => {
    const lines = render(screen, state, out.columns || 80, out.rows || 24, s);
    out.write(`\x1b[H${lines.map((line, i) => `\x1b[${i + 1};1H${line}\x1b[K`).join('')}\x1b[J`);
  };
  const board = clipboard ?? new Clipboard((sequence) => out.write(sequence), () => {
    if (state.status.startsWith('Copied')) {
      state.status = s.dim('Cleared the clipboard.');
      draw();
    }
  });

  let shown = true;
  const leave = () => {
    if (!shown) return;
    shown = false;
    out.write('\x1b[?25h\x1b[?1049l');
  };
  const signals = (['SIGINT', 'SIGTERM', 'SIGHUP'] as const).map((signal) => {
    const handler = () => {
      leave();
      keys.setRawMode?.(false);
      process.exit(128 + ({ SIGINT: 2, SIGTERM: 15, SIGHUP: 1 } as const)[signal]);
    };
    process.on(signal, handler);
    return () => process.off(signal, handler);
  });
  process.on('exit', leave);
  const resize = () => draw();
  out.on('resize', resize);

  out.write('\x1b[?1049h\x1b[?25l\x1b[2J');
  try {
    draw();
    await readKeys(keys, async (key) => {
      const done = await press(key, screen, state, board, s);
      if (!done) draw();
      return done;
    });
  } finally {
    await board.settle();
    leave();
    out.off('resize', resize);
    process.off('exit', leave);
    for (const off of signals) off();
  }
}

/** Act on one key; true to leave. */
async function press(key: Key, screen: Screen, state: ScreenState, clipboard: Clipboard, s: Style): Promise<boolean> {
  const quit = key.name === 'q' || key.name === 'escape' || (key.ctrl === true && key.name === 'c');
  if (state.confirming) {
    // A second Ctrl-C leaves too: whoever presses it twice means it.
    if (key.name === 'y' || (key.ctrl === true && key.name === 'c')) return true;
    state.confirming = false;
    return false;
  }
  if (quit) {
    state.confirming = true;
    return false;
  }
  const list = items(screen, state.view);
  const at = state.selected[state.view];
  const item = list[at];
  if (key.name === 'up' || key.name === 'k' || (key.name === 'tab' && key.shift === true)) {
    state.selected[state.view] = (at - 1 + list.length) % list.length;
  } else if (key.name === 'down' || key.name === 'j' || key.name === 'tab') {
    state.selected[state.view] = (at + 1) % list.length;
  } else if (key.name === 'w') {
    state.view = state.view === 'values' ? 'guide' : 'values';
    state.status = '';
  } else if (key.name === 'r' && key.shift === true) {
    state.revealAll = !state.revealAll;
    if (!state.revealAll) state.revealed.clear();
  } else if (key.name === 'r' && item !== undefined) {
    if (state.revealed.has(item.id)) state.revealed.delete(item.id);
    else state.revealed.add(item.id);
  } else if ((key.name === 'c' || key.name === 'return' || key.name === 'enter') && item !== undefined) {
    try {
      const where = await clipboard.copy(item.text);
      state.copied.add(item.id);
      state.status =
        where === 'system'
          ? `Copied ${item.name}. ${s.dim(`The clipboard clears in ${CLEAR_AFTER_MS / 1000} s, or when you leave.`)}`
          : `Copied ${item.name}, through the terminal. ${s.dim('Clear the clipboard once it is pasted.')}`;
    } catch (error) {
      state.status = s.red(`Couldn't copy ${item.name}: ${error instanceof Error ? error.message : String(error)}. Reveal it with r.`);
    }
  }
  return false;
}

/** Masking dots, dimmed: what is hidden recedes. */
function dimDots(text: string, s: Style): string {
  return text.replace(/•+/g, (dots) => s.dim(dots));
}

function lower(label: string): string {
  return label.replace(/^[A-Z](?![A-Z])/, (first) => first.toLowerCase());
}
