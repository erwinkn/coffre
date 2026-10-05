#!/usr/bin/env node
// Reads TLC's output for a counterexample, run with -difftrace, and prints it
// one step a line: which process moved, the step it took, and what changed in
// the rows, the locks and the log. scripts/formal.sh prints every
// counterexample through it; docs/formal.md shows some.
//
//   node scripts/formal-trace.mjs < tlc-output.txt

import { readFileSync } from 'node:fs';

/** A TLA+ value as TLC prints it: records, functions, tuples, sets, strings, numbers, booleans. */
function parse(text) {
  let i = 0;
  const space = () => {
    while (/\s/.test(text[i] ?? '')) i += 1;
  };
  const expect = (token) => {
    space();
    if (!text.startsWith(token, i)) throw new Error(`expected ${token} at ${i}: ${text.slice(i, i + 40)}`);
    i += token.length;
  };
  const list = (close, item) => {
    const items = [];
    space();
    if (text.startsWith(close, i)) {
      i += close.length;
      return items;
    }
    for (;;) {
      items.push(item());
      space();
      if (text.startsWith(close, i)) {
        i += close.length;
        return items;
      }
      expect(',');
    }
  };
  const value = () => {
    space();
    if (text.startsWith('<<', i)) {
      i += 2;
      return list('>>', value);
    }
    if (text[i] === '{') {
      i += 1;
      return { set: list('}', value) };
    }
    if (text[i] === '[') {
      i += 1;
      return Object.fromEntries(
        list(']', () => {
          space();
          const key = /^[A-Za-z_][\w]*/.exec(text.slice(i))[0];
          i += key.length;
          expect('|->');
          return [key, value()];
        }),
      );
    }
    if (text[i] === '"') {
      const end = text.indexOf('"', i + 1);
      const string = text.slice(i + 1, end);
      i = end + 1;
      return string;
    }
    const atom = /^(TRUE|FALSE|-?\d+)/.exec(text.slice(i));
    if (atom === null) throw new Error(`unexpected value at ${i}: ${text.slice(i, i + 40)}`);
    i += atom[0].length;
    return atom[0] === 'TRUE' ? true : atom[0] === 'FALSE' ? false : Number(atom[0]);
  };
  return value();
}

/** The trace's states, each its action and the variables it printed. */
function states(output) {
  const start = output.indexOf('The behavior up to this point is:');
  if (start === -1) return [];
  const found = [];
  let current = null;
  let variable = null;
  for (const line of output.slice(start).split('\n').slice(1)) {
    const header = /^State (\d+): <(\w+)/.exec(line);
    if (header !== null) {
      current = { n: Number(header[1]), action: header[2], vars: {} };
      found.push(current);
      variable = null;
      continue;
    }
    if (current === null) continue;
    const assignment = /^\/\\ (\w+) = (.*)$/.exec(line);
    if (assignment !== null) {
      variable = assignment[1];
      current.vars[variable] = assignment[2];
    } else if (variable !== null && line.trim() !== '' && !/^\d+ states generated|^(Error|Finished|The number)/.test(line)) {
      current.vars[variable] += ` ${line.trim()}`;
    } else {
      variable = null;
    }
  }
  return found.map((state) => ({ ...state, vars: Object.fromEntries(Object.entries(state.vars).map(([k, v]) => [k, parse(v)])) }));
}

/** A reference, named by the operation that made it, or the one a scenario starts with. */
const reference = (id) => (id[0] === 'none' ? 'none' : id[0]);

const show = (value) => {
  if (Array.isArray(value)) return `<<${value.map(show).join(', ')}>>`;
  if (value !== null && typeof value === 'object') {
    if ('set' in value) return `{${value.set.map(show).join(', ')}}`;
    if ('who' in value && 'at' in value && Object.keys(value).length === 2) return `${value.who}@${value.at}`;
    if ('kind' in value && 'at' in value && 'id' in value) {
      const via = value.via === undefined || value.via[0] === 'none' ? '' : ` via ${reference(value.via)}`;
      const reader = value.kind === 'secret.read' ? ` as ${value.who}${value.granted ? '' : ', ungranted'}` : '';
      return `${value.kind} ${value.at} (${value.id[0]})${via}${reader}`;
    }
    return `[${Object.entries(value).map(([k, v]) => `${k} ${show(v)}`).join(', ')}]`;
  }
  return String(value);
};

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** What changed in a variable, in words. */
function change(name, before, after) {
  if (after?.set !== undefined && before?.set !== undefined) {
    const added = after.set.filter((x) => !before.set.some((y) => same(x, y)));
    const removed = before.set.filter((x) => !after.set.some((y) => same(x, y)));
    return [...added.map((x) => `${name} +${show(x)}`), ...removed.map((x) => `${name} -${show(x)}`)];
  }
  if (Array.isArray(after) && Array.isArray(before) && after.length > before.length) {
    return after.slice(before.length).map((x) => `${name} +${show(x)}`);
  }
  if (after !== null && typeof after === 'object' && !Array.isArray(after) && before !== null && typeof before === 'object') {
    return Object.keys(after)
      .filter((key) => !same(before[key], after[key]))
      .map((key) => `${name}[${key}] ${show(before[key])} -> ${show(after[key])}`);
  }
  if (name === 'refRow') return [`ref ${reference(before)} -> ${reference(after)}`];
  return [`${name} ${show(before)} -> ${show(after)}`];
}

const SHOWN = ['slug', 'archived', 'held', 'version', 'grants', 'refRow', 'status', 'gen', 'memberLock', 'head', 'log', 'creds'];

function describe(op) {
  switch (op.kind) {
    case 'none': return '';
    case 'read': case 'write': return `${op.kind} ${op.at} as ${op.who}`;
    case 'grant': case 'revoke': return `${op.kind} ${op.who}@${op.at} by ${op.actor}`;
    case 'remove': return `remove ${op.who} by ${op.actor}`;
    case 'signin': return `signin ${op.who}`;
    case 'rotate': return 'rotate';
    default: return `${op.kind} ${op.at} by ${op.actor}`;
  }
}

const output = readFileSync(0, 'utf8');
const violated = /Error: (Invariant \w+ is violated|Deadlock reached)/.exec(output);
const trace = states(output);
if (trace.length === 0) {
  console.log('no counterexample in the output');
  process.exit(0);
}
if (violated) console.log(violated[1]);
const state = { ...trace[0].vars };
for (const step of trace.slice(1)) {
  const lines = [];
  const before = { pc: state.pc, l: state.l, op: state.op };
  for (const [name, value] of Object.entries(step.vars)) {
    if (SHOWN.includes(name) && !same(state[name], value)) lines.push(...change(name, state[name], value));
    state[name] = value;
  }
  // The process that moved: its label, its locals or its operation changed.
  const who = Object.keys(state.pc).find((p) => ['pc', 'l', 'op'].some((v) => !same(before[v][p], state[v][p]))) ?? '';
  const doing = who === '' ? '' : describe(state.op[who]);
  const label = who === '' ? '' : state.pc[who];
  console.log(`${String(step.n).padStart(3)}. ${who.padEnd(9)} ${step.action.padEnd(17)} ${doing.padEnd(26)} -> ${label.padEnd(15)} ${lines.join('; ')}`.trimEnd());
}
