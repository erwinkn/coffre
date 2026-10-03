#!/usr/bin/env node
// Check that the docs name only things that exist: every relative link and
// its #anchor, every repository path in backticks, and every `pnpm <script>`.
// The design record and the spikes describe what was, so only their links
// are checked.
//
//   pnpm check:docs
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (path) => readFileSync(join(root, path), 'utf8');

function markdown(dir) {
  return readdirSync(join(root, dir)).flatMap((name) => {
    const path = join(dir, name);
    if (name === 'node_modules' || name === 'dist') return [];
    if (statSync(join(root, path)).isDirectory()) return markdown(path);
    return name.endsWith('.md') ? [path] : [];
  });
}

const files = [
  'README.md',
  'AGENTS.md',
  ...markdown('docs'),
  ...markdown('examples').filter((path) => !path.includes('node_modules')),
  ...readdirSync(join(root, 'packages')).map((name) => `packages/${name}/README.md`).filter((path) => existsSync(join(root, path))),
];
const historical = (path) => path.startsWith('docs/design/') || path.startsWith('docs/spikes/');

/** GitHub's anchor for a heading. */
function slug(heading) {
  return heading
    .replace(/`/g, '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .replace(/\s/g, '-');
}

const anchors = new Map();
function anchorsOf(path) {
  if (!anchors.has(path)) {
    const text = read(path).replace(/```[\s\S]*?```/g, '');
    anchors.set(path, new Set([...text.matchAll(/^#{1,6}\s+(.+)$/gm)].map((match) => slug(match[1].trim()))));
  }
  return anchors.get(path);
}

const scriptsOf = (path) => (existsSync(join(root, path)) ? Object.keys(JSON.parse(read(path)).scripts ?? {}) : []);
const rootScripts = scriptsOf('package.json');
const exampleScripts = ['examples/workers/package.json', 'examples/node/package.json'].flatMap(scriptsOf);
const builtins = new Set(['install', 'exec', 'add', 'run', 'dlx', 'remove', 'update']);

const problems = [];
for (const file of files) {
  const text = read(file);
  const here = dirname(file);

  for (const [, target] of text.matchAll(/\]\(([^)\s]+)\)/g)) {
    if (/^(https?:|mailto:)/.test(target)) continue;
    const [path, anchor] = target.split('#');
    const resolved = path === '' ? file : relative(root, resolve(join(root, here), path));
    if (!existsSync(join(root, resolved))) {
      problems.push(`${file}: links to ${target}, which does not exist`);
      continue;
    }
    if (anchor !== undefined && resolved.endsWith('.md') && !anchorsOf(resolved).has(anchor)) {
      problems.push(`${file}: links to ${target}, but ${resolved} has no heading #${anchor}`);
    }
  }
  if (historical(file)) continue;

  for (const [, token] of text.matchAll(/`([^`\s]+)`/g)) {
    const path = token.replace(/[.,:;)]+$/, '').replace(/:\d+$/, '');
    if (!/^(packages|scripts|dev|examples|docs|\.github)\//.test(path) || /[{*<…]/.test(path)) continue;
    if (!existsSync(join(root, path))) problems.push(`${file}: names ${path}, which does not exist`);
  }

  const known = file.startsWith('examples/workers/')
    ? scriptsOf('examples/workers/package.json')
    : file.startsWith('examples/node/')
      ? scriptsOf('examples/node/package.json')
      : [...rootScripts, ...exampleScripts];
  // Commands are in code: fenced blocks and backticked spans.
  const code = [...text.matchAll(/```[\s\S]*?```|`[^`\n]+`/g)].map((match) => match[0]).join('\n');
  for (const [, rest] of code.matchAll(/\bpnpm\s+([^\n`#|&;]*)/g)) {
    const tokens = rest.trim().split(/\s+/);
    let dir;
    let script;
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token === '--dir' || token === '--filter' || token === '-C') dir = tokens[++i];
      else if (token.startsWith('--dir=') || token.startsWith('--filter=')) dir = token.split('=')[1];
      else if (token.startsWith('-') || token === 'run') continue;
      else {
        script = token;
        break;
      }
    }
    if (script === undefined || builtins.has(script) || !/^[\w:-]+$/.test(script)) continue;
    if (dir !== undefined) {
      const scripts = dir.startsWith('packages/')
        ? scriptsOf(`${dir}/package.json`)
        : [...exampleScripts, ...readdirSync(join(root, 'packages')).flatMap((name) => scriptsOf(`packages/${name}/package.json`))];
      if (!scripts.includes(script)) problems.push(`${file}: runs pnpm ${dir} ${script}, which is no such script`);
      continue;
    }
    const known = file.startsWith('examples/workers/')
      ? scriptsOf('examples/workers/package.json')
      : file.startsWith('examples/node/')
        ? scriptsOf('examples/node/package.json')
        : [...rootScripts, ...exampleScripts];
    if (!known.includes(script)) problems.push(`${file}: runs pnpm ${script}, which is no such script`);
  }
}

if (problems.length > 0) {
  console.error(problems.join('\n'));
  console.error(`\n${problems.length} problem${problems.length === 1 ? '' : 's'} in the docs`);
  process.exit(1);
}
console.log(`The docs name only what exists: ${files.length} files checked.`);
