// The repository's file graph, for `pnpm validate` (scripts/affected.mjs): which
// tracked files each source file runs and reads. A file runs another when it
// imports it (`import`, `export … from`, `import()`, `require()`), resolving
// `@coffre/*` through each package's `coffre:source` export, or names that one file
// in a string: a path relative to itself (`new URL('../src/main.ts',
// import.meta.url)`, a worker, a fixture) or to the repository's root (a test file a
// shell script runs). A directory named so, or a template literal's head (the text
// before its first `${`), is read: every file under it, as bytes, not run (`init`
// copies the examples and does not run their pages; the migrator reads
// `./migrations/${engine}`). A package's or the repository's root, named so, is a
// working directory. A package's build output stands for the source it is built from
// (`packages/cli/dist/main.js` is `src/main.ts`), so a bin that runs `dist/` runs its
// sources. A glob a test names scans every tracked file it matches but the tests (a
// test that greps the sources: deploy-on-push's libsodium check): a read that tests
// their text, not what they do; a glob elsewhere is a list of tests to run, which
// affected.mjs models, or a pattern (eslint.config.js's).
// A module that imports a tool reads the configuration the tool loads from the
// working directory (`eslint` loads eslint.config.js). Comments are not read.
//
// It may see more than a file uses, which only runs more tests. What it cannot see
// is a path built in pieces (`join('a', 'b')`): affected.mjs falls back to the
// package's tests for a file nothing reaches.
import { readFileSync } from 'node:fs'
import { dirname, join, normalize } from 'node:path'

/** The files whose text is scanned for edges. */
export const scanned = (file) => /\.(?:[cm]?[jt]sx?|sh)$/.test(file)
/** A test file, run by the suite: nothing but a script runs one. */
export const testFile = (file) => /\.(?:test|alone|matrix)\.(?:[cm]?[jt]s)$/.test(file)

// import x from '…', export { x } from '…', import '…'; import('…'), require('…').
const IMPORT = /\b(?:from|import)\s*(['"])([^'"\n]+)\1|\b(?:import|require)\s*\(\s*(['"])([^'"\n]+)\3/g
// Any string that reads as a path: relative, or from the repository's root.
const PATH = /(['"`])((?:\.\.?\/|(?:packages|scripts|examples|dev|formal|terraform-provider|action|docs)\/)[^'"`\s]*?)\1/g
// A shell word that may be a path: `./scripts/x.sh`, `packages/cli/test/setup.test.ts`, `src/migrate-main.ts`.
const SHELL_WORD = /(?<![\w$./-])(?:\$\{?\w+\}?\/|\.\/)?([\w.-]+\/[\w./-]+\.(?:[cm]?[jt]sx?|sh|sql))(?![\w/-])/g
// A pnpm script a command runs: at the root, or in the package a flag names.
const PNPM = /\bpnpm(?:\s+-s)?(?:\s+(--filter|-F|--dir|-C)\s+(\S+))?\s+(?:run\s+)?([a-z][\w:-]*)/g
// A template literal's head: `./migrations/${engine}` reads ./migrations/.
const HEAD = /`((?:\.\.?\/|(?:packages|scripts|examples|dev|formal)\/)[^`$\s]*)\$\{/g
// A tool an import names, to the configuration it loads from the repository's root.
const CONFIG = { eslint: 'eslint.config.js' }

/** A glob (`*`, `**`, `?`, `{a,b}`) as a regular expression over paths. */
const globToRegExp = (glob) =>
  new RegExp(
    `^${glob
      .replace(/[.+^$()|[\]\\]/g, '\\$&')
      .replace(/\*\*\/|\*\*|\*|\?|\{([^}]*)\}/g, (m, alts) =>
        m === '**/' ? '(?:.*/)?' : m === '**' ? '.*' : m === '*' ? '[^/]*' : m === '?' ? '[^/]' : `(?:${alts.split(',').join('|')})`,
      )}$`,
  )

/**
 * Source text without its comments, its strings kept: for JavaScript and
 * TypeScript, `//` and `/* *\/` outside strings, templates and regular
 * expressions; for shell, lines that start with `#`.
 */
export function uncommented(file, text) {
  if (file.endsWith('.sh')) return text.replace(/^\s*#.*$/gm, '')
  let out = ''
  let i = 0
  // Template nesting: each entry, the brace depth at which a `${` returns to its template.
  const templates = []
  let depth = 0
  let last = '' // the last significant character, to tell a regular expression from a division
  const regexAfter = /[(,=:[!&|?{};+\-*%<>~^]|^$/
  while (i < text.length) {
    const c = text[i]
    const next = text[i + 1]
    if (c === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') i++
      continue
    }
    if (c === '/' && next === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? text.length : end + 2
      out += ' '
      continue
    }
    if (c === "'" || c === '"' || c === '`' || (c === '}' && templates.at(-1) === depth)) {
      // A string, a template, or the rest of a template after one of its `${…}`.
      const quote = c === '}' ? '`' : c
      if (c === '}') templates.pop()
      let j = i + 1
      let opened = false
      while (j < text.length && text[j] !== quote && !(quote !== '`' && text[j] === '\n')) {
        if (text[j] === '\\') j++
        else if (quote === '`' && text[j] === '$' && text[j + 1] === '{') {
          templates.push(depth)
          opened = true
          j++
          break
        }
        j++
      }
      out += text.slice(i, j + 1)
      i = j + 1
      last = opened ? '{' : quote
      continue
    }
    if (c === '/' && (regexAfter.test(last) || /\b(?:return|typeof|case|in|of|void|yield|await|else|do)$/.test(out.trimEnd()))) {
      let j = i + 1
      let inClass = false
      while (j < text.length && text[j] !== '\n' && (inClass || text[j] !== '/')) {
        if (text[j] === '\\') j++
        else if (text[j] === '[') inClass = true
        else if (text[j] === ']') inClass = false
        j++
      }
      out += text.slice(i, j + 1)
      i = j + 1
      last = '/'
      continue
    }
    if (c === '{') depth++
    else if (c === '}') depth--
    if (!/\s/.test(c)) last = c
    out += c
    i++
  }
  return out
}

/**
 * The graph of `files` (tracked paths, relative to `root`): a Map from each scanned
 * file, and each `package.json`'s scripts (`packages/db/package.json#db:migrate`), to
 * `{ runs, reads, scans }`, the sets of what it runs, reads, and scans (a test's glob). `read(file)` returns a
 * file's text (default: from disk), so tests can hand it a tree of their own.
 */
export function buildGraph(root, files, read = (file) => readFileSync(join(root, file), 'utf8')) {
  const tracked = new Set(files)
  const sorted = [...tracked].sort()
  // The repository's root, its top directories and each package's: a plain string naming
  // one is a working directory or a prefix to match (`f.startsWith('packages/')`), not a read.
  const roots = new Set(['', ...files.filter((f) => f.includes('/')).map((f) => f.slice(0, f.indexOf('/')))])
  const manifests = new Map()
  for (const file of files) {
    if (file !== 'package.json' && !file.endsWith('/package.json')) continue
    const dir = dirname(file) === '.' ? '' : dirname(file)
    roots.add(dir)
    try {
      manifests.set(file, { dir, ...JSON.parse(read(file)) })
    } catch {}
  }
  const byName = new Map([...manifests].map(([file, m]) => [m.name, file]))

  /** Every tracked file whose path starts with `prefix`. */
  const under = (prefix) => {
    let lo = 0
    let hi = sorted.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (sorted[mid] < prefix) lo = mid + 1
      else hi = mid
    }
    const out = []
    for (let i = lo; i < sorted.length && sorted[i].startsWith(prefix); i++) out.push(sorted[i])
    return out
  }

  /** A path from the root to the tracked file it names (`file`), or the files under it (`dir`). */
  const resolvePath = (path) => {
    if (path.startsWith('..') || path.startsWith('/') || path.includes('*')) return {}
    const clean = path.replace(/\/+$/, '')
    // dist/ is built, never tracked: the file it is built from.
    const built = /^(packages\/[^/]+)\/dist\/(.+)\.[cm]?js$/.exec(clean)
    const sources = built ? [`${built[1]}/src/${built[2]}.ts`, `${built[1]}/src/${built[2]}.tsx`] : []
    for (const candidate of [...sources, clean, `${clean}.ts`, `${clean}.tsx`, `${clean}/index.ts`]) if (tracked.has(candidate)) return { file: candidate }
    if (roots.has(clean === '.' ? '' : clean)) return {}
    return { dir: under(`${clean}/`) }
  }

  /** `@coffre/x/sub` to the source file its `coffre:source` condition names. */
  const resolvePackage = (specifier) => {
    const match = /^(@coffre\/[^/]+)(\/.*)?$/.exec(specifier)
    const pkg = match && manifests.get(byName.get(match[1]))
    if (!pkg) return {}
    const subpath = `.${match[2] ?? ''}`
    for (const [key, entry] of Object.entries(pkg.exports ?? {})) {
      const to = typeof entry === 'string' ? entry : (entry?.['coffre:source'] ?? entry?.default)
      if (typeof to !== 'string') continue
      if (key === subpath) return resolvePath(normalize(join(pkg.dir, to)))
      const star = key.indexOf('*')
      if (star >= 0 && subpath.startsWith(key.slice(0, star)) && subpath.endsWith(key.slice(star + 1))) {
        const middle = subpath.slice(star, subpath.length - (key.length - star - 1))
        return resolvePath(normalize(join(pkg.dir, to.replace('*', middle))))
      }
    }
    // A subpath the exports do not list: the whole package, run.
    return { dir: under(`${pkg.dir}/src/`), run: true }
  }

  // A workspace package's command (`coffre-conformance`) to the file it runs (dist/'s, its source).
  const bins = new Map()
  for (const { dir, bin } of manifests.values()) {
    for (const [name, to] of Object.entries(bin ?? {})) {
      const { file } = resolvePath(normalize(join(dir, to)))
      if (file) bins.set(name, file)
    }
  }

  /**
   * What a shell command, run in `cwd`, runs: each word that is a path to a tracked
   * file or a workspace package's command, and each pnpm script it names (`pnpm test:schema`, `pnpm --filter
   * @coffre/db run db:migrate`, `pnpm --dir packages/cli run build:action`).
   */
  const shell = (text, cwd, add) => {
    for (const [, word] of text.matchAll(SHELL_WORD)) {
      const path = normalize(join(cwd, word))
      if (tracked.has(path)) add({ file: path })
    }
    // A command where one starts (a line, after `;`, `&`, `|`, `(`, `pnpm [exec]`, `exec` or `env`, and any
    // `VAR=value`): not an argument (`ensure-database.mjs coffre`), nor `--conditions=coffre:source`.
    for (const [name, file] of bins) {
      if (new RegExp(`(?:^|[;&|(]|\\b(?:pnpm(?:\\s+exec)?|exec|env)\\s)\\s*(?:\\w+=\\S*\\s+)*${name}(?=$|[\\s;&|)])`, 'm').test(text)) add({ file })
    }
    for (const [, flag, target, name] of text.matchAll(PNPM)) {
      let manifest = 'package.json'
      if (flag) {
        const unquoted = target.replace(/^['"]|['"]$/g, '')
        manifest = byName.get(unquoted) ?? normalize(join(cwd, unquoted, 'package.json'))
      }
      if (manifests.get(manifest)?.scripts?.[name] !== undefined) add({ file: `${manifest}#${name}` })
    }
  }

  const graph = new Map()
  const edges = (from, sh) => {
    const runs = new Set()
    const reads = new Set()
    const scans = new Set()
    graph.set(from, { runs, reads, scans })
    // Only a script runs a test file: an edge into one from anything else is a mention.
    return ({ file: one, dir: many = [], run = false, scan = false }) => {
      const runnable = (to) => to !== from && (!testFile(to) || sh)
      if (one && runnable(one)) runs.add(one), reads.delete(one), scans.delete(one)
      for (const to of many) if (runnable(to) && !runs.has(to)) (run ? runs : scan ? scans : reads).add(to)
    }
  }

  for (const [file, { dir, scripts = {} }] of manifests) {
    for (const [name, command] of Object.entries(scripts)) shell(command, dir, edges(`${file}#${name}`, true))
  }
  for (const file of files) {
    if (!scanned(file)) continue
    let text
    try {
      text = uncommented(file, read(file))
    } catch {
      continue
    }
    const sh = file.endsWith('.sh')
    const add = edges(file, sh)
    // A shell script runs from the root (each cds there), a module from its own directory.
    const dir = sh ? '' : dirname(file)
    const fromHere = (spec) => (spec.startsWith('.') ? normalize(join(dir, spec)) : normalize(spec))
    if (sh) shell(text, '', add)
    for (const [, , a, , b] of text.matchAll(IMPORT)) {
      const spec = a ?? b
      if (spec.startsWith('@coffre/')) add(resolvePackage(spec))
      else if (spec.startsWith('./') || spec.startsWith('../')) add(resolvePath(fromHere(spec)))
      else if (tracked.has(CONFIG[spec])) add({ file: CONFIG[spec] })
    }
    for (const [, , spec] of text.matchAll(PATH)) {
      if (spec.includes('${')) continue
      if (!spec.includes('*')) {
        // A test that walks a source tree by name scans it, as a glob does: what it finds there is not reached.
        const target = resolvePath(fromHere(spec))
        add(testFile(file) && target.dir && /(^|\/)src(\/|$)/.test(fromHere(spec)) ? { ...target, scan: true } : target)
      } else if (testFile(file)) {
        const glob = globToRegExp(fromHere(spec))
        add({ dir: sorted.filter((f) => glob.test(f) && !testFile(f)), scan: true })
      }
    }
    for (const [, head] of text.matchAll(HEAD)) {
      const path = `${fromHere(head).replace(/\/+$/, '')}/`
      // A head that names the repository's root or a package's (`./${name}`) reads too much to mean anything.
      if (!path.startsWith('..') && !path.startsWith('/') && path !== './' && !manifests.has(`${path}package.json`)) add({ dir: under(path) })
    }
  }
  return graph
}

/**
 * Every file whose behaviour `changed` can change: each of them, each file that
 * reads, scans or runs one, and each file that runs one of those, and so on. Reading
 * stops there: a file that copies another's bytes does not run what it imports.
 */
export function affectedBy(graph, changed) {
  const runners = new Map()
  const readers = new Map()
  for (const [file, { runs, reads, scans = [] }] of graph) {
    for (const to of runs) runners.set(to, [...(runners.get(to) ?? []), file])
    for (const to of [...reads, ...scans]) readers.set(to, [...(readers.get(to) ?? []), file])
  }
  const seen = new Set(changed)
  for (const file of changed) for (const reader of readers.get(file) ?? []) seen.add(reader)
  const queue = [...seen]
  while (queue.length) for (const runner of runners.get(queue.pop()) ?? []) if (!seen.has(runner)) seen.add(runner), queue.push(runner)
  return seen
}

/**
 * Every file `entries` run or read, through what they run, and `entries` themselves;
 * and what they scan, unless `scans` is false (what a test reaches, for affected.mjs's
 * fallback: a test that greps a file does not test it).
 */
export function closureOf(graph, entries, { scans: scanned = true } = {}) {
  const ran = new Set(entries)
  const read = new Set()
  const queue = [...entries]
  while (queue.length) {
    const { runs = [], reads = [], scans = [] } = graph.get(queue.pop()) ?? {}
    for (const to of reads) read.add(to)
    if (scanned) for (const to of scans) read.add(to)
    for (const to of runs) if (!ran.has(to)) ran.add(to), queue.push(to)
  }
  return new Set([...ran, ...read])
}
