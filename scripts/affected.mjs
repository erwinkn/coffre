// What `pnpm validate` runs for a diff (scripts/validate.mjs): each step of the
// Validate workflow the diff can change (and the growth sweep, which has no job there), and for the test suite, the files it can
// change. The rules, in order:
//
// - A step runs when the diff touches a file it runs or reads: its entry points
//   through the repository's file graph (scripts/graph.mjs), or the paths it names.
//   The graph is the head's, which has no deleted file: a deletion touches each step
//   that runs or reads a file in its directory, or the nearest above it that still
//   has one (an example `init` copies, a module).
//   The suite runs each test file that runs or reads a changed file; all of them when
//   the diff touches the harness every file runs on (scripts/test-suite.sh, the
//   migrations its template takes, Postgres's compose file). A diff leaves out the
//   cases named `[full]` (a growth, heap or large-N check, or a buffer count a dead row
//   can move) but in the test files it edits; `--full` runs them all.
// - A file of a package, an example or the dev deployment that no test reaches (a path
//   built in pieces, or code nothing tests) runs that package's tests.
// - The dependencies (a lockfile, a manifest's fields other than its scripts, the
//   pinned Node) run every step but the slow tier's matrices and TLC.
// - The slow tier runs on its own inputs alone: the use matrices on the matrix files,
//   their worlds and the vault's use path (not the core rules it calls: the proofs and
//   the suite hold those, and the matrices' two hours are not worth every change to
//   core); TLC on the scenarios whose configuration,
//   module, or a module it extends or instantiates changed; Node conformance on what
//   only the Node deployment runs, while `nodeConformance` is on; Terraform on its
//   provider and the routes it calls; the packed consumer on manifests, build configs
//   and the examples `init` writes; the growth sweep on the migrations and the source
//   it runs, so that a statement that starts reading history fails before it merges.
// - A changed file no rule claims selects every step but TLC, the growth sweep and the
//   upgrade check: a miss fails safe, never as a skip.
// - `--full` runs everything, as the release's Validate does, and the growth sweep,
//   which Validate has no job for: before a tag, a local `--full` runs it. The upgrade
//   check (0.14.5 through 0.15.0 to this revision, minutes, from npm) runs there, and on a
//   change to its own scripts, its Postgres or its direct input, the migrations, the
//   migrator with its precheck and the vault's upgrade step; not on the pages and reports
//   it reads, which nearly every change reaches.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { affectedBy, buildGraph, closureOf } from './graph.mjs'

/**
 * Node's conformance, at both gates: its own step, and its run inside the packed
 * consumer. Off while 0.16.0 ships Workers alone: Node is built and
 * typechecked, nothing more. Turning it on is this flag and
 * .github/workflows/validate.yml's `node` and `consumer` jobs.
 */
export const nodeConformance = false

/** The suite's files, as scripts/test-suite.sh names them. */
export const isTest = (f) =>
  /^scripts\/[^/]+\.test\.mjs$/.test(f) || /^packages\/[^/]+\/test\/(?:.+\/)?[^/]+\.test\.ts$/.test(f) || /^(?:dev|examples)\/(?:.+\/)?test\/[^/]+\.test\.ts$/.test(f)
export const isAlone = (f) => /^packages\/[^/]+\/test\/[^/]+\.alone\.ts$/.test(f)
export const isMatrix = (f) => /^packages\/[^/]+\/test\/[^/]+\.matrix\.ts$/.test(f)

/** The workspace unit a file belongs to: `packages/<name>`, `examples/<name>` or `dev`. */
export const unitOf = (f) => /^(?:packages|examples)\/[^/]+(?=\/)/.exec(f)?.[0] ?? (f.startsWith('dev/') ? 'dev' : null)

const any = (...patterns) => (f) => patterns.some((p) => (typeof p === 'string' ? f === p || (p.endsWith('/') && f.startsWith(p)) : p.test(f)))
// Files no step runs or reads: editor and agent settings, the license.
const inert = any('.cursor/', '.vscode/', '.mcp.json', '.gitignore', '.gitattributes', 'LICENSE', '.env.dev')
// Prose and pictures: the docs check alone (every change runs it, for the paths docs name).
const prose = any(/\.md$/, 'docs/', /^[^/]+\.png$/)
// What every install and every step that runs workspace code depends on.
const dependencies = any('pnpm-lock.yaml', /(?:^|\/)pnpm-workspace\.yaml$/, /(?:^|\/)\.node-version$/, '.npmrc', 'tsconfig.base.json')
// Postgres's container, which every step that needs one starts from this file.
const compose = any('docker-compose.yml', 'docker-compose.subnet.yml', 'docker-compose.network.yml')
// What scripts/check-pins.mjs reads, beside its own sources.
const pinned = any(/(?:^|\/)package\.json$/, /\.ya?ml$/, /(?:^|\/)Dockerfile[^/]*$/, /\.sh$/, '.github/', 'action/', 'pnpm-workspace.yaml', /(?:^|\/)\.node-version$/)
// The upgrade check's own scripts and command, the Postgres it starts and the logins it makes there,
// the migrator and its precheck (`migrate.ts`), the CLI's `coffre migrate` it runs this checkout's
// migrations through, the vault's upgrade step, and the migrations: the files that select it short of --full.
const UPGRADE_CHECK = ['package.json#upgrade:check', 'scripts/upgrade-check.sh', 'scripts/upgrade-check.mjs', 'scripts/compat/release.sh',
  'scripts/ensure-postgres.sh', 'scripts/ensure-database.mjs', 'docker-compose.yml', 'docker-compose.subnet.yml', 'docker-compose.network.yml',
  'packages/db/src/migrate.ts', 'packages/db/src/online-indexes.ts', 'packages/cli/src/migrate.ts', 'packages/vault/src/upgrade.ts']
// What the growth sweep's command graph cannot see: the command, the requests it makes, the growths it knows and the
// Postgres containers its scripts start.
const SWEEP = ['package.json#sweep:growth', 'packages/server/test/growth.sweep.ts', 'scripts/growth-sweep-known.txt',
  'docker-compose.yml', 'docker-compose.subnet.yml', 'docker-compose.network.yml']
const upgrades = (f) => UPGRADE_CHECK.includes(f) || f.startsWith('packages/db/src/migrations/')
const lintable = (f) => /^packages\/[^/]+\/(?:src|test|scripts)\/.+\.tsx?$/.test(f)

/**
 * The plan for `changed` (paths, and `<manifest>#<script>` for a pnpm script whose
 * command changed). `files` are the tracked files at the head, `read` reads one,
 * `readBase` reads one at the base (or throws), and `full` asks for every step.
 * Returns `{ steps, everything }`: each step `{ name, why }`, `why` null when it does
 * not run, and what it runs: `files` (null for all), `scenarios` or `units`; the `tests` and
 * `alone` steps also give `whole`, the files among `files` that run with their `[full]` cases.
 */
export function plan({ root, files, changed, read = (f) => readFileSync(join(root, f), 'utf8'), readBase = () => '', full = false }) {
  const graph = buildGraph(root, files, read)
  const tracked = new Set(files)
  const tests = files.filter(isTest)
  const alone = files.filter(isAlone)
  const matrices = files.filter(isMatrix)
  const affected = affectedBy(graph, changed)
  const inputs = (...entries) => closureOf(graph, entries.flat())
  const under = (prefix) => files.filter((f) => f.startsWith(prefix))
  const why = (file) => (file ? `${file} changed` : null)
  // Whether `set` holds `f`, or, when `f` is gone from the head, a file beside it: in its directory, or the
  // nearest above it that still has a file of its own. Only that directory's own files count, not its
  // subdirectories' (a change to `formal/` is not one to `formal/lean/`), so deleting the last file of a
  // directory that a step reads whole hits the step only through a sibling file (e.g. deleting the
  // UI's sole stylesheet misses contrast, but its export changes `package.json`, which runs everything).
  const inDir = (dir) => (g) => dirname(g) === dir
  const besideGone = (f) => {
    let dir = dirname(f)
    while (dir !== '.' && !files.some(inDir(dir))) dir = dirname(dir)
    return inDir(dir)
  }
  const gone = new Map(changed.filter((f) => !tracked.has(f) && !f.includes('#')).map((f) => [f, besideGone(f)]))
  const hits = (set, f) => set.has(f) || (gone.has(f) && [...set].some(gone.get(f)))

  // The harness every test file runs on: the suite's script and what it runs (the
  // template's migrations among them).
  const harness = inputs('scripts/test-suite.sh')
  // What the tests reach, scans aside: a package's file outside it runs its package's tests.
  const reached = closureOf(graph, [...tests, ...alone, ...matrices, 'scripts/test-suite.sh'], { scans: false })

  // Each step's own inputs.
  // Conformance also runs the deployment's own CLI, found by its manifest's bin (deploymentCli in the harness), which no path names.
  const cli = 'packages/cli/src/main.ts'
  const workers = inputs('package.json#conformance:workers', under('examples/workers/'), cli)
  const onlyBeside = (set, ...others) => new Set([...set].filter((f) => !others.some((o) => o.has(f))))
  const inputsOf = {
    pins: inputs('package.json#check:pins', 'package.json#check:workflows'),
    contrast: new Set([...inputs('package.json#check:contrast'), ...under('packages/ui/src/styles/')]),
    action: new Set([...inputs('package.json#check:action', 'packages/cli/scripts/action.ts', 'packages/cli/src/main.ts'), ...under('action/')]),
    schema: inputs('package.json#test:schema'),
    proofs: new Set([...inputs('package.json#formal:lean'), ...under('formal/lean/')]),
    workers,
    // What only the Node deployment runs.
    node: onlyBeside(inputs('package.json#conformance:node', under('examples/node/'), cli), workers),
    // The provider, its fixture, and the routes it calls (terraform-provider/internal/acceptance): the routes'
    // table, the secrets' list and writes, the reveals (in the table), the dismissals, and POST /api/auth/oidc.
    terraform: new Set([
      ...onlyBeside(inputs('package.json#test:terraform', 'packages/conformance/scripts/terraform-fixture.ts'), workers),
      ...under('terraform-provider/'),
      'packages/server/src/api/routes.ts',
      'packages/server/src/api/secrets.ts',
      'packages/server/src/api/missing.ts',
      'packages/server/src/auth-routes.ts',
    ]),
    // What it packs and installs as a deployment would: each package's manifest and build, `init`, and the examples it writes.
    consumer: new Set([
      ...onlyBeside(inputs('package.json#test:consumer'), workers),
      'packages/cli/src/init.ts',
      'packages/cli/scripts/copy-templates.ts',
      'packages/cli/scripts/copy-migrations.ts',
      ...files.filter((f) => /^packages\/[^/]+\/(?:package\.json|tsdown\.config\.ts|vite\.config\.ts)$/.test(f)),
      ...under('examples/'),
    ]),
    // Its own files, the scripts it runs through (its runner, the suite's harness, its Postgres), the migrations and the
    // source it runs; not the test helpers it shares with the suite.
    sweep: new Set([...SWEEP, ...[...inputs('package.json#sweep:growth')].filter((f) => tracked.has(f) && (f.endsWith('.sql') || f.includes('/src/') || f.startsWith('scripts/')))]),
    // The matrices, the worlds and scripts they run, and the vault's use path: what use.ts runs in the vault, not in core.
    matrices: new Set([
      ...[...inputs(matrices)].filter((f) => !f.includes('/src/')),
      ...[...inputs('packages/vault/src/use.ts')].filter((f) => f.startsWith('packages/vault/src/')),
    ]),
  }
  const ownHit = (name) => changed.find((f) => hits(inputsOf[name], f) || (name === 'pins' && pinned(f)))

  // TLC's scenarios, each its configuration and the closure of the module it names.
  const scenarios = formalScenarios(files, read)
  const formalHit = formalSelection(scenarios, changed, read, readBase)

  // A file of a package that no test reaches runs its package's tests.
  const fallback = new Set(changed.filter((f) => unitOf(f) && !reached.has(f) && !prose(f)).map(unitOf))

  // A changed file no rule claims selects everything.
  const claimed = (f) =>
    inert(f) ||
    prose(f) ||
    dependencies(f) ||
    compose(f) ||
    f.endsWith('package.json') ||
    f.includes('package.json#') ||
    f.startsWith('formal/') ||
    unitOf(f) ||
    reached.has(f) ||
    Object.keys(inputsOf).some((name) => hits(inputsOf[name], f)) ||
    pinned(f) ||
    f === 'eslint.config.js' ||
    ['scripts/formal.sh', 'scripts/formal-trace.mjs', 'scripts/formal-key.sh', 'scripts/validate.mjs'].includes(f)
  const unclaimed = changed.find((f) => !claimed(f))
  const everything = full ? '--full' : unclaimed ? `${unclaimed} changed and no rule claims it` : null
  // The dependencies: every step but the matrices and TLC.
  const deps = changed.find((f) => dependencies(f) || f.endsWith('package.json'))
  const wide = everything ?? why(deps)
  // Postgres's compose file: every step that starts one.
  const postgres = changed.find(compose)

  const testsFrom = (list, label) => {
    const harnessHit = changed.find((f) => hits(harness, f)) ?? postgres
    // The files run whole, their `[full]` cases too: every one under --full, else the ones the diff edits.
    const whole = (files) => (full ? files : files.filter((f) => changed.includes(f)))
    if (wide) return { why: wide, files: list, whole: whole(list) }
    if (harnessHit) return { why: `${harnessHit} changed (every test file runs on it)`, files: list, whole: whole(list) }
    const hit = list.filter((f) => affected.has(f) || fallback.has(unitOf(f)))
    if (!hit.length) return { why: null }
    const read = inputs(hit)
    const by = changed.filter((f) => read.has(f) || fallback.has(unitOf(f)))
    return { why: `${hit.length} of ${list.length} ${label}, for ${by.slice(0, 2).join(', ')}${by.length > 2 ? ` and ${by.length - 2} more` : ''}`, files: hit, whole: whole(hit) }
  }
  const rule = (name, { slow = false, db = false } = {}) => () => ({
    why: everything ?? (slow ? null : why(deps)) ?? (db ? why(postgres) : null) ?? why(ownHit(name)),
  })

  const units = files.filter((f) => /^(?:packages\/[^/]+|examples\/[^/]+|dev)\/package\.json$/.test(f)).map((f) => f.slice(0, -'/package.json'.length))
  const typecheck = wide
    ? units
    : units.filter((u) => changed.some((f) => f.startsWith(`${u}/`) && /(?:tsconfig\.json|package\.json#typecheck)$/.test(f)) || [...affected].some((f) => f.startsWith(`${u}/`) && /\.tsx?$/.test(f)))
  const lint = changed.filter((f) => lintable(f) && tracked.has(f))
  const lintAll = wide ?? why(changed.find((f) => f === 'eslint.config.js' || f === 'package.json#lint'))

  const steps = [
    { name: 'docs', why: 'every change' },
    { name: 'pins', ...rule('pins')() },
    { name: 'contrast', ...rule('contrast')() },
    { name: 'lint', ...(lintAll ? { why: lintAll, files: null } : lint.length ? { why: `${lint.length} changed files`, files: lint } : { why: null }) },
    { name: 'typecheck', ...(typecheck.length ? { why: wide ?? `${typecheck.length} of ${units.length} packages read what changed`, units: typecheck } : { why: null }) },
    { name: 'action', ...rule('action')() },
    { name: 'tests', ...testsFrom(tests, 'test files') },
    { name: 'alone', ...testsFrom(alone, 'files that run alone') },
    { name: 'matrices', ...rule('matrices', { slow: true, db: true })() },
    { name: 'schema', ...rule('schema', { db: true })() },
    { name: 'formal', ...(full ? { why: '--full', scenarios: scenarios.names } : formalHit) },
    { name: 'proofs', ...rule('proofs')() },
    { name: 'workers', ...rule('workers', { db: true })() },
    { name: 'node', ...(nodeConformance ? rule('node')() : { why: null, off: 'off until 0.16.1 (T270)' }) },
    { name: 'terraform', ...rule('terraform')() },
    { name: 'consumer', ...rule('consumer', { db: true })() },
    { name: 'sweep', why: full ? '--full' : why(ownHit('sweep')) },
    { name: 'upgrade', why: full ? '--full' : why(changed.find(upgrades)) },
  ]
  return { steps, everything, unclaimed }
}

/**
 * TLC's scenarios: each configuration's name, and the modules it reads (the one its
 * second line names, `\* model MCFoo`, MC's by default, and what that extends or
 * instantiates, transitively).
 */
export function formalScenarios(files, read) {
  const modules = new Map()
  for (const f of files.filter((f) => /^formal\/[^/]+\.tla$/.test(f))) {
    const text = read(f).replace(/\(\*[\s\S]*?\*\)/g, '').replace(/\\\*.*$/gm, '')
    const uses = new Set()
    for (const [, list] of text.matchAll(/^\s*EXTENDS\s+([\w\s,]+?)\s*$/gm)) for (const m of list.split(/\s*,\s*/)) uses.add(m.trim())
    for (const [, m] of text.matchAll(/\bINSTANCE\s+(\w+)/g)) uses.add(m)
    modules.set(f.slice('formal/'.length, -'.tla'.length), uses)
  }
  const closure = (start) => {
    const seen = new Set([start])
    // A module it names that is not in formal/ (Naturals, or one the diff deleted) is read too; only formal/'s are followed.
    for (const queue = [start]; queue.length; ) for (const m of modules.get(queue.pop()) ?? []) if (!seen.has(m)) seen.add(m), modules.has(m) && queue.push(m)
    return seen
  }
  const names = []
  const reads = new Map()
  for (const f of files.filter((f) => /^formal\/[^/]+\.cfg$/.test(f))) {
    const name = f.slice('formal/'.length, -'.cfg'.length)
    const model = /^\\\* model ([A-Za-z0-9]+)$/.exec(read(f).split('\n')[1] ?? '')?.[1] ?? 'MC'
    names.push(name)
    reads.set(name, new Set([f, ...[...closure(model)].map((m) => `formal/${m}.tla`)]))
  }
  return { names: names.sort(), reads }
}

/** The lines of scripts/formal.sh that name one scenario: its entries in REMOVALS and EXPECTED. */
const formalEntries = (text) => {
  const entries = new Map()
  const rest = []
  let list = false
  for (const line of text.split('\n')) {
    if (/^(?:REMOVALS|EXPECTED)=\($/.test(line)) list = true
    else if (list && line === ')') list = false
    const entry = list && /^\s*"([A-Za-z0-9]+) [^"]*"$/.exec(line)
    if (entry) entries.set(entry[1], [...(entries.get(entry[1]) ?? []), line.trim()].sort())
    // A comment changes nothing TLC does; CI's shards are its own concern (formal-shards.test.mjs).
    else if (!/^\s*#/.test(line) && !/^SHARDS=/.test(line) && !/^\s+[\w|*-]+\) echo [\w-]+ ;;$/.test(line)) rest.push(line)
  }
  return { entries, rest: rest.join('\n') }
}

/** The scenarios a diff can change, and why. */
export function formalSelection({ names, reads }, changed, read, readBase) {
  const all = (file) => ({ why: `${file} changed`, scenarios: names })
  for (const file of ['scripts/formal-trace.mjs', 'scripts/fetch.sh']) if (changed.includes(file)) return all(file)
  const picked = new Map()
  if (changed.includes('scripts/formal.sh')) {
    let before
    try {
      before = formalEntries(readBase('scripts/formal.sh'))
    } catch {
      return all('scripts/formal.sh')
    }
    const after = formalEntries(read('scripts/formal.sh'))
    if (before.rest !== after.rest) return all('scripts/formal.sh')
    for (const name of new Set([...before.entries.keys(), ...after.entries.keys()])) {
      if (names.includes(name) && JSON.stringify(before.entries.get(name)) !== JSON.stringify(after.entries.get(name))) picked.set(name, 'scripts/formal.sh')
    }
  }
  for (const name of names) {
    // A module a scenario reads that the diff deleted is still among its reads (formalScenarios).
    const hit = changed.find((f) => reads.get(name).has(f))
    if (hit && !picked.has(name)) picked.set(name, hit)
  }
  const scenarios = names.filter((n) => picked.has(n))
  const by = [...new Set(picked.values())]
  return { why: scenarios.length ? `${scenarios.length} of ${names.length} scenarios, from ${by.slice(0, 3).join(', ')}${by.length > 3 ? ` and ${by.length - 3} more` : ''}` : null, scenarios }
}

/** The diff from `base` to `head` as `plan` takes it: paths, a manifest's changed scripts as `<manifest>#<name>`. */
export function changedFiles(root, base, head) {
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 1 << 28 }).trim()
  const changed = []
  for (const f of git('diff', '--name-only', '--no-renames', base, head).split('\n').filter(Boolean)) {
    if (!f.endsWith('package.json')) {
      changed.push(f)
      continue
    }
    const manifest = (rev) => {
      try {
        return JSON.parse(git('show', `${rev}:${f}`))
      } catch {
        return null
      }
    }
    const before = manifest(base)
    const after = manifest(head)
    const { scripts: was = {}, ...restBefore } = before ?? {}
    const { scripts: is = {}, ...restAfter } = after ?? {}
    // A manifest's fields beyond its scripts are the dependencies; its scripts, each a command.
    if (!before || !after || JSON.stringify(restBefore) !== JSON.stringify(restAfter)) changed.push(f)
    for (const name of new Set([...Object.keys(was), ...Object.keys(is)])) if (was[name] !== is[name]) changed.push(`${f}#${name}`)
  }
  return changed
}
