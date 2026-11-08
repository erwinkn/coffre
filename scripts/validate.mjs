#!/usr/bin/env node
// The checks a change passes before it merges (R46: no pull request runs CI; the
// Validate workflow gates releases). Runs, on this exact commit, the jobs of
// .github/workflows/validate.yml that the diff against main can change, one at a
// time, and prints what it ran: the commit, its tree, the base, and each step's
// result. Paste that on the pull request, then merge with
// `gh pr merge --squash --match-head-commit <sha>`.
//
//   pnpm validate                  the steps this diff needs
//   pnpm validate --all            every step but the image
//   pnpm validate --full-formal    also TLC, even when no model changed
//   pnpm validate --base <rev>     the revision the change is on (default origin/main)
//   pnpm validate --skip a,b       leave steps out; one the diff needs is OMITTED and the
//                                  summary reads PARTIAL (exit 1), never pass
//   pnpm validate --only a,b       just these steps (the others are left out the same way)
//   pnpm validate --list           the steps and why each runs, running none
//   pnpm validate --out <file>     also write the summary there
//   pnpm validate --keep-db        leave the Postgres it started running
//
// The tree must be clean and rebased on the base, and is checked again when the
// run ends, or the summary would vouch for a commit it did not run. Dependencies
// are installed from the lockfile first (`pnpm install --frozen-lockfile`), as
// every job does. A step also runs when the diff changes a file its commands run
// or the entry of root package.json that names them. The local COFFRE_TEST_* and
// COFFRE_DEV_* settings are dropped (they would shard or redirect the suites), and
// the summary says so. The Pins step needs GH_TOKEN or a logged-in `gh`, to audit the pinned
// actions against GitHub as CI does, and fails without. The matrices step runs the use matrices as CI's shards do
// (Postgres in sixths, SQLite in halves, one at a time, then the coverage check). Postgres is the script's own container (a compose project
// and a free port of its own, never the shared :55432), removed when it ends. The
// image step is not here: `pnpm test:image` builds for two architectures and is
// the release's (Validate on the tagged commit runs it).
import { execFileSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'

const root = resolve(import.meta.dirname, '..')

/** What a diff has to touch for a step to run; the rest is the diff's own. */
const code = (f) => !/\.md$/.test(f) && !f.startsWith('docs/')
const anyOf = (...prefixes) => (f) => prefixes.some((p) => f.startsWith(p))
// What every install and every step that runs workspace code depends on.
const manifests = anyOf('package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', '.node-version')
// docker-compose.yml: every step that boots Postgres, or builds on one, starts it from this file.
// Any file of a package, example or the dev deployment: the Postgres-backed jobs run the packages together
// (the matrices call the client, the schema job runs the CLI's setup), so none is picked by naming which
// package it thinks it needs.
const workspace = anyOf('packages/', 'examples/', 'dev/')
const packages = (f) => anyOf('packages/', 'examples/', 'dev/', 'docker-compose.yml')(f) || manifests(f)
const formalModel = (f) =>
  /^formal\/[^/]+\.(tla|cfg)$/.test(f) ||
  ['scripts/formal.sh', 'scripts/formal-trace.mjs'].includes(f)
const leanInputs = (f) => f.startsWith('formal/lean/') || anyOf('packages/core/src/', 'packages/vault/src/', 'scripts/formal-lean')(f)
const BROWSER = '"$COFFRE_VALIDATE_BROWSER"'
// The use matrices as CI runs them (validate.yml, `matrices-shard`): Postgres in sixths, SQLite in halves, one
// shard at a time (each takes the slots of a stock Postgres, so none runs beside another), each from a database of
// its own, then `matrix-coverage.mjs` holds the reports to every case run exactly once. Unsharded, the server's
// matrix alone outlasts its own 7,200 s timeout on Postgres, so no unsharded run can pass.
const MATRIX_SHARDS = { postgres: 6, sqlite: 2 }
const matrixCommands = [
  ...Object.entries(MATRIX_SHARDS).flatMap(([engine, of]) =>
    Array.from({ length: of }, (_, i) => `COFFRE_TEST_ENGINE=${engine} COFFRE_TEST_SHARD=${i + 1}/${of} COFFRE_TEST_SHARD_REPORT="$COFFRE_VALIDATE_REPORTS/${engine}-${i + 1}" pnpm test:matrices`),
  ),
  `node scripts/matrix-coverage.mjs "$COFFRE_VALIDATE_REPORTS" ${Object.keys(MATRIX_SHARDS).join(' ')}`,
]

/**
 * Each step is a job of validate.yml (`job`), its commands, whether it needs the
 * packages built, Postgres, a browser, and the rule picking it. `needs` is the diff
 * predicate; a step with none runs on every change. Beyond it, a step is picked by
 * a change to a script file its commands run, directly or through root package.json
 * (`inputs` below), or to the package.json entry that names it.
 */
const STEPS = [
  { name: 'action', job: 'action', build: true, run: ['pnpm check:action'] },
  { name: 'pins', job: 'pins', run: ['pnpm check:pins', 'pnpm check:workflows'] },
  {
    name: 'checks',
    job: 'checks',
    build: true,
    run: ['pnpm lint', 'pnpm typecheck', 'pnpm check:contrast', 'pnpm check:docs'],
  },
  { name: 'tests', job: 'tests', postgres: true, needs: code, run: ['pnpm test'] },
  {
    name: 'tests-014',
    job: 'tests-014',
    postgres: true,
    needs: code,
    env: { COFFRE_TEST_LOG: '0.14' },
    run: ['./scripts/test-suite.sh'],
  },
  {
    name: 'matrices',
    job: 'matrices-shard',
    postgres: true,
    needs: (f) => workspace(f) || anyOf('scripts/matrix', 'docker-compose.yml')(f) || manifests(f),
    run: matrixCommands,
  },
  { name: 'schema', job: 'schema', postgres: true, needs: (f) => workspace(f) || anyOf('scripts/setup-test-database', 'scripts/test-setup', 'scripts/test-backup-role', 'docker-compose.yml')(f) || manifests(f), run: ['pnpm test:schema'] },
  { name: 'formal', job: 'formal', needs: formalModel, run: ['./scripts/formal.sh --workers 4 --heap 4g'], full: true },
  { name: 'proofs', job: 'proofs', needs: (f) => leanInputs(f) || manifests(f), run: ['pnpm formal:lean'] },
  { name: 'workers', job: 'workers', build: true, postgres: true, browser: true, needs: packages, run: [`pnpm conformance:workers --browser ${BROWSER}`] },
  { name: 'node', job: 'node', build: true, browser: true, needs: packages, run: [`pnpm conformance:node --browser ${BROWSER}`] },
  { name: 'terraform', job: 'terraform', build: true, needs: (f) => packages(f) || f.startsWith('terraform-provider/'), run: ['pnpm test:terraform'] },
  // The consumer script starts Postgres itself (ensure-postgres.sh), so it gets this run's.
  { name: 'consumer', job: 'consumer', build: true, postgres: true, needs: (f) => packages(f) || f === 'scripts/client-smoke.cjs', run: ['pnpm test:consumer'] },
  { name: 'compat', job: 'compat', postgres: true, needs: (f) => workspace(f) || anyOf('scripts/compat', 'docker-compose.yml')(f) || manifests(f), run: ['pnpm test:compat'] },
]

const { values: opt } = parseArgs({
  options: {
    all: { type: 'boolean', default: false },
    'full-formal': { type: 'boolean', default: false },
    base: { type: 'string', default: 'origin/main' },
    skip: { type: 'string', default: '' },
    only: { type: 'string', default: '' },
    list: { type: 'boolean', default: false },
    out: { type: 'string' },
    'keep-db': { type: 'boolean', default: false },
  },
})

const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim()
const fail = (message) => {
  console.error(`validate: ${message}`)
  process.exit(2)
}

const names = new Set(STEPS.map((s) => s.name))
const csv = (value, flag) => {
  const list = value.split(',').filter(Boolean)
  for (const name of list) if (!names.has(name)) fail(`--${flag}: no step ${name} (${[...names].join(', ')})`)
  return new Set(list)
}
const skip = csv(opt.skip, 'skip')
const only = csv(opt.only, 'only')

const head = git('rev-parse', 'HEAD')
const tree = git('rev-parse', 'HEAD^{tree}')
let base
try {
  base = git('rev-parse', '--verify', `${opt.base}^{commit}`)
} catch {
  fail(`no revision ${opt.base} (fetch it, or name another with --base)`)
}
if (!opt.list) {
  if (git('status', '--porcelain', '--untracked-files=all')) fail('the tree is not clean: commit or stash first, so the summary names what ran.')
  try {
    git('merge-base', '--is-ancestor', base, head)
  } catch {
    fail(`${opt.base} (${base.slice(0, 10)}) is not an ancestor of HEAD: rebase on it first.`)
  }
}

// Root package.json at the base and at HEAD: an entry of `scripts` that changed
// stands for `root script <name>`; any other change stays `package.json`.
const manifest = (rev) => {
  try {
    return JSON.parse(git('show', `${rev}:package.json`))
  } catch {
    return {}
  }
}
const diffFiles = git('diff', '--name-only', '--no-renames', base, head).split('\n').filter(Boolean)
const changed = diffFiles.filter((f) => f !== 'package.json')
if (diffFiles.includes('package.json')) {
  const { scripts: before = {}, ...otherBefore } = manifest(base)
  const { scripts: after = {}, ...otherAfter } = manifest(head)
  if (JSON.stringify(otherBefore) !== JSON.stringify(otherAfter)) changed.push('package.json')
  for (const name of new Set([...Object.keys(before), ...Object.keys(after)])) if (before[name] !== after[name]) changed.push(`root script ${name}`)
}

// What a step runs: the pnpm scripts its commands name (and those they name), the
// script files all of these call, and the files those call in turn (a wrapper runs
// test-databases.mjs without the step's command naming it). A file counts as called
// when another's text holds its name; reading too much only runs a step more often.
const scriptFiles = (text) => [...text.matchAll(/(?:^|[\s'"=])(?:\.\/)?(scripts\/[A-Za-z0-9_./-]+)/g)].map((m) => m[1])
// A root script the change deleted still names the steps that run it.
const rootScripts = { ...(manifest(base).scripts ?? {}), ...(manifest(head).scripts ?? {}) }
// A helper the change deleted still names the steps that call it.
const tracked = [...new Set([...git('ls-files', 'scripts').split('\n'), ...git('ls-tree', '-r', '--name-only', base, 'scripts').split('\n')])].filter(Boolean)
const readTracked = (file) => {
  try {
    return readFileSync(resolve(root, file), 'utf8')
  } catch {
    return ''
  }
}
const inputsOf = (step) => {
  const scripts = new Set(step.build ? ['build'] : [])
  const texts = [...step.run]
  const queue = [...texts]
  while (queue.length) {
    for (const m of queue.pop().matchAll(/\bpnpm (?:run )?([a-z][\w:-]*)/g)) {
      if (rootScripts[m[1]] && !scripts.has(m[1])) {
        scripts.add(m[1])
        queue.push(rootScripts[m[1]])
      }
    }
  }
  for (const name of scripts) texts.push(rootScripts[name])
  const files = new Set(texts.flatMap(scriptFiles))
  const pending = [...files]
  while (pending.length) {
    const text = readTracked(pending.pop())
    for (const other of tracked) {
      if (files.has(other)) continue
      const name = other.slice('scripts/'.length)
      const escaped = [name, name.split('/').pop()].map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      if (escaped.some((n) => new RegExp(`(^|[^\\w.-])${n}($|[^\\w-])`).test(text))) {
        files.add(other)
        pending.push(other)
      }
    }
  }
  return { scripts, files }
}

const claims = (step, f) => {
  const { scripts, files } = inputsOf(step)
  return step.needs(f) || files.has(f) || (f.startsWith('root script ') && scripts.has(f.slice(12)))
}
// A changed file that is code, outside the few that cannot affect a run, and that no
// step claims (the tests take any code file, so they claim nothing here): the rules above missed it, so every step but TLC (its own key) runs,
// rather than the miss passing as a skip.
// (The JavaScript tools in scripts/ and their tests are exercised by `tests`; the shell scripts name their steps.)
const inert = (f) => !code(f) || anyOf('.github/', '.cursor/', '.vscode/', '.gitignore', 'LICENSE', 'scripts/validate.mjs')(f) || /^scripts\/[^/]+\.(mjs|cjs|ts)$/.test(f)
const unclaimed = changed.find((f) => !inert(f) && !STEPS.some((s) => s.needs && s.needs !== code && claims(s, f)))

// Whether the diff needs a step, apart from what the flags choose.
const needed = (step) => {
  if (!step.needs) return 'every change'
  const hit = changed.find((f) => claims(step, f))
  if (hit) return `${hit} changed`
  return unclaimed && !step.full ? `${unclaimed} changed and no step claims it` : null
}
const decide = (step) => {
  if (only.size) return only.has(step.name) ? 'only' : null
  if (skip.has(step.name)) return null
  if (opt.all) return '--all'
  if (step.full && opt['full-formal']) return '--full-formal'
  return needed(step)
}
const plan = STEPS.map((step) => ({ step, why: decide(step), need: needed(step) }))
// Why a step is not run: left out by a flag (and the diff needs it, or not), or the diff does not touch it.
const omission = ({ step, need }) => {
  const flag = skip.has(step.name) ? '--skip' : only.size ? '--only' : null
  if (!flag) return { status: 'skipped', why: 'diff does not touch it' }
  return need ? { status: 'OMITTED', why: `${flag}, though ${need}` } : { status: 'skipped', why: `${flag}; the diff does not touch it` }
}

if (opt.list) {
  for (const entry of plan) console.log(`${entry.step.name.padEnd(10)} ${entry.why ?? `not run: ${omission(entry).why}`}`)
  process.exit(0)
}

// The client is smoke-tested on each Node binary COFFRE_CLIENT_NODES lists (space-separated;
// unset, this one alone). CI covers 20, 22, 24 and 26: say which of them this run did not.
const clientNodes = () => {
  const majors = new Set()
  for (const bin of (env.COFFRE_CLIENT_NODES || 'node').split(/\s+/).filter(Boolean)) {
    try {
      majors.add(Number(execFileSync(bin, ['--version'], { encoding: 'utf8' }).trim().replace(/^v/, '').split('.')[0]))
    } catch {}
  }
  const missing = [20, 22, 24, 26].filter((n) => !majors.has(n))
  return missing.length ? `; client smoke on Node ${[...majors].join(', ') || 'none'} only, not ${missing.join(', ')} (CI runs 20, 22, 24, 26)` : ''
}

const results = []
const started = Date.now()
const env = { ...process.env }
const dropped = Object.keys(env).filter((k) => /^COFFRE_(TEST|DEV)_/.test(k))
for (const k of dropped) delete env[k]
let browser = ''
for (const candidate of ['google-chrome', 'chromium']) {
  if (browser) break
  try {
    browser = execFileSync('bash', ['-c', `command -v ${candidate}`], { encoding: 'utf8' }).trim()
  } catch {}
}
env.COFFRE_VALIDATE_BROWSER = browser
// The Pins step asks GitHub whether each pinned action commit belongs to its repository, as CI
// does with the workflow's token (scripts/zizmor.sh runs that audit only with GH_TOKEN set).
// Without one it would run offline and pass a pin CI rejects, so the step takes GH_TOKEN or
// `gh auth token`, and fails when it has neither. Only that step gets it.
let pinsToken = env.GH_TOKEN || ''
delete env.GH_TOKEN
if (!pinsToken) {
  try {
    pinsToken = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {}
}

// The child of the step now running, so that a signal reaches it: each runs in a
// process group of its own, and the signal goes to the whole group.
let active = null
let interrupted = null
// A step may start servers in groups of their own (conformance does), which a signal to
// its group misses: the processes below it are signalled one by one, and any that
// outlive the step are killed when it ends.
const strays = new Set()
// Process groups of steps that were interrupted: their leader may exit while a
// cleanup child it started is still running, so they are awaited until empty.
const groups = new Set()
const below = (pid) => {
  let table = ''
  try {
    table = execFileSync('ps', ['-e', '-o', 'pid=,ppid='], { encoding: 'utf8' })
  } catch {}
  const children = new Map()
  for (const line of table.split('\n')) {
    const [p, pp] = line.trim().split(/\s+/).map(Number)
    if (p) children.set(pp, [...(children.get(pp) ?? []), p])
  }
  const found = []
  for (const queue = [pid]; queue.length; ) for (const c of children.get(queue.pop()) ?? []) found.push(c), queue.push(c)
  return found
}
const kill = (pid, signal) => {
  try {
    process.kill(pid, signal)
  } catch {}
}
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    interrupted ??= signal
    if (!active) return
    groups.add(active.pid)
    for (const pid of below(active.pid)) {
      strays.add(pid)
      kill(pid, signal)
    }
    kill(-active.pid, signal)
    // A step that handles the signal but hangs while shutting down must not hold the
    // run: three seconds on, whatever is left of it is killed, so teardown and the
    // summary are reached.
    setTimeout(() => {
      for (const group of groups) kill(-group, 'SIGKILL')
      for (const pid of strays) kill(pid, 'SIGKILL')
    }, 3000).unref()
  })
}
const alive = (pid) => {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}
const reap = async () => {
  if (!strays.size && !groups.size) return
  // Wait for the interrupted groups and strays to go (at most 3 s), then kill what is left.
  for (const end = Date.now() + 3000; Date.now() < end && ([...groups].some((g) => alive(-g)) || [...strays].some(alive)); ) await new Promise((ok) => setTimeout(ok, 100))
  for (const group of groups) kill(-group, 'SIGKILL')
  for (const pid of strays) kill(pid, 'SIGKILL')
  strays.clear()
  groups.clear()
}
const sh = (command, extra = {}) =>
  new Promise((ok) => {
    const child = spawn('bash', ['-c', command], { cwd: root, stdio: 'inherit', env: { ...env, ...extra }, detached: true })
    active = child
    child.on('exit', async (code, signal) => {
      active = null
      await reap()
      ok(code ?? (signal ? 128 : 1))
    })
  })

// Postgres of its own: a compose project (one per run) and a port nobody holds, so
// a run never touches the shared container on :55432, another checkout's, or the
// leftovers of a run that was killed.
const freePort = () =>
  new Promise((ok, no) => {
    const server = createServer()
    server.once('error', no)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => ok(port))
    })
  })

let database = false
let teardownFailed = false
let reports = ''
const teardown = async () => {
  if (reports) rmSync(reports, { recursive: true, force: true })
  if (!database || opt['keep-db']) return
  active = null
  if ((await sh('docker compose down --volumes --remove-orphans')) !== 0) {
    teardownFailed = true
    console.error(`validate: could not remove Postgres ${env.COMPOSE_PROJECT_NAME}; remove it with COMPOSE_PROJECT_NAME=${env.COMPOSE_PROJECT_NAME} docker compose down --volumes`)
  }
}

try {
  if (plan.some(({ why }) => why)) {
    console.log('\n== install: pnpm install --frozen-lockfile')
    const at = Date.now()
    const code = await sh('pnpm install --frozen-lockfile')
    results.push({ name: 'install', status: code === 0 ? 'pass' : 'FAIL', why: 'every run', seconds: Math.round((Date.now() - at) / 1000) })
    if (code !== 0) interrupted ??= 'install failed'
  }

  if (!interrupted && plan.some(({ step, why }) => why && step.postgres)) {
    const port = await freePort()
    if (port === 55432) throw new Error('picked the shared Postgres port.')
    env.COFFRE_POSTGRES_PORT = String(port)
    env.COMPOSE_PROJECT_NAME = `coffre_validate_${createHash('sha256').update(root).digest('hex').slice(0, 8)}_${process.pid}`
    console.log(`validate: Postgres ${env.COMPOSE_PROJECT_NAME} on :${port}`)
    database = true
    if ((await sh('./scripts/ensure-postgres.sh')) !== 0) {
      results.push({ name: 'postgres', status: 'FAIL', why: 'did not start' })
      interrupted ??= 'postgres did not start'
    }
  }

  let built = false
  for (const entry of plan) {
    const { step, why } = entry
    if (!why) {
      results.push({ name: step.name, ...omission(entry) })
      continue
    }
    if (interrupted) {
      results.push({ name: step.name, status: 'not run', why: interrupted })
      continue
    }
    if (step.name === 'pins' && !pinsToken) {
      results.push({ name: step.name, status: 'FAIL', why: 'no GH_TOKEN and no `gh auth token`: the pinned actions cannot be checked against GitHub, as CI does' })
      continue
    }
    if (step.browser && !browser) {
      results.push({ name: step.name, status: 'FAIL', why: 'no google-chrome or chromium on PATH' })
      continue
    }
    const at = Date.now()
    let code = 0
    if (step.name === 'matrices') env.COFFRE_VALIDATE_REPORTS = reports = mkdtempSync(join(tmpdir(), 'coffre-validate-matrices-'))
    if (step.build && !built) {
      console.log('\n== build')
      code = await sh('pnpm build')
      built = code === 0
    }
    for (const command of code === 0 ? step.run : []) {
      if (interrupted) break
      console.log(`\n== ${step.name}: ${command}`)
      code = await sh(command, step.name === 'pins' ? { GH_TOKEN: pinsToken } : step.env)
      if (code !== 0) break
    }
    const partial = step.name === 'consumer' ? clientNodes() : ''
    results.push({ name: step.name, status: interrupted ? 'interrupted' : code === 0 ? 'pass' : 'FAIL', why: `${why}${partial}`, seconds: Math.round((Date.now() - at) / 1000) })
  }
} catch (error) {
  console.error(`validate: ${error.message}`)
  interrupted ??= error.message
} finally {
  await teardown()
}

// The summary vouches for HEAD's tree: it must be what the steps ran on.
const headAfter = git('rev-parse', 'HEAD')
const dirty = git('status', '--porcelain', '--untracked-files=all')
if (headAfter !== head || dirty) results.push({ name: 'tree', status: 'FAIL', why: headAfter !== head ? `HEAD moved to ${headAfter.slice(0, 10)}` : 'files changed or appeared during the run' })
if (teardownFailed) results.push({ name: 'postgres', status: 'FAIL', why: 'not removed' })

const ok = !interrupted && results.every((r) => r.status === 'pass' || r.status === 'skipped')
const omitted = results.filter((r) => r.status === 'OMITTED').map((r) => r.name)
const verdict = ok ? 'pass' : !interrupted && results.every((r) => r.status !== 'FAIL' && r.status !== 'interrupted') ? `PARTIAL, left out: ${omitted.join(', ')}` : 'FAIL'
const summary = [
  `## validate: ${verdict}${interrupted ? ` (${interrupted})` : ''}`,
  '',
  `- commit \`${head}\``,
  `- tree \`${tree}\``,
  `- base \`${base}\` (${opt.base}), an ancestor of the commit; ${diffFiles.length} files differ`,
  `- ${new Date().toISOString()}, ${Math.round((Date.now() - started) / 1000)} s, Node ${process.version}`,
  ...(dropped.length ? [`- ignored from the environment: ${dropped.join(', ')}`] : []),
  '',
  '| step | result | why | seconds |',
  '| --- | --- | --- | --- |',
  ...results.map((r) => `| ${r.name} | ${r.status} | ${r.why} | ${r.seconds ?? ''} |`),
  '',
].join('\n')
console.log(`\n${summary}`)
if (opt.out) writeFileSync(opt.out, summary)
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary)
process.exit(ok ? 0 : interrupted?.startsWith('SIG') ? 130 : 1)
