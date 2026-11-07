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
//   pnpm validate --skip a,b       leave steps out (reported as skipped, so the summary says so)
//   pnpm validate --only a,b       just these steps
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
// the summary says so. Postgres is the script's own container (a compose project
// and a free port of its own, never the shared :55432), removed when it ends. The
// image step is not here: `pnpm test:image` builds for two architectures and is
// the release's (Validate on the tagged commit runs it).
import { execFileSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { resolve } from 'node:path'
import { parseArgs } from 'node:util'

const root = resolve(import.meta.dirname, '..')

/** What a diff has to touch for a step to run; the rest is the diff's own. */
const code = (f) => !/\.md$/.test(f) && !f.startsWith('docs/')
const anyOf = (...prefixes) => (f) => prefixes.some((p) => f.startsWith(p))
const packages = anyOf('packages/', 'examples/', 'dev/', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', '.node-version')
const formalModel = (f) =>
  /^formal\/[^/]+\.(tla|cfg)$/.test(f) ||
  ['scripts/formal.sh', 'scripts/formal-trace.mjs'].includes(f)
const leanInputs = (f) => f.startsWith('formal/lean/') || anyOf('packages/core/src/', 'packages/vault/src/', 'scripts/formal-lean')(f)
const BROWSER = '"$COFFRE_VALIDATE_BROWSER"'

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
    needs: (f) => anyOf('packages/vault/', 'packages/server/', 'packages/core/', 'packages/db/', 'package.json', 'scripts/matrix')(f),
    // CI splits these over eight runners; one machine runs them whole (about three quarters of an hour on Postgres).
    run: ['pnpm test:matrices', 'pnpm test:matrices:sqlite'],
  },
  { name: 'schema', job: 'schema', postgres: true, needs: anyOf('packages/db/', 'packages/server/', 'packages/vault/', 'package.json', 'scripts/setup-test-database', 'scripts/test-setup', 'scripts/test-backup-role', 'docker-compose.yml'), run: ['pnpm test:schema'] },
  { name: 'formal', job: 'formal', needs: formalModel, run: ['./scripts/formal.sh --workers 4 --heap 4g'], full: true },
  { name: 'proofs', job: 'proofs', needs: leanInputs, run: ['pnpm formal:lean'] },
  { name: 'workers', job: 'workers', build: true, postgres: true, browser: true, needs: packages, run: [`pnpm conformance:workers --browser ${BROWSER}`] },
  { name: 'node', job: 'node', build: true, browser: true, needs: packages, run: [`pnpm conformance:node --browser ${BROWSER}`] },
  { name: 'terraform', job: 'terraform', build: true, needs: (f) => anyOf('terraform-provider/', 'packages/server/', 'packages/conformance/', 'package.json')(f), run: ['pnpm test:terraform'] },
  // The consumer script starts Postgres itself (ensure-postgres.sh), so it gets this run's.
  { name: 'consumer', job: 'consumer', build: true, postgres: true, needs: (f) => packages(f) || f === 'scripts/client-smoke.cjs', run: ['pnpm test:consumer'] },
  { name: 'compat', job: 'compat', postgres: true, needs: anyOf('packages/db/', 'packages/server/', 'packages/vault/', 'packages/conformance/', 'package.json', 'scripts/compat'), run: ['pnpm test:compat'] },
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
  if (git('status', '--porcelain')) fail('the tree is not clean: commit or stash first, so the summary names what ran.')
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
const diffFiles = git('diff', '--name-only', base, head).split('\n').filter(Boolean)
const changed = diffFiles.filter((f) => f !== 'package.json')
if (diffFiles.includes('package.json')) {
  const { scripts: before = {}, ...otherBefore } = manifest(base)
  const { scripts: after = {}, ...otherAfter } = manifest(head)
  if (JSON.stringify(otherBefore) !== JSON.stringify(otherAfter)) changed.push('package.json')
  for (const name of new Set([...Object.keys(before), ...Object.keys(after)])) if (before[name] !== after[name]) changed.push(`root script ${name}`)
}

// What a step runs: the pnpm scripts its commands name and the script files those
// (and the commands themselves) call.
const scriptFiles = (text) => [...text.matchAll(/(?:^|[\s'"=])(?:\.\/)?(scripts\/[A-Za-z0-9_./-]+)/g)].map((m) => m[1])
const rootScripts = manifest(head).scripts ?? {}
const inputsOf = (step) => {
  const scripts = new Set(step.build ? ['build'] : [])
  const files = new Set()
  for (const command of step.run) {
    for (const m of command.matchAll(/\bpnpm ([a-z][\w:-]*)/g)) if (rootScripts[m[1]]) scripts.add(m[1])
    for (const file of scriptFiles(command)) files.add(file)
  }
  for (const name of scripts) for (const file of scriptFiles(rootScripts[name])) files.add(file)
  return { scripts, files }
}

const decide = (step) => {
  if (only.size) return only.has(step.name) ? 'only' : null
  if (skip.has(step.name)) return null
  if (opt.all) return '--all'
  if (step.full && opt['full-formal']) return '--full-formal'
  if (!step.needs) return 'every change'
  const { scripts, files } = inputsOf(step)
  const hit = changed.find((f) => step.needs(f) || files.has(f) || (f.startsWith('root script ') && scripts.has(f.slice(12))))
  return hit ? `${hit} changed` : null
}
const plan = STEPS.map((step) => ({ step, why: decide(step) }))

if (opt.list) {
  for (const { step, why } of plan) console.log(`${step.name.padEnd(10)} ${why ?? 'not needed by this diff'}`)
  process.exit(0)
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

// The child of the step now running, so that a signal reaches it: each runs in a
// process group of its own, and the signal goes to the whole group.
let active = null
let interrupted = null
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    interrupted ??= signal
    if (active) {
      try {
        process.kill(-active.pid, signal)
      } catch {}
    }
  })
}
const sh = (command, extra = {}) =>
  new Promise((ok) => {
    const child = spawn('bash', ['-c', command], { cwd: root, stdio: 'inherit', env: { ...env, ...extra }, detached: true })
    active = child
    child.on('exit', (code, signal) => {
      active = null
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
const teardown = async () => {
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
  for (const { step, why } of plan) {
    if (!why) {
      results.push({ name: step.name, status: 'skipped', why: skip.has(step.name) ? '--skip' : 'diff does not touch it' })
      continue
    }
    if (interrupted) {
      results.push({ name: step.name, status: 'not run', why: interrupted })
      continue
    }
    if (step.browser && !browser) {
      results.push({ name: step.name, status: 'FAIL', why: 'no google-chrome or chromium on PATH' })
      continue
    }
    const at = Date.now()
    let code = 0
    if (step.build && !built) {
      console.log('\n== build')
      code = await sh('pnpm build')
      built = code === 0
    }
    for (const command of code === 0 ? step.run : []) {
      console.log(`\n== ${step.name}: ${command}`)
      code = await sh(command, step.env)
      if (code !== 0) break
    }
    // The client is smoke-tested on each Node COFFRE_CLIENT_NODES names; unset, on this one alone.
    const partial = step.name === 'consumer' && !env.COFFRE_CLIENT_NODES ? `; client on Node ${process.version} only (CI: 20, 22, 24, 26)` : ''
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
const dirty = git('status', '--porcelain', '--untracked-files=no')
if (headAfter !== head || dirty) results.push({ name: 'tree', status: 'FAIL', why: headAfter !== head ? `HEAD moved to ${headAfter.slice(0, 10)}` : 'tracked files changed during the run' })
if (teardownFailed) results.push({ name: 'postgres', status: 'FAIL', why: 'not removed' })

const ok = !interrupted && results.every((r) => r.status === 'pass' || r.status === 'skipped')
const summary = [
  `## validate: ${ok ? 'pass' : 'FAIL'}${interrupted ? ` (${interrupted})` : ''}`,
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
