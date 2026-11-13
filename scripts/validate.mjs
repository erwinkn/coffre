#!/usr/bin/env node
// The checks a change passes before it merges (no pull request runs CI; the Validate
// workflow gates releases). Runs, on this exact commit, what the diff against main can
// change (scripts/affected.mjs says what and why), side by side, and prints the commit,
// its tree, the base, and each step's result. Paste that on the pull request, then merge
// with `gh pr merge --squash --match-head-commit <sha>`.
//
//   pnpm validate                  what this diff can change
//   pnpm validate --full           everything, as the release's Validate (the image aside; the
//                                  packed client on this Node, or those COFFRE_CLIENT_NODES lists),
//                                  and the growth sweep, which Validate has no job for; the
//                                  upgrade check runs here alone
//   pnpm validate --base <rev>     the revision the change is on (default origin/main)
//   pnpm validate --skip a,b       leave steps out; one the diff needs is OMITTED and the
//                                  summary reads PARTIAL (exit 1), never pass
//   pnpm validate --only a,b       just these steps (the others are left out the same way)
//   pnpm validate --list           the steps, why each runs and what it runs, running none
//   pnpm validate --jobs <n>       at most n steps at once, cheap checks aside (default 4)
//   pnpm validate --logs <dir>     where each step writes its log (default: a temp dir)
//   pnpm validate --out <file>     also write the summary there
//   pnpm validate --keep-db        leave the Postgres containers it started running (once it has
//                                  exited, the next run here with a Postgres step removes them)
//
// The tree must be clean and rebased on the base, and is checked again when the run
// ends, or the summary would vouch for a commit it did not run. Dependencies are
// installed from the lockfile first. Each step that needs Postgres gets a container of
// its own (a compose project and a free port, never the shared :55432), removed when the
// step ends, whether it passed, failed or was stopped; the containers of one run share
// its network, so a run takes one of Docker's subnets (and the upgrade check, which starts its own, one more). A run with a Postgres step first
// removes what runs killed outright left behind: the projects and networks of a
// validate.mjs of this boot no longer alive. A teardown that hangs holds the run until a
// second signal, which ends that attempt and skips its retry. Each conformance run gets free ports of its own. The local COFFRE_TEST_* and
// COFFRE_DEV_* settings are dropped (they would shard or redirect the suites), and
// COFFRE_POSTGRES_SUBNET (the run's network is its own, on a subnet Docker picks, and
// ensure-postgres.sh still checks where it routes); the summary says so. The Pins step needs GH_TOKEN or a logged-in `gh`, to audit the pinned
// actions against GitHub as CI does. The image is the release's (`pnpm test:image`).
import { execFileSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, createWriteStream, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { hostname, tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { changedFiles, nodeConformance, plan } from './affected.mjs'

const root = resolve(import.meta.dirname, '..')

const { values: opt } = parseArgs({
  options: {
    full: { type: 'boolean', default: false },
    base: { type: 'string', default: 'origin/main' },
    skip: { type: 'string', default: '' },
    only: { type: 'string', default: '' },
    list: { type: 'boolean', default: false },
    jobs: { type: 'string', default: '4' },
    logs: { type: 'string' },
    out: { type: 'string' },
    'keep-db': { type: 'boolean', default: false },
  },
})

const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 1 << 28 }).trim()
const fail = (message) => {
  console.error(`validate: ${message}`)
  process.exit(2)
}

const head = git('rev-parse', 'HEAD')
const tree = git('rev-parse', 'HEAD^{tree}')
let base
try {
  base = git('rev-parse', '--verify', `${opt.base}^{commit}`)
} catch {
  fail(`no revision ${opt.base} (fetch it, or name another with --base)`)
}
if (!opt.list) {
  if (git('status', '--porcelain', '--untracked-files=all')) fail('the tree is not clean: commit first, so the summary names what ran.')
  try {
    git('merge-base', '--is-ancestor', base, head)
  } catch {
    fail(`${opt.base} (${base.slice(0, 10)}) is not an ancestor of HEAD: rebase on it first.`)
  }
}
const jobs = Number(opt.jobs)
if (!Number.isInteger(jobs) || jobs < 1) fail(`--jobs ${opt.jobs}: expected a positive integer`)

const files = git('ls-files').split('\n').filter(Boolean)
const changed = changedFiles(root, base, head)
const { steps: selected } = plan({
  root,
  files,
  changed,
  full: opt.full,
  readBase: (file) => git('show', `${base}:${file}`),
})

// What each step runs, given what the plan picked. `install`: it runs workspace code;
// `build`: it reads the packages' dist; `postgres`: a container of its own; `ports`: three
// free ports for a conformance run; `cheap`: seconds, outside the --jobs limit.
const BROWSER = '"$COFFRE_VALIDATE_BROWSER"'
const quote = (list) => list.map((f) => `'${f}'`).join(' ')
// The use matrices as CI runs them (validate.yml, `matrices-shard`): in sixths, one at a time (each takes the slots of a
// stock Postgres), each from a database of its own, then `matrix-coverage.mjs` holds the reports to every case run
// exactly once.
const MATRIX_SHARDS = 6
const STEPS = {
  docs: { job: 'checks', cheap: true, run: () => ['pnpm check:docs'] },
  pins: { job: 'pins', cheap: true, install: true, run: () => ['pnpm check:pins', 'pnpm check:workflows'] },
  contrast: { job: 'checks', cheap: true, run: () => ['pnpm check:contrast'] },
  lint: { job: 'checks', install: true, run: ({ files }) => [files ? `pnpm exec eslint ${quote(files)}` : 'pnpm lint'] },
  typecheck: {
    job: 'checks',
    install: true,
    // The examples and the dev deployment read the packages' dist, as a deployment does.
    build: ({ units }) => units.some((u) => !u.startsWith('packages/')),
    run: ({ units }) => [`pnpm -r --no-sort ${units.map((u) => `--filter ./${u}`).join(' ')} run typecheck`],
  },
  action: { job: 'action', install: true, build: true, run: () => ['pnpm check:action'] },
  tests: { job: 'tests', install: true, postgres: true, run: ({ files }) => [`./scripts/test-suite.sh --files ${quote(files)}`] },
  // On a cluster of their own, no other test's migration resets their backends' caches (scripts/test-suite.sh).
  alone: { job: 'tests', install: true, postgres: true, run: ({ files }) => [`./scripts/test-suite.sh --serial --files ${quote(files)}`] },
  matrices: {
    job: 'matrices-shard',
    install: true,
    postgres: true,
    run: () => [
      ...Array.from({ length: MATRIX_SHARDS }, (_, i) => `COFFRE_TEST_SHARD=${i + 1}/${MATRIX_SHARDS} COFFRE_TEST_SHARD_REPORT="$COFFRE_VALIDATE_REPORTS/${i + 1}" pnpm test:matrices`),
      'node scripts/matrix-coverage.mjs "$COFFRE_VALIDATE_REPORTS"',
    ],
  },
  schema: { job: 'schema', install: true, postgres: true, run: () => ['pnpm test:schema'] },
  formal: { job: 'formal', run: ({ scenarios, why }) => [`./scripts/formal.sh --workers 4 --heap 4g${why === '--full' ? '' : ` ${scenarios.join(' ')}`}`] },
  proofs: { job: 'proofs', install: true, run: () => ['pnpm formal:lean'] },
  workers: { job: 'workers', install: true, build: true, postgres: true, browser: true, ports: true, run: () => [`pnpm conformance:workers --browser ${BROWSER} --port "$COFFRE_VALIDATE_PORT"`] },
  node: { job: 'node', install: true, build: true, postgres: true, browser: true, ports: true, run: () => [`pnpm conformance:node --browser ${BROWSER} --port "$COFFRE_VALIDATE_PORT"`] },
  terraform: { job: 'terraform', install: true, build: true, postgres: true, run: () => ['pnpm test:terraform'] },
  // The consumer script starts Postgres itself (ensure-postgres.sh), so it gets the step's.
  consumer: {
    job: 'consumer',
    install: true,
    build: true,
    postgres: true,
    ports: true,
    run: () => [`pnpm test:consumer --built --port "$COFFRE_VALIDATE_PORT"${nodeConformance ? '' : ' --skip-conformance node'}`],
  },
  // No job of validate.yml: the growth sweep (docs/growth-sweep.md) runs before a tag, on the step's own Postgres, as it requires.
  sweep: { install: true, postgres: true, run: () => [`pnpm sweep:growth --out ${quote([join(logs, 'sweep')])}`] },
  // A database of 0.14.5's through 0.15.0 to this revision (scripts/upgrade-check.sh), about 4.5 min: --full
  // runs it, and a change to its own files. Its Postgres is a compose project the script starts and removes
  // itself, on a network of its own, beside the run's.
  upgrade: { job: 'upgrade', install: true, build: true, ports: true, run: () => ['pnpm upgrade:check --port "$COFFRE_VALIDATE_PORT"'] },
}

const names = new Set(Object.keys(STEPS))
const csv = (value, flag) => {
  const list = value.split(',').filter(Boolean)
  for (const name of list) if (!names.has(name)) fail(`--${flag}: no step ${name} (${[...names].join(', ')})`)
  return new Set(list)
}
const skip = csv(opt.skip, 'skip')
const only = csv(opt.only, 'only')

// Whether a step runs, and why not when it does not.
const entries = selected.map((s) => {
  const flag = only.size ? (only.has(s.name) ? null : '--only') : skip.has(s.name) ? '--skip' : null
  if (flag) return { ...s, run: false, status: s.why ? 'OMITTED' : 'skipped', note: s.why ? `${flag}, though ${s.why}` : `${flag}; ${s.off ?? 'the diff does not touch it'}` }
  return s.why ? { ...s, run: true } : { ...s, run: false, status: 'skipped', note: s.off ?? 'diff does not touch it' }
})
const detail = (s) => {
  if (s.files) return `\n    ${s.files.join('\n    ')}`
  if (s.scenarios && s.why !== '--full') return `: ${s.scenarios.join(' ')}`
  if (s.units) return `: ${s.units.join(' ')}`
  return ''
}

if (opt.list) {
  for (const s of entries) console.log(`${s.name.padEnd(10)} ${s.run ? s.why : `not run: ${s.note}`}${s.run ? detail(s) : ''}`)
  process.exit(0)
}

const started = Date.now()
const env = { ...process.env }
const dropped = Object.keys(env).filter((k) => /^COFFRE_(?:TEST_|DEV_|POSTGRES_SUBNET$)/.test(k))
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
if (!pinsToken && entries.some((s) => s.name === 'pins' && s.run)) {
  try {
    pinsToken = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {}
}

const logs = opt.logs ? resolve(opt.logs) : mkdtempSync(join(tmpdir(), `coffre-validate-${head.slice(0, 10)}-`))
mkdirSync(logs, { recursive: true })
// A run is named for its process, under a prefix for the processes it can see: this
// boot's PID namespace. A name of that prefix whose process is gone is a run killed
// before its teardown, whose leftovers the next run removes; one of another namespace
// (another container or VM on the same Docker) is never judged from here.
const space = (() => {
  try {
    return readFileSync('/proc/sys/kernel/random/boot_id', 'utf8') + readlinkSync('/proc/self/ns/pid')
  } catch {
    return hostname()
  }
})()
const runPrefix = `coffre_validate_${createHash('sha256').update(space).digest('hex').slice(0, 8)}_`
const runId = `${runPrefix.slice('coffre_validate_'.length)}${process.pid}`

// Every child runs in a process group of its own, so that a signal reaches all of it.
// A step may start servers in groups of their own (conformance does), which a signal to
// its group misses, and which outlive it when it dies before its own teardown, orphaned:
// no longer below it. So each child's environment carries a tag of its own, which every
// process it starts inherits, and when it ends, or a signal ends the run, whatever
// carries the tag goes too. The processes below it count as well, for a system with no
// /proc to read environments from.
const active = new Set()
let interrupted = null
let signals = 0
const TAG = 'VALIDATE_STEP_TAG' // not COFFRE_*, which conformance's harness drops
let tags = 0
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
const tagged = (tag) => {
  const found = []
  let pids = []
  try {
    pids = readdirSync('/proc').filter((p) => /^\d+$/.test(p))
  } catch {}
  for (const p of pids) {
    try {
      if (readFileSync(`/proc/${p}/environ`, 'latin1').split('\0').includes(`${TAG}=${tag}`)) found.push(Number(p))
    } catch {}
  }
  return found
}
const strays = (child) => [...new Set([...below(child.pid), ...tagged(child.tag)])].filter((pid) => pid !== process.pid)
const kill = (pid, signal) => {
  try {
    process.kill(pid, signal)
  } catch {}
}
const alive = (pid) => {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error.code === 'EPERM' // another user's
  }
}
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    interrupted ??= signal
    signals++
    // Only what was running when the signal came: the teardown it sets off (each
    // step's `docker compose down`) starts after, and must be left to finish.
    const running = [...active]
    for (const child of running) {
      for (const pid of strays(child)) kill(pid, signal)
      kill(-child.pid, signal)
    }
    // A step that handles the signal but hangs while shutting down must not hold the
    // run: three seconds on, whatever is left of it is killed, so teardown and the
    // summary are reached.
    setTimeout(() => {
      for (const child of running) {
        kill(-child.pid, 'SIGKILL')
        for (const pid of strays(child)) kill(pid, 'SIGKILL')
      }
    }, 3000).unref()
  })
}

/** Runs `command` with `extra` in the environment, its output to `log`; resolves to its exit code. */
const sh = (command, { extra = {}, log }) =>
  new Promise((ok) => {
    const out = createWriteStream(log, { flags: 'a' })
    out.write(`\n== ${command}\n`)
    const tag = `${runId}_${++tags}`
    const child = spawn('bash', ['-c', command], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], env: { ...env, ...extra, [TAG]: tag }, detached: true })
    child.tag = tag
    child.stdout.pipe(out, { end: false })
    child.stderr.pipe(out, { end: false })
    active.add(child)
    child.on('close', async (code, signal) => {
      active.delete(child)
      // Whatever it left behind, its group and the servers it started, goes with it:
      // asked to stop, three seconds to finish shutting down, then killed. A clean
      // close costs one scan.
      let left = strays(child)
      if (alive(-child.pid) || left.length) {
        kill(-child.pid, 'SIGTERM')
        for (const pid of left) kill(pid, 'SIGTERM')
        for (const end = Date.now() + 3000; Date.now() < end && (alive(-child.pid) || (left = strays(child)).length); ) await new Promise((r) => setTimeout(r, 100))
        kill(-child.pid, 'SIGKILL')
        for (const pid of strays(child)) kill(pid, 'SIGKILL')
      }
      out.end(() => ok(code ?? (signal ? 128 : 1)))
    })
  })

// Free ports, none of them the shared Postgres's, none handed out twice in this run.
const taken = new Set([55432])
const listenable = (port) =>
  new Promise((ok) => {
    const server = createServer()
    server.once('error', () => ok(false))
    server.listen(port, '127.0.0.1', () => server.close(() => ok(true)))
  })
const freePort = async () => {
  for (;;) {
    const port = await new Promise((ok, no) => {
      const server = createServer()
      server.once('error', no)
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address()
        server.close(() => ok(port))
      })
    })
    if (!taken.has(port)) return taken.add(port), port
  }
}
// Three in a row, for conformance: coffre's, the IdP's, wrangler's.
const freeRange = async () => {
  for (;;) {
    const start = 20000 + Math.floor(Math.random() * 10000)
    const range = [start, start + 1, start + 2]
    if (range.some((p) => taken.has(p))) continue
    if ((await Promise.all(range.map(listenable))).every(Boolean)) return range.forEach((p) => taken.add(p)), start
  }
}

// One task per prerequisite, run once and awaited by every step that needs it.
const once = (fn) => {
  let promise
  return () => (promise ??= fn())
}

// Postgres's containers: one compose project per step, all on the run's network.
const network = `coffre_validate_${runId}`
const composeEnv = (project) => ({
  COMPOSE_PROJECT_NAME: project,
  COMPOSE_FILE: ['docker-compose.yml', 'docker-compose.network.yml'].join(env.COMPOSE_PATH_SEPARATOR ?? ':'),
  COFFRE_POSTGRES_NETWORK: network,
})
const docker = (...args) => {
  try {
    return execFileSync('docker', args, { cwd: root, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\n').filter(Boolean)
  } catch {
    return null
  }
}
const sweepLog = join(logs, 'postgres.log')
/**
 * Runs a teardown command, once more on failure: one that a stop interrupts says "Error
 * while Stopping". Not when a signal came during the first attempt: that signal ended it.
 */
const twice = async (command, options) => {
  const before = signals
  return (await sh(command, options)) === 0 || (signals === before && (await sh(command, options)) === 0)
}
// What runs killed outright (SIGKILL, a crash) left: their projects, whatever survives
// of each (container, network, volume), then their networks. Only runs of this boot's
// PID namespace are judged (above), so what a run of an earlier boot left, or of
// validate.mjs before runs were named so, stays until removed by hand. Each is judged
// dead again just before it goes, so that a pid reused by a run starting meanwhile
// keeps its own.
const sweep = async () => {
  const dead = (name) => name.startsWith(runPrefix) && !alive(Number(name.slice(runPrefix.length).split('_')[0]))
  const label = '{{.Label "com.docker.compose.project"}}'
  const removed = []
  const left = []
  // A listing that fails hides what it would have shown: said, as what is left is.
  const unlisted = new Set()
  const list = (...args) => docker(...args) ?? (unlisted.add(`docker ${args.slice(0, 2).join(' ')}`), [])
  try {
    const projects = new Set(
      [['ps', '-a'], ['network', 'ls'], ['volume', 'ls']].flatMap((ls) => list(...ls, '--filter', `label=com.docker.compose.project`, '--format', label)).filter(dead),
    )
    for (const project of projects) {
      if (interrupted) return
      if (!dead(project)) continue
      // The base file alone: a project of a run before networks were shared has one of its own.
      let gone = await twice('docker compose down --volumes --remove-orphans', { extra: { COMPOSE_PROJECT_NAME: project, COMPOSE_FILE: 'docker-compose.yml' }, log: sweepLog })
      const volumes = docker('volume', 'ls', '-q', '--filter', `label=com.docker.compose.project=${project}`)
      if (volumes?.length) gone = (await sh(`docker volume rm ${volumes.join(' ')}`, { log: sweepLog })) === 0 && gone
      ;(gone && volumes ? removed : left).push(project)
    }
    for (const name of list('network', 'ls', '--filter', 'label=coffre.validate', '--format', '{{.Name}}').filter(dead)) {
      if (interrupted) return
      if (dead(name)) ((await twice(`docker network rm ${name}`, { log: sweepLog })) ? removed : left).push(name)
    }
  } finally {
    // Also when a signal cut it short: what it did by then.
    if (removed.length) console.log(`validate: removed ${removed.length} projects and networks of runs no longer alive (${sweepLog})`)
    if (left.length) console.error(`validate: could not remove ${left.join(', ')}, of runs no longer alive (${sweepLog})`)
    if (unlisted.size) console.error(`validate: could not list (${[...unlisted].join(', ')}); what runs no longer alive left there stays until a later run`)
  }
}
let networkMade = false
const ownNetwork = once(async () => (networkMade = (await sh(`docker network create --label coffre.validate=1 ${network}`, { log: sweepLog })) === 0))
let teardownFailed = false
const down = async (project, log) => {
  if (await twice('docker compose down --volumes --remove-orphans', { extra: composeEnv(project), log })) return
  teardownFailed = true
  console.error(`validate: could not remove Postgres ${project}; the next run removes it, or now: COMPOSE_PROJECT_NAME=${project} docker compose down --volumes`)
}

const results = new Map()
const record = (name, result) => results.set(name, result)
for (const s of entries) if (!s.run) record(s.name, { status: s.status, why: s.note })

const timed = async (name, why, fn) => {
  const at = Date.now()
  const log = join(logs, `${name}.log`)
  const code = await fn(log)
  const result = { status: interrupted ? 'interrupted' : code === 0 ? 'pass' : 'FAIL', why, seconds: Math.round((Date.now() - at) / 1000), log }
  record(name, result)
  console.log(`validate: ${name} ${result.status} (${result.seconds} s)${result.status === 'pass' ? '' : `, log: ${log}`}`)
  return code === 0
}
const install = once(() => timed('install', 'every run that runs workspace code', (log) => sh('pnpm install --frozen-lockfile', { log })))
const build = once(async () => (await install()) && !interrupted && timed('build', 'a step reads the packages’ dist', (log) => sh('pnpm build', { log })))

// The --jobs limit: steps beyond it wait for a slot; the cheap checks never do.
let running = 0
const waiting = []
const slot = async (cheap) => {
  if (cheap) return () => {}
  if (running >= jobs) await new Promise((ok) => waiting.push(ok))
  running++
  return () => {
    running--
    waiting.shift()?.()
  }
}

const runStep = async (s) => {
  const spec = STEPS[s.name]
  const not = (why) => record(s.name, { status: 'not run', why })
  if (interrupted) return not(interrupted)
  if (spec.install && !(await install())) return not('install failed')
  if ((typeof spec.build === 'function' ? spec.build(s) : spec.build) && !(await build())) return not('build failed')
  if (s.name === 'pins' && !pinsToken) return record(s.name, { status: 'FAIL', why: 'no GH_TOKEN and no `gh auth token`: the pinned actions cannot be checked against GitHub, as CI does' })
  if (spec.browser && !browser) return record(s.name, { status: 'FAIL', why: 'no google-chrome or chromium on PATH' })
  const release = await slot(spec.cheap)
  if (interrupted) return release(), not(interrupted)
  const extra = { ...spec.env }
  if (s.name === 'pins') extra.GH_TOKEN = pinsToken
  let project = null
  let reports = null
  try {
    return await timed(s.name, s.why, async (log) => {
      if (spec.postgres) {
        const port = await freePort()
        if (!(await ownNetwork())) return appendFileSync(log, `no network ${network}: ${sweepLog}\n`), 1
        project = `coffre_validate_${runId}_${s.name.replace(/\W/g, '_')}`
        Object.assign(extra, composeEnv(project), { COFFRE_POSTGRES_PORT: String(port) })
        const code = await sh('./scripts/ensure-postgres.sh', { extra, log })
        if (code !== 0) return code
      }
      if (spec.ports) extra.COFFRE_VALIDATE_PORT = String(await freeRange())
      if (s.name === 'matrices') extra.COFFRE_VALIDATE_REPORTS = reports = mkdtempSync(join(tmpdir(), 'coffre-validate-matrices-'))
      for (const command of spec.run(s)) {
        if (interrupted) return 130
        const code = await sh(command, { extra, log })
        if (code !== 0) return code
      }
      return 0
    })
  } finally {
    release()
    if (reports) rmSync(reports, { recursive: true, force: true })
    if (project && !opt['keep-db']) await down(project, join(logs, `${s.name}.log`))
  }
}

const toRun = entries.filter((s) => s.run)
console.log(`validate: ${toRun.map((s) => s.name).join(', ') || 'nothing'} on ${head.slice(0, 10)}, logs in ${logs}`)
// The longest first, so that the --jobs slots go to what holds the run up.
const ORDER = ['tests', 'matrices', 'formal', 'consumer', 'upgrade', 'alone', 'workers', 'schema', 'sweep', 'node', 'terraform', 'typecheck', 'proofs', 'action', 'lint']
if (toRun.some((s) => STEPS[s.name].postgres)) await sweep()
await Promise.all(toRun.sort((a, b) => ORDER.indexOf(a.name) - ORDER.indexOf(b.name)).map((s) => runStep(s).catch((error) => record(s.name, { status: 'FAIL', why: error.message }))))
if (networkMade && !opt['keep-db'] && !(await twice(`docker network rm ${network}`, { log: sweepLog }))) {
  teardownFailed = true
  console.error(`validate: could not remove network ${network}; the next run removes it, or now: docker network rm ${network}`)
}

// The summary vouches for HEAD's tree: it must be what the steps ran on.
const rows = [...(results.has('install') ? ['install'] : []), ...(results.has('build') ? ['build'] : []), ...entries.map((s) => s.name)].map((name) => ({ name, ...results.get(name) }))
const headAfter = git('rev-parse', 'HEAD')
const dirty = git('status', '--porcelain', '--untracked-files=all')
if (headAfter !== head || dirty) rows.push({ name: 'tree', status: 'FAIL', why: headAfter !== head ? `HEAD moved to ${headAfter.slice(0, 10)}` : 'files changed or appeared during the run' })
if (teardownFailed) rows.push({ name: 'postgres', status: 'FAIL', why: 'not removed' })

const ok = !interrupted && rows.every((r) => r.status === 'pass' || r.status === 'skipped')
const omitted = rows.filter((r) => r.status === 'OMITTED').map((r) => r.name)
const verdict = ok ? 'pass' : !interrupted && rows.every((r) => !['FAIL', 'interrupted', 'not run'].includes(r.status)) ? `PARTIAL, left out: ${omitted.join(', ')}` : 'FAIL'
const summary = [
  `## validate${opt.full ? ' --full' : ''}: ${verdict}${interrupted ? ` (${interrupted})` : ''}`,
  '',
  `- commit \`${head}\``,
  `- tree \`${tree}\``,
  `- base \`${base}\` (${opt.base}), an ancestor of the commit; ${changed.length} files differ`,
  `- ${new Date().toISOString()}, ${Math.round((Date.now() - started) / 1000)} s, Node ${process.version}`,
  ...(dropped.length ? [`- ignored from the environment: ${dropped.join(', ')}`] : []),
  // CI loads the packed client on Node 20, 22, 24 and 26; a run here, on those its environment names.
  ...(results.get('consumer')?.status === 'pass' ? [`- the packed client loaded on ${env.COFFRE_CLIENT_NODES ? `COFFRE_CLIENT_NODES (${env.COFFRE_CLIENT_NODES})` : `this Node alone (${process.version}); CI's, on 20, 22, 24 and 26`}`] : []),
  '',
  '| step | result | why | seconds |',
  '| --- | --- | --- | --- |',
  ...rows.map((r) => `| ${r.name} | ${r.status} | ${r.why ?? ''} | ${r.seconds ?? ''} |`),
  '',
].join('\n')
console.log(`\n${summary}`)
if (!ok) for (const r of rows.filter((r) => r.log && r.status !== 'pass')) console.log(`${r.name}: ${r.log}`)
if (opt.out) writeFileSync(opt.out, summary)
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary)
process.exit(ok ? 0 : interrupted?.startsWith('SIG') ? 130 : 1)
