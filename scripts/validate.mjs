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
// The tree must be clean and rebased on the base, or the summary would vouch for a
// commit it did not run. Postgres is the script's own container (a compose project
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
const packages = anyOf('packages/', 'examples/', 'dev/', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'package.json', '.node-version')
const formalModel = (f) =>
  /^formal\/[^/]+\.(tla|cfg)$/.test(f) ||
  ['scripts/formal.sh', 'scripts/formal-trace.mjs'].includes(f)
const leanInputs = (f) => f.startsWith('formal/lean/') || anyOf('packages/core/src/', 'packages/vault/src/', 'scripts/formal-lean')(f)

/**
 * Each step is a job of validate.yml (`job`), its commands, whether it needs the
 * packages built, Postgres, and the rule picking it. `needs` is the diff predicate;
 * a step with none runs on every change.
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
    needs: anyOf('packages/vault/', 'packages/server/', 'packages/core/', 'packages/db/', 'scripts/matrix', 'scripts/test-suite.sh', 'scripts/test-databases', 'scripts/test-database-worker'),
    // CI splits these over eight runners; one machine runs them whole (about three quarters of an hour on Postgres).
    run: ['pnpm test:matrices', 'pnpm test:matrices:sqlite'],
  },
  { name: 'schema', job: 'schema', postgres: true, needs: anyOf('packages/db/', 'packages/server/', 'packages/vault/', 'scripts/test-schema', 'scripts/setup-test-database', 'scripts/test-setup', 'scripts/test-backup-role', 'docker-compose.yml'), run: ['pnpm test:schema'] },
  { name: 'formal', job: 'formal', needs: formalModel, run: ['./scripts/formal.sh --workers 4 --heap 4g'], full: true },
  { name: 'proofs', job: 'proofs', needs: leanInputs, run: ['pnpm formal:lean'] },
  { name: 'workers', job: 'workers', build: true, postgres: true, needs: packages, run: ['pnpm conformance:workers --browser "$(command -v google-chrome || command -v chromium)"'] },
  { name: 'node', job: 'node', build: true, needs: packages, run: ['pnpm conformance:node --browser "$(command -v google-chrome || command -v chromium)"'] },
  { name: 'terraform', job: 'terraform', build: true, needs: (f) => f.startsWith('terraform-provider/') || f.startsWith('packages/server/') || f.startsWith('packages/conformance/'), run: ['pnpm test:terraform'] },
  { name: 'consumer', job: 'consumer', build: true, needs: packages, run: ['pnpm test:consumer'] },
  { name: 'compat', job: 'compat', postgres: true, needs: anyOf('packages/db/', 'packages/server/', 'packages/vault/', 'packages/conformance/', 'scripts/compat'), run: ['pnpm test:compat'] },
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
const changed = git('diff', '--name-only', base, head).split('\n').filter(Boolean)

const decide = (step) => {
  if (only.size) return only.has(step.name) ? 'only' : null
  if (skip.has(step.name)) return null
  if (opt.all) return '--all'
  if (step.full && opt['full-formal']) return '--full-formal'
  if (!step.needs) return 'every change'
  const hit = changed.find(step.needs)
  return hit ? `${hit} changed` : null
}
const plan = STEPS.map((step) => ({ step, why: decide(step) }))

if (opt.list) {
  for (const { step, why } of plan) console.log(`${step.name.padEnd(10)} ${why ?? 'not needed by this diff'}`)
  process.exit(0)
}

// Postgres of its own: a compose project and a port nobody holds, so a run never
// touches the shared container on :55432 or another checkout's.
const freePort = () =>
  new Promise((ok, no) => {
    const server = createServer()
    server.once('error', no)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => ok(port))
    })
  })

const results = []
const started = Date.now()
const env = { ...process.env }
let database = false
const sh = (command, extra = {}) =>
  new Promise((ok) => {
    const child = spawn('bash', ['-c', command], { cwd: root, stdio: 'inherit', env: { ...env, ...extra } })
    child.on('exit', (code, signal) => ok(code ?? (signal ? 128 : 1)))
  })

if (plan.some(({ step, why }) => why && step.postgres)) {
  const port = await freePort()
  if (port === 55432) fail('picked the shared Postgres port.')
  env.COFFRE_POSTGRES_PORT = String(port)
  env.COMPOSE_PROJECT_NAME = `coffre_validate_${createHash('sha256').update(root).digest('hex').slice(0, 8)}`
  console.log(`validate: Postgres ${env.COMPOSE_PROJECT_NAME} on :${port}`)
  if ((await sh('./scripts/ensure-postgres.sh')) !== 0) fail('Postgres did not start.')
  database = true
}

let built = false
let interrupted = false
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => (interrupted = true))

for (const { step, why } of plan) {
  if (!why) {
    results.push({ name: step.name, status: 'skipped', why: skip.has(step.name) ? '--skip' : 'diff does not touch it' })
    continue
  }
  if (interrupted) {
    results.push({ name: step.name, status: 'not run', why: 'interrupted' })
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
  results.push({ name: step.name, status: code === 0 ? 'pass' : 'FAIL', why, seconds: Math.round((Date.now() - at) / 1000) })
}

if (database && !opt['keep-db']) {
  await sh('docker compose down --volumes --remove-orphans >/dev/null 2>&1')
}

const ok = results.every((r) => r.status === 'pass' || r.status === 'skipped')
const summary = [
  `## validate: ${ok ? 'pass' : 'FAIL'}`,
  '',
  `- commit \`${head}\``,
  `- tree \`${tree}\``,
  `- base \`${base}\` (${opt.base}), an ancestor of the commit; ${changed.length} files differ`,
  `- ${new Date().toISOString()}, ${Math.round((Date.now() - started) / 1000)} s, Node ${process.version}`,
  '',
  '| step | result | why | seconds |',
  '| --- | --- | --- | --- |',
  ...results.map((r) => `| ${r.name} | ${r.status} | ${r.why} | ${r.seconds ?? ''} |`),
  '',
].join('\n')
console.log(`\n${summary}`)
if (opt.out) writeFileSync(opt.out, summary)
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary)
process.exit(ok ? 0 : 1)
