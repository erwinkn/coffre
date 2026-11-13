// `pnpm validate` (scripts/validate.mjs): its flags, and that every step it can run is
// a job of the Validate workflow it stands in for, but the growth sweep, which has none. What a diff selects is
// scripts/affected.test.mjs's.
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { nodeConformance } from './affected.mjs'

const script = new URL('./validate.mjs', import.meta.url).pathname
const list = (...args) =>
  Object.fromEntries(
    execFileSync('node', [script, '--list', ...args], { encoding: 'utf8' })
      .split('\n')
      .filter((line) => /^\S/.test(line))
      .map((line) => [line.slice(0, 10).trim(), line.slice(11)]),
  )
const workflow = readFileSync(new URL('../.github/workflows/validate.yml', import.meta.url), 'utf8')

test('--full selects every step, and each but the sweep is a job of validate.yml', () => {
  const steps = list('--full', '--base', 'HEAD')
  const jobs = new Set([...workflow.matchAll(/^ {2}([a-z0-9-]+):$/gm)].map((m) => m[1]))
  assert.equal(Object.keys(steps).length, 17)
  for (const [name, why] of Object.entries(steps)) assert.match(why, name === 'docs' ? /every change/ : name === 'node' && !nodeConformance ? /^not run: off until 0\.16\.1 \(T270\)$/ : /^--full/, name)
  // The image is the release's, not a step here.
  assert.equal('image' in steps, false)
  const source = readFileSync(script, 'utf8')
  const declared = [...source.matchAll(/^ {2}([a-z0-9]+): \{\s*(?:job: '([a-z0-9-]+)')?/gm)].filter(([, name]) => name in steps)
  assert.equal(declared.length, Object.keys(steps).length)
  for (const [, name, job] of declared) if (job) assert.ok(jobs.has(job), `${name}'s ${job} is a job of validate.yml`)
  assert.deepEqual(declared.filter(([, , job]) => !job).map(([, name]) => name), ['sweep'])
})

// Each job's commands, from its `run:` lines and blocks, comments aside.
const jobs = {}
{
  let job = null
  let block = null
  for (const line of workflow.split('\n')) {
    const head = /^ {2}([a-z0-9-]+):$/.exec(line)
    if (head) {
      job = head[1]
      jobs[job] = { needs: [], run: [] }
      block = null
      continue
    }
    if (!job) continue
    if (block !== null && (line.trim() === '' || line.search(/\S/) > block)) {
      if (!line.trim().startsWith('#')) jobs[job].run.push(line.trim())
      continue
    }
    block = null
    const needs = /^ {4}needs: \[?([^\]]+)\]?$/.exec(line)
    if (needs) jobs[job].needs = needs[1].split(/,\s*/)
    const run = /^(\s*)(?:- )?run: (.*)$/.exec(line)
    if (run) run[2].trim() === '|' ? (block = run[1].length) : jobs[job].run.push(run[2])
  }
}

test('--full runs every job Validate needs, the image aside, and every command of those jobs', () => {
  const source = readFileSync(script, 'utf8')
  const stepJobs = new Set([...source.matchAll(/job: '([a-z0-9-]+)'/g)].map((m) => m[1]))
  for (const job of jobs.validate.needs) {
    if (job === 'image') continue
    // A job that only judges others' results (matrices, formal) stands on theirs.
    assert.ok(stepJobs.has(job) || jobs[job].needs.some((j) => stepJobs.has(j)), `${job}: no step of pnpm validate runs it`)
  }
  // What a job runs that pnpm validate runs otherwise, and why.
  const otherwise = {
    'pnpm store': 'the runner’s cache',
    'scripts/check-pins.mjs': 'pnpm check:pins runs it',
    'pnpm typecheck': 'the typecheck step, package by package (pnpm -r … run typecheck)',
    'pnpm test': 'lint, then the suite and the files that run alone: the lint, tests and alone steps',
    'scripts/formal-key.sh': 'the cache key of CI’s TLC shards: pnpm validate runs TLC on the scenarios, uncached',
    'scripts/formal-trace.mjs': 'formal.sh runs it',
  }
  for (const [job, { run }] of Object.entries(jobs)) {
    if (!stepJobs.has(job) && !jobs.validate.needs.includes(job)) continue
    const text = run.join('\n')
    const commands = [...text.matchAll(/\bpnpm (?:run )?([a-z][\w:-]*)/g)].map((m) => `pnpm ${m[1]}`).concat([...text.matchAll(/(?<![\w/])(?:\.\/)?(scripts\/[\w.-]+)/g)].map((m) => m[1]))
    for (const command of commands) {
      const named = new RegExp(`${command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w:.-])`).test(source)
      assert.ok(named || command in otherwise, `${job} runs ${command}, which pnpm validate does not`)
    }
  }
})

test('a diff-free change runs the docs check alone', () => {
  const steps = list('--base', 'HEAD')
  assert.equal(steps.docs, 'every change')
  for (const [name, why] of Object.entries(steps)) if (name !== 'docs') assert.match(why, name === 'node' && !nodeConformance ? /not run: off until/ : /not run: diff does not touch it/, name)
})

test('--only and --skip name known steps, and a step the diff needs left out is OMITTED', () => {
  const only = list('--only', 'pins', '--base', 'HEAD')
  assert.match(only.docs, /not run: --only, though every change/)
  const bad = spawnSync('node', [script, '--list', '--skip', 'nope'], { encoding: 'utf8' })
  assert.equal(bad.status, 2)
  assert.match(bad.stderr, /no step nope/)
})

test('the matrices step runs CI\'s Postgres shards one at a time, then the coverage check', () => {
  const source = readFileSync(script, 'utf8')
  const workflow = readFileSync(new URL('../.github/workflows/validate.yml', import.meta.url), 'utf8')
  const ci = [...workflow.matchAll(/- \{ shard: (\d+)\/(\d+) \}/g)].map((m) => `${m[1]}/${m[2]}`)
  const of = Number(source.match(/const MATRIX_SHARDS = (\d+)/)[1])
  assert.deepEqual(Array.from({ length: of }, (_, i) => `${i + 1}/${of}`), ci)
  // Unsharded, the server's matrix outlasts its own timeout on Postgres: no plain `pnpm test:matrices`.
  assert.match(source, /COFFRE_TEST_SHARD=\$\{i \+ 1\}\/\$\{MATRIX_SHARDS\} COFFRE_TEST_SHARD_REPORT="\$COFFRE_VALIDATE_REPORTS\/\$\{i \+ 1\}" pnpm test:matrices/)
  assert.match(source, /'node scripts\/matrix-coverage\.mjs "\$COFFRE_VALIDATE_REPORTS"'/)
  assert.match(workflow, /node scripts\/matrix-coverage\.mjs "\$RUNNER_TEMP\/matrix-shards"\n/)
})
