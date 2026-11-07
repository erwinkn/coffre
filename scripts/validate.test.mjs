// `pnpm validate` (scripts/validate.mjs): which steps a diff selects, and that
// every step it can run is a job of the Validate workflow it stands in for.
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const script = new URL('./validate.mjs', import.meta.url).pathname
const list = (...args) =>
  Object.fromEntries(
    execFileSync('node', [script, '--list', ...args], { encoding: 'utf8' })
      .trim()
      .split('\n')
      .map((line) => [line.slice(0, 10).trim(), line.slice(11)]),
  )

test('--all selects every step, and each is a job of validate.yml', () => {
  const steps = list('--all', '--base', 'HEAD')
  const workflow = readFileSync(new URL('../.github/workflows/validate.yml', import.meta.url), 'utf8')
  const jobs = new Set([...workflow.matchAll(/^ {2}([a-z0-9-]+):$/gm)].map((m) => m[1]))
  assert.ok(Object.keys(steps).length >= 10)
  for (const [name, why] of Object.entries(steps)) assert.equal(why, '--all', name)
  // The image is the release's, not a step here.
  assert.equal('image' in steps, false)
  const source = readFileSync(script, 'utf8')
  for (const [, job] of source.matchAll(/job: '([a-z0-9-]+)'/g)) assert.ok(jobs.has(job), `${job} is a job of validate.yml`)
})

test('a diff-free change selects only what every change needs', () => {
  const steps = list('--base', 'HEAD')
  for (const name of ['action', 'pins', 'checks']) assert.equal(steps[name], 'every change')
  for (const name of ['tests', 'matrices', 'formal', 'workers', 'terraform']) assert.match(steps[name], /not needed/)
})

test('--only and --skip name known steps', () => {
  const only = list('--only', 'pins', '--base', 'HEAD')
  assert.deepEqual(Object.keys(only).filter((name) => !only[name].startsWith('not')), ['pins'])
  const bad = spawnSync('node', [script, '--list', '--skip', 'nope'], { encoding: 'utf8' })
  assert.equal(bad.status, 2)
  assert.match(bad.stderr, /no step nope/)
})
