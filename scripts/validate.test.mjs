// `pnpm validate` (scripts/validate.mjs): which steps a diff selects, and that
// every step it can run is a job of the Validate workflow it stands in for.
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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
  for (const name of ['tests', 'matrices', 'formal', 'workers', 'terraform']) assert.match(steps[name], /not run: diff does not touch it/)
})

test('--only and --skip name known steps', () => {
  const only = list('--only', 'pins', '--base', 'HEAD')
  assert.deepEqual(Object.keys(only).filter((name) => !only[name].startsWith('not')), ['pins'])
  const bad = spawnSync('node', [script, '--list', '--skip', 'nope'], { encoding: 'utf8' })
  assert.equal(bad.status, 2)
  assert.match(bad.stderr, /no step nope/)
})

// A throwaway repository holding the script and a root package.json: commit a
// base, then a change, and ask which steps the change selects.
const selected = (change) => {
  const dir = mkdtempSync(join(tmpdir(), 'validate-test-'))
  const git = (...args) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...args], { cwd: dir, encoding: 'utf8' }).trim()
  try {
    mkdirSync(join(dir, 'scripts'))
    copyFileSync(script, join(dir, 'scripts/validate.mjs'))
    for (const file of ['consumer-test.sh', 'client-smoke.cjs', 'helper.sh']) writeFileSync(join(dir, 'scripts', file), '')
    writeFileSync(join(dir, 'scripts/terraform-provider.sh'), 'bash scripts/helper.sh\n')
    const manifest = (extra = {}) => JSON.stringify({ name: 'x', scripts: { 'test:terraform': './scripts/terraform-provider.sh', 'test:consumer': './scripts/consumer-test.sh', build: 'true', ...extra }, ...extra.top })
    writeFileSync(join(dir, 'package.json'), manifest())
    git('init', '-q')
    git('add', '.')
    git('commit', '-qm', 'base')
    const base = git('rev-parse', 'HEAD')
    change(dir, manifest)
    git('add', '.')
    git('commit', '-qm', 'change')
    const out = execFileSync('node', [join(dir, 'scripts/validate.mjs'), '--list', '--base', base], { cwd: dir, encoding: 'utf8' })
    return Object.fromEntries(out.trim().split('\n').map((line) => [line.slice(0, 10).trim(), line.slice(11)]))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('a change to the script a step runs selects the step', () => {
  const terraform = selected((dir) => writeFileSync(join(dir, 'scripts/terraform-provider.sh'), '# changed'))
  assert.match(terraform.terraform, /terraform-provider\.sh changed/)
  assert.match(terraform.consumer, /not run: diff does not touch it/)
  for (const file of ['consumer-test.sh', 'client-smoke.cjs']) {
    const steps = selected((dir) => writeFileSync(join(dir, 'scripts', file), '# changed'))
    assert.match(steps.consumer, new RegExp(`${file.replace('.', '\\.')} changed`))
    assert.match(steps.terraform, /not run: diff does not touch it/)
  }
})

test('a change to a root package.json entry selects the steps that name it, the rest of it every package step', () => {
  const entry = selected((dir, manifest) => writeFileSync(join(dir, 'package.json'), manifest({ 'test:terraform': './scripts/terraform-provider.sh --unit' })))
  assert.match(entry.terraform, /root script test:terraform changed/)
  assert.match(entry.consumer, /not run: diff does not touch it/)
  const build = selected((dir, manifest) => writeFileSync(join(dir, 'package.json'), manifest({ build: 'false' })))
  assert.match(build.consumer, /root script build changed/)
  assert.match(build.terraform, /root script build changed/)
  assert.match(build.schema, /not run: diff does not touch it/)
  const deps = selected((dir, manifest) => writeFileSync(join(dir, 'package.json'), manifest({ top: { dependencies: { a: '1.0.0' } } })))
  for (const name of ['terraform', 'consumer', 'schema', 'compat', 'matrices']) assert.match(deps[name], /package\.json changed/)
})

test('a helper the change deleted still selects the steps that call it', () => {
  const steps = selected((dir) => rmSync(join(dir, 'scripts/helper.sh')))
  assert.match(steps.terraform, /helper\.sh changed/)
  assert.match(steps.consumer, /not run: diff does not touch it/)
})

test('a rename selects the steps of the path it left', () => {
  const steps = selected((dir) => {
    mkdirSync(join(dir, 'docs'))
    execFileSync('git', ['mv', 'scripts/terraform-provider.sh', 'docs/terraform-provider.sh'], { cwd: dir })
  })
  assert.match(steps.terraform, /terraform-provider\.sh changed/)
})

test('a root script the change deleted still selects the steps that run it', () => {
  const steps = selected((dir) => {
    const { scripts, ...rest } = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
    delete scripts['test:terraform']
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ ...rest, scripts }))
  })
  assert.match(steps.terraform, /root script test:terraform changed/)
  assert.match(steps.consumer, /not run: diff does not touch it/)
})

test('packages and the compose file select the steps that boot a deployment on them', () => {
  for (const file of ['packages/core/src/a.ts', 'examples/node/vault.ts', 'packages/db/src/a.ts', 'docker-compose.yml']) {
    const steps = selected((dir) => {
      mkdirSync(join(dir, file, '..'), { recursive: true })
      writeFileSync(join(dir, file), '# changed')
    })
    for (const name of ['terraform', 'consumer', 'workers']) assert.match(steps[name], /changed/, `${name} for ${file}`)
  }
})

test('a code file no step claims runs every step but TLC', () => {
  const steps = selected((dir) => writeFileSync(join(dir, 'mystery.config'), '# changed'))
  assert.match(steps.tests, /mystery\.config changed/)
  for (const name of ['terraform', 'matrices', 'workers']) assert.match(steps[name], /no step claims it/)
  assert.match(steps.formal, /not run/)
  const docs = selected((dir) => writeFileSync(join(dir, 'NOTES.md'), '# changed'))
  assert.match(docs.tests, /not run: diff does not touch it/)
})

test('the CLI selects the schema step (its setup tests) and the client selects the matrices (they call it)', () => {
  const cli = selected((dir) => {
    mkdirSync(join(dir, 'packages/cli/src'), { recursive: true })
    writeFileSync(join(dir, 'packages/cli/src/setup.ts'), '// changed')
  })
  assert.match(cli.schema, /setup\.ts changed/)
  const client = selected((dir) => {
    mkdirSync(join(dir, 'packages/client/src'), { recursive: true })
    writeFileSync(join(dir, 'packages/client/src/index.ts'), '// changed')
  })
  assert.match(client.matrices, /index\.ts changed/)
})
