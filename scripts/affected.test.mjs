// What `pnpm validate` selects for a diff (scripts/affected.mjs, scripts/graph.mjs), on
// a small repository of its own: each case changes a few files and reads the plan.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { nodeConformance, plan } from './affected.mjs'
import { uncommented } from './graph.mjs'

const json = (value) => JSON.stringify(value)
const source = (path) => ({ 'coffre:source': path })
const TREE = {
  'package.json': json({
    scripts: {
      'test:schema': './scripts/test-schema.sh',
      'conformance:workers': 'pnpm --filter coffre-workers conformance',
      'conformance:node': 'pnpm --filter coffre-node conformance',
      'test:terraform': './scripts/terraform-provider.sh',
      'check:pins': 'node scripts/check-pins.mjs',
      'sweep:growth': './scripts/growth-sweep.sh',
    },
  }),
  'pnpm-lock.yaml': '',
  'docker-compose.yml': '',
  'README.md': '',
  'docs/guide.md': '',
  'scripts/test-suite.sh': '# runs every file on a migrated template\n./scripts/setup-test-database.sh\nnode --import ./scripts/test-database-worker.mjs --test',
  // `coffre` here is no command: the CLI's bin is not the harness's.
  'scripts/setup-test-database.sh': 'node --conditions=coffre:source scripts/ensure-database.mjs coffre\npnpm --filter @coffre/db run db:migrate',
  'scripts/test-database-worker.mjs': "import { clone } from './test-databases.mjs'",
  'scripts/test-databases.mjs': '',
  'scripts/test-schema.sh': './scripts/setup-test-database.sh\npsql < packages/db/test/schema.sql',
  'scripts/check-pins.mjs': '',
  'scripts/growth-sweep.sh': './scripts/setup-test-database.sh\nnode --test packages/server/test/growth.sweep.ts',
  'scripts/terraform-provider.sh': 'node packages/conformance/scripts/terraform-fixture.ts',
  'scripts/x.mjs': '',
  'scripts/x.test.mjs': "import { x } from './x.mjs'",
  'scripts/lonely.mjs': '',
  'scripts/formal.sh': 'REMOVALS=(\n  # One, without P\n  "One P Inv"\n)\nEXPECTED=(\n)\njava -jar tlc.jar',
  'eslint.config.js': "export default [{ files: ['packages/*/src/**/*.ts'] }]",
  'formal/A.tla': '---- MODULE A ----\nEXTENDS Naturals, Sequences\n====',
  'formal/MCA.tla': '---- MODULE MCA ----\nEXTENDS A\n====',
  'formal/B.tla': '---- MODULE B ----\nEXTENDS Naturals\nI == INSTANCE A\n====',
  'formal/C.tla': '---- MODULE C ----\n\\* EXTENDS A, in a comment\n====',
  'formal/One.cfg': '\\* One\n\\* model MCA\nSPECIFICATION Spec',
  'formal/Two.cfg': '\\* Two\n\\* model B\nSPECIFICATION Spec',
  'formal/Three.cfg': '\\* Three\n\\* model C\nSPECIFICATION Spec',
  'packages/db/package.json': json({ name: '@coffre/db', exports: { '.': source('./src/index.ts') }, scripts: { 'db:migrate': 'node src/migrate-main.ts' } }),
  'packages/db/src/index.ts': 'export const db = 1',
  'packages/db/src/migrate-main.ts': "import { migrate } from './migrate.ts'",
  'packages/db/src/migrate.ts': 'export const dir = new URL(`./migrations/${engine}`, import.meta.url)',
  'packages/db/src/migrations/postgres/0001.sql': '',
  'packages/db/test/schema.sql': '',
  'packages/db/test/index.test.ts': "import { db } from '@coffre/db'",
  'packages/core/package.json': json({ name: '@coffre/core', exports: { './access': source('./src/access.ts') } }),
  'packages/core/src/access.ts': "// as packages/db/src/index.ts does\nexport const decide = (s) => s.replace(/'\\//g, '') // packages/db/src/index.ts",
  'packages/core/src/built.ts': "const parts = ['src', 'built-in.ts']",
  'packages/core/test/access.test.ts': "import { decide } from '@coffre/core/access'",
  'packages/server/package.json': json({ name: '@coffre/server', exports: { '.': source('./src/index.ts'), './node': source('./src/node.ts') } }),
  'packages/server/src/index.ts': "export * from './app.ts'",
  'packages/server/src/app.ts': "import { decide } from '@coffre/core/access'",
  'packages/server/test/growth.sweep.ts': "import '../src/api/routes.ts'\nimport './helpers.ts'",
  'packages/server/test/helpers.ts': '',
  'packages/server/src/node.ts': "import './app.ts'",
  'packages/server/src/api/secrets.ts': "import '../app.ts'",
  'packages/server/src/api/routes.ts': "import './secrets.ts'\nimport './missing.ts'",
  'packages/server/src/api/missing.ts': '',
  'packages/server/test/app.test.ts': "import '../src/app.ts'",
  'packages/server/test/fixture.test.ts': "const seed = new URL('./fixtures/seed.sql', import.meta.url)",
  'packages/server/test/fixtures/seed.sql': '',
  'packages/server/test/cost.alone.ts': "import '../src/app.ts'",
  // ESLint loads eslint.config.js from the root.
  'packages/server/test/eslint-boundary.test.ts': "import { ESLint } from 'eslint'\nnew ESLint({ cwd: '../../../' })",
  'packages/cli/package.json': json({ name: '@coffre/cli', bin: { coffre: './dist/main.js' } }),
  'packages/cli/src/main.ts': "import './init.ts'",
  'packages/cli/src/init.ts': 'export const templates = new URL(`../../../examples/${kind}/`, import.meta.url)',
  'packages/cli/test/init.test.ts': "import { templates } from '../src/init.ts'",
  // A test that greps every package's sources, as deploy-on-push's libsodium check does.
  'packages/cli/test/sources.test.ts': "const files = globSync('packages/*/src/**/*.{ts,tsx}')",
  'packages/conformance/package.json': json({ name: '@coffre/conformance', bin: { 'coffre-conformance': './bin/run.js' } }),
  // As the real bin: the build, which a fresh checkout lacks.
  'packages/conformance/bin/run.js': "const main = new URL('../dist/main.js', import.meta.url)\nawait import(main.href)",
  'packages/conformance/src/main.ts': "import './harness.ts'",
  'packages/conformance/src/harness.ts': '',
  'packages/conformance/scripts/terraform-fixture.ts': "import '../src/harness.ts'",
  'packages/vault/package.json': json({ name: '@coffre/vault' }),
  'packages/vault/src/use.ts': "import './decide.ts'",
  'packages/vault/src/decide.ts': '',
  'packages/vault/src/other.ts': '',
  'packages/vault/test/use.matrix.ts': "import './use-world.ts'\nimport '../src/use.ts'\nimport '@coffre/server'",
  'packages/vault/test/use-world.ts': '',
  'examples/workers/package.json': json({ name: 'coffre-workers', scripts: { conformance: 'coffre-conformance workers' } }),
  'examples/workers/app/routes.tsx': "import '@coffre/server'",
  'examples/workers/app/routes/index.tsx': '',
  'examples/node/package.json': json({ name: 'coffre-node', scripts: { conformance: 'coffre-conformance node' } }),
  'examples/node/app/server.ts': "import '@coffre/server/node'",
  'terraform-provider/main.go': '',
}

/** The steps a change to `changed` runs: name to `why`, and the test files and scenarios it picks. */
const run = (changed, { tree = TREE, base = TREE, full = false } = {}) => {
  const result = plan({ root: '/repo', files: Object.keys(tree), changed, read: (f) => tree[f], readBase: (f) => base[f], full })
  const steps = Object.fromEntries(result.steps.filter((s) => s.why).map((s) => [s.name, s]))
  return { steps, all: result.steps, everything: result.everything, names: Object.keys(steps).sort(), files: (name) => steps[name]?.files?.slice().sort() }
}

test('a docs-only diff runs the docs check and nothing else', () => {
  assert.deepEqual(run(['docs/guide.md', 'README.md']).names, ['docs'])
})

test('a source file runs the tests that import it, through the packages’ exports, and nothing they do not reach', () => {
  const { files, names } = run(['packages/core/src/access.ts'])
  // The comments that name packages/db/src/index.ts are no edge, and the regular expression no comment.
  assert.deepEqual(files('tests'), ['packages/cli/test/sources.test.ts', 'packages/core/test/access.test.ts', 'packages/server/test/app.test.ts'])
  assert.deepEqual(files('alone'), ['packages/server/test/cost.alone.ts'])
  for (const name of ['matrices', 'schema', 'formal', 'consumer', 'terraform']) assert.ok(!names.includes(name), name)
  assert.ok(names.includes('workers'), 'the workers deployment runs it')
})

test('a file a test names by path runs that test', () => {
  assert.deepEqual(run(['packages/server/test/fixtures/seed.sql']).files('tests'), ['packages/server/test/fixture.test.ts'])
})

test('a changed test file runs itself', () => {
  assert.deepEqual(run(['packages/db/test/index.test.ts']).files('tests'), ['packages/db/test/index.test.ts'])
})

test('a directory read as files is not run: init copies the examples, and does not run what they import', () => {
  assert.deepEqual(run(['examples/workers/app/routes.tsx']).files('tests'), ['packages/cli/test/init.test.ts'])
  assert.ok(!run(['packages/server/src/app.ts']).files('tests').includes('packages/cli/test/init.test.ts'))
})

test('a package file no test reaches runs its package’s tests; one a test only greps is not reached', () => {
  assert.deepEqual(run(['packages/core/src/built.ts']).files('tests'), ['packages/cli/test/sources.test.ts', 'packages/core/test/access.test.ts'])
})

test('a bin that runs its package’s build runs its sources: conformance’s, the CLI’s', () => {
  // coffre-conformance imports ../dist/main.js, built from src/main.ts.
  for (const file of ['packages/conformance/src/main.ts', 'packages/conformance/src/harness.ts']) assert.ok(run([file]).names.includes('workers'), file)
  // The CLI's bin is dist/main.js; `coffre:source` and an argument named coffre are no command, so the harness
  // does not run it: its package's tests (no test runs main.ts), not every test file.
  assert.deepEqual(run(['packages/cli/src/main.ts']).files('tests'), ['packages/cli/test/init.test.ts', 'packages/cli/test/sources.test.ts'])
  // Conformance runs the deployment's CLI by its manifest's bin.
  assert.ok(run(['packages/cli/src/main.ts']).names.includes('workers'))
  // And init, though Workers' run reaches it, still runs the packed consumer: its output is what that diffs.
  assert.ok(run(['packages/cli/src/init.ts']).names.includes('consumer'))
})

test('a tool’s configuration runs the tests that load it from the root: eslint.config.js', () => {
  const { steps } = run(['eslint.config.js'])
  assert.deepEqual(steps.tests.files, ['packages/server/test/eslint-boundary.test.ts'])
  assert.equal(steps.lint.files, null, 'every file')
})

test('a deletion runs what reads or runs the files beside it, or above it when none is left', () => {
  const without = (...gone) => Object.fromEntries(Object.entries(TREE).filter(([f]) => !gone.includes(f)))
  const example = run(['examples/workers/app/routes/index.tsx'], { tree: without('examples/workers/app/routes/index.tsx') }).names
  assert.ok(example.includes('workers') && example.includes('consumer'), 'init copies the examples')
  const emptied = run(['examples/workers/app/routes.tsx', 'examples/workers/app/routes/index.tsx'], { tree: without('examples/workers/app/routes.tsx', 'examples/workers/app/routes/index.tsx') }).names
  assert.ok(emptied.includes('consumer'), 'app/ is gone: examples/workers/ holds its package.json')
  // A module the diff deleted and a scenario still extends.
  assert.deepEqual(run(['formal/A.tla'], { tree: without('formal/A.tla') }).steps.formal.scenarios, ['One', 'Two'])
  // Beside it, not below: the proofs in formal/lean/ are no neighbour of a model.
  assert.ok(!run(['formal/A.tla'], { tree: { ...without('formal/A.tla'), 'formal/lean/Proof.lean': '' } }).names.includes('proofs'))
})

test('the harness and what it runs, the migrations among them, run every test file', () => {
  for (const file of ['packages/db/src/migrations/postgres/0001.sql', 'scripts/test-databases.mjs', 'docker-compose.yml']) {
    const { steps } = run([file])
    assert.equal(steps.tests.files.length, 8, file)
    assert.equal(steps.alone.files.length, 1, file)
  }
  const migration = run(['packages/db/src/migrations/postgres/0001.sql']).names
  assert.ok(migration.includes('schema'))
  assert.ok(!migration.includes('matrices'), 'the matrices run on their own inputs')
})

test('a script file no rule claims runs every step but TLC, the growth sweep and what is off', () => {
  const { steps, names } = run(['scripts/lonely.mjs'])
  assert.match(steps.tests.why, /scripts\/lonely\.mjs changed and no rule claims it/)
  assert.equal(steps.tests.files.length, 8)
  for (const name of ['matrices', 'schema', 'workers', 'terraform', 'consumer']) assert.ok(names.includes(name), name)
  assert.ok(!names.includes('formal') && !names.includes('sweep'))
  assert.equal(names.includes('node'), nodeConformance)
  // One its test reaches is claimed.
  assert.deepEqual(run(['scripts/x.mjs']).names, ['docs', 'tests'])
})

test('the dependencies run every step but the matrices and TLC', () => {
  const { names } = run(['pnpm-lock.yaml'])
  for (const name of ['tests', 'alone', 'schema', 'workers', 'consumer', 'terraform']) assert.ok(names.includes(name), name)
  assert.ok(!names.includes('matrices') && !names.includes('formal'))
  assert.equal(names.includes('node'), nodeConformance)
})

test('a pnpm script’s command runs the steps that call it', () => {
  const { names } = run(['package.json#test:schema'])
  assert.ok(names.includes('schema'))
  assert.ok(!names.includes('tests'))
  // db:migrate runs under the harness: every test file.
  assert.equal(run(['packages/db/package.json#db:migrate']).files('tests').length, 8)
})

test('TLC runs the scenarios whose module, or a module it extends or instantiates, changed', () => {
  assert.deepEqual(run(['formal/A.tla']).steps.formal.scenarios, ['One', 'Two'])
  assert.deepEqual(run(['formal/MCA.tla']).steps.formal.scenarios, ['One'])
  assert.deepEqual(run(['formal/Three.cfg']).steps.formal.scenarios, ['Three'])
  assert.deepEqual(run(['formal/C.tla']).steps.formal.scenarios, ['Three'])
  assert.deepEqual(run(['formal/A.tla']).names, ['docs', 'formal'])
})

test('formal.sh runs the scenarios whose runs without a protection changed, and every one for anything else', () => {
  const added = { ...TREE, 'scripts/formal.sh': TREE['scripts/formal.sh'].replace('"One P Inv"', '"One P Inv"\n  # Two, without Q\n  "Two Q Inv"') }
  assert.deepEqual(run(['scripts/formal.sh'], { tree: added }).steps.formal.scenarios, ['Two'])
  const commented = { ...TREE, 'scripts/formal.sh': `# a note\n${TREE['scripts/formal.sh']}` }
  assert.equal(run(['scripts/formal.sh'], { tree: commented }).steps.formal, undefined)
  const other = { ...TREE, 'scripts/formal.sh': TREE['scripts/formal.sh'].replace('java -jar', 'java -Xmx4g -jar') }
  assert.deepEqual(run(['scripts/formal.sh'], { tree: other }).steps.formal.scenarios, ['One', 'Three', 'Two'])
})

test('Node conformance runs on what only the Node deployment runs, while it is on; Workers’ on what it runs', () => {
  const { names: node, everything } = run(['packages/server/src/node.ts'])
  assert.equal(node.includes('node'), nodeConformance)
  assert.ok(!node.includes('workers') && !everything, 'claimed, so a Node file never runs everything')
  // Off, not even --full runs it, and the summary says why.
  const full = run([], { full: true })
  assert.equal(full.names.includes('node'), nodeConformance)
  if (!nodeConformance) assert.match(full.all.find((s) => s.name === 'node').off, /T270/)
  const shared = run(['packages/server/src/app.ts']).names
  assert.ok(shared.includes('workers') && !shared.includes('node'))
  const harness = run(['packages/conformance/src/harness.ts']).names
  assert.ok(harness.includes('workers') && !harness.includes('node') && !harness.includes('terraform'))
})

test('the slow tier runs on its own inputs: the matrices and Terraform', () => {
  for (const file of ['packages/vault/src/decide.ts', 'packages/vault/test/use-world.ts', 'packages/vault/test/use.matrix.ts']) assert.ok(run([file]).names.includes('matrices'), file)
  assert.ok(!run(['packages/vault/src/other.ts']).names.includes('matrices'))
  for (const file of ['terraform-provider/main.go', 'packages/server/src/api/secrets.ts', 'packages/server/src/api/routes.ts', 'packages/server/src/api/missing.ts', 'packages/conformance/scripts/terraform-fixture.ts']) {
    assert.ok(run([file]).names.includes('terraform'), file)
  }
  assert.ok(!run(['packages/server/src/app.ts']).names.includes('terraform'))
})

test('the growth sweep runs on the migrations and on the source it runs', () => {
  // missing.ts imports no query builder: a file that passes a table and a filter to a helper changes a plan too.
  for (const file of ['packages/db/src/migrations/postgres/0001.sql', 'packages/server/src/api/missing.ts']) assert.equal(run([file]).steps.sweep?.why, `${file} changed`, file)
  // Its own test and helpers, source it does not run, SQL it does not run, docs and the dependencies.
  for (const file of ['packages/server/test/growth.sweep.ts', 'packages/server/test/helpers.ts', 'packages/vault/src/other.ts', 'packages/server/test/fixtures/seed.sql', 'docs/guide.md', 'pnpm-lock.yaml']) {
    assert.ok(!run([file]).names.includes('sweep'), file)
  }
})

test('a diff leaves out the cases named [full], which --full runs', () => {
  for (const changed of [['packages/server/src/app.ts'], ['scripts/test-databases.mjs'], ['pnpm-lock.yaml']]) {
    const { steps } = run(changed)
    assert.deepEqual([steps.tests.skipFull, steps.alone.skipFull], [true, true], changed[0])
  }
  const { steps } = run([], { full: true })
  assert.deepEqual([steps.tests.skipFull, steps.alone.skipFull], [false, false])
})

test('--full runs every step that is on, every file and every scenario', () => {
  const { steps, all } = run([], { full: true })
  assert.equal(all.length, 17)
  assert.equal(Object.keys(steps).length, nodeConformance ? 17 : 16)
  assert.equal(steps.tests.files.length, 8)
  assert.deepEqual(steps.formal.scenarios, ['One', 'Three', 'Two'])
  assert.equal(steps.sweep.why, '--full')
})

test('comments go, strings and regular expressions stay', () => {
  const text = "const a = 'http://x' // b\nconst r = /\\/*x/ /* c */\nconst t = `${'//'}`"
  assert.equal(uncommented('a.ts', text), "const a = 'http://x' \nconst r = /\\/*x/  \nconst t = `${'//'}`")
  assert.equal(uncommented('a.sh', '# note\n  # more\nrun ./x.sh # trailing stays'), '\n\nrun ./x.sh # trailing stays')
})
