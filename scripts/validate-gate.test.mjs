import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// Exercise the expression the real final job runs, including rejected states.
const workflow = readFileSync(new URL('../.github/workflows/validate.yml', import.meta.url), 'utf8');
const expression = workflow.match(/Require every job[\s\S]*?jq -e '([\s\S]*?)' <<</)[1];
const jobs = ['action', 'pins', 'checks', 'tests', 'tests-014', 'matrices', 'schema', 'formal', 'proofs', 'workers', 'node', 'terraform', 'consumer', 'compat', 'image'];
function needs() {
    return Object.fromEntries(jobs.map((name) => [name, { result: 'success' }]));
}
function accepted(input) {
    const result = spawnSync('jq', ['-e', expression], { input: JSON.stringify(input), encoding: 'utf8', timeout: 5000 });
    assert.ok([0, 1].includes(result.status), result.stderr); // A broken expression is not a passing rejection.
    assert.equal(result.error, undefined);
    return result.status === 0;
}

test('Validate accepts complete validation', () => {
    assert.equal(accepted(needs()), true);
});

test('each failed, cancelled or skipped job makes Validate fail', () => {
    for (const job of jobs) {
        for (const result of ['failure', 'cancelled', 'skipped']) {
            const input = needs();
            input[job].result = result;
            assert.equal(accepted(input), false, `${job}: ${result}`);
        }
    }
});

test('Validate waits for exactly the jobs this list names, each of them', () => {
    const waits = workflow.match(/\n  validate:\n[\s\S]*?needs: \[([a-z0-9, -]+)\]/)[1].split(', ');
    assert.deepEqual([...waits].sort(), [...jobs].sort());
    // Every job of the workflow is waited on, or is a step of one: the Formal model's plan and shards.
    const defined = [...workflow.matchAll(/\n  ([a-z0-9-]+):\n    (?:name|needs|if):/g)].map((match) => match[1]);
    const inside = new Set(['validate', 'matrices-shard', 'formal-plan', 'formal-shard']);
    assert.deepEqual(defined.filter((job) => !waits.includes(job) && !inside.has(job)), []);
});

// A job that judges the results of the ones before it runs even when they failed, or the failure would skip it
// and not be seen. These are the Formal model and the use matrices.
test('the jobs that judge shards run when a shard failed', () => {
    for (const job of ['matrices', 'formal']) {
        const block = workflow.match(new RegExp(`\\n  ${job}:\\n[\\s\\S]*?\\n    runs-on:`))[0];
        assert.match(block, /\n    if: \$\{\{ !cancelled\(\) \}\}\n/, job);
    }
});

// Validate is run by hand and nightly, never by a pull request (R46).
test('no pull request runs Validate', () => {
    const triggers = workflow.match(/\non:\n([\s\S]*?)\npermissions:/)[1];
    assert.match(triggers, /^ {2}workflow_dispatch:/m);
    assert.match(triggers, /^ {2}schedule:/m);
    assert.doesNotMatch(triggers, /pull_request|push:/);
});

// `Formal model` answers for its plan and shards: the shards ran and held, or
// the plan found a green run of the same inputs and they were skipped.
const formalGate = workflow.match(/Require every shard[\s\S]*?jq -e '([\s\S]*?)' <<</)[1];
function formalAccepted(plan, shard) {
    const input = { 'formal-plan': plan, 'formal-shard': { result: shard } };
    const result = spawnSync('jq', ['-e', formalGate], { input: JSON.stringify(input), encoding: 'utf8', timeout: 5000 });
    assert.ok([0, 1].includes(result.status), result.stderr);
    return result.status === 0;
}

test('Formal model passes on held shards or a hit, and on nothing else', () => {
    const planned = (hit) => ({ result: 'success', outputs: { hit } });
    assert.equal(formalAccepted(planned('false'), 'success'), true);
    assert.equal(formalAccepted(planned('true'), 'skipped'), true);
    for (const result of ['failure', 'cancelled', 'skipped']) {
        assert.equal(formalAccepted(planned('false'), result), false, `shards ${result}`);
    }
    for (const result of ['success', 'failure', 'cancelled']) {
        assert.equal(formalAccepted(planned('true'), result), false, `hit, shards ${result}`);
    }
    // A plan with no answer is no hit: the shards must have held.
    assert.equal(formalAccepted({ result: 'success', outputs: {} }, 'skipped'), false);
    assert.equal(formalAccepted({ result: 'success', outputs: {} }, 'success'), true);
    for (const result of ['failure', 'cancelled', 'skipped']) {
        assert.equal(formalAccepted({ result, outputs: { hit: 'true' } }, 'skipped'), false, `plan ${result}`);
        assert.equal(formalAccepted({ result, outputs: { hit: 'false' } }, 'success'), false, `plan ${result}`);
    }
});

// That the shards partition formal.sh, and that the workflow's matrix runs each of them, is formal-shards.test.mjs's.
test('Tampering has a shard of its own, and only Tampering is in it', () => {
    const matrix = workflow.match(/shard: \[([a-z, -]+)\]/)[1].split(', ');
    assert.ok(matrix.includes('tampering'));
    const tampering = spawnSync('scripts/formal.sh', ['--list', '--shard', 'tampering'], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname }).stdout.trim().split('\n');
    assert.ok(tampering.length > 0 && tampering.every((line) => line.split(/\s+/)[1] === 'Tampering'));
});

// `Use matrices` answers for its shards: every one ran and held. That each case ran in exactly one is
// `scripts/matrix-coverage.mjs`'s, the job's last step (matrix-coverage.test.mjs).
const matricesGate = workflow.match(/Require every matrix shard\n[\s\S]*?jq -e '([\s\S]*?)' <<</)[1];
test('Use matrices passes on held shards, and on nothing else', () => {
    for (const result of ['success', 'failure', 'cancelled', 'skipped']) {
        const run = spawnSync('jq', ['-e', matricesGate], { input: JSON.stringify({ 'matrices-shard': { result } }), encoding: 'utf8', timeout: 5000 });
        assert.ok([0, 1].includes(run.status), run.stderr);
        assert.equal(run.status === 0, result === 'success', result);
    }
});

test('the use matrices run in shards 1 to n, which Use matrices checks', () => {
    const shards = [...workflow.matchAll(/- \{ shard: (\d+)\/(\d+) \}/g)].map((m) => ({ shard: Number(m[1]), of: Number(m[2]) }));
    assert.ok(shards.length > 0);
    assert.deepEqual(shards.map((s) => s.shard), Array.from({ length: shards.length }, (_, i) => i + 1));
    assert.ok(shards.every((s) => s.of === shards.length));
    assert.ok(workflow.includes('run: node scripts/matrix-coverage.mjs "$RUNNER_TEMP/matrix-shards"\n'));
});

test('the plan job and every formal shard run the same exact, pinned Java', () => {
    // The key hashes the JVM, and a rolling ubuntu-24.04 image gives two jobs of one run other builds.
    const body = (job) => workflow.match(new RegExp(`\\n  ${job}:\\n[\\s\\S]*?(?=\\n  [a-z0-9-]+:\\n)`))[0];
    const pins = (job) =>
        [...body(job).matchAll(/uses: actions\/setup-java@([0-9a-f]{40}) # .*\n\s+with:\n((?:\s+[a-z-]+: .*\n)+)/g)].map((m) => `${m[1]} ${m[2].replace(/\s+/g, ' ').trim()}`);
    const plan = pins('formal-plan');
    const shard = pins('formal-shard');
    assert.equal(plan.length, 1);
    assert.deepEqual(shard, plan);
    assert.match(plan[0], /^[0-9a-f]{40} distribution: temurin java-version: \d+\.\d+\.\d+\+\d+$/);
    // The JVM is pinned before the first step that takes the key.
    for (const job of ['formal-plan', 'formal-shard']) {
        const text = body(job);
        assert.ok(text.indexOf('actions/setup-java@') < text.indexOf('scripts/formal-key.sh'), job);
    }
});

test('formal-key.sh is deterministic, keyed on the models and names the Java', () => {
    const cwd = new URL('..', import.meta.url).pathname;
    const key = () => spawnSync('scripts/formal-key.sh', { encoding: 'utf8', cwd });
    const first = key();
    assert.equal(first.status, 0, first.stderr);
    assert.equal(key().stdout, first.stdout);
    assert.match(first.stdout, /\nformal-[0-9a-f]{64}\n$/);
    for (const line of ['formal/Coffre.tla', 'formal/Tampering.cfg', 'scripts/formal.sh', '.github/workflows/validate.yml', 'java.version = ', 'java.vendor = ', 'os.arch = ']) {
        assert.ok(first.stdout.includes(line), line);
    }
});
