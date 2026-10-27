import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// Exercise the expression the real final job runs, including rejected states.
const workflow = readFileSync(new URL('../.github/workflows/validate.yml', import.meta.url), 'utf8');
const expression = workflow.match(/Require full validation[\s\S]*?jq -e '([\s\S]*?)' <<</)[1];
const jobs = ['checks', 'tests', 'schema', 'formal', 'proofs', 'workers', 'node', 'consumer', 'compat', 'image'];
function needs(fast) {
    return {
        changes: { result: 'success', outputs: { version_only: String(fast) } },
        ...Object.fromEntries(jobs.map((name) => [name, { result: fast ? 'skipped' : 'success' }])),
    };
}
function accepted(input) {
    const result = spawnSync('jq', ['-e', expression], { input: JSON.stringify(input), encoding: 'utf8', timeout: 5000 });
    assert.ok([0, 1].includes(result.status), result.stderr); // A broken expression is not a passing rejection.
    assert.equal(result.error, undefined);
    return result.status === 0;
}

test('Validate accepts complete validation and only the explicitly proven fast path', () => {
    assert.equal(accepted(needs(false)), true);
    assert.equal(accepted(needs(true)), true);
});

test('each failed, cancelled or unexpected skipped job makes normal Validate fail', () => {
    for (const job of ['changes', ...jobs]) {
        for (const result of ['failure', 'cancelled', 'skipped']) {
            const input = needs(false);
            input[job].result = result;
            assert.equal(accepted(input), false, `${job}: ${result}`);
        }
    }
});

test('fast Validate refuses a failed classifier or any unexpectedly run heavy job', () => {
    for (const result of ['failure', 'cancelled', 'skipped']) {
        const input = needs(true);
        input.changes.result = result;
        assert.equal(accepted(input), false);
    }
    for (const job of jobs) {
        for (const result of ['success', 'failure', 'cancelled']) {
            const input = needs(true);
            input[job].result = result;
            assert.equal(accepted(input), false, `${job}: ${result}`);
        }
    }
});

test('missing or unknown detector output requires every normal job to pass', () => {
    for (const output of [undefined, 'unknown', 'false']) {
        const input = needs(false);
        input.changes.outputs.version_only = output;
        assert.equal(accepted(input), true);
        input.tests.result = 'skipped';
        assert.equal(accepted(input), false);
    }
});

// These job predicates use only the shared JS/GitHub boolean operators and
// string comparisons. Evaluate the actual eleven expressions with known states:
// the ten jobs Validate waits on, and the Formal model's plan beside them.
test('every heavy lane runs unless classification succeeds with a true output', () => {
    const predicates = [...workflow.matchAll(/    if: \$\{\{ (always\(\).*?) \}\}/g)].map((match) => match[1]);
    assert.equal(predicates.length, jobs.length + 1);
    for (const expression of predicates) {
        const run = new Function('needs', 'always', 'cancelled', `return (${expression});`);
        assert.equal(run(needs(true), () => true, () => false), false);
        assert.equal(run(needs(false), () => true, () => false), true);
        const failed = needs(true);
        failed.changes.result = 'failure';
        assert.equal(run(failed, () => true, () => false), true);
        assert.equal(run(needs(false), () => true, () => true), false);
    }
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

test('the shards partition formal.sh and the workflow runs each of them', () => {
    const list = (...args) => spawnSync('scripts/formal.sh', ['--list', ...args], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname });
    const all = list().stdout.trim().split('\n');
    assert.ok(all.length > 100);
    const matrix = workflow.match(/shard: \[([a-z, -]+)\]/)[1].split(', ');
    assert.deepEqual(matrix, ['tampering', 'large', 'rest', 'hotpath', 'hotpath-policy', 'hotpath-bulk', 'hotpath-skew', 'seal', 'seal-plugin']);
    const sharded = matrix.flatMap((shard) => list('--shard', shard).stdout.trim().split('\n'));
    assert.deepEqual([...sharded].sort(), [...all].sort());
    const tampering = list('--shard', 'tampering').stdout.trim().split('\n');
    assert.ok(tampering.every((line) => line.split(/\s+/)[1] === 'Tampering'));
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
