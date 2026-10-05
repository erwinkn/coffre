import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// Exercise the expression the real final job runs, including rejected states.
const workflow = readFileSync(new URL('../.github/workflows/validate.yml', import.meta.url), 'utf8');
const expression = workflow.match(/jq -e '([\s\S]*?)' <<</)[1];
const jobs = ['checks', 'tests', 'schema', 'formal', 'workers', 'node', 'consumer'];
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
// string comparisons. Evaluate the actual eight expressions with known states.
test('every heavy lane runs unless classification succeeds with a true output', () => {
    const predicates = [...workflow.matchAll(/    if: \$\{\{ (.*?) \}\}/g)].map((match) => match[1]);
    assert.equal(predicates.length, jobs.length);
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
