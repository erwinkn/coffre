// --import, beside test-database-worker.mjs: a test file's process ends with its tests. The root after()
// runs once every test registered so far has ended, before the file's own root after hooks. A process still
// running two minutes later holds something nothing closed (a server, a child, a socket): it exits 1, naming
// its file and what still runs, and the run goes on without it. Every file's teardown takes seconds, so two
// minutes fails only a stuck file, and fails it before it holds up the run.
import { after } from 'node:test';

if (process.env.NODE_TEST_CONTEXT === 'child-v8') {
    after(() => {
        setTimeout(() => {
            console.error(`${process.argv[1]} still runs 2 minutes after its tests: ${process.getActiveResourcesInfo().join(', ')}`);
            process.exit(1);
        }, 120_000).unref();
    });
}
