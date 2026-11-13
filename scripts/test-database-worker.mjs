// --import runs before a test file's imports read their connection settings.
// The runner itself and any subprocesses a test launches must keep their env.
import { cloneDatabase } from './test-databases.mjs';

if (process.env.NODE_TEST_CONTEXT === 'child-v8') {
    const template = process.env.COFFRE_TEST_DATABASE;
    const name = `${template}_${process.pid}`;
    await cloneDatabase(template, name);
    process.env.COFFRE_TEST_DATABASE = name;
}
