// --import runs before a test file's imports read their connection settings.
// The runner itself and any subprocesses a test launches must keep their env.
import { copyFile } from 'node:fs/promises';
import { cloneDatabase } from './test-databases.mjs';

if (process.env.NODE_TEST_CONTEXT === 'child-v8') {
    if (process.env.COFFRE_TEST_ENGINE === 'sqlite') {
        const template = process.env.COFFRE_TEST_DATABASE_URL;
        const file = `${template}.${process.pid}`;
        await copyFile(new URL(template), new URL(file));
        process.env.COFFRE_TEST_DATABASE_URL = file;
    } else {
        const template = process.env.COFFRE_TEST_DATABASE;
        const name = `${template}_${process.pid}`;
        await cloneDatabase(template, name);
        process.env.COFFRE_TEST_DATABASE = name;
    }
}
