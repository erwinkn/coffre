import assert from 'node:assert/strict';
import test from 'node:test';

import { imageTags } from './image-tags.mjs';

const published = ['0.13.0', '0.13.1', '0.14.0', '0.14.4', '0.14.5', '0.15.0-rc.1', '0.9.2'];

test('the newest release takes its line and latest', () => {
    assert.deepEqual(imageTags('0.14.5', published), ['0.14.5', '0.14', 'latest']);
    // 0.9.2 is older than 0.14.5, though it sorts after it as text.
    assert.deepEqual(imageTags('0.9.2', published), ['0.9.2', '0.9']);
});

test('an image published late, for an older release, moves neither its line nor latest back', () => {
    assert.deepEqual(imageTags('0.14.4', published), ['0.14.4']);
    assert.deepEqual(imageTags('0.13.1', published), ['0.13.1', '0.13']);
    assert.deepEqual(imageTags('0.13.0', published), ['0.13.0']);
    assert.deepEqual(imageTags('1.0.0', [...published, '1.0.0', '1.0.1']), ['1.0.0']);
    assert.deepEqual(imageTags('0.14.5', [...published, '1.0.0']), ['0.14.5', '0.14']);
});

test('a pre-release is its version alone, and never holds a release back', () => {
    assert.deepEqual(imageTags('0.15.0-rc.1', published), ['0.15.0-rc.1']);
    assert.deepEqual(imageTags('0.15.0', [...published, '0.15.0', '0.15.1-rc.1']), ['0.15.0', '0.15', 'latest']);
});

test('a version npm does not have, or no version, is refused', () => {
    assert.throws(() => imageTags('0.14.6', published), /not on npm/);
    assert.throws(() => imageTags('latest', ['latest']), /no version/);
});
