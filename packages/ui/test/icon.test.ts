import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { markSvg } from '../src/components/mark.ts';

test('the favicon the package ships is the mark, as markSvg draws it', () => {
  assert.equal(readFileSync(new URL('../src/assets/icon.svg', import.meta.url), 'utf8'), `${markSvg(16, { adaptive: true })}\n`);
});
