import test from 'node:test';
import assert from 'node:assert/strict';

import { Eye } from 'lucide';

import { glyphMarkup } from '../src/components/glyph.ts';

test('a glyph is its strokes as markup, in a group that carries the stroke', () => {
  assert.equal(
    glyphMarkup(Eye, 1.75),
    '<g fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/>' +
      '<circle cx="12" cy="12" r="3"/></g>',
  );
});

test("a glyph's attribute values are escaped, whatever they hold", () => {
  assert.equal(
    glyphMarkup([['path', { d: 'a"b<c&d' }]], 2),
    '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="a&quot;b&lt;c&amp;d"/></g>',
  );
});
