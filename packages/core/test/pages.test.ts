import test from 'node:test';
import assert from 'node:assert/strict';

import { preferencesIn } from '../src/pages.ts';

test("the visitor's preferences are read from a Cookie header as from document.cookie, and nothing else is taken", () => {
  assert.deepEqual(preferencesIn(null), { theme: 'system', sidebar: 'expanded' });
  assert.deepEqual(preferencesIn('coffre_session=abc; coffre-theme=dark; coffre-sidebar=collapsed'), { theme: 'dark', sidebar: 'collapsed' });
  assert.deepEqual(preferencesIn('coffre-theme=light'), { theme: 'light', sidebar: 'expanded' });
  assert.deepEqual(preferencesIn('coffre-theme="dark"; coffre-sidebar=open; xcoffre-theme=dark'), { theme: 'system', sidebar: 'expanded' });
  assert.deepEqual(preferencesIn('coffre-theme=<script>'), { theme: 'system', sidebar: 'expanded' });
});
