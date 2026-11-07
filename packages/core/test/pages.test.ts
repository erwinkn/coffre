import test from 'node:test';
import assert from 'node:assert/strict';

import { preferencesIn } from '../src/pages.ts';

test("the visitor's preferences are read from a Cookie header as from document.cookie, and nothing else is taken", () => {
  assert.deepEqual(preferencesIn(null), { theme: 'system', sidebar: 'expanded', passkeyPrompt: 'shown' });
  assert.deepEqual(preferencesIn('coffre_session=abc; coffre-theme=dark; coffre-sidebar=collapsed'), { theme: 'dark', sidebar: 'collapsed', passkeyPrompt: 'shown' });
  assert.deepEqual(preferencesIn('coffre-theme=light'), { theme: 'light', sidebar: 'expanded', passkeyPrompt: 'shown' });
  assert.deepEqual(preferencesIn('coffre-theme="dark"; coffre-sidebar=open; xcoffre-theme=dark'), { theme: 'system', sidebar: 'expanded', passkeyPrompt: 'shown' });
  assert.deepEqual(preferencesIn('coffre-theme=<script>'), { theme: 'system', sidebar: 'expanded', passkeyPrompt: 'shown' });
  // Not now, on the prompt to add a passkey: the cookie's presence alone, for as long as it lasts (30 days).
  assert.deepEqual(preferencesIn('coffre-passkey-later=1'), { theme: 'system', sidebar: 'expanded', passkeyPrompt: 'later' });
  assert.deepEqual(preferencesIn('coffre-passkey-later=yes'), { theme: 'system', sidebar: 'expanded', passkeyPrompt: 'shown' });
});
