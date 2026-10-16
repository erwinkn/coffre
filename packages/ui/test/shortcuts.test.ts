import test from 'node:test';
import assert from 'node:assert/strict';

import { inDialog } from '../src/lib/shortcuts.ts';

/** An element whose nearest ancestor matching a selector is `found`, as `Element.closest` answers. */
const element = (found: unknown) => ({ closest: (selector: string) => (selector.includes('dialog') ? found : null) });

test('a key pressed in a dialog is not the page\'s', () => {
  assert.equal(inDialog(element({ role: 'dialog' }) as unknown as EventTarget), true);
});

test('a key pressed on the page, or on no element, is', () => {
  assert.equal(inDialog(element(null) as unknown as EventTarget), false);
  assert.equal(inDialog({} as EventTarget), false);
  assert.equal(inDialog(null), false);
});
