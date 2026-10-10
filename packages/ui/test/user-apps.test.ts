import test from 'node:test';
import assert from 'node:assert/strict';

import { hasAppsTab, shellOf, type MemberReport } from '../src/lib/queries.ts';

const member = {
  principal: { type: 'user', id: 'ada@acme.example' },
  registered: true,
  tampered: false,
  instanceRole: 'owner',
  isRootAdmin: false,
  canReadAudit: true,
  environments: [],
  features: { mcp: 'https://coffre.example/mcp', workloads: false },
};

const shell = (me: Partial<typeof member> = {}) =>
  shellOf({ mode: 'signin', signin: null, access: null } as never, { ...member, ...me } as never, { ok: true, projects: [] } as never);

const report = (status: string): MemberReport => ({ ok: true, report: { status, apps: [] } }) as never;

test('an active user has a Connected apps tab, and /apps is open to an owner', () => {
  assert.equal(hasAppsTab(shell(), report('active')), true);
});

test('a removed user has none, so /apps sends the loader to their offboarding', () => {
  assert.equal(hasAppsTab(shell(), report('removed')), false);
});

test('nobody is shown the tab for someone unknown, or without MCP, or unless an owner', () => {
  assert.equal(hasAppsTab(shell(), { ok: true, report: null } as never), false);
  assert.equal(hasAppsTab(shell({ features: { mcp: null as never, workloads: false } }), report('active')), false);
  assert.equal(hasAppsTab(shell({ instanceRole: 'member' }), null), false);
});
