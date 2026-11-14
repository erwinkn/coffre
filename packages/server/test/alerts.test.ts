// An unknown key's alert, capped in its service's gate (`unknownKeyAlert`),
// against a gate that fails and one that admits: no database here.
import assert from 'node:assert/strict';
import { mock, test } from 'node:test';

import type { WorkloadAlert, WorkloadsConfig } from '@coffre/core/identity';

import { unknownKeyAlert } from '../src/alerts.ts';
import type { Gates } from '../src/gate.ts';

const SERVICE = 'token:deploy';
const refusal = { service: SERVICE, binding: { id: 'binding-1', profile: 'github' }, issuer: 'https://token.actions.githubusercontent.com', kid: 'rotated' };
const HOUR = 60 * 60 * 1000;

/** A deployment's workloads that alert into `alerts`: a configuration of its own each, as an isolate's. */
function alerting(alerts: WorkloadAlert[]): WorkloadsConfig {
  return { alert: (alert: WorkloadAlert) => void alerts.push(alert) } as unknown as WorkloadsConfig;
}

test("a gate that fails a burst of refusals at once: the isolate's own cap says the alert once", async (t) => {
  t.mock.method(console, 'error', () => {});
  const alerts: WorkloadAlert[] = [];
  const failing: Gates = () => ({ admit: async () => Promise.reject(new Error('the gate is down')) }) as unknown as ReturnType<Gates>;
  const workloads = alerting(alerts);
  await Promise.all(Array.from({ length: 5 }, () => unknownKeyAlert(workloads, failing, refusal, null, () => {})));
  assert.equal(alerts.length, 1);
});

test("a gate that admits the hour's alert: the isolate keeps quiet until the clock's hour ends, not an hour from it", async () => {
  mock.timers.enable({ apis: ['Date'], now: 10 * HOUR + 59 * 60_000 });
  try {
    const alerts: WorkloadAlert[] = [];
    const admitting: Gates = () => ({ admit: async () => ({ ok: true, nonce: 'n' }) }) as unknown as ReturnType<Gates>;
    const workloads = alerting(alerts);
    await unknownKeyAlert(workloads, admitting, refusal, null, () => {});
    mock.timers.tick(30_000);
    await unknownKeyAlert(workloads, admitting, refusal, null, () => {});
    assert.equal(alerts.length, 1, 'quiet within the hour');
    mock.timers.tick(31_000);
    await unknownKeyAlert(workloads, admitting, refusal, null, () => {});
    assert.equal(alerts.length, 2, "the next hour's gate decides again");
  } finally {
    mock.timers.reset();
  }
});

test("with no gate, or one that fails, the isolate caps each service on its own for an hour from its alert", async (t) => {
  t.mock.method(console, 'error', () => {});
  mock.timers.enable({ apis: ['Date'] });
  try {
    const failing: Gates = () => ({ admit: async () => Promise.reject(new Error('the gate is down')) }) as unknown as ReturnType<Gates>;
    for (const gates of [null, failing]) {
      mock.timers.setTime(10 * HOUR + 30 * 60_000);
      const alerts: WorkloadAlert[] = [];
      const workloads = alerting(alerts);
      const raise = (service: string, kid: string) => unknownKeyAlert(workloads, gates, { ...refusal, service, kid }, null, () => {});
      await raise(SERVICE, 'a');
      // Another key of the same service within the hour: quiet, whatever the key.
      await raise(SERVICE, 'b');
      // Another service is capped on its own.
      await raise('token:worker', 'c');
      assert.deepEqual(alerts.map((alert) => alert.service), [SERVICE, 'token:worker']);
      // Past the clock's hour, short of an hour from the alert: still quiet. An hour on, said again.
      mock.timers.tick(59 * 60_000);
      await raise(SERVICE, 'd');
      assert.equal(alerts.length, 2);
      mock.timers.tick(60_001);
      await raise(SERVICE, 'e');
      assert.deepEqual(alerts.map((alert) => alert.service), [SERVICE, 'token:worker', SERVICE]);
      assert.match(alerts[2]!.text, /names key "e"/);
    }
  } finally {
    mock.timers.reset();
  }
});
