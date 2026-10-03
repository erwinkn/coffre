// Health: up, and ready only once the scheduled job has beaten and the
// vault has checkpointed it. What else anyone on the network sees, its
// headers among it, `coffre verify instance` checks, here as anywhere.
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';

export async function health(deployment: Deployment): Promise<string> {
  const { origin } = deployment;
  const live = await fetch(`${origin}/livez`);
  expect(live.ok, `/livez answered ${live.status}`);
  // Readiness follows the audit heartbeat and the vault's checkpoint of it,
  // which only the scheduled job writes: not ready until it has run.
  if (deployment.beforeFirstBeat) {
    const early = await fetch(`${origin}/readyz`);
    expect(early.status === 503, `/readyz answered ${early.status} before any heartbeat`, await early.text());
    await deployment.scheduled();
  }
  await until('/readyz', async () => (await fetch(`${origin}/readyz`)).ok, 20);
  const ready = (await (await fetch(`${origin}/readyz`)).json()) as { checkpointed?: unknown };
  expect(ready.checkpointed === true, '/readyz passed without a checkpoint covering the heartbeat', ready);
  return deployment.beforeFirstBeat ? '/livez, and /readyz only once the heartbeat ran and was checkpointed' : '/livez and /readyz';
}
