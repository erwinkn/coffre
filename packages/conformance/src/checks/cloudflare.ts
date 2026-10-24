// A Worker of the same account that binds the app's `CoffreWorkload`
// (docs/design/workload-access.md, section 9.2): its props are its proof,
// so a binding without props naming a service, or naming one no
// cloudflare binding trusts, must get nothing, through `fetch` or over RPC,
// and no binding reaches anything but the credential proxy's `/use`. The
// harness's own entry is that Worker (draining.ts).
import type { Deployment } from '../harness.ts';
import { expect, Skip } from '../report.ts';

type Called = { status?: number; body?: string; answer?: unknown; threw?: string };

async function call(deployment: Deployment, binding: string, asked: Record<string, string> = {}): Promise<Called> {
  const response = await fetch(`${deployment.origin}/__conformance/binding?${new URLSearchParams({ binding, ...asked })}`);
  expect(response.ok, `the harness could not call through ${binding}`, { status: response.status, body: await response.clone().text() });
  return (await response.json()) as Called;
}

const reason = (called: Called) => {
  try {
    return (JSON.parse(called.body ?? '{}') as { reason?: string }).reason;
  } catch {
    return undefined;
  }
};

export async function bindingsRefused(deployment: Deployment): Promise<string> {
  if (deployment.kind !== 'workers') throw new Skip('a service binding is a Workers deployment\'s');
  for (const binding of ['NO_PROPS', 'EXTRA']) {
    const fetched = await call(deployment, binding);
    expect(fetched.status === 401 && reason(fetched) === 'props', `a binding with props ${binding === 'EXTRA' ? 'of another field' : 'absent'} was not refused as such`, fetched);
    const signed = await call(deployment, binding, { op: 'sign' });
    expect(signed.answer === undefined && /without props naming its service/.test(signed.threw ?? ''), `${binding}'s sign was not refused`, signed);
  }
  const unbound = await call(deployment, 'UNBOUND');
  expect(unbound.status !== undefined && unbound.status >= 400, 'props naming a service no binding trusts got an answer', unbound);
  const unsigned = await call(deployment, 'UNBOUND', { op: 'sign' });
  expect(unsigned.answer === undefined && unsigned.threw !== undefined, 'props naming a service no binding trusts got a signature', unsigned);
  for (const path of ['/api/members', '/api/auth/session', '/', '/use/../api/members']) {
    const answered = await call(deployment, 'UNBOUND', { path });
    expect(answered.status === 404, `a binding reached ${path}`, answered);
  }
  return `no props and another field: 401 props; a service no binding trusts: ${unbound.status} ${reason(unbound) ?? ''}, sign refused; /api and the pages: 404`;
}
