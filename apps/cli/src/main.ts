#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { verifyChain } from '../../../packages/core/src/audit';
import type { AuditEvent, Command, Environment, Project, RpcResult, Secret } from '../../../packages/contracts/src/index';
const help = `coffre <command>
  projects                             List accessible projects
  list <environment-id>                List secret metadata
  get <secret-id> [version]             Print one value (audited)
  set <secret-id> <expected-version>    Read exact new value from stdin
  history <secret-id>                   List version metadata
  restore <secret-id> <version> <expected-version>
  export <environment-id>               Export JSON (audited per value)
  run <environment-id> -- command ...   Inject configuration into a child
  audit                                Print the latest audit page
  verify                               Verify the complete visible audit chain

Configuration: COFFRE_URL and COFFRE_TOKEN or CF_ACCESS_JWT.
Protected writes additionally require COFFRE_CONFIRM_PROTECTED=1.
Never pass secret values as command-line arguments. TLS is mandatory except
with COFFRE_LOCAL=1 and an explicit loopback URL for local development.
`;
const args = process.argv.slice(2);
async function stdin() { const chunks: Buffer[] = []; let size = 0; for await (const chunk of process.stdin) { size += chunk.length; if (size > 65536) throw new Error('Value exceeds 64 KiB'); chunks.push(Buffer.from(chunk)); } return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); }
async function request<T>(command: Command): Promise<T> {
  const base = new URL(process.env.COFFRE_URL ?? '');
  if (base.username || base.password || base.search || base.hash || base.pathname !== '/' || (base.protocol !== 'https:' && !(process.env.COFFRE_LOCAL === '1' && base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)))) throw new Error('Set COFFRE_URL to a trusted HTTPS origin');
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Coffre-Request': '1' };
  if (process.env.COFFRE_TOKEN) headers.Authorization = `Bearer ${process.env.COFFRE_TOKEN}`;
  else if (process.env.CF_ACCESS_JWT) headers['Cf-Access-Jwt-Assertion'] = process.env.CF_ACCESS_JWT;
  else if (process.env.COFFRE_LOCAL !== '1') throw new Error('Configure COFFRE_TOKEN or CF_ACCESS_JWT');
  const response = await fetch(new URL('/api/v1/operations', base), { method: 'POST', headers, body: JSON.stringify({ requestId: crypto.randomUUID(), command }), redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (!response.headers.get('Content-Type')?.includes('application/json')) throw new Error('Expected an API response. Check authentication and the API hostname.');
  const result = await response.json() as RpcResult;
  if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`);
  return result.data as T;
}
const output = (value: unknown) => process.stdout.write(JSON.stringify(value, null, 2) + '\n');
async function main() {
  const [command, id, arg, next] = args;
  const confirmed = process.env.COFFRE_CONFIRM_PROTECTED === '1';
  switch (command) {
    case undefined: case 'help': case '--help': process.stdout.write(help); return;
    case 'projects': output(await request<{ projects: Project[]; environments: Environment[] }>({ type: 'workspace.get' })); return;
    case 'list': if (!id) break; output(await request<Secret[]>({ type: 'secret.list', envId: id })); return;
    case 'get': if (!id) break; process.stdout.write((await request<{ value: string }>({ type: 'secret.read', id, purpose: 'cli', ...(arg ? { version: Number(arg) } : {}) })).value); return;
    case 'set': if (!id || !arg) break; output(await request({ type: 'secret.write', id, expectedVersion: Number(arg), value: await stdin(), confirmed })); return;
    case 'history': if (!id) break; output(await request({ type: 'secret.history', id })); return;
    case 'restore': if (!id || !arg || !next) break; output(await request({ type: 'secret.restore', id, version: Number(arg), expectedVersion: Number(next), confirmed })); return;
    case 'export': if (!id) break; output(Object.fromEntries((await request<{ values: { key: string; value: string }[] }>({ type: 'environment.export', envId: id })).values.map(x => [x.key, x.value]))); return;
    case 'run': {
      if (!id || arg !== '--' || args.length < 4) break;
      const result = await request<{ values: { key: string; value: string }[] }>({ type: 'environment.export', envId: id });
      const env = { ...process.env };
      for (const key of ['COFFRE_TOKEN', 'CF_ACCESS_JWT', 'COFFRE_CONFIRM_PROTECTED']) delete env[key];
      for (const { key, value } of result.values) env[key] = value;
      const child = spawn(args[3]!, args.slice(4), { env, stdio: 'inherit', shell: false });
      for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => child.kill(signal));
      child.on('error', () => { process.stderr.write('Could not launch child process.\n'); process.exitCode = 1; });
      child.on('exit', (code, signal) => { process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1); }); return;
    }
    case 'audit': output(await request({ type: 'audit.list', limit: 100 })); return;
    case 'verify': {
      const events: AuditEvent[] = []; let before: number | undefined, head: { seq: number; hash: string } | null = null;
      do {
        const page: { events: AuditEvent[]; nextBefore: number | null; head: { seq: number; hash: string } | null } = await request({ type: 'audit.list', before, limit: 200 });
        if (!head) head = page.head;
        if (!head) throw new Error('Full-chain verification requires instance-wide audit permission');
        events.push(...page.events); before = page.nextBefore ?? undefined;
      } while (before !== undefined);
      const checkpoint = await verifyChain(events.filter(e => e.seq <= head!.seq).sort((a, b) => a.seq - b.seq));
      if (checkpoint.seq !== head.seq || checkpoint.hash !== head.hash) throw new Error('Audit head mismatch');
      output({ verified: true, ...checkpoint, note: 'Compare with an independently retained checkpoint to detect journal rewriting.' }); return;
    }
  }
  throw new Error('Invalid command or missing arguments. Run coffre help.');
}
main().catch(error => { process.stderr.write(`coffre: ${error instanceof Error ? error.message : 'Operation failed'}\n`); process.exitCode = 1; });
