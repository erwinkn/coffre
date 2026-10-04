// The request's page context, in Start's own handler: a page rendered without coffre's
// middleware fails, saying how to add it, as its server routes do. Start's
// entries, which its Vite plugin provides in a build, are the fixtures in
// fixtures/start/.
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';

const entries: Record<string, string> = {
  '#tanstack-router-entry': './fixtures/start/router.ts',
  '#tanstack-start-entry': './fixtures/start/start.ts',
};
registerHooks({
  resolve: (specifier, context, next) =>
    specifier in entries ? { url: new URL(entries[specifier]!, import.meta.url).href, shortCircuit: true } : next(specifier, context),
});
process.env.TSS_DEV_SERVER = 'true';
const { createStartHandler, defaultStreamHandler } = await import('@tanstack/react-start/server');

test("a page rendered without coffre's middleware fails, naming src/start.ts", async (t) => {
  const logged: string[] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => void logged.push(args.map(String).join(' ')));
  const handler = createStartHandler(defaultStreamHandler);
  // As the server entry hands it: coffre's request, which only the middleware turns into a page's client.
  const response = await handler(new Request('https://coffre.test/page'), { context: { coffre: {} } } as never);
  assert.equal(response.status, 500);
  assert.match(logged.join('\n'), /coffre's request middleware is not installed: add coffreMiddleware, from @coffre\/server\/start, to createStart\(\(\) => \(\{ requestMiddleware: \[coffreMiddleware\] \}\)\) in the app's src\/start\.ts/);
});
