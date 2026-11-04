// How coffre-conformance ends: its message, then the exit, once both streams
// have written everything. To a pipe, Node writes stdout and stderr
// asynchronously, and `process.exit` drops what is still queued: a failed
// run's report, printed just before, is megabytes of the processes' output.
export async function end(code: number, message: string): Promise<never> {
  (code === 0 ? console.log : console.error)(message);
  // A write's callback runs once it and every write queued before it are out.
  await Promise.all([process.stdout, process.stderr].map((stream) => new Promise((written) => stream.write('', written))));
  process.exit(code);
}
