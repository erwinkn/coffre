// Every test file has its own process. Tasks belong to the current case,
// including work handed to a custom waitUntil observer by the sync tests.
const background = new Set<Promise<unknown>>();

export function trackBackgroundTask(promise: Promise<unknown>): void {
  background.add(promise);
  // The caller still observes/reports errors. Tracking only owns lifetime.
  promise.then(() => background.delete(promise), () => background.delete(promise));
}

export async function drainBackgroundTasks(): Promise<void> {
  // Completing one task can schedule more. Drain all of them, including
  // rejected tasks, before letting a reset or pool shutdown start.
  while (background.size > 0) await Promise.allSettled([...background]);
}
