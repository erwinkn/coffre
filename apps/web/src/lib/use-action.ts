import { useState } from 'react';
import { useRouter } from '@tanstack/react-router';

type ActionResult = { ok: true } | { ok: false; error: string };

/**
 * Run a mutating server function, then refresh what is on screen.
 *
 * `router.invalidate()` is this app's replacement for Next's
 * `revalidatePath`. The difference worth knowing: `revalidatePath` named the
 * routes to refresh and got it wrong quietly when a mutation touched more than
 * the page it was called from -- renaming a project had to remember to
 * revalidate both `/` and `/:project`. Invalidating refetches every mounted
 * loader instead, so the sidebar's project tree stays honest without anyone
 * having to remember it exists.
 */
export function useAction() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run<T extends ActionResult>(
    fn: () => Promise<T>,
    // `unknown` rather than `void`, so a one-expression callback can end in
    // `toast.success(...)` -- which returns an id -- without a block body.
    onSuccess?: (result: Extract<T, { ok: true }>) => unknown,
  ): Promise<void> {
    setPending(true);
    let result: T;
    try {
      result = await fn();
    } catch {
      setError('The request could not be sent. Nothing was changed.');
      setPending(false);
      return;
    }

    if (!result.ok) {
      setError(result.error);
      setPending(false);
      return;
    }

    setError(null);
    try {
      await router.invalidate();
      await onSuccess?.(result as Extract<T, { ok: true }>);
    } catch {
      setError('The change was saved, but the page could not refresh. Reload before you retry.');
    }
    setPending(false);
  }

  return { pending, error, setError, run };
}
