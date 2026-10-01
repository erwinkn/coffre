import {
  SyncConfigError,
  SyncProviderError,
  type SyncApplyResult,
  type SyncProvider,
} from './types.ts';

// Shorter values are left alone: redacting "1" or "on" would shred every
// message, and a secret that short leaks nothing a guess would not.
const MIN_REDACTED_LENGTH = 4;

/**
 * Wraps a provider with the guarantees every provider owes the engine, so no
 * single adapter has to get them right on its own:
 *
 * - keys that `checkKey` rejects are reported as failed and never sent;
 * - no error message, thrown or per-key, contains the token or a value, even
 *   when an upstream API echoes our request back in its error.
 */
export function guard<Config>(provider: SyncProvider<Config>): SyncProvider<Config> {
  return {
    ...provider,

    async listKeys(ctx, config) {
      try {
        return await provider.listKeys(ctx, config);
      } catch (error) {
        throw redactError(error, [ctx.token]);
      }
    },

    async apply(ctx, config, plan) {
      const secrets = [ctx.token, ...plan.upsert.map((variable) => variable.value)];
      const rejected: SyncApplyResult['failed'] = [];
      const upsert = plan.upsert.filter((variable) => {
        const check = provider.checkKey(variable.key);
        if (!check.ok) rejected.push({ key: variable.key, operation: 'upsert', message: check.reason });
        return check.ok;
      });

      if (upsert.length === 0 && plan.delete.length === 0) {
        return { upserted: [], deleted: [], failed: rejected };
      }

      let result: SyncApplyResult;
      try {
        result = await provider.apply(ctx, config, { upsert, delete: plan.delete });
      } catch (error) {
        throw redactError(error, secrets);
      }

      return {
        upserted: result.upserted,
        deleted: result.deleted,
        failed: [
          ...rejected,
          ...result.failed.map((failure) => ({ ...failure, message: redact(failure.message, secrets) })),
        ],
      };
    },
  };
}

export function redact(message: string, secrets: readonly string[]): string {
  const needles = new Set<string>();
  for (const secret of secrets) {
    if (secret.length < MIN_REDACTED_LENGTH) continue;
    needles.add(secret);
    // Upstreams that quote our request body quote it as JSON.
    needles.add(JSON.stringify(secret).slice(1, -1));
  }
  // Longest first, so a value containing another is not left half-visible.
  for (const needle of [...needles].sort((a, b) => b.length - a.length)) {
    message = message.split(needle).join('[redacted]');
  }
  return message;
}

function redactError(error: unknown, secrets: readonly string[]): Error {
  if (error instanceof SyncProviderError) {
    return new SyncProviderError(redact(error.message, secrets), error.code, error.status);
  }
  if (error instanceof SyncConfigError) return new SyncConfigError(redact(error.message, secrets));
  // Anything else is a bug in the adapter; keep its message, never its cause.
  return new Error(redact(error instanceof Error ? error.message : String(error), secrets));
}
