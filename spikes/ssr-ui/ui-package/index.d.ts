export type UiBindings = {
  HYPERDRIVE: { connectionString: string };
  [name: `COFFRE_${string}`]: string | undefined;
};

export type UiExecutionContext = {
  waitUntil(promise: Promise<unknown>): void;
};

export type UiRequestContext = {
  cspNonce: string;
};

export type UiWorker = {
  fetch(
    request: Request,
    bindings: UiBindings,
    context: UiExecutionContext,
    options: { context: UiRequestContext },
  ): Response | Promise<Response>;
  scheduled(
    controller: unknown,
    bindings: UiBindings,
    context: UiExecutionContext,
  ): void | Promise<void>;
};

declare const uiWorker: UiWorker;

export default uiWorker;
