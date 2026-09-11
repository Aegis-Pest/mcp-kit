import type { ToolResponse } from "./rbac.js";
import type { RateLimiter } from "./rate-limiter.js";
import { log } from "./logger.js";

export interface WrapHandlerOptions {
  /**
   * When set, every wrapped handler awaits `rateLimiter.acquire()` before it
   * runs, so one limiter governs the total call rate to the downstream API.
   */
  rateLimiter?: RateLimiter;
  /**
   * Recognise errors raised by the downstream API client. A matching error is
   * reported as `Error (<status>): <message>` so the model can distinguish an
   * upstream 4xx/5xx from a local failure.
   */
  isApiError?: (err: unknown) => boolean;
}

/**
 * Build a `wrapHandler` for an MCP server.
 *
 * `wrapHandler(fn)` turns a plain async tool implementation into the callback
 * the MCP SDK's `server.tool()` expects: it applies the shared rate limiter,
 * then converts any thrown error into an `isError: true` {@link ToolResponse}
 * instead of letting it escape as a JSON-RPC failure. The model sees a
 * readable `Error: ...` text block and can recover; the error is also logged
 * (with secrets redacted) to stderr.
 *
 * The SDK passes a second `extra` argument (request metadata) which the
 * wrapped handler ignores; it is accepted so the returned function is
 * assignable to the SDK's callback type.
 */
export function createWrapHandler(options: WrapHandlerOptions = {}) {
  return function wrapHandler<T>(
    handler: (args: T) => Promise<ToolResponse>,
  ): (args: T, extra?: unknown) => Promise<ToolResponse> {
    return async (args: T, _extra?: unknown): Promise<ToolResponse> => {
      try {
        if (options.rateLimiter) await options.rateLimiter.acquire();
        return await handler(args);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        const text = options.isApiError?.(err)
          ? `Error (${(err as { status?: number }).status}): ${message}`
          : `Error: ${message}`;
        log("error", "Tool handler error", { error: message });
        return { content: [{ type: "text", text }], isError: true };
      }
    };
  };
}
