import { describe, it, expect, vi, afterEach } from "vitest";
import { createWrapHandler } from "../mcp-wrap-handler.js";
import { RateLimiter } from "../rate-limiter.js";
import type { ToolResponse } from "../rbac.js";

/** Capture the single JSON line `log()` writes to stderr during `fn`. */
async function captureStderr(fn: () => Promise<unknown>): Promise<string[]> {
  const writes: string[] = [];
  const spy = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    });
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
  return writes;
}

describe("createWrapHandler", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("passes the args through and returns the handler's response unchanged", async () => {
    const wrapHandler = createWrapHandler();
    const ok: ToolResponse = { content: [{ type: "text", text: "hi" }] };
    const wrapped = wrapHandler(async (args: { name: string }) => {
      expect(args).toEqual({ name: "x" });
      return ok;
    });
    await expect(wrapped({ name: "x" }, { requestId: 1 })).resolves.toBe(ok);
  });

  it("turns a thrown Error into an isError response and logs it", async () => {
    const wrapHandler = createWrapHandler();
    const wrapped = wrapHandler(async () => {
      throw new Error("upstream exploded");
    });
    let res: ToolResponse | undefined;
    const writes = await captureStderr(async () => {
      res = await wrapped(undefined);
    });
    expect(res).toEqual({
      content: [{ type: "text", text: "Error: upstream exploded" }],
      isError: true,
    });
    expect(writes).toHaveLength(1);
    const line = JSON.parse(writes[0]) as Record<string, unknown>;
    expect(line).toMatchObject({
      level: "error",
      message: "Tool handler error",
      error: "upstream exploded",
    });
  });

  it("stringifies non-Error throwables", async () => {
    const wrapHandler = createWrapHandler();
    const wrapped = wrapHandler(async () => {
      throw "plain string";
    });
    let res: ToolResponse | undefined;
    await captureStderr(async () => {
      res = await wrapped(undefined);
    });
    expect(res?.isError).toBe(true);
    expect(res?.content[0]?.text).toBe("Error: plain string");
  });

  it("reports the upstream status when isApiError recognises the error", async () => {
    class ApiError extends Error {
      constructor(readonly status: number, message: string) {
        super(message);
      }
    }
    const wrapHandler = createWrapHandler({
      isApiError: (err) => err instanceof ApiError,
    });
    const wrapped = wrapHandler(async () => {
      throw new ApiError(429, "rate limited");
    });
    let res: ToolResponse | undefined;
    await captureStderr(async () => {
      res = await wrapped(undefined);
    });
    expect(res?.content[0]?.text).toBe("Error (429): rate limited");
    expect(res?.isError).toBe(true);
  });

  it("acquires a rate-limiter token before running the handler", async () => {
    const order: string[] = [];
    const limiter = new RateLimiter(5, 60);
    const acquireSpy = vi
      .spyOn(limiter, "acquire")
      .mockImplementation(async () => {
        order.push("acquire");
      });
    const wrapHandler = createWrapHandler({ rateLimiter: limiter });
    const wrapped = wrapHandler(async () => {
      order.push("handler");
      return { content: [{ type: "text", text: "ok" }] };
    });
    await wrapped(undefined);
    expect(acquireSpy).toHaveBeenCalledTimes(1);
    expect(order).toEqual(["acquire", "handler"]);
  });

  it("surfaces a rate-limiter overload as an error response, not an exception", async () => {
    const limiter = new RateLimiter(5, 60);
    vi.spyOn(limiter, "acquire").mockRejectedValue(new Error("RateLimiter overloaded"));
    const wrapHandler = createWrapHandler({ rateLimiter: limiter });
    const handler = vi.fn(async () => ({ content: [{ type: "text" as const, text: "never" }] }));
    let res: ToolResponse | undefined;
    await captureStderr(async () => {
      res = await wrapHandler(handler)(undefined);
    });
    expect(handler).not.toHaveBeenCalled();
    expect(res?.isError).toBe(true);
    expect(res?.content[0]?.text).toBe("Error: RateLimiter overloaded");
  });
});
