import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  RateLimiter,
  RateLimiterOverloadError,
  DEFAULT_MAX_WAITERS,
} from "../rate-limiter.js";

describe("RateLimiter", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("acquires a token immediately when bucket is full", async () => {
    const limiter = new RateLimiter(5, 5);
    await limiter.acquire();
    expect(limiter.availableTokens).toBe(4);
  });

  it("depletes all tokens after max acquires", async () => {
    const limiter = new RateLimiter(3, 3);
    await limiter.acquire();
    await limiter.acquire();
    await limiter.acquire();
    expect(limiter.availableTokens).toBe(0);
  });

  it("refills tokens after enough time passes", async () => {
    const limiter = new RateLimiter(5, 5);
    // 5 tokens/min → 1 token per 12 seconds

    // Drain all tokens
    for (let i = 0; i < 5; i++) await limiter.acquire();
    expect(limiter.availableTokens).toBe(0);

    // Advance 12 seconds → 1 token refilled
    vi.advanceTimersByTime(12_000);
    expect(limiter.availableTokens).toBe(1);
  });

  it("does not exceed maxTokens after long idle", async () => {
    const limiter = new RateLimiter(3, 3);
    await limiter.acquire();

    // Advance 10 minutes — should cap at maxTokens (3)
    vi.advanceTimersByTime(600_000);
    expect(limiter.availableTokens).toBe(3);
  });

  it("waits for a token when bucket is empty", async () => {
    const limiter = new RateLimiter(1, 60); // 1 token max, refill 1/sec

    await limiter.acquire(); // drain
    expect(limiter.availableTokens).toBe(0);

    const acquirePromise = limiter.acquire();
    // Should not resolve yet
    let resolved = false;
    acquirePromise.then(() => { resolved = true; });
    await vi.advanceTimersByTimeAsync(500);
    expect(resolved).toBe(false);

    // Advance past 1 second refill interval
    await vi.advanceTimersByTimeAsync(600);
    expect(resolved).toBe(true);
  });

  it("serves queued waiters in FIFO order (fairness)", async () => {
    const limiter = new RateLimiter(1, 60); // 1 token max, refill 1/sec
    await limiter.acquire(); // drain the only token
    expect(limiter.availableTokens).toBe(0);

    const order: number[] = [];
    const p1 = limiter.acquire().then(() => order.push(1));
    const p2 = limiter.acquire().then(() => order.push(2));
    const p3 = limiter.acquire().then(() => order.push(3));
    expect(limiter.pendingWaiters).toBe(3);

    // 3 tokens refill one per second → all three resolve, in order queued.
    await vi.advanceTimersByTimeAsync(3100);
    await Promise.all([p1, p2, p3]);

    expect(order).toEqual([1, 2, 3]);
    expect(limiter.pendingWaiters).toBe(0);
  });

  it("rejects with RateLimiterOverloadError when the waiter queue is full", async () => {
    const limiter = new RateLimiter(1, 60, 2); // cap at 2 pending waiters
    await limiter.acquire(); // drain

    const p1 = limiter.acquire();
    const p2 = limiter.acquire();
    expect(limiter.pendingWaiters).toBe(2);

    // Third waiter exceeds the cap → rejects instead of growing unbounded.
    await expect(limiter.acquire()).rejects.toBeInstanceOf(
      RateLimiterOverloadError,
    );
    expect(limiter.pendingWaiters).toBe(2);

    // Drain the two legitimate waiters so no dangling promises remain.
    await vi.advanceTimersByTimeAsync(2100);
    await Promise.all([p1, p2]);
  });

  it("waits with a single positive-delay timer (no tight reschedule loop)", async () => {
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");
    const limiter = new RateLimiter(1, 60); // 1 token, 1/sec
    await limiter.acquire(); // drain
    setTimeoutSpy.mockClear();

    const p = limiter.acquire(); // must wait ~1s for a refill
    await vi.advanceTimersByTimeAsync(1100);
    await p;

    // Exactly one timer scheduled — not a storm of 0ms reschedules.
    expect(setTimeoutSpy).toHaveBeenCalledTimes(1);
    // And its delay is strictly positive (the old code could pass 0).
    expect(Number(setTimeoutSpy.mock.calls[0]![1])).toBeGreaterThan(0);

    setTimeoutSpy.mockRestore();
  });
});

describe("RateLimiter background reserve", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("background traffic never drains the bucket below the reserve", async () => {
    // 5 tokens, 60/min (1/sec), reserve 3 for interactive.
    const limiter = new RateLimiter(5, 60, DEFAULT_MAX_WAITERS, 3);
    await limiter.acquire({ background: true }); // 5 -> 4
    await limiter.acquire({ background: true }); // 4 -> 3 (at the reserve floor)
    expect(limiter.availableTokens).toBe(3);

    // A third background acquire is blocked at the floor — it queues instead.
    const blocked = limiter.acquire({ background: true });
    let done = false;
    blocked.then(() => { done = true; });
    await vi.advanceTimersByTimeAsync(50);
    expect(done).toBe(false);
    expect(limiter.pendingWaiters).toBe(1);

    // One refill lifts the bucket above the reserve → the background waiter runs.
    await vi.advanceTimersByTimeAsync(1100);
    await blocked;
    expect(done).toBe(true);
  });

  it("interactive may consume the reserve and is served before queued background", async () => {
    const limiter = new RateLimiter(3, 60, DEFAULT_MAX_WAITERS, 2); // reserve 2
    await limiter.acquire({ background: true }); // 3 -> 2 (at floor)
    const bg = limiter.acquire({ background: true }); // blocked at floor
    let bgDone = false;
    bg.then(() => { bgDone = true; });
    await vi.advanceTimersByTimeAsync(10);
    expect(limiter.pendingWaiters).toBe(1);

    // Interactive drains straight through the reserve, down to 0.
    await limiter.acquire(); // 2 -> 1
    await limiter.acquire(); // 1 -> 0
    expect(limiter.availableTokens).toBe(0);
    expect(bgDone).toBe(false); // background stayed starved

    // With both an interactive AND the background waiter queued, the next token
    // goes to interactive first.
    const order: string[] = [];
    const iw = limiter.acquire().then(() => order.push("i"));
    await vi.advanceTimersByTimeAsync(1100); // +1 token → serves interactive
    await iw;
    expect(order).toEqual(["i"]);
    expect(bgDone).toBe(false);

    // Enough refill to clear the reserve resolves the background waiter last.
    await vi.advanceTimersByTimeAsync(3100);
    await bg;
    expect(bgDone).toBe(true);
  });

  it("with the default reserve of 0, background behaves like interactive", async () => {
    const limiter = new RateLimiter(2, 60); // reserve defaults to 0
    await limiter.acquire({ background: true }); // 2 -> 1
    await limiter.acquire({ background: true }); // 1 -> 0 (can reach zero)
    expect(limiter.availableTokens).toBe(0);
  });

  it("clamps an over-large reserve to maxTokens-1 so background can still progress", async () => {
    const limiter = new RateLimiter(3, 60, DEFAULT_MAX_WAITERS, 99); // clamped to 2
    await limiter.acquire({ background: true }); // 3 -> 2 (floor); one token was reachable
    expect(limiter.availableTokens).toBe(2);
    const blocked = limiter.acquire({ background: true });
    let done = false;
    blocked.then(() => { done = true; });
    await vi.advanceTimersByTimeAsync(50);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1100); // refill past the floor
    await blocked;
    expect(done).toBe(true);
  });
});
