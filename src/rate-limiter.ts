/**
 * Token-bucket rate limiter.
 *
 * Tokens are consumed on each `acquire()` call. When the bucket is empty,
 * `acquire()` returns a promise that resolves once a token becomes available.
 * Tokens refill at a steady rate (default: 30 per minute).
 *
 * Two traffic classes share one bucket (so the total rate to the downstream
 * API is still honored):
 *   - interactive (default): may consume tokens down to 0, and is always served
 *     before background waiters.
 *   - background (`acquire({ background: true })`): may only consume tokens ABOVE
 *     `backgroundReserve`, and yields to interactive waiters. This reserves a
 *     burst of `backgroundReserve` tokens that a best-effort bulk job (e.g. a
 *     cache warmer paginating thousands of rows) can never drain, so an
 *     interactive request always finds headroom instead of starting at zero.
 *     With the default `backgroundReserve` of 0, background behaves like
 *     interactive except for its lower queue priority — so existing single-class
 *     callers are unaffected.
 *
 * Within each class, waiters are served strictly FIFO (fair). The total number
 * of pending waiters is capped; once the cap is reached, `acquire()` rejects
 * with a {@link RateLimiterOverloadError} rather than growing the queue unbounded.
 */

/** Thrown by `acquire()` when the pending-waiter queue is full. */
export class RateLimiterOverloadError extends Error {
  constructor(maxWaiters: number) {
    super(
      `RateLimiter overloaded: too many pending waiters (max ${maxWaiters})`,
    );
    this.name = "RateLimiterOverloadError";
  }
}

/** Default cap on the number of callers that may be queued waiting for a token. */
export const DEFAULT_MAX_WAITERS = 1000;

/** Options for a single {@link RateLimiter.acquire} call. */
export interface AcquireOptions {
  /**
   * Background (best-effort) traffic: only consumes tokens above
   * `backgroundReserve` and is served after interactive waiters. Defaults to
   * false (interactive).
   */
  background?: boolean;
}

interface Waiter {
  resolve: () => void;
  reject: (err: Error) => void;
}

export class RateLimiter {
  private tokens: number;
  private readonly maxTokens: number;
  private readonly refillIntervalMs: number;
  private lastRefillTime: number;

  // Interactive waiters are drained before background waiters; each queue is
  // FIFO internally.
  private readonly iWaiters: Waiter[] = [];
  private readonly bgWaiters: Waiter[] = [];
  private readonly maxWaiters: number;
  private readonly backgroundReserve: number;
  private drainTimer: ReturnType<typeof setTimeout> | undefined;

  /**
   * @param maxTokens          Maximum (and initial) number of tokens in the bucket.
   * @param refillRatePerMin   How many tokens are added per minute.
   * @param maxWaiters         Cap on queued waiters before `acquire()` rejects.
   * @param backgroundReserve  Tokens kept in reserve for interactive traffic:
   *                           `acquire({ background: true })` never drains the
   *                           bucket below this. Default 0 (no reserve → prior
   *                           behavior). Clamped to `[0, maxTokens - 1]` so at
   *                           least one token is always reachable by background.
   */
  constructor(
    maxTokens = 30,
    refillRatePerMin = 30,
    maxWaiters = DEFAULT_MAX_WAITERS,
    backgroundReserve = 0,
  ) {
    this.maxTokens = maxTokens;
    this.tokens = maxTokens;
    this.refillIntervalMs = 60_000 / refillRatePerMin;
    this.lastRefillTime = Date.now();
    this.maxWaiters = maxWaiters;
    this.backgroundReserve = Math.max(0, Math.min(backgroundReserve, maxTokens - 1));
  }

  /** Refill tokens based on elapsed time. */
  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefillTime;
    const newTokens = Math.floor(elapsed / this.refillIntervalMs);
    if (newTokens > 0) {
      this.tokens = Math.min(this.maxTokens, this.tokens + newTokens);
      this.lastRefillTime += newTokens * this.refillIntervalMs;
    }
  }

  /**
   * Acquire a token, waiting FIFO (within the caller's class) if necessary.
   *
   * Interactive callers resolve immediately if a token is free and no
   * interactive caller is already queued. Background callers resolve immediately
   * only if the bucket is above `backgroundReserve` and no one is queued at all.
   * Otherwise the caller is enqueued and resolved as tokens refill — interactive
   * waiters first. Rejects with {@link RateLimiterOverloadError} if the combined
   * queue is already at `maxWaiters`.
   */
  async acquire(opts?: AcquireOptions): Promise<void> {
    this.refill();
    const background = opts?.background === true;

    if (background) {
      // Fast path: above the interactive reserve AND nobody is ahead of us.
      if (
        this.tokens > this.backgroundReserve &&
        this.iWaiters.length === 0 &&
        this.bgWaiters.length === 0
      ) {
        this.tokens--;
        return;
      }
      if (this.iWaiters.length + this.bgWaiters.length >= this.maxWaiters) {
        throw new RateLimiterOverloadError(this.maxWaiters);
      }
      return new Promise<void>((resolve, reject) => {
        this.bgWaiters.push({ resolve, reject });
        this.scheduleDrain();
      });
    }

    // Interactive fast path: a token is free and no interactive caller is ahead.
    // (Interactive may jump ahead of queued background waiters — that is the
    // whole point of the priority split.)
    if (this.tokens > 0 && this.iWaiters.length === 0) {
      this.tokens--;
      return;
    }
    if (this.iWaiters.length + this.bgWaiters.length >= this.maxWaiters) {
      throw new RateLimiterOverloadError(this.maxWaiters);
    }
    return new Promise<void>((resolve, reject) => {
      this.iWaiters.push({ resolve, reject });
      this.scheduleDrain();
    });
  }

  /** Milliseconds until the next token refills. Always strictly > 0. */
  private msUntilNextToken(): number {
    const elapsed = Date.now() - this.lastRefillTime;
    const remaining = this.refillIntervalMs - elapsed;
    // Guarantee a positive delay so we never busy-reschedule a 0ms timer.
    return remaining > 0 ? remaining : 1;
  }

  /** Ensure a single timer is pending to serve the waiter queues. */
  private scheduleDrain(): void {
    if (
      this.drainTimer !== undefined ||
      (this.iWaiters.length === 0 && this.bgWaiters.length === 0)
    ) {
      return;
    }
    const delay = this.msUntilNextToken();
    this.drainTimer = setTimeout(() => {
      this.drainTimer = undefined;
      this.drain();
    }, delay);
    // Don't keep the process alive solely to wake a waiter.
    (this.drainTimer as { unref?: () => void }).unref?.();
  }

  /**
   * Refill, then resolve waiters: all interactive waiters the bucket can serve
   * (down to 0), then background waiters only while the bucket stays above
   * `backgroundReserve`.
   */
  private drain(): void {
    this.refill();
    while (this.tokens > 0 && this.iWaiters.length > 0) {
      this.tokens--;
      (this.iWaiters.shift() as Waiter).resolve();
    }
    while (this.tokens > this.backgroundReserve && this.bgWaiters.length > 0) {
      this.tokens--;
      (this.bgWaiters.shift() as Waiter).resolve();
    }
    if (this.iWaiters.length > 0 || this.bgWaiters.length > 0) {
      this.scheduleDrain();
    }
  }

  /** Current number of available tokens (for testing). */
  get availableTokens(): number {
    this.refill();
    return this.tokens;
  }

  /** Current number of queued waiters, both classes (for testing/observability). */
  get pendingWaiters(): number {
    return this.iWaiters.length + this.bgWaiters.length;
  }
}
