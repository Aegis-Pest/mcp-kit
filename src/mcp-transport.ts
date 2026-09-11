import { timingSafeEqual } from "node:crypto";
import type { Server as HttpServer } from "node:http";
import { log } from "./logger.js";

/** Structural type for any MCP server that supports connect(transport). */
export interface McpServerLike {
  connect(transport: unknown): Promise<void>;
}

/**
 * Factory that produces a FRESH MCP server instance per SSE connection.
 *
 * Each MCP `Server` holds exactly one transport binding (`_transport`). If a
 * single server instance is shared across concurrent SSE clients, the second
 * `connect()` overwrites the first binding and one session's tool responses get
 * written to another session's stream (a cross-user data leak). Passing a
 * factory lets `createHttpTransport` build an isolated server per connection.
 */
export type McpServerFactory = () => McpServerLike | Promise<McpServerLike>;

/**
 * Constant-time string comparison for secrets. A plain `===`/`!==` on the API
 * secret short-circuits on the first differing byte, leaking the secret to a
 * timing attack. The length check up front is not sensitive (the length is not
 * the secret); the body runs in time independent of how many bytes matched.
 */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export interface HttpTransportConfig {
  port: number;
  apiSecret: string;
  serverName: string;
  /**
   * Maximum number of concurrent SSE sessions to retain. When exceeded, the
   * least-recently-active session is evicted (and its transport closed) to make
   * room. Defaults to {@link DEFAULT_MAX_SESSIONS}.
   */
  maxSessions?: number;
  /**
   * Idle time (ms) after which a session with no `/messages` activity is
   * evicted and its transport closed. Backstops half-open connections that
   * never fire `res.on("close")`. Defaults to {@link DEFAULT_IDLE_TIMEOUT_MS}.
   */
  sessionIdleTimeoutMs?: number;
  /**
   * How often (ms) to sweep for idle sessions. Defaults to
   * {@link DEFAULT_SWEEP_INTERVAL_MS}.
   */
  sessionSweepIntervalMs?: number;
}

/** Handle returned by {@link createHttpTransport} for graceful shutdown/tests. */
export interface HttpTransportHandle {
  /** The underlying Node HTTP server. */
  httpServer: HttpServer;
  /** The bound port (useful when `config.port` is `0`). */
  port: number;
  /** Stop the idle sweep, close all sessions, and close the HTTP server. */
  close(): Promise<void>;
}

/** Default cap on concurrent SSE sessions. */
export const DEFAULT_MAX_SESSIONS = 1024;
/** Default idle-eviction timeout (30 minutes). */
export const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60_000;
/** Default idle-sweep interval (1 minute). */
export const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

/** Minimal shape of a transport the {@link SessionStore} can hold and close. */
export interface ClosableTransport {
  readonly sessionId: string;
  close(): Promise<void> | void;
}

export interface SessionStoreOptions {
  maxSessions?: number;
  idleTimeoutMs?: number;
  /** Injectable clock (ms). Defaults to `Date.now`. Present for testability. */
  now?: () => number;
  /** Notified when a session is evicted (capacity or idle). Present for tests. */
  onEvict?: (sessionId: string, reason: "idle" | "capacity") => void;
}

/**
 * Bounded, idle-evicting store of SSE sessions.
 *
 * Fixes an unbounded-map leak: without a cap or TTL, a half-open `/sse`
 * connection that never fires `res.on("close")` would leak a transport entry
 * forever. This store caps the number of sessions (evicting the
 * least-recently-active when full) and periodically evicts sessions idle beyond
 * a timeout. Evicted transports are always `close()`d.
 */
export class SessionStore<T extends ClosableTransport> {
  private readonly sessions = new Map<
    string,
    { transport: T; lastActivity: number }
  >();
  private readonly maxSessions: number;
  private readonly idleTimeoutMs: number;
  private readonly now: () => number;
  private readonly onEvict?: (
    sessionId: string,
    reason: "idle" | "capacity",
  ) => void;

  constructor(opts: SessionStoreOptions = {}) {
    this.maxSessions =
      opts.maxSessions && opts.maxSessions > 0
        ? opts.maxSessions
        : DEFAULT_MAX_SESSIONS;
    this.idleTimeoutMs =
      opts.idleTimeoutMs && opts.idleTimeoutMs > 0
        ? opts.idleTimeoutMs
        : DEFAULT_IDLE_TIMEOUT_MS;
    this.now = opts.now ?? Date.now;
    this.onEvict = opts.onEvict;
  }

  get size(): number {
    return this.sessions.size;
  }

  /** Add a session, evicting the oldest first if at capacity. */
  add(transport: T): void {
    while (this.sessions.size >= this.maxSessions) {
      const oldest = this.oldestSessionId();
      if (oldest === undefined) break;
      this.evict(oldest, "capacity");
    }
    this.sessions.set(transport.sessionId, {
      transport,
      lastActivity: this.now(),
    });
  }

  /** Look up a session, refreshing its last-activity timestamp. */
  get(sessionId: string): T | undefined {
    const entry = this.sessions.get(sessionId);
    if (!entry) return undefined;
    entry.lastActivity = this.now();
    return entry.transport;
  }

  /** Remove a session WITHOUT closing it (e.g. the client already closed). */
  delete(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /** Evict + close every session idle beyond the configured timeout. */
  sweep(): void {
    const cutoff = this.now() - this.idleTimeoutMs;
    for (const [id, entry] of this.sessions) {
      if (entry.lastActivity <= cutoff) {
        this.evict(id, "idle");
      }
    }
  }

  /** Close and remove all sessions (used on shutdown). */
  closeAll(): void {
    for (const id of [...this.sessions.keys()]) {
      this.evict(id, "capacity");
    }
  }

  private oldestSessionId(): string | undefined {
    let oldestId: string | undefined;
    let oldestTs = Infinity;
    for (const [id, entry] of this.sessions) {
      if (entry.lastActivity < oldestTs) {
        oldestTs = entry.lastActivity;
        oldestId = id;
      }
    }
    return oldestId;
  }

  private evict(sessionId: string, reason: "idle" | "capacity"): void {
    const entry = this.sessions.get(sessionId);
    if (!entry) return;
    this.sessions.delete(sessionId);
    try {
      const result = entry.transport.close();
      // close() may be async; swallow a rejected close so a single bad
      // transport can't crash the sweep or take down the process.
      if (result && typeof (result as Promise<void>).catch === "function") {
        (result as Promise<void>).catch(() => {});
      }
    } catch {
      /* ignore close errors */
    }
    this.onEvict?.(sessionId, reason);
  }
}

/**
 * Creates an HTTP/SSE transport for an MCP server.
 * Handles Bearer auth, SSE session management, health endpoint, and 404 fallback.
 *
 * @param serverOrFactory  Either a factory `() => McpServerLike` (RECOMMENDED —
 *   each SSE connection gets its OWN isolated server instance, preventing the
 *   concurrent-client cross-wire) or a single bare `McpServerLike` (legacy;
 *   safe only when there is at most one concurrent SSE client — a one-time
 *   warning is logged).
 * @param config  Port, auth secret, server name, and optional session limits.
 * @returns A handle exposing the HTTP server, bound port, and a `close()` for
 *   graceful shutdown. (Existing callers that `await` and ignore the result are
 *   unaffected.)
 */
export async function createHttpTransport(
  serverOrFactory: McpServerLike | McpServerFactory,
  config: HttpTransportConfig,
): Promise<HttpTransportHandle> {
  const { SSEServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/sse.js"
  );
  const http = await import("node:http");

  const isFactory = typeof serverOrFactory === "function";
  if (!isFactory) {
    // One-time warning: a bare server holds a single transport binding, so a
    // second concurrent SSE client overwrites the first and cross-wires their
    // streams. Callers should pass a factory instead.
    log(
      "warn",
      `${config.serverName}: createHttpTransport received a bare MCP server instance. ` +
        `A single server holds one transport binding, so concurrent SSE clients will ` +
        `cross-wire (one session's responses can be written to another session's stream). ` +
        `Pass a factory ( () => new McpServer(...).server ) so each SSE connection gets ` +
        `its own isolated server instance.`,
    );
  }

  const sessions = new SessionStore<InstanceType<typeof SSEServerTransport>>({
    maxSessions: config.maxSessions,
    idleTimeoutMs: config.sessionIdleTimeoutMs,
  });

  const sweepTimer = setInterval(
    () => sessions.sweep(),
    config.sessionSweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS,
  );
  // Don't let the sweep timer keep the process alive on its own.
  (sweepTimer as { unref?: () => void }).unref?.();

  const httpServer = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "", `http://${req.headers.host}`);

      // Authenticate SSE and message endpoints (constant-time secret compare)
      if (url.pathname === "/sse" || url.pathname === "/messages") {
        const authHeader = req.headers["authorization"];
        if (
          !authHeader ||
          !safeEqual(authHeader, `Bearer ${config.apiSecret}`)
        ) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Unauthorized" }));
          return;
        }
      }

      if (req.method === "GET" && url.pathname === "/sse") {
        const transport = new SSEServerTransport("/messages", res);
        sessions.add(transport);

        res.on("close", () => {
          sessions.delete(transport.sessionId);
        });

        // Isolate each SSE connection: with a factory, build a FRESH server so
        // concurrent clients never share one server's single transport binding.
        // With a bare server (legacy), reuse it — safe only for one client.
        const connectionServer: McpServerLike = isFactory
          ? await (serverOrFactory as McpServerFactory)()
          : (serverOrFactory as McpServerLike);
        await connectionServer.connect(transport);
      } else if (req.method === "POST" && url.pathname === "/messages") {
        const sessionId = url.searchParams.get("sessionId");
        const transport = sessionId ? sessions.get(sessionId) : undefined;

        if (!transport) {
          res.writeHead(400);
          res.end("Invalid or missing session");
          return;
        }

        await transport.handlePostMessage(req, res);
      } else if (req.method === "GET" && url.pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", server: config.serverName }));
      } else {
        res.writeHead(404);
        res.end("Not found");
      }
    } catch (err: unknown) {
      // Without this, a throw in connect()/handlePostMessage() becomes an
      // unhandled promise rejection: the response never completes (client
      // hangs) and Node may terminate on unhandledRejection. Fail the request
      // with a 500 instead.
      log(
        "error",
        `${config.serverName} request handler error: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal error" }));
      } else {
        res.end();
      }
    }
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(config.port, () => resolve());
  });

  // Report the port actually bound (config.port may be 0 = "any free port").
  const addr = httpServer.address();
  const boundPort =
    typeof addr === "object" && addr ? addr.port : config.port;
  log("info", `${config.serverName} listening on http://localhost:${boundPort}`);

  return {
    httpServer,
    port: boundPort,
    close: () =>
      new Promise<void>((resolve) => {
        clearInterval(sweepTimer);
        sessions.closeAll();
        httpServer.close(() => resolve());
      }),
  };
}
