import { describe, expect, it, vi } from "vitest";
import http from "node:http";
import {
  safeEqual,
  SessionStore,
  createHttpTransport,
} from "../mcp-transport.js";

describe("safeEqual (constant-time secret compare)", () => {
  it("returns true for identical strings", () => {
    expect(safeEqual("Bearer s3cr3t", "Bearer s3cr3t")).toBe(true);
  });

  it("returns false for different strings of equal length", () => {
    expect(safeEqual("Bearer s3cr3t", "Bearer x3cr3t")).toBe(false);
  });

  it("returns false for different lengths (no timingSafeEqual throw)", () => {
    expect(safeEqual("Bearer s3cr3t", "Bearer s3cr3t-extra")).toBe(false);
    expect(safeEqual("", "x")).toBe(false);
  });

  it("returns true for two empty strings", () => {
    expect(safeEqual("", "")).toBe(true);
  });
});

describe("SessionStore (bounded + idle-evicting session map)", () => {
  class FakeTransport {
    closed = false;
    constructor(public readonly sessionId: string) {}
    async close(): Promise<void> {
      this.closed = true;
    }
  }

  it("evicts + closes the least-recently-active session when over capacity", () => {
    let t = 0;
    const store = new SessionStore<FakeTransport>({
      maxSessions: 2,
      now: () => t,
    });

    const a = new FakeTransport("a");
    store.add(a); // active @0
    t = 10;
    const b = new FakeTransport("b");
    store.add(b); // active @10
    t = 20;
    store.get("a"); // refresh a → active @20
    t = 30;
    const c = new FakeTransport("c");
    store.add(c); // over cap → evict oldest active (b)

    expect(store.size).toBe(2);
    expect(b.closed).toBe(true);
    expect(store.get("b")).toBeUndefined();
    expect(store.get("a")).toBeDefined();
    expect(store.get("c")).toBeDefined();
  });

  it("sweeps + closes sessions idle beyond the timeout, keeping active ones", () => {
    let t = 0;
    const store = new SessionStore<FakeTransport>({
      idleTimeoutMs: 100,
      now: () => t,
    });

    const a = new FakeTransport("a");
    store.add(a); // active @0
    t = 50;
    const b = new FakeTransport("b");
    store.add(b); // active @50

    t = 120; // a idle 120ms (> 100), b idle 70ms (< 100)
    store.sweep();

    expect(a.closed).toBe(true);
    expect(store.get("a")).toBeUndefined();
    expect(b.closed).toBe(false);
    expect(store.get("b")).toBeDefined();
  });

  it("delete() removes a session WITHOUT closing it (client already closed)", () => {
    const store = new SessionStore<FakeTransport>();
    const a = new FakeTransport("a");
    store.add(a);
    store.delete("a");
    expect(store.size).toBe(0);
    expect(a.closed).toBe(false);
  });
});

describe("createHttpTransport — per-connection server isolation (SSE cross-wire fix)", () => {
  const SECRET = "test-secret";

  // Minimal fake MCP server: records the transport it was bound to, completes
  // the SSE handshake (so the client learns its sessionId), and records
  // inbound messages so we can prove routing isolation.
  class FakeServer {
    connectedTransport: { sessionId: string } | null = null;
    messages: unknown[] = [];
    async connect(transport: {
      sessionId: string;
      start: () => Promise<void>;
      onmessage?: (msg: unknown) => void;
    }): Promise<void> {
      this.connectedTransport = transport;
      transport.onmessage = (msg: unknown) => {
        this.messages.push(msg);
      };
      await transport.start(); // writes SSE headers + endpoint event
    }
  }

  function openSse(
    port: number,
  ): Promise<{ sessionId: string; req: http.ClientRequest }> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: "/sse",
          method: "GET",
          headers: { authorization: `Bearer ${SECRET}` },
        },
        (res) => {
          res.setEncoding("utf8");
          let buf = "";
          res.on("data", (chunk: string) => {
            buf += chunk;
            const m = /sessionId=([^\s"&]+)/.exec(buf);
            if (m) resolve({ sessionId: m[1]!, req });
          });
          res.on("error", reject);
        },
      );
      req.on("error", reject);
      req.end();
    });
  }

  function postMessage(
    port: number,
    sessionId: string,
    body: unknown,
  ): Promise<number> {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(body);
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: `/messages?sessionId=${sessionId}`,
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(data),
            authorization: `Bearer ${SECRET}`,
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        },
      );
      req.on("error", reject);
      req.write(data);
      req.end();
    });
  }

  it("gives two concurrent /sse clients distinct servers and routes a message only to its own transport", async () => {
    const created: FakeServer[] = [];
    const factory = () => {
      const s = new FakeServer();
      created.push(s);
      return s;
    };

    const handle = await createHttpTransport(factory, {
      port: 0,
      apiSecret: SECRET,
      serverName: "iso-test",
    });
    const port = handle.port;

    try {
      const a = await openSse(port);
      const b = await openSse(port);

      // Two connections → two FRESH, distinct server instances, each bound to
      // its own transport (the cross-wire fix).
      expect(created.length).toBe(2);
      expect(created[0]).not.toBe(created[1]);
      expect(created[0]!.connectedTransport).not.toBe(
        created[1]!.connectedTransport,
      );
      expect(a.sessionId).not.toBe(b.sessionId);

      const serverA = created.find(
        (s) => s.connectedTransport?.sessionId === a.sessionId,
      )!;
      const serverB = created.find(
        (s) => s.connectedTransport?.sessionId === b.sessionId,
      )!;
      expect(serverA).toBeDefined();
      expect(serverB).toBeDefined();
      expect(serverA).not.toBe(serverB);

      // A message for session A must land on A's transport, never B's.
      const status = await postMessage(port, a.sessionId, {
        jsonrpc: "2.0",
        id: 1,
        method: "ping",
      });
      expect(status).toBe(202);
      expect(serverA.messages.length).toBe(1);
      expect(serverB.messages.length).toBe(0);

      a.req.destroy();
      b.req.destroy();
    } finally {
      await handle.close();
    }
  });

  it("warns once when passed a bare server instead of a factory", async () => {
    const writes: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: unknown): boolean => {
        writes.push(String(chunk));
        return true;
      });

    const bareServer = { connect: async () => {} };
    const handle = await createHttpTransport(bareServer, {
      port: 0,
      apiSecret: SECRET,
      serverName: "bare-test",
    });
    spy.mockRestore();
    await handle.close();

    const warned = writes.some(
      (w) => w.includes('"level":"warn"') && w.includes("bare MCP server"),
    );
    expect(warned).toBe(true);
  });
});
