import { describe, it, expect, vi, afterEach } from "vitest";
import { log, redactSecrets, redactMetadata, REDACTED } from "../logger.js";

/**
 * Capture whatever `log()` writes to stderr and return it parsed. The logger
 * emits exactly one JSON line per call, so we grab the first write.
 */
function captureLogLine(fn: () => void): Record<string, unknown> {
  const writes: string[] = [];
  const spy = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    });
  try {
    fn();
  } finally {
    spy.mockRestore();
  }
  expect(writes).toHaveLength(1);
  return JSON.parse(writes[0]) as Record<string, unknown>;
}

describe("log() secret redaction", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("redacts the value of top-level sensitive keys in the emitted line", () => {
    const secretValue = "eyJ-super-secret-graph-token";
    const line = captureLogLine(() =>
      log("error", "graph call failed", {
        graph_access_token: secretValue,
        api_key: "ak_live_123",
        access_token: "at_456",
        request_id: "req-1",
      }),
    );

    const raw = JSON.stringify(line);
    // The actual secrets must not appear anywhere in the serialized output.
    expect(raw).not.toContain(secretValue);
    expect(raw).not.toContain("ak_live_123");
    expect(raw).not.toContain("at_456");
    // The redaction marker stands in for each.
    expect(line.graph_access_token).toBe(REDACTED);
    expect(line.api_key).toBe(REDACTED);
    expect(line.access_token).toBe(REDACTED);
    // Non-sensitive scaffolding is preserved.
    expect(line.request_id).toBe("req-1");
    expect(line.level).toBe("error");
    expect(line.message).toBe("graph call failed");
  });

  it("redacts a whole McpToolContext.credentials object nested in metadata", () => {
    const line = captureLogLine(() =>
      log("error", "tool blew up", {
        context: {
          tenant_id: "t-1",
          user_id: "u-1",
          credentials: {
            graph_access_token: "nested-graph-token",
            refresh_token: "nested-refresh-token",
            vendor_api_key: "fw_key_should_be_gone",
          },
        },
      }),
    );

    const raw = JSON.stringify(line);
    expect(raw).not.toContain("nested-graph-token");
    expect(raw).not.toContain("nested-refresh-token");
    expect(raw).not.toContain("fw_key_should_be_gone");

    const context = line.context as Record<string, unknown>;
    // The entire credentials value is replaced, not merely its known children.
    expect(context.credentials).toBe(REDACTED);
    // Sibling non-sensitive fields survive.
    expect(context.tenant_id).toBe("t-1");
    expect(context.user_id).toBe("u-1");
  });

  it("preserves ordinary fields untouched", () => {
    const line = captureLogLine(() =>
      log("info", "ok", {
        request_id: "req-42",
        count: 3,
        nested: { name: "widget", flag: true, tags: ["a", "b"] },
      }),
    );

    expect(line.count).toBe(3);
    expect(line.nested).toEqual({ name: "widget", flag: true, tags: ["a", "b"] });
  });
});

describe("redactSecrets()", () => {
  it("masks known-sensitive keys case-insensitively at every depth", () => {
    const input = {
      Password: "hunter2",
      Authorization: "Bearer abc",
      profile: {
        name: "Alex",
        Secret: "s3cr3t",
        list: [{ token: "tok-1" }, { note: "keep-me" }],
      },
    };

    const out = redactSecrets(input);

    expect(out.Password).toBe(REDACTED);
    expect(out.Authorization).toBe(REDACTED);
    expect(out.profile.name).toBe("Alex");
    expect(out.profile.Secret).toBe(REDACTED);
    expect((out.profile.list[0] as Record<string, unknown>).token).toBe(REDACTED);
    expect((out.profile.list[1] as Record<string, unknown>).note).toBe("keep-me");
  });

  it("does not mutate the caller's object", () => {
    const input = { api_key: "k", nested: { secret: "s" } };
    const out = redactSecrets(input);
    expect(input.api_key).toBe("k");
    expect(input.nested.secret).toBe("s");
    expect(out.api_key).toBe(REDACTED);
  });

  it("is defensive against null, primitives, arrays, and cycles", () => {
    expect(redactSecrets(null)).toBeNull();
    expect(redactSecrets(undefined)).toBeUndefined();
    expect(redactSecrets("plain")).toBe("plain");
    expect(redactSecrets(7)).toBe(7);
    expect(redactSecrets([1, 2, 3])).toEqual([1, 2, 3]);

    const cyclic: Record<string, unknown> = { token: "t", ordinary: 1 };
    cyclic.self = cyclic;
    const out = redactSecrets(cyclic) as Record<string, unknown>;
    expect(out.token).toBe(REDACTED);
    expect(out.ordinary).toBe(1);
    expect(out.self).toBe("[Circular]");
  });

  it("redactMetadata is an alias of redactSecrets", () => {
    expect(redactMetadata).toBe(redactSecrets);
  });
});

describe("expanded key-name coverage", () => {
  it("redacts token/secret/key/session variants the exact-match set missed", () => {
    const out = redactSecrets({
      id_token: "idt",
      session_token: "sess",
      session_id: "sid",
      bearer: "brr",
      "x-api-key": "xak",
      secret_key: "sk",
      csrf_token: "csrf",
      client_secret: "cs",
      "proxy-authorization": "pa",
      pwd: "hunter2",
      connection_string: "Server=db;Password=s3cr3t;",
    }) as Record<string, unknown>;
    for (const k of [
      "id_token",
      "session_token",
      "session_id",
      "bearer",
      "x-api-key",
      "secret_key",
      "csrf_token",
      "client_secret",
      "proxy-authorization",
      "pwd",
      "connection_string",
    ]) {
      expect(out[k]).toBe(REDACTED);
    }
  });

  it("does NOT over-redact lookalike non-secret keys", () => {
    const out = redactSecrets({
      token_count: 128,
      token_usage: { prompt: 10 },
      public_key: "-----BEGIN PUBLIC KEY-----",
      idempotency_key: "idem-1",
      account_id: "acct-1",
      // Pagination cursors end in `token` but are not secrets.
      next_page_token: "cursor-abc",
      page_token: "p-1",
      continuation_token: "c-1",
      // Substring-collision victims of the earlier approach.
      secretary: "Pat",
      has_credentials: true,
      credential_type: "oauth",
      authorization_url: "https://login.example.test/authorize",
    }) as Record<string, unknown>;
    for (const [k, v] of Object.entries({
      token_count: 128,
      public_key: "-----BEGIN PUBLIC KEY-----",
      idempotency_key: "idem-1",
      account_id: "acct-1",
      next_page_token: "cursor-abc",
      page_token: "p-1",
      continuation_token: "c-1",
      secretary: "Pat",
      has_credentials: true,
      credential_type: "oauth",
      authorization_url: "https://login.example.test/authorize",
    })) {
      expect(out[k]).toEqual(v);
    }
    expect(out.token_usage).toEqual({ prompt: 10 });
  });
});

describe("value scrubbing (secrets embedded in strings)", () => {
  it("redacts secret query-param values inside a string field, keeps the name", () => {
    const out = redactSecrets({
      url: "https://api.example.test/v1/x?api_key=LIVE_KEY_123&page=2",
    }) as Record<string, unknown>;
    expect(out.url).not.toContain("LIVE_KEY_123");
    expect(out.url).toContain(`api_key=${REDACTED}`);
    expect(out.url).toContain("page=2");
  });

  it("scrubs the log message itself", () => {
    const line = captureLogLine(() =>
      log("error", "fetch failed for https://x.test/y?token=SECRET_TOK&z=1"),
    );
    expect(JSON.stringify(line)).not.toContain("SECRET_TOK");
    expect(line.message).toContain(`token=${REDACTED}`);
    expect(line.message).toContain("z=1");
  });

  it("masks a semicolon-delimited connection-string password and URL userinfo", () => {
    const out = redactSecrets({
      conn: "Server=db.host;Database=app;Password=s3cr3t;Encrypt=true",
      pg: "postgres://appuser:p@ssw0rd@db.host:5432/app",
    }) as Record<string, unknown>;
    expect(out.conn).not.toContain("s3cr3t");
    expect(out.conn).toContain(`Password=${REDACTED}`);
    expect(out.conn).toContain("Encrypt=true");
    // The password contains a literal `@`; its tail must NOT survive the mask.
    expect(out.pg).not.toContain("p@ssw0rd");
    expect(out.pg).not.toContain("ssw0rd");
    expect(out.pg).toContain(`appuser:${REDACTED}@db.host`);
  });
});

describe("cycle detection", () => {
  it("breaks a genuine cycle with [Circular]", () => {
    const cyclic: Record<string, unknown> = { token: "t" };
    cyclic.self = cyclic;
    const out = redactSecrets(cyclic) as Record<string, unknown>;
    expect(out.token).toBe(REDACTED);
    expect(out.self).toBe("[Circular]");
  });
});
