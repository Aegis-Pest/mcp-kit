/**
 * Boot-time enforcement-mode line.
 *
 * The property under test: a verifying server and a no-key passthrough are
 * indistinguishable on every successful call, so the mode MUST be visible at
 * boot — one structured line, `warn` when passthrough, `info` when enforced,
 * never carrying key material.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  describeContextEnforcement,
  logContextEnforcementMode,
  isContextEnforcementEnabled,
  generateContextKeyPair,
  contextVerificationKeysFromEnv,
  CONTEXT_SIGNING_ENV_VARS,
} from "../context-signing.js";
import { log } from "../logger.js";

const HS_KEY = "test-signing-key-do-not-use-in-prod-0123456789";
const kp = await generateContextKeyPair();

type Call = { level: string; message: string; metadata?: Record<string, unknown> };

function fakeLogger(): { calls: Call[]; logger: (l: "info" | "warn", m: string, md?: Record<string, unknown>) => void } {
  const calls: Call[] = [];
  return {
    calls,
    logger: (level, message, metadata) => {
      calls.push({ level, message, metadata });
    },
  };
}

describe("logContextEnforcementMode", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("passthrough (no keys) → ONE warn line with event/server/mode/reason", () => {
    const { calls, logger } = fakeLogger();
    const report = logContextEnforcementMode(logger, "admin-mcp", {});

    expect(calls).toHaveLength(1);
    expect(calls[0].level).toBe("warn");
    expect(calls[0].metadata).toMatchObject({
      event: "context_enforcement",
      server: "admin-mcp",
      mode: "passthrough",
      reason: `no ${CONTEXT_SIGNING_ENV_VARS.publicKey}`,
      algorithms: [],
    });
    expect(report.mode).toBe("passthrough");
    expect(isContextEnforcementEnabled({})).toBe(false);
  });

  it("enforced (public key) → ONE info line, reason 'public key present', EdDSA only", () => {
    const { calls, logger } = fakeLogger();
    const report = logContextEnforcementMode(logger, "mail-mcp", { publicKey: kp.publicKey });

    expect(calls).toHaveLength(1);
    expect(calls[0].level).toBe("info");
    expect(calls[0].metadata).toMatchObject({
      event: "context_enforcement",
      server: "mail-mcp",
      mode: "enforced",
      reason: "public key present",
      algorithms: ["EdDSA"],
    });
    expect(report.mode).toBe("enforced");
  });

  it("enforced (legacy HS256 secret only) → info, HS256 only, names the missing public key", () => {
    const { calls, logger } = fakeLogger();
    logContextEnforcementMode(logger, "crm-mcp", HS_KEY);

    expect(calls[0].level).toBe("info");
    expect(calls[0].metadata).toMatchObject({
      mode: "enforced",
      algorithms: ["HS256"],
    });
    expect(String(calls[0].metadata?.reason)).toContain("shared HS256 secret present");
    expect(String(calls[0].metadata?.reason)).toContain(CONTEXT_SIGNING_ENV_VARS.publicKey);
  });

  it("dual-accept (public key + secret) → enforced, both algorithms, reason says dual-accept", () => {
    const { calls, logger } = fakeLogger();
    logContextEnforcementMode(logger, "billing-mcp", {
      publicKey: kp.publicKey,
      hs256Secret: HS_KEY,
    });

    expect(calls[0].level).toBe("info");
    expect(calls[0].metadata).toMatchObject({
      mode: "enforced",
      algorithms: ["EdDSA", "HS256"],
    });
    expect(String(calls[0].metadata?.reason)).toMatch(/dual-accept/);
  });

  it("mirrors exactly what isContextEnforcementEnabled / resolveTrustedContext decide", () => {
    const inputs = [
      undefined,
      "",
      {},
      { hs256Secret: "", publicKey: "" },
      HS_KEY,
      { hs256Secret: HS_KEY },
      { publicKey: kp.publicKey },
      { publicKey: kp.publicKey, hs256Secret: HS_KEY },
      contextVerificationKeysFromEnv({}),
      contextVerificationKeysFromEnv({ [CONTEXT_SIGNING_ENV_VARS.publicKey]: kp.publicKey }),
    ] as const;
    for (const keys of inputs) {
      const expected = isContextEnforcementEnabled(keys) ? "enforced" : "passthrough";
      expect(describeContextEnforcement("x", keys).mode).toBe(expected);
    }
  });

  it("never puts key material in the line", () => {
    const { calls, logger } = fakeLogger();
    logContextEnforcementMode(logger, "admin-mcp", {
      publicKey: kp.publicKey,
      hs256Secret: HS_KEY,
    });
    const line = JSON.stringify(calls[0]);
    expect(line).not.toContain(HS_KEY);
    expect(line).not.toContain("BEGIN PUBLIC KEY");
    expect(line).not.toContain(kp.publicKey.replace(/-----[A-Z ]+-----|\s/g, "").slice(0, 16));
  });

  it("defaults `keys` to the process environment (what the context boundary reads)", () => {
    const { calls, logger } = fakeLogger();
    vi.stubEnv(CONTEXT_SIGNING_ENV_VARS.publicKey, kp.publicKey);
    vi.stubEnv(CONTEXT_SIGNING_ENV_VARS.hs256Secret, "");
    try {
      logContextEnforcementMode(logger, "admin-mcp");
      expect(calls[0].metadata).toMatchObject({ mode: "enforced", reason: "public key present" });
    } finally {
      vi.unstubAllEnvs();
    }

    const second = fakeLogger();
    vi.stubEnv(CONTEXT_SIGNING_ENV_VARS.publicKey, "");
    vi.stubEnv(CONTEXT_SIGNING_ENV_VARS.hs256Secret, "");
    try {
      logContextEnforcementMode(second.logger, "admin-mcp");
      expect(second.calls[0].level).toBe("warn");
      expect(second.calls[0].metadata).toMatchObject({ mode: "passthrough" });
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("the shared log() satisfies the logger shape and emits the fields intact (nothing redacted)", () => {
    const writes: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    });
    try {
      logContextEnforcementMode(log, "admin-mcp", {});
    } finally {
      spy.mockRestore();
    }
    expect(writes).toHaveLength(1);
    const entry = JSON.parse(writes[0]) as Record<string, unknown>;
    expect(entry).toMatchObject({
      level: "warn",
      event: "context_enforcement",
      server: "admin-mcp",
      mode: "passthrough",
      reason: `no ${CONTEXT_SIGNING_ENV_VARS.publicKey}`,
    });
  });
});
