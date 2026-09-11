/**
 * Signed credential keys and the audience / issuer / replay policy.
 *
 * Signed credential keys: `_context.credentials.ms365_*` allowlists decide
 * WHICH mailbox/drives a tenant-wide app-only token may touch, so they must
 * not ride through the JWT gate unsigned. They arrive only via the signed
 * `creds` claim; an unsigned copy is dropped under enforcement.
 *
 * Policy: one fleet key verifies every server, so without `aud`/`iss` checks
 * and a `jti` a captured token would be valid at any server, any number of
 * times, for its lifetime.
 */
import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import {
  signContextToken,
  verifyContextToken,
  resolveTrustedContext,
  contextVerificationKeysFromEnv,
  describeContextEnforcement,
  createContextReplayCache,
  generateContextKeyPair,
  SIGNED_CREDENTIAL_KEYS,
  CONTEXT_TOKEN_ALG,
  CONTEXT_TOKEN_TTL_SECONDS,
  CONTEXT_TOKEN_CLOCK_SKEW_SECONDS,
} from "../context-signing.js";
import type { McpToolContext } from "../rbac.js";

const KEY = "test-signing-key-do-not-use-in-prod-0123456789";
const secret = new TextEncoder().encode(KEY);

function referenceContext(): McpToolContext {
  return {
    tenant_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
    role_name: "owner",
    permissions: [
      { id: "p1", role_id: "r1", resource: "email", action: "send", granted: true },
    ],
    scopes: [],
    request_id: "req-abc-123",
  };
}

function decodePayload(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
}

/** Mint the way an OLD injector does: no jti, no aud, no creds; iss optional. */
async function mintLegacyToken(
  extra: Record<string, unknown> = {},
  { iss }: { iss?: string } = {},
): Promise<string> {
  const ctx = referenceContext();
  const iat = Math.floor(Date.now() / 1000);
  const signer = new SignJWT({
    tid: ctx.tenant_id,
    sub: ctx.user_id,
    role: ctx.role_name,
    perms: ctx.permissions,
    scopes: ctx.scopes,
    ...extra,
  })
    .setProtectedHeader({ alg: CONTEXT_TOKEN_ALG, typ: "JWT" })
    .setIssuedAt(iat)
    .setExpirationTime(iat + CONTEXT_TOKEN_TTL_SECONDS);
  if (iss) signer.setIssuer(iss);
  return signer.sign(secret);
}

// ───────────────────────────── signed credential keys ─────────────────────────────────

describe("signed credential keys — authorization-bearing credential keys are signed", () => {
  it("the contract names exactly the ms365 allowlist/pin keys", () => {
    expect([...SIGNED_CREDENTIAL_KEYS]).toEqual([
      "ms365_mailbox",
      "ms365_mailbox_allowlist",
      "ms365_sharepoint_drive_ids",
    ]);
  });

  it("signer lifts ONLY the contract keys into `creds` — secrets never enter the JWT", async () => {
    const token = await signContextToken(
      {
        ...referenceContext(),
        credentials: {
          ms365_sharepoint_drive_ids: "drive-A,drive-B",
          ms365_mailbox: "ops@example.com",
          graph_access_token: "SECRET-delegated-token",
          ms365_app_password: "SECRET-app-pw",
        },
      },
      KEY,
    );
    const payload = decodePayload(token);
    expect(payload.creds).toEqual({
      ms365_sharepoint_drive_ids: "drive-A,drive-B",
      ms365_mailbox: "ops@example.com",
    });
    // The whole payload — not just `creds` — must be free of the secrets.
    expect(JSON.stringify(payload)).not.toContain("SECRET-");
  });

  it("signer omits `creds` when no contract key is present", async () => {
    const token = await signContextToken(
      { ...referenceContext(), credentials: { graph_access_token: "x" } },
      KEY,
    );
    expect(decodePayload(token).creds).toBeUndefined();
    const plain = await signContextToken(referenceContext(), KEY);
    expect(decodePayload(plain).creds).toBeUndefined();
  });

  it("enforcement DROPS unsigned allowlist keys — a valid token cannot carry an attacker's drive list", async () => {
    // Token from an injector that did not sign creds (an older injector release). The
    // unsigned credentials object names drives/mailboxes the operator never
    // approved. Without the signed claim every one of them would reach the trusted context.
    const token = await signContextToken(referenceContext(), KEY);
    const out = await resolveTrustedContext(
      {
        _token: token,
        credentials: {
          ms365_sharepoint_drive_ids: "VICTIM-DRIVE",
          ms365_mailbox_allowlist: "ceo@example.com",
          ms365_mailbox: "ceo@example.com",
          graph_access_token: "delegated-xyz",
          ms365_app_password: "app-pw",
        },
      },
      KEY,
    );
    expect(out.credentials).toEqual({
      graph_access_token: "delegated-xyz",
      ms365_app_password: "app-pw",
    });
    for (const key of SIGNED_CREDENTIAL_KEYS) {
      expect(out.credentials).not.toHaveProperty(key);
    }
  });

  it("enforcement takes allowlist keys from the SIGNED claim, not the unsigned copy", async () => {
    const token = await signContextToken(
      {
        ...referenceContext(),
        credentials: { ms365_sharepoint_drive_ids: "drive-A", ms365_mailbox: "ops@example.com" },
      },
      KEY,
    );
    const out = await resolveTrustedContext(
      {
        _token: token,
        credentials: {
          ms365_sharepoint_drive_ids: "VICTIM-DRIVE", // rewritten after signing
          ms365_mailbox: "ceo@example.com",
          ms365_mailbox_allowlist: "ceo@example.com", // never signed at all
          graph_access_token: "delegated-xyz",
        },
      },
      KEY,
    );
    expect(out.credentials).toEqual({
      ms365_sharepoint_drive_ids: "drive-A",
      ms365_mailbox: "ops@example.com",
      graph_access_token: "delegated-xyz",
    });
  });

  it("signed creds are attached even when the request carries no credentials object", async () => {
    const token = await signContextToken(
      { ...referenceContext(), credentials: { ms365_mailbox: "ops@example.com" } },
      KEY,
    );
    const out = await resolveTrustedContext({ _token: token }, KEY);
    expect(out.credentials).toEqual({ ms365_mailbox: "ops@example.com" });
    // A second token (the first one's jti is spent) — the raw verifier surfaces it too.
    const token2 = await signContextToken(
      { ...referenceContext(), credentials: { ms365_mailbox: "ops@example.com" } },
      KEY,
    );
    const verified = await verifyContextToken(token2, KEY);
    expect(verified.credentials).toEqual({ ms365_mailbox: "ops@example.com" });
  });

  it("passthrough (no key) is untouched: raw context returned as-is, allowlists included", async () => {
    const raw = { ...referenceContext(), credentials: { ms365_sharepoint_drive_ids: "drive-A" } };
    const out = await resolveTrustedContext(raw, undefined);
    expect(out).toBe(raw);
  });

  it("a non-string contract value in `creds` → invalid_claims", async () => {
    const token = await mintLegacyToken({ creds: { ms365_sharepoint_drive_ids: ["drive-A"] } });
    await expect(verifyContextToken(token, KEY)).rejects.toMatchObject({
      name: "ContextTokenError",
      code: "invalid_claims",
    });
  });

  it("a non-object `creds` → invalid_claims", async () => {
    const token = await mintLegacyToken({ creds: "ms365_sharepoint_drive_ids=drive-A" });
    await expect(verifyContextToken(token, KEY)).rejects.toMatchObject({ code: "invalid_claims" });
  });

  it("unknown keys inside `creds` are ignored (forward-compatible), contract keys lifted", async () => {
    const token = await mintLegacyToken({
      creds: { ms365_mailbox: "ops@example.com", future_key: "whatever" },
    });
    const ctx = await verifyContextToken(token, KEY);
    expect(ctx.credentials).toEqual({ ms365_mailbox: "ops@example.com" });
  });
});

// ───────────────────────────── verifier policy ─────────────────────────────────

describe("verifier policy — jti replay", () => {
  it("signer always mints a unique jti", async () => {
    const a = await signContextToken(referenceContext(), KEY);
    const b = await signContextToken(referenceContext(), KEY);
    const ja = decodePayload(a).jti;
    const jb = decodePayload(b).jti;
    expect(typeof ja).toBe("string");
    expect(ja).toMatch(/^[0-9a-f-]{36}$/);
    expect(ja).not.toBe(jb);
  });

  it("a captured token presented twice is rejected the second time (replayed)", async () => {
    const token = await signContextToken(referenceContext(), KEY);
    const first = await verifyContextToken(token, KEY);
    expect(first.tenant_id).toBe(referenceContext().tenant_id);
    await expect(verifyContextToken(token, KEY)).rejects.toMatchObject({
      name: "ContextTokenError",
      code: "replayed",
    });
    // And through the boundary helper too.
    await expect(resolveTrustedContext({ _token: token }, KEY)).rejects.toMatchObject({
      code: "replayed",
    });
  });

  it("replay is tracked per verifier cache — a token accepted by one server is still fresh at another", async () => {
    const token = await signContextToken(referenceContext(), KEY);
    const serverA = { hs256Secret: KEY, replayCache: createContextReplayCache() };
    const serverB = { hs256Secret: KEY, replayCache: createContextReplayCache() };
    await verifyContextToken(token, serverA);
    await expect(verifyContextToken(token, serverA)).rejects.toMatchObject({ code: "replayed" });
    await expect(verifyContextToken(token, serverB)).resolves.toMatchObject({
      tenant_id: referenceContext().tenant_id,
    });
  });

  it("a token that fails another check does not burn its jti", async () => {
    const cache = createContextReplayCache();
    const token = await signContextToken(referenceContext(), KEY, { jti: "fixed-id" });
    // Wrong audience first → invalid_claims, id must remain unclaimed.
    await expect(
      verifyContextToken(token, { hs256Secret: KEY, replayCache: cache, audience: "other" }),
    ).rejects.toMatchObject({ code: "invalid_claims" });
    await expect(
      verifyContextToken(token, { hs256Secret: KEY, replayCache: cache }),
    ).resolves.toBeTruthy();
  });

  it("legacy id-less tokens stay accepted (and cannot be replay-checked) unless requireJti", async () => {
    const token = await mintLegacyToken();
    await verifyContextToken(token, KEY);
    await verifyContextToken(token, KEY); // no jti → nothing to replay-check
    await expect(
      verifyContextToken(token, { hs256Secret: KEY, requireJti: true }),
    ).rejects.toMatchObject({ code: "invalid_claims" });
  });

  it("an empty/non-string jti → invalid_claims", async () => {
    await expect(verifyContextToken(await mintLegacyToken({ jti: "" }), KEY)).rejects.toMatchObject({
      code: "invalid_claims",
    });
    await expect(verifyContextToken(await mintLegacyToken({ jti: 42 }), KEY)).rejects.toMatchObject({
      code: "invalid_claims",
    });
  });

  it("createContextReplayCache: ids expire and are swept, memory stays bounded", () => {
    const cache = createContextReplayCache();
    const now = 1_000_000;
    expect(cache.claim("a", now + 10, now)).toBe(true);
    expect(cache.claim("a", now + 10, now + 1)).toBe(false); // replay inside lifetime
    expect(cache.claim("a", now + 30, now + 11)).toBe(true); // expired → fresh again
    // Sweep: fill, jump past every expiry, and confirm the old ids are gone.
    for (let i = 0; i < 100; i++) cache.claim(`id-${i}`, now + 20, now + 12);
    const later = now + 20 + CONTEXT_TOKEN_CLOCK_SKEW_SECONDS + 5;
    expect(cache.claim("sweep", later + 10, later)).toBe(true);
    expect(cache.claim("id-0", later + 10, later)).toBe(true); // swept, not a replay
  });
});

describe("verifier policy — audience", () => {
  it("signer sets aud from opts.aud (string or list)", async () => {
    const one = await signContextToken(referenceContext(), KEY, { aud: "mail-mcp" });
    expect(decodePayload(one).aud).toBe("mail-mcp");
    const many = await signContextToken(referenceContext(), KEY, { aud: ["a", "b"] });
    expect(decodePayload(many).aud).toEqual(["a", "b"]);
  });

  it("verifier with an audience rejects a token minted for ANOTHER server", async () => {
    const forOtherServer = await signContextToken(referenceContext(), KEY, { aud: "crm-mcp" });
    await expect(
      verifyContextToken(forOtherServer, { hs256Secret: KEY, audience: "billing-mcp" }),
    ).rejects.toMatchObject({ name: "ContextTokenError", code: "invalid_claims" });
  });

  it("verifier with an audience rejects a token that carries NO aud", async () => {
    const noAud = await signContextToken(referenceContext(), KEY);
    await expect(
      verifyContextToken(noAud, { hs256Secret: KEY, audience: "billing-mcp" }),
    ).rejects.toMatchObject({ code: "invalid_claims" });
  });

  it("verifier with an audience accepts a token naming it (string or list)", async () => {
    const exact = await signContextToken(referenceContext(), KEY, { aud: "billing-mcp" });
    await expect(
      verifyContextToken(exact, { hs256Secret: KEY, audience: "billing-mcp" }),
    ).resolves.toMatchObject({ tenant_id: referenceContext().tenant_id });
    const listed = await signContextToken(referenceContext(), KEY, {
      aud: ["admin-mcp", "billing-mcp"],
    });
    await expect(
      verifyContextToken(listed, { hs256Secret: KEY, audience: "billing-mcp" }),
    ).resolves.toBeTruthy();
  });

  it("no audience configured → aud is not checked (backward compatible)", async () => {
    const token = await signContextToken(referenceContext(), KEY, { aud: "somewhere-else" });
    await expect(verifyContextToken(token, KEY)).resolves.toBeTruthy();
  });

  it("dual-accept verifier: a policy rejection outranks the other key's bad_signature", async () => {
    const kp = await generateContextKeyPair();
    const hsToken = await signContextToken(referenceContext(), KEY, { aud: "crm-mcp" });
    await expect(
      verifyContextToken(hsToken, {
        hs256Secret: KEY,
        publicKey: kp.publicKey,
        audience: "billing-mcp",
      }),
    ).rejects.toMatchObject({ code: "invalid_claims" });
  });
});

describe("verifier policy — issuer allowlist", () => {
  it("accepts a listed issuer, rejects an unlisted or missing one", async () => {
    const policy = { hs256Secret: KEY, issuers: ["web-app", "bot"] };
    await expect(
      verifyContextToken(await signContextToken(referenceContext(), KEY, { iss: "bot" }), policy),
    ).resolves.toBeTruthy();
    await expect(
      verifyContextToken(await signContextToken(referenceContext(), KEY, { iss: "rogue" }), policy),
    ).rejects.toMatchObject({ name: "ContextTokenError", code: "invalid_claims" });
    await expect(
      verifyContextToken(await signContextToken(referenceContext(), KEY), policy),
    ).rejects.toMatchObject({ code: "invalid_claims" });
  });

  it("no issuer list configured → iss is not checked (backward compatible)", async () => {
    await expect(
      verifyContextToken(await signContextToken(referenceContext(), KEY, { iss: "rogue" }), KEY),
    ).resolves.toBeTruthy();
  });
});

describe("verifier policy — env + boot line", () => {
  it("contextVerificationKeysFromEnv reads the policy vars", () => {
    const keys = contextVerificationKeysFromEnv({
      AEGIS_CONTEXT_SIGNING_KEY: KEY,
      AEGIS_CONTEXT_AUDIENCE: " mail-mcp ",
      AEGIS_CONTEXT_ISSUERS: "web-app, bot",
      AEGIS_CONTEXT_REQUIRE_JTI: "true",
    });
    expect(keys).toEqual({
      hs256Secret: KEY,
      audience: "mail-mcp",
      issuers: ["web-app", "bot"],
      requireJti: true,
    });
    expect(
      contextVerificationKeysFromEnv({
        AEGIS_CONTEXT_SIGNING_KEY: KEY,
        AEGIS_CONTEXT_AUDIENCE: "",
        AEGIS_CONTEXT_ISSUERS: "",
        AEGIS_CONTEXT_REQUIRE_JTI: "0",
      }),
    ).toEqual({ hs256Secret: KEY });
  });

  it("env-configured policy is enforced end to end", async () => {
    const keys = contextVerificationKeysFromEnv({
      AEGIS_CONTEXT_SIGNING_KEY: KEY,
      AEGIS_CONTEXT_AUDIENCE: "mail-mcp",
      AEGIS_CONTEXT_ISSUERS: "web-app",
      AEGIS_CONTEXT_REQUIRE_JTI: "1",
    });
    const good = await signContextToken(referenceContext(), KEY, { iss: "web-app", aud: "mail-mcp" });
    await expect(resolveTrustedContext({ _token: good }, keys)).resolves.toMatchObject({
      user_id: referenceContext().user_id,
    });
    const legacy = await mintLegacyToken({}, { iss: "web-app" }); // no aud, no jti
    await expect(resolveTrustedContext({ _token: legacy }, keys)).rejects.toMatchObject({
      code: "invalid_claims",
    });
  });

  it("describeContextEnforcement surfaces the policy on the boot line", () => {
    expect(
      describeContextEnforcement("mail-mcp", {
        hs256Secret: KEY,
        audience: "mail-mcp",
        issuers: ["web-app"],
        requireJti: true,
      }),
    ).toMatchObject({
      mode: "enforced",
      audience: "mail-mcp",
      issuers: ["web-app"],
      requireJti: true,
    });
    const bare = describeContextEnforcement("mail-mcp", KEY);
    expect(bare.requireJti).toBe(false);
    expect(bare.audience).toBeUndefined();
    expect(bare.issuers).toBeUndefined();
  });
});
