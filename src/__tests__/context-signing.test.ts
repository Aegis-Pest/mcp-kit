import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import {
  signContextToken,
  verifyContextToken,
  resolveTrustedContext,
  ContextTokenError,
  CONTEXT_TOKEN_ALG,
  CONTEXT_TOKEN_TTL_SECONDS,
} from "../context-signing.js";
import type { McpToolContext } from "../rbac.js";

const KEY = "test-signing-key-do-not-use-in-prod-0123456789";
const secret = new TextEncoder().encode(KEY);

/**
 * Reference claim set — the exact shape a signer in any language mints. Mirrors
 * SignedContextClaims. Kept here as an executable spec so a token minted by
 * another JWT library (PyJWT, say) with these claim names round-trips through
 * verifyContextToken.
 */
function referenceContext(): McpToolContext {
  return {
    tenant_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
    role_name: "owner",
    permissions: [
      { id: "p1", role_id: "r1", resource: "financials", action: "view", granted: true },
      { id: "p2", role_id: "r1", resource: "jobs", action: "modify", granted: true },
    ],
    scopes: [
      { id: "s1", user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22", scope_type: "company", scope_ref_id: "c1", fieldwork_entity: "service_route" },
    ],
    request_id: "req-abc-123",
  };
}

/**
 * Mint a token exactly the way a non-TypeScript signer must, using the
 * low-level jose SignJWT with the literal claim names (tid/sub/role/perms/scopes/rid).
 * This proves the wire contract independently of signContextToken().
 */
async function mintReferenceToken(
  overrides: Record<string, unknown> = {},
  { iat = Math.floor(Date.now() / 1000), ttl = CONTEXT_TOKEN_TTL_SECONDS } = {},
): Promise<string> {
  const ctx = referenceContext();
  const claims: Record<string, unknown> = {
    tid: ctx.tenant_id,
    sub: ctx.user_id,
    role: ctx.role_name,
    perms: ctx.permissions,
    scopes: ctx.scopes,
    rid: ctx.request_id,
    ...overrides,
  };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: CONTEXT_TOKEN_ALG, typ: "JWT" })
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttl)
    .setIssuer("web-app")
    .sign(secret);
}

describe("verifyContextToken", () => {
  it("valid token → correct verified context with claim→field mapping", async () => {
    const token = await mintReferenceToken();
    const ctx = await verifyContextToken(token, KEY);
    const ref = referenceContext();
    expect(ctx.tenant_id).toBe(ref.tenant_id); // tid → tenant_id
    expect(ctx.user_id).toBe(ref.user_id); // sub → user_id
    expect(ctx.role_name).toBe(ref.role_name); // role → role_name
    expect(ctx.permissions).toEqual(ref.permissions); // perms → permissions
    expect(ctx.scopes).toEqual(ref.scopes); // scopes → scopes
    expect(ctx.request_id).toBe(ref.request_id); // rid → request_id
  });

  it("round-trips a token minted by the reference signer", async () => {
    const ref = referenceContext();
    const token = await signContextToken(ref, KEY, { iss: "web-app" });
    const ctx = await verifyContextToken(token, KEY);
    expect(ctx.tenant_id).toBe(ref.tenant_id);
    expect(ctx.user_id).toBe(ref.user_id);
    expect(ctx.role_name).toBe(ref.role_name);
    expect(ctx.permissions).toEqual(ref.permissions);
    expect(ctx.scopes).toEqual(ref.scopes);
    expect(ctx.request_id).toBe(ref.request_id);
  });

  it("defaults scopes to [] and request_id to '' when rid/scopes absent", async () => {
    const iat = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      tid: "t1", sub: "u1", role: "tech", perms: [],
    })
      .setProtectedHeader({ alg: CONTEXT_TOKEN_ALG, typ: "JWT" })
      .setIssuedAt(iat)
      .setExpirationTime(iat + CONTEXT_TOKEN_TTL_SECONDS)
      .sign(secret);
    const ctx = await verifyContextToken(token, KEY);
    expect(ctx.scopes).toEqual([]);
    expect(ctx.request_id).toBe("");
  });

  it("expired token → throws ContextTokenError(expired)", async () => {
    const iat = Math.floor(Date.now() / 1000) - 1000; // well past exp + skew
    const token = await mintReferenceToken({}, { iat, ttl: CONTEXT_TOKEN_TTL_SECONDS });
    await expect(verifyContextToken(token, KEY)).rejects.toMatchObject({
      name: "ContextTokenError",
      code: "expired",
    });
  });

  it("future-dated iat → throws ContextTokenError(expired)", async () => {
    const iat = Math.floor(Date.now() / 1000) + 3600; // an hour ahead
    const token = await mintReferenceToken({}, { iat, ttl: CONTEXT_TOKEN_TTL_SECONDS });
    await expect(verifyContextToken(token, KEY)).rejects.toMatchObject({
      code: "expired",
    });
  });

  it("tampered payload → throws ContextTokenError(bad_signature)", async () => {
    const token = await mintReferenceToken();
    const parts = token.split(".");
    // Re-encode a payload that escalates role to owner-of-another-tenant.
    const forged = Buffer.from(
      JSON.stringify({ tid: "attacker", sub: "attacker", role: "owner", perms: [], exp: 9999999999, iat: 1 }),
    ).toString("base64url");
    const tampered = `${parts[0]}.${forged}.${parts[2]}`;
    await expect(verifyContextToken(tampered, KEY)).rejects.toMatchObject({
      name: "ContextTokenError",
      code: "bad_signature",
    });
  });

  it("wrong key → throws ContextTokenError(bad_signature)", async () => {
    const token = await mintReferenceToken();
    await expect(verifyContextToken(token, "a-different-key")).rejects.toMatchObject({
      code: "bad_signature",
    });
  });

  it("garbage token → throws ContextTokenError(malformed)", async () => {
    await expect(verifyContextToken("not-a-jwt", KEY)).rejects.toMatchObject({
      name: "ContextTokenError",
      code: "malformed",
    });
  });

  it("empty key → throws ContextTokenError(missing_key)", async () => {
    const token = await mintReferenceToken();
    await expect(verifyContextToken(token, "")).rejects.toMatchObject({
      code: "missing_key",
    });
  });

  it("signature ok but missing tid → throws ContextTokenError(invalid_claims)", async () => {
    const iat = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ sub: "u1", role: "tech", perms: [] })
      .setProtectedHeader({ alg: CONTEXT_TOKEN_ALG, typ: "JWT" })
      .setIssuedAt(iat)
      .setExpirationTime(iat + CONTEXT_TOKEN_TTL_SECONDS)
      .sign(secret);
    await expect(verifyContextToken(token, KEY)).rejects.toMatchObject({
      code: "invalid_claims",
    });
  });

  it("rejects a token signed with a disallowed algorithm (alg confusion)", async () => {
    // HS512 instead of the pinned HS256 — must be refused even with the right key.
    const iat = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ tid: "t1", sub: "u1", role: "owner", perms: [] })
      .setProtectedHeader({ alg: "HS512", typ: "JWT" })
      .setIssuedAt(iat)
      .setExpirationTime(iat + CONTEXT_TOKEN_TTL_SECONDS)
      .sign(secret);
    await expect(verifyContextToken(token, KEY)).rejects.toBeInstanceOf(ContextTokenError);
  });

  it("accepts a token within the clock-skew tolerance", async () => {
    // iat 3s in the future — inside the 5s skew allowance.
    const iat = Math.floor(Date.now() / 1000) + 3;
    const token = await mintReferenceToken({}, { iat, ttl: CONTEXT_TOKEN_TTL_SECONDS });
    const ctx = await verifyContextToken(token, KEY);
    expect(ctx.tenant_id).toBe(referenceContext().tenant_id);
  });
});

describe("resolveTrustedContext", () => {
  it("key unset → passthrough returns rawContext unchanged", async () => {
    const raw = { ...referenceContext(), _token: "ignored-when-off", credentials: { realm_id: "9341" } };
    const out = await resolveTrustedContext(raw, undefined);
    expect(out).toBe(raw); // same reference, unchanged
  });

  it("empty-string key → passthrough (staging no-op)", async () => {
    const raw = referenceContext();
    const out = await resolveTrustedContext(raw, "");
    expect(out).toBe(raw);
  });

  it("enforcement on + valid _token → context built from verified claims", async () => {
    const token = await signContextToken(referenceContext(), KEY, { iss: "web-app" });
    // Unsigned structured fields are hostile/forged; they must be IGNORED.
    const raw = {
      tenant_id: "FORGED-TENANT",
      user_id: "FORGED-USER",
      role_name: "FORGED-ROLE",
      permissions: [{ resource: "admin", action: "manage", granted: true }],
      scopes: [],
      request_id: "forged",
      _token: token,
    };
    const out = await resolveTrustedContext(raw, KEY);
    const ref = referenceContext();
    expect(out.tenant_id).toBe(ref.tenant_id);
    expect(out.user_id).toBe(ref.user_id);
    expect(out.role_name).toBe(ref.role_name);
    expect(out.permissions).toEqual(ref.permissions);
    // Forged fields did not leak through.
    expect(out.tenant_id).not.toBe("FORGED-TENANT");
    expect(out.role_name).not.toBe("FORGED-ROLE");
  });

  it("enforcement on preserves unsigned credentials verbatim while trusting only signed authz", async () => {
    const token = await signContextToken(referenceContext(), KEY, { iss: "web-app" });
    // credentials = runtime API material (a delegated OAuth token, a pinned
    // mailbox, an app password). It must survive onto the verified context. The forged authz
    // fields must NOT — including any attempt to smuggle authz via credentials.
    const raw = {
      tenant_id: "FORGED-TENANT",
      role_name: "FORGED-ROLE",
      permissions: [{ resource: "admin", action: "manage", granted: true }],
      credentials: {
        graph_access_token: "delegated-token-xyz",
        enforced_mailbox: "shared@example.com",
        ms365_app_password: "app-pw-abc",
      },
      _token: token,
    };
    const out = await resolveTrustedContext(raw, KEY);
    const ref = referenceContext();
    // Credentials preserved exactly.
    expect(out.credentials).toEqual(raw.credentials);
    expect(out.credentials?.graph_access_token).toBe("delegated-token-xyz");
    // Identity/authz come ONLY from the signed token, never from raw fields.
    expect(out.tenant_id).toBe(ref.tenant_id);
    expect(out.role_name).toBe(ref.role_name);
    expect(out.permissions).toEqual(ref.permissions);
    expect(out.tenant_id).not.toBe("FORGED-TENANT");
    expect(out.role_name).not.toBe("FORGED-ROLE");
    // The forged admin:manage grant did not leak in via credentials or raw perms.
    expect(out.permissions.some((p) => p.resource === "admin" && p.action === "manage")).toBe(false);
  });

  it("enforcement on + no credentials on rawContext → returned context has no credentials", async () => {
    const token = await signContextToken(referenceContext(), KEY);
    const out = await resolveTrustedContext({ _token: token }, KEY);
    expect(out.credentials).toBeUndefined();
  });

  it("enforcement on + missing _token → throws ContextTokenError(missing_token)", async () => {
    const raw = referenceContext(); // no _token
    await expect(resolveTrustedContext(raw, KEY)).rejects.toMatchObject({
      name: "ContextTokenError",
      code: "missing_token",
    });
  });

  it("enforcement on + non-object context → throws missing_token", async () => {
    await expect(resolveTrustedContext(null, KEY)).rejects.toMatchObject({
      code: "missing_token",
    });
  });

  it("enforcement on + tampered _token → throws bad_signature", async () => {
    const token = await mintReferenceToken();
    const parts = token.split(".");
    const forged = Buffer.from(JSON.stringify({ tid: "x", sub: "x", role: "owner", perms: [], exp: 9999999999, iat: 1 })).toString("base64url");
    const raw = { _token: `${parts[0]}.${forged}.${parts[2]}` };
    await expect(resolveTrustedContext(raw, KEY)).rejects.toMatchObject({
      code: "bad_signature",
    });
  });
});
