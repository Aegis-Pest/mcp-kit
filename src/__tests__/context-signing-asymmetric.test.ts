/**
 * Asymmetric (Ed25519 / EdDSA) signed-context tests.
 *
 * The security property under test: an MCP verifier must be able to hold ONLY a
 * PUBLIC key, so a leak from any single verifier can no longer mint tokens for
 * the whole fleet. The HS256 path must keep working byte-for-byte during the
 * migration, and no attacker-supplied header may ever steer key selection.
 */
import { describe, it, expect } from "vitest";
import { SignJWT, importPKCS8 } from "jose";
import {
  signContextToken,
  verifyContextToken,
  resolveTrustedContext,
  generateContextKeyPair,
  contextSigningKeysFromEnv,
  contextVerificationKeysFromEnv,
  isContextEnforcementEnabled,
  importContextPublicKey,
  importContextPrivateKey,
  ContextTokenError,
  CONTEXT_TOKEN_ALG,
  CONTEXT_TOKEN_ALG_EDDSA,
  CONTEXT_TOKEN_ALG_HS256,
  CONTEXT_TOKEN_TTL_SECONDS,
  CONTEXT_SIGNING_ENV_VARS,
} from "../context-signing.js";
import type { McpToolContext } from "../rbac.js";

const HS_KEY = "test-signing-key-do-not-use-in-prod-0123456789";
const hsSecret = new TextEncoder().encode(HS_KEY);

/** One keypair for the whole suite + a second one for "wrong signer" tests. */
const kp = await generateContextKeyPair();
const otherKp = await generateContextKeyPair();

function referenceContext(): McpToolContext {
  return {
    tenant_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
    role_name: "owner",
    permissions: [
      { id: "p1", role_id: "r1", resource: "financials", action: "view", granted: true },
    ],
    scopes: [
      {
        id: "s1",
        user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
        scope_type: "company",
        scope_ref_id: "c1",
        fieldwork_entity: "service_route",
      },
    ],
    request_id: "req-abc-123",
  };
}

function decodeHeader(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
}

describe("key material helpers", () => {
  it("generateContextKeyPair returns a PKCS8 private PEM + SPKI public PEM", async () => {
    expect(kp.privateKey).toContain("-----BEGIN PRIVATE KEY-----");
    expect(kp.publicKey).toContain("-----BEGIN PUBLIC KEY-----");
    // Distinct keypairs each call.
    expect(otherKp.privateKey).not.toBe(kp.privateKey);
  });

  it("accepts raw PEM, base64-of-PEM, and \\n-escaped PEM for both key kinds", async () => {
    const b64Priv = Buffer.from(kp.privateKey, "utf8").toString("base64");
    const b64Pub = Buffer.from(kp.publicKey, "utf8").toString("base64");
    const escPriv = kp.privateKey.replace(/\n/g, "\\n");
    const escPub = kp.publicKey.replace(/\n/g, "\\n");

    for (const priv of [kp.privateKey, b64Priv, escPriv]) {
      for (const pub of [kp.publicKey, b64Pub, escPub]) {
        const token = await signContextToken(referenceContext(), { privateKey: priv });
        const ctx = await verifyContextToken(token, { publicKey: pub });
        expect(ctx.tenant_id).toBe(referenceContext().tenant_id);
      }
    }
  });

  it("importContextPublicKey / importContextPrivateKey reject junk with ContextTokenError", async () => {
    await expect(importContextPublicKey("not-a-key")).rejects.toBeInstanceOf(ContextTokenError);
    await expect(importContextPrivateKey("not-a-key")).rejects.toBeInstanceOf(ContextTokenError);
    // A public key is not a private key and vice versa.
    await expect(importContextPrivateKey(kp.publicKey)).rejects.toBeInstanceOf(ContextTokenError);
    await expect(importContextPublicKey(kp.privateKey)).rejects.toBeInstanceOf(ContextTokenError);
  });
});

describe("EdDSA round-trip", () => {
  it("mints with the private key and verifies with the public key", async () => {
    const ref = referenceContext();
    const token = await signContextToken(ref, { privateKey: kp.privateKey }, { iss: "web-app" });
    expect(decodeHeader(token).alg).toBe(CONTEXT_TOKEN_ALG_EDDSA);

    const ctx = await verifyContextToken(token, { publicKey: kp.publicKey });
    expect(ctx.tenant_id).toBe(ref.tenant_id);
    expect(ctx.user_id).toBe(ref.user_id);
    expect(ctx.role_name).toBe(ref.role_name);
    expect(ctx.permissions).toEqual(ref.permissions);
    expect(ctx.scopes).toEqual(ref.scopes);
    expect(ctx.request_id).toBe(ref.request_id);
  });

  it("prefers EdDSA when BOTH a private key and an HS256 secret are configured", async () => {
    const token = await signContextToken(referenceContext(), {
      privateKey: kp.privateKey,
      hs256Secret: HS_KEY,
    });
    expect(decodeHeader(token).alg).toBe(CONTEXT_TOKEN_ALG_EDDSA);
    // and it is genuinely asymmetric: the HS256-only verifier must NOT take it.
    await expect(verifyContextToken(token, HS_KEY)).rejects.toBeInstanceOf(ContextTokenError);
  });

  it("resolveTrustedContext enforces with only a public key configured", async () => {
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey });
    const raw = {
      tenant_id: "FORGED-TENANT",
      role_name: "FORGED-ROLE",
      permissions: [{ resource: "admin", action: "manage", granted: true }],
      credentials: { graph_access_token: "delegated-xyz" },
      _token: token,
    };
    const out = await resolveTrustedContext(raw, { publicKey: kp.publicKey });
    expect(out.tenant_id).toBe(referenceContext().tenant_id);
    expect(out.role_name).toBe("owner");
    expect(out.credentials).toEqual({ graph_access_token: "delegated-xyz" });
    expect(out.permissions.some((p) => p.resource === "admin")).toBe(false);
  });

  it("public-key-only verifier + missing _token → missing_token", async () => {
    await expect(
      resolveTrustedContext(referenceContext(), { publicKey: kp.publicKey }),
    ).rejects.toMatchObject({ code: "missing_token" });
  });
});

describe("HS256 regression (must be untouched)", () => {
  it("legacy string key still mints + verifies HS256", async () => {
    const ref = referenceContext();
    const token = await signContextToken(ref, HS_KEY, { iss: "web-app" });
    expect(decodeHeader(token).alg).toBe(CONTEXT_TOKEN_ALG); // "HS256"
    expect(CONTEXT_TOKEN_ALG).toBe(CONTEXT_TOKEN_ALG_HS256);
    const ctx = await verifyContextToken(token, HS_KEY);
    expect(ctx.tenant_id).toBe(ref.tenant_id);
  });

  it("object form { hs256Secret } is equivalent to the legacy string", async () => {
    const token = await signContextToken(referenceContext(), { hs256Secret: HS_KEY });
    expect(decodeHeader(token).alg).toBe("HS256");
    const ctx = await verifyContextToken(token, { hs256Secret: HS_KEY });
    expect(ctx.tenant_id).toBe(referenceContext().tenant_id);
  });

  it("default config (only the HS256 secret set) behaves exactly as before", async () => {
    const env = { AEGIS_CONTEXT_SIGNING_KEY: HS_KEY } as Record<string, string | undefined>;
    const verifyKeys = contextVerificationKeysFromEnv(env);
    const signKeys = contextSigningKeysFromEnv(env);
    expect(verifyKeys).toEqual({ hs256Secret: HS_KEY });
    expect(signKeys).toEqual({ hs256Secret: HS_KEY });
    expect(isContextEnforcementEnabled(verifyKeys)).toBe(true);

    const token = await signContextToken(referenceContext(), signKeys);
    expect(decodeHeader(token).alg).toBe("HS256");
    const out = await resolveTrustedContext({ _token: token }, verifyKeys);
    expect(out.tenant_id).toBe(referenceContext().tenant_id);

    // ...and an EdDSA token is refused, because no public key is configured.
    const eddsa = await signContextToken(referenceContext(), { privateKey: kp.privateKey });
    await expect(resolveTrustedContext({ _token: eddsa }, verifyKeys)).rejects.toBeInstanceOf(
      ContextTokenError,
    );
  });

  it("no keys at all → passthrough, same object reference (staging no-op)", async () => {
    const raw = { ...referenceContext(), _token: "ignored" };
    expect(await resolveTrustedContext(raw, undefined)).toBe(raw);
    expect(await resolveTrustedContext(raw, "")).toBe(raw);
    expect(await resolveTrustedContext(raw, {})).toBe(raw);
    expect(await resolveTrustedContext(raw, { hs256Secret: "", publicKey: "" })).toBe(raw);
    expect(await resolveTrustedContext(raw, contextVerificationKeysFromEnv({}))).toBe(raw);
    expect(isContextEnforcementEnabled(undefined)).toBe(false);
    expect(isContextEnforcementEnabled({})).toBe(false);
  });

  it("no verification key → missing_key from verifyContextToken", async () => {
    const token = await signContextToken(referenceContext(), HS_KEY);
    await expect(verifyContextToken(token, {})).rejects.toMatchObject({ code: "missing_key" });
    await expect(verifyContextToken(token, "")).rejects.toMatchObject({ code: "missing_key" });
  });

  it("no signing key → missing_key from signContextToken", async () => {
    await expect(signContextToken(referenceContext(), {})).rejects.toMatchObject({
      code: "missing_key",
    });
    await expect(signContextToken(referenceContext(), "")).rejects.toMatchObject({
      code: "missing_key",
    });
  });
});

describe("dual-accept during migration", () => {
  const dual = () => ({ hs256Secret: HS_KEY, publicKey: kp.publicKey });

  it("accepts an EdDSA token", async () => {
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey });
    const ctx = await verifyContextToken(token, dual());
    expect(ctx.tenant_id).toBe(referenceContext().tenant_id);
  });

  it("accepts an HS256 token", async () => {
    const token = await signContextToken(referenceContext(), HS_KEY);
    const ctx = await verifyContextToken(token, dual());
    expect(ctx.tenant_id).toBe(referenceContext().tenant_id);
  });

  it("accepts either through resolveTrustedContext", async () => {
    for (const keys of [{ privateKey: kp.privateKey }, { hs256Secret: HS_KEY }]) {
      const token = await signContextToken(referenceContext(), keys);
      const out = await resolveTrustedContext({ _token: token }, dual());
      expect(out.user_id).toBe(referenceContext().user_id);
    }
  });

  it("still rejects a token signed with neither configured key", async () => {
    const token = await signContextToken(referenceContext(), { privateKey: otherKp.privateKey });
    await expect(verifyContextToken(token, dual())).rejects.toMatchObject({
      code: "bad_signature",
    });
    const hsToken = await signContextToken(referenceContext(), "some-other-hs-secret");
    await expect(verifyContextToken(hsToken, dual())).rejects.toMatchObject({
      code: "bad_signature",
    });
  });

  it("reports 'expired' (not 'bad_signature') for an expired EdDSA token on a dual verifier", async () => {
    const iat = Math.floor(Date.now() / 1000) - 10_000;
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey }, { now: iat });
    await expect(verifyContextToken(token, dual())).rejects.toMatchObject({ code: "expired" });
  });
});

describe("⛔ algorithm confusion", () => {
  async function hmacToken(secretBytes: Uint8Array, alg = "HS256"): Promise<string> {
    const ref = referenceContext();
    const iat = Math.floor(Date.now() / 1000);
    return new SignJWT({
      tid: "ATTACKER-TENANT",
      sub: "ATTACKER",
      role: "owner",
      perms: [{ resource: "admin", action: "manage", granted: true }],
      scopes: [],
      rid: ref.request_id,
    })
      .setProtectedHeader({ alg, typ: "JWT" })
      .setIssuedAt(iat)
      .setExpirationTime(iat + CONTEXT_TOKEN_TTL_SECONDS)
      .sign(secretBytes);
  }

  it("HS256 token HMAC-signed with the PUBLIC KEY (PEM text) is rejected by an EdDSA verifier", async () => {
    const token = await hmacToken(new TextEncoder().encode(kp.publicKey));
    await expect(verifyContextToken(token, { publicKey: kp.publicKey })).rejects.toBeInstanceOf(
      ContextTokenError,
    );
    await expect(
      resolveTrustedContext({ _token: token }, { publicKey: kp.publicKey }),
    ).rejects.toBeInstanceOf(ContextTokenError);
  });

  it("HS256 token HMAC-signed with public-key variants (trimmed PEM / base64 / raw DER) is rejected", async () => {
    const pemTrimmed = kp.publicKey.trim();
    const b64OfPem = Buffer.from(kp.publicKey, "utf8").toString("base64");
    const derBody = kp.publicKey
      .replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "")
      .replace(/\s+/g, "");
    const rawDer = new Uint8Array(Buffer.from(derBody, "base64"));
    const variants: Uint8Array[] = [
      new TextEncoder().encode(pemTrimmed),
      new TextEncoder().encode(b64OfPem),
      new TextEncoder().encode(derBody),
      rawDer,
    ];
    for (const v of variants) {
      const token = await hmacToken(v);
      await expect(verifyContextToken(token, { publicKey: kp.publicKey })).rejects.toBeInstanceOf(
        ContextTokenError,
      );
      // ...and on a dual-configured verifier the real HS256 secret must not save it either.
      await expect(
        verifyContextToken(token, { publicKey: kp.publicKey, hs256Secret: HS_KEY }),
      ).rejects.toBeInstanceOf(ContextTokenError);
    }
  });

  it("alg:none is rejected (EdDSA, HS256, and dual verifiers)", async () => {
    const iat = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        tid: "ATTACKER",
        sub: "ATTACKER",
        role: "owner",
        perms: [{ resource: "admin", action: "manage", granted: true }],
        iat,
        exp: iat + 3600,
      }),
    ).toString("base64url");
    const token = `${header}.${payload}.`;
    for (const keys of [
      { publicKey: kp.publicKey },
      { hs256Secret: HS_KEY },
      { publicKey: kp.publicKey, hs256Secret: HS_KEY },
    ]) {
      await expect(verifyContextToken(token, keys)).rejects.toBeInstanceOf(ContextTokenError);
    }
  });

  it("a token signed by a DIFFERENT Ed25519 private key is rejected", async () => {
    const token = await signContextToken(referenceContext(), { privateKey: otherKp.privateKey });
    await expect(verifyContextToken(token, { publicKey: kp.publicKey })).rejects.toMatchObject({
      code: "bad_signature",
    });
  });

  it("an EdDSA token is rejected when only the HS256 secret is configured", async () => {
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey });
    await expect(verifyContextToken(token, HS_KEY)).rejects.toBeInstanceOf(ContextTokenError);
  });

  it("an HS256 token is rejected when only the public key is configured", async () => {
    const token = await signContextToken(referenceContext(), HS_KEY);
    await expect(verifyContextToken(token, { publicKey: kp.publicKey })).rejects.toBeInstanceOf(
      ContextTokenError,
    );
  });

  it("the EdDSA alg name is pinned exactly — a valid Ed25519 signature under the 'Ed25519' header name is refused", async () => {
    // jose also knows "Ed25519" as an alg identifier. The allow-list is exactly
    // ["EdDSA"], so even a cryptographically valid signature is refused when the
    // header does not say what the contract says. Documents the pinning.
    const iat = Math.floor(Date.now() / 1000);
    const priv = await importPKCS8(kp.privateKey, "Ed25519");
    const token = await new SignJWT({ tid: "t1", sub: "u1", role: "owner", perms: [] })
      .setProtectedHeader({ alg: "Ed25519", typ: "JWT" })
      .setIssuedAt(iat)
      .setExpirationTime(iat + CONTEXT_TOKEN_TTL_SECONDS)
      .sign(priv);
    await expect(verifyContextToken(token, { publicKey: kp.publicKey })).rejects.toMatchObject({
      code: "bad_signature",
    });
  });

  it("a misconfigured public key fails loudly (invalid_key) — never a silent downgrade to HS256", async () => {
    const token = await signContextToken(referenceContext(), HS_KEY);
    // The operator pasted the PRIVATE key (or junk) into the public-key var while
    // the HS256 secret is still set. The HS256 token must NOT be quietly accepted.
    for (const bad of ["not-a-key", kp.privateKey]) {
      await expect(
        verifyContextToken(token, { publicKey: bad, hs256Secret: HS_KEY }),
      ).rejects.toMatchObject({ code: "invalid_key" });
      await expect(
        resolveTrustedContext({ _token: token }, { publicKey: bad, hs256Secret: HS_KEY }),
      ).rejects.toMatchObject({ code: "invalid_key" });
    }
  });

  it("a tampered EdDSA payload is rejected", async () => {
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey });
    const parts = token.split(".");
    const forged = Buffer.from(
      JSON.stringify({ tid: "x", sub: "x", role: "owner", perms: [], exp: 9999999999, iat: 1 }),
    ).toString("base64url");
    await expect(
      verifyContextToken(`${parts[0]}.${forged}.${parts[2]}`, { publicKey: kp.publicKey }),
    ).rejects.toMatchObject({ code: "bad_signature" });
  });

  it("ES256/HS512 header variants are rejected by the EdDSA verifier", async () => {
    const es = await hmacToken(hsSecret, "HS512");
    await expect(verifyContextToken(es, { publicKey: kp.publicKey })).rejects.toBeInstanceOf(
      ContextTokenError,
    );
    // Also rejected on a dual verifier that holds the very secret it was signed with.
    await expect(
      verifyContextToken(es, { publicKey: kp.publicKey, hs256Secret: HS_KEY }),
    ).rejects.toBeInstanceOf(ContextTokenError);
  });
});

describe("exp / iat / skew under EdDSA", () => {
  const pub = () => ({ publicKey: kp.publicKey });

  it("expired token → expired", async () => {
    const iat = Math.floor(Date.now() / 1000) - 1000;
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey }, { now: iat });
    await expect(verifyContextToken(token, pub())).rejects.toMatchObject({ code: "expired" });
  });

  it("future-dated iat → expired", async () => {
    const iat = Math.floor(Date.now() / 1000) + 3600;
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey }, { now: iat });
    await expect(verifyContextToken(token, pub())).rejects.toMatchObject({ code: "expired" });
  });

  it("within the clock-skew tolerance → accepted", async () => {
    const iat = Math.floor(Date.now() / 1000) + 3;
    const token = await signContextToken(referenceContext(), { privateKey: kp.privateKey }, { now: iat });
    const ctx = await verifyContextToken(token, pub());
    expect(ctx.tenant_id).toBe(referenceContext().tenant_id);
  });

  it("signature ok but missing tid → invalid_claims (never a partial context)", async () => {
    const iat = Math.floor(Date.now() / 1000);
    const priv = await importPKCS8(kp.privateKey, "EdDSA");
    const token = await new SignJWT({ sub: "u1", role: "tech", perms: [] })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuedAt(iat)
      .setExpirationTime(iat + CONTEXT_TOKEN_TTL_SECONDS)
      .sign(priv);
    await expect(verifyContextToken(token, pub())).rejects.toMatchObject({
      code: "invalid_claims",
    });
  });

  it("garbage token → malformed", async () => {
    await expect(verifyContextToken("not-a-jwt", pub())).rejects.toMatchObject({
      code: "malformed",
    });
  });
});

describe("env wiring", () => {
  it("reads the six documented env vars", async () => {
    expect(CONTEXT_SIGNING_ENV_VARS).toEqual({
      hs256Secret: "AEGIS_CONTEXT_SIGNING_KEY",
      privateKey: "AEGIS_CONTEXT_SIGNING_PRIVATE_KEY",
      publicKey: "AEGIS_CONTEXT_SIGNING_PUBLIC_KEY",
      audience: "AEGIS_CONTEXT_AUDIENCE",
      issuers: "AEGIS_CONTEXT_ISSUERS",
      requireJti: "AEGIS_CONTEXT_REQUIRE_JTI",
    });
    const env = {
      AEGIS_CONTEXT_SIGNING_KEY: HS_KEY,
      AEGIS_CONTEXT_SIGNING_PRIVATE_KEY: kp.privateKey,
      AEGIS_CONTEXT_SIGNING_PUBLIC_KEY: kp.publicKey,
    };
    expect(contextSigningKeysFromEnv(env)).toEqual({
      hs256Secret: HS_KEY,
      privateKey: kp.privateKey,
    });
    expect(contextVerificationKeysFromEnv(env)).toEqual({
      hs256Secret: HS_KEY,
      publicKey: kp.publicKey,
    });

    // End-to-end through the env helpers: injector mints, verifier accepts.
    const token = await signContextToken(referenceContext(), contextSigningKeysFromEnv(env));
    expect(decodeHeader(token).alg).toBe("EdDSA");
    const out = await resolveTrustedContext({ _token: token }, contextVerificationKeysFromEnv(env));
    expect(out.user_id).toBe(referenceContext().user_id);
  });

  it("empty env values are treated as unset", () => {
    const env = {
      AEGIS_CONTEXT_SIGNING_KEY: "",
      AEGIS_CONTEXT_SIGNING_PRIVATE_KEY: "",
      AEGIS_CONTEXT_SIGNING_PUBLIC_KEY: "",
    };
    expect(contextSigningKeysFromEnv(env)).toEqual({});
    expect(contextVerificationKeysFromEnv(env)).toEqual({});
    expect(isContextEnforcementEnabled(contextVerificationKeysFromEnv(env))).toBe(false);
  });
});
