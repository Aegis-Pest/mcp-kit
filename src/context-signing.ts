/**
 * Signed-context primitive — REFERENCE SIGNER + VERIFIER.
 *
 * An MCP server that trusts a caller-supplied `_context` (identity +
 * permissions) behind a single shared bearer lets any bearer-holder forge
 * identity and permissions. This module closes that hole: the trusted
 * "injector" (whichever process authenticated the user — a web front-end, a
 * chat bot, a job runner) mints a short-lived JWT over the context and attaches
 * it as `_context._token`; servers verify it here and rebuild the
 * identity/permission context FROM THE VERIFIED CLAIMS, discarding the unsigned
 * AUTHORIZATION fields (which are attacker-controllable).
 *
 * ── Two signature modes: HS256 (legacy) and EdDSA (target) ──────────────────
 * `AEGIS_CONTEXT_SIGNING_KEY` is a single **shared HMAC secret**: every verifier
 * that can check a token can also MINT one, so a leak from any component (even
 * the lowest-value MCP server) forges any identity across the whole fleet.
 *
 * The asymmetric mode fixes that. Injectors hold an **Ed25519 PRIVATE key**
 * (`AEGIS_CONTEXT_SIGNING_PRIVATE_KEY`) and mint `alg: "EdDSA"`; verifiers hold
 * only the **PUBLIC key** (`AEGIS_CONTEXT_SIGNING_PUBLIC_KEY`), which cannot
 * mint anything. Both modes coexist so the fleet can migrate without downtime:
 * a verifier configured with BOTH accepts either token type.
 *
 * ── ⛔ No algorithm confusion ───────────────────────────────────────────────
 * The verification algorithm is NEVER derived from the token header. Each
 * configured key is bound to exactly one algorithm before any attacker-supplied
 * bytes are consulted:
 *   - the Ed25519 public key is only ever used with `algorithms: ["EdDSA"]`
 *   - the shared secret is only ever used with `algorithms: ["HS256"]`
 * The public key is imported as an Ed25519 `CryptoKey` and is never converted to
 * HMAC key material, so the classic "sign HS256 with the public key bytes"
 * attack has nothing to bite on; `alg: none` and any other algorithm are refused
 * by the pinned allow-list.
 *
 * ── What is signed vs. carried unsigned ─────────────────────────────────────
 * AUTHORIZATION data is signed: identity (tid/sub/role), grants (perms/scopes)
 * AND the authorization-bearing credential keys listed in
 * {@link SIGNED_CREDENTIAL_KEYS} (`creds` claim). SECRET runtime API material in
 * `_context.credentials` — a delegated OAuth access token, an app password and
 * the like — is NOT signed: a JWT is signed, not encrypted, and would leak the
 * secret. Those keys are preserved verbatim onto the trusted context because
 * they carry no authorization weight — the downstream API validates them
 * independently.
 *
 * ⛔ The line between the two is NOT "secret vs. not secret", it is "does the
 * value decide WHAT the caller may touch". `ms365_sharepoint_drive_ids`,
 * `ms365_mailbox_allowlist` and `ms365_mailbox` are consumed by a Microsoft 365
 * server as the drive/mailbox allowlist and pin for a TENANT-WIDE app-only
 * Graph token — they are authorization, not credentials, so an unsigned copy is
 * an attacker-writable allowlist. Under enforcement {@link resolveTrustedContext}
 * therefore DROPS every {@link SIGNED_CREDENTIAL_KEYS} entry from the unsigned
 * `credentials` object and re-attaches only the values carried in the verified
 * `creds` claim. Consumers keep reading `credentials.<key>` unchanged — the
 * value simply cannot arrive there without a signature any more. Adding a key
 * that scopes access to a new consumer means adding it to that list.
 *
 * ── Audience, issuer and replay ─────────────────────────────────────────────
 * One fleet key pair verifies every server, so without an audience a token
 * minted for one server is equally valid at every other, and without a token
 * id a captured token can be presented again for its whole lifetime.
 *   - `aud`: the signer sets it to the target server's name (`opts.aud`); a
 *     verifier configured with `AEGIS_CONTEXT_AUDIENCE` rejects tokens that do
 *     not name it (or that carry no `aud` at all).
 *   - `iss`: a verifier configured with `AEGIS_CONTEXT_ISSUERS` (comma list)
 *     rejects tokens whose issuer is not on the list.
 *   - `jti`: the signer always mints a fresh random id; a verifier records every
 *     `jti` it accepts until that token's `exp` (+skew) and rejects a second
 *     presentation with `replayed`. The default cache is in-process, so it
 *     covers replays against the SAME replica only; `AEGIS_CONTEXT_REQUIRE_JTI`
 *     makes id-less tokens a rejection once every injector mints one.
 * All three are opt-in on the verifier so the fleet can roll them out injector-
 * first (see the rollout section) — an unconfigured verifier behaves as before.
 *
 * ── Staged rollout (key-gated) ──────────────────────────────────────────────
 * A component with NO configured key NO-OPS:
 *   - injector with no key  → does not mint a token (sends the plain `_context`)
 *   - server with no key    → {@link resolveTrustedContext} returns the raw
 *                             context unchanged (trust-the-caller behavior)
 * Roll out HS256 by setting `AEGIS_CONTEXT_SIGNING_KEY` on the INJECTORS first,
 * then on the SERVERS. Never set a server key before every injector that talks
 * to it is minting, or legitimate calls will be rejected for a missing `_token`.
 *
 * Migrating HS256 → EdDSA (same rule, one extra beat — verifiers accept the new
 * mode BEFORE any injector uses it):
 *   1. Generate one fleet keypair ({@link generateContextKeyPair}).
 *   2. VERIFIERS: add `AEGIS_CONTEXT_SIGNING_PUBLIC_KEY`, keep
 *      `AEGIS_CONTEXT_SIGNING_KEY`. They now dual-accept.
 *   3. INJECTORS: add `AEGIS_CONTEXT_SIGNING_PRIVATE_KEY` (minting flips to
 *      EdDSA; the HS256 secret may stay set, it is simply unused for signing).
 *   4. Once every injector is on EdDSA, remove `AEGIS_CONTEXT_SIGNING_KEY`
 *      everywhere — no verifier can mint after that.
 *
 * Rolling out the `creds` / `aud` / `iss` / `jti` claims — INJECTORS FIRST,
 * always (an old verifier ignores claims it does not know, so minting them
 * early is harmless; a verifier that requires them before every injector mints
 * them rejects legitimate calls):
 *   1. INJECTORS: mint `jti` (always), `aud` = the target server's name (one
 *      token per target), `iss` = the injector's name, and `creds` = the
 *      SIGNED_CREDENTIAL_KEYS entries of the credentials being forwarded.
 *   2. VERIFIERS: upgrade to a library version that drops unsigned
 *      SIGNED_CREDENTIAL_KEYS. ⛔ Do this only after step 1, or every mailbox /
 *      drive allowlist still forwarded unsigned silently disappears and the
 *      consumer falls back to its process-env allowlist (or refuses).
 *   3. VERIFIERS: set `AEGIS_CONTEXT_AUDIENCE=<own name>`,
 *      `AEGIS_CONTEXT_ISSUERS=<injector names>`, then
 *      `AEGIS_CONTEXT_REQUIRE_JTI=1`, checking the boot line and rejection
 *      counts after each.
 *
 * ── The claim contract (authoritative; signers in any language mint to this) ─
 *   alg = "HS256" (shared secret) or "EdDSA" (Ed25519 private key)
 *   tid   : string            tenant_id
 *   sub   : string            user_id
 *   role  : string            role_name
 *   perms : object[]          permissions — same shape as _context.permissions
 *                             ({ resource, action, granted, ... })
 *   scopes: object[]          scopes — same shape as _context.scopes
 *                             ({ scope_type, scope_ref_id, fieldwork_entity })
 *   rid   : string  (opt)     request_id
 *   iss   : string  (opt)     injector name (e.g. "web-app", "bot");
 *                             REQUIRED by verifiers that set AEGIS_CONTEXT_ISSUERS
 *   aud   : string  (opt)     target server name (e.g. "mail-mcp");
 *                             REQUIRED by verifiers that set AEGIS_CONTEXT_AUDIENCE
 *   jti   : string  (opt)     unique token id (random, never reused);
 *                             REQUIRED by verifiers that set AEGIS_CONTEXT_REQUIRE_JTI
 *   creds : object  (opt)     the SIGNED_CREDENTIAL_KEYS entries of
 *                             _context.credentials, string-valued — ONLY those
 *                             keys, NEVER a secret (the JWT is not encrypted)
 *   iat   : number            issued-at, epoch SECONDS
 *   exp   : number            expiry, epoch SECONDS = iat + CONTEXT_TOKEN_TTL_SECONDS
 *
 * {@link signContextToken} is the reference signer — mint from it in TypeScript
 * injectors and mirror it exactly in signers written in other languages.
 */

import {
  SignJWT,
  jwtVerify,
  importPKCS8,
  importSPKI,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  type JWTPayload,
} from "jose";
import { randomUUID } from "node:crypto";
import type {
  McpToolContext,
  RolePermission,
  UserScope,
} from "./rbac.js";

/**
 * JWT signature algorithm for the legacy shared-secret mode.
 *
 * Kept as the historical `CONTEXT_TOKEN_ALG` name for backward compatibility;
 * {@link CONTEXT_TOKEN_ALG_HS256} is the explicit alias.
 */
export const CONTEXT_TOKEN_ALG = "HS256" as const;

/** JWT signature algorithm for the legacy shared-secret (symmetric) mode. */
export const CONTEXT_TOKEN_ALG_HS256 = "HS256" as const;

/** JWT signature algorithm for the Ed25519 (asymmetric) mode. */
export const CONTEXT_TOKEN_ALG_EDDSA = "EdDSA" as const;

/** Token lifetime in seconds. `exp = iat + CONTEXT_TOKEN_TTL_SECONDS`. */
export const CONTEXT_TOKEN_TTL_SECONDS = 120;

/**
 * Clock-skew tolerance (seconds) applied to `exp`/`iat` validation, absorbing
 * small clock differences between the injector and the verifying server.
 */
export const CONTEXT_TOKEN_CLOCK_SKEW_SECONDS = 5;

/** The environment variables this module reads key material from. */
export const CONTEXT_SIGNING_ENV_VARS = {
  /** Shared HS256 secret — legacy symmetric mode (mint AND verify). */
  hs256Secret: "AEGIS_CONTEXT_SIGNING_KEY",
  /** Ed25519 PKCS#8 private key (PEM or base64-of-PEM) — injectors only. */
  privateKey: "AEGIS_CONTEXT_SIGNING_PRIVATE_KEY",
  /** Ed25519 SPKI public key (PEM or base64-of-PEM) — verifiers only. */
  publicKey: "AEGIS_CONTEXT_SIGNING_PUBLIC_KEY",
  /**
   * This verifier's own name (e.g. `mail-mcp`). When set, a token must carry
   * an `aud` claim naming it — a token minted for another server is rejected.
   */
  audience: "AEGIS_CONTEXT_AUDIENCE",
  /**
   * Comma/space-separated issuer allowlist (e.g. `web-app,bot`). When
   * set, a token must carry an `iss` claim on the list.
   */
  issuers: "AEGIS_CONTEXT_ISSUERS",
  /**
   * `1`/`true` ⇒ a token without a `jti` is rejected. Set once every injector
   * mints ids; until then id-less tokens are accepted (and cannot be replay-
   * checked).
   */
  requireJti: "AEGIS_CONTEXT_REQUIRE_JTI",
} as const;

/**
 * The `_context.credentials` keys that are AUTHORIZATION, not credentials: each
 * one decides WHICH mailbox / drives a tenant-wide app-only token may touch.
 * They are signed into the `creds` claim by the injector and, under
 * enforcement, accepted ONLY from that claim — an unsigned copy on the request
 * is dropped by {@link resolveTrustedContext}.
 *
 * ⛔ Never list a secret here: the JWT payload is base64, not encrypted.
 * Signers in other languages mirror this list exactly.
 */
export const SIGNED_CREDENTIAL_KEYS = [
  "ms365_mailbox",
  "ms365_mailbox_allowlist",
  "ms365_sharepoint_drive_ids",
] as const;

/** One of {@link SIGNED_CREDENTIAL_KEYS}. */
export type SignedCredentialKey = (typeof SIGNED_CREDENTIAL_KEYS)[number];

const SIGNED_CREDENTIAL_KEY_SET: ReadonlySet<string> = new Set(
  SIGNED_CREDENTIAL_KEYS,
);

/**
 * The exact claim set carried by a signed context token. This interface is the
 * unambiguous spec signers in other languages replicate. `iat`/`exp` are stamped at
 * signing time; everything else is derived from the {@link McpToolContext}.
 */
export interface SignedContextClaims extends JWTPayload {
  /** tenant_id */
  tid: string;
  /** user_id */
  sub: string;
  /** role_name */
  role: string;
  /** permissions — same array shape as `_context.permissions` */
  perms: RolePermission[];
  /** scopes — same array shape as `_context.scopes` */
  scopes?: UserScope[];
  /** request_id (optional) */
  rid?: string;
  /** injector name (optional), e.g. "web-app" */
  iss?: string;
  /** target server name (optional), e.g. "mail-mcp" — see AEGIS_CONTEXT_AUDIENCE */
  aud?: string | string[];
  /** unique token id (optional) — replay-checked when present */
  jti?: string;
  /**
   * The {@link SIGNED_CREDENTIAL_KEYS} entries of `_context.credentials`
   * (optional). Only those keys, only string values, never a secret.
   */
  creds?: Partial<Record<SignedCredentialKey, string>>;
  /** issued-at, epoch seconds */
  iat: number;
  /** expiry, epoch seconds (= iat + CONTEXT_TOKEN_TTL_SECONDS) */
  exp: number;
}

/**
 * The verified, trustworthy context returned by {@link verifyContextToken} and
 * {@link resolveTrustedContext}. Structurally identical to {@link McpToolContext}
 * so it drops straight into existing server code; the distinct name marks that
 * every field originated from a signature-verified claim (in enforcement mode).
 */
export type TrustedContext = McpToolContext;

/** Machine-readable reason a context token was rejected. */
export type ContextTokenErrorCode =
  | "missing_token" // enforcement on but no `_context._token` present
  | "missing_key" // sign/verify called without any usable key configured
  | "invalid_key" // configured key material could not be parsed/imported
  | "malformed" // not a well-formed JWT / claim shape wrong
  | "expired" // `exp` in the past (beyond skew), or `iat` in the future
  | "bad_signature" // signature did not verify against any configured key
  | "invalid_claims" // signature ok but a required claim is missing/ill-typed/wrong (incl. aud/iss)
  | "replayed"; // signature ok but this `jti` was already accepted by this verifier

/**
 * Typed error thrown on any failure to establish a trusted context. A caught
 * `ContextTokenError` means the context could NOT be trusted — callers must
 * reject the request; never fall back to the unsigned context.
 */
export class ContextTokenError extends Error {
  readonly code: ContextTokenErrorCode;
  constructor(code: ContextTokenErrorCode, message: string) {
    super(message);
    this.name = "ContextTokenError";
    this.code = code;
  }
}

/**
 * Key material an INJECTOR signs with. `privateKey` (Ed25519) wins when both are
 * present. A bare string is the legacy shared HMAC secret.
 */
export interface ContextSigningKeys {
  /** Shared HS256 secret — `AEGIS_CONTEXT_SIGNING_KEY`. */
  hs256Secret?: string;
  /**
   * Ed25519 private key — `AEGIS_CONTEXT_SIGNING_PRIVATE_KEY`. PKCS#8 PEM, or
   * base64 of that PEM (literal `\n` escapes are tolerated).
   */
  privateKey?: string;
}

/**
 * Replay store a verifier records accepted token ids in. `claim` returns
 * `true` when `jti` was not seen before (and records it until `expiresAt`,
 * epoch seconds), `false` when it was — i.e. the token is being replayed.
 * The default ({@link createContextReplayCache}) is in-process; a fleet that
 * runs several replicas of one verifier and wants cross-replica replay
 * protection can supply a shared implementation.
 */
export interface ContextReplayCache {
  claim(jti: string, expiresAt: number, now: number): boolean;
}

/**
 * In-process replay cache: a `Map` of accepted `jti` → expiry, swept lazily so
 * it never holds more than one TTL window of tokens. Memory is bounded by the
 * verifier's own accept rate × (TTL + skew).
 */
export function createContextReplayCache(): ContextReplayCache {
  const seen = new Map<string, number>();
  let nextSweep = 0;
  return {
    claim(jti, expiresAt, now) {
      if (now >= nextSweep) {
        for (const [id, exp] of seen) if (exp <= now) seen.delete(id);
        nextSweep = now + CONTEXT_TOKEN_CLOCK_SKEW_SECONDS + 1;
      }
      const existing = seen.get(jti);
      if (existing !== undefined && existing > now) return false;
      seen.set(jti, expiresAt);
      return true;
    },
  };
}

const defaultReplayCache = createContextReplayCache();

/**
 * Verifier POLICY — which claims a token must carry to be accepted here, on top
 * of a valid signature. Every field is optional and off by default so a
 * verifier that only configures key material behaves exactly as before.
 */
export interface ContextVerificationPolicy {
  /**
   * This verifier's name — `AEGIS_CONTEXT_AUDIENCE`. When set, the token's `aud`
   * MUST include it; a token minted for a different server (or with no `aud`)
   * is rejected with `invalid_claims`.
   */
  audience?: string;
  /**
   * Accepted `iss` values — `AEGIS_CONTEXT_ISSUERS`. When non-empty, the token
   * MUST carry an `iss` on the list; anything else is `invalid_claims`.
   */
  issuers?: string[];
  /**
   * `AEGIS_CONTEXT_REQUIRE_JTI` — when true, a token without a `jti` is
   * `invalid_claims`. Tokens WITH a `jti` are always replay-checked.
   */
  requireJti?: boolean;
  /** Replay store for accepted `jti`s; defaults to the in-process cache. */
  replayCache?: ContextReplayCache;
}

/**
 * Key material a VERIFIER accepts, plus its {@link ContextVerificationPolicy}.
 * Configure both keys during migration to dual-accept EdDSA and HS256. A bare
 * string is the legacy shared HMAC secret (no policy).
 */
export interface ContextVerificationKeys extends ContextVerificationPolicy {
  /** Shared HS256 secret — `AEGIS_CONTEXT_SIGNING_KEY`. */
  hs256Secret?: string;
  /**
   * Ed25519 public key — `AEGIS_CONTEXT_SIGNING_PUBLIC_KEY`. SPKI PEM, or base64
   * of that PEM (literal `\n` escapes are tolerated).
   */
  publicKey?: string;
}

/** A bare string is the legacy shared HMAC secret. */
export type ContextSigningKeyInput = string | ContextSigningKeys;

/** A bare string is the legacy shared HMAC secret; falsy ⇒ enforcement off. */
export type ContextVerificationKeyInput =
  | string
  | ContextVerificationKeys
  | undefined
  | null;

/** The `CryptoKey` type jose hands back from its PEM importers. */
type ContextCryptoKey = Awaited<ReturnType<typeof importSPKI>>;

function keyToSecret(key: string): Uint8Array {
  return new TextEncoder().encode(key);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function normalizeSigningKeys(
  input: ContextSigningKeyInput,
): ContextSigningKeys {
  if (typeof input === "string") {
    return isNonEmptyString(input) ? { hs256Secret: input } : {};
  }
  if (!input || typeof input !== "object") return {};
  const out: ContextSigningKeys = {};
  if (isNonEmptyString(input.hs256Secret)) out.hs256Secret = input.hs256Secret;
  if (isNonEmptyString(input.privateKey)) out.privateKey = input.privateKey;
  return out;
}

function normalizeVerificationKeys(
  input: ContextVerificationKeyInput,
): ContextVerificationKeys {
  if (typeof input === "string") {
    return isNonEmptyString(input) ? { hs256Secret: input } : {};
  }
  if (!input || typeof input !== "object") return {};
  const out: ContextVerificationKeys = {};
  if (isNonEmptyString(input.hs256Secret)) out.hs256Secret = input.hs256Secret;
  if (isNonEmptyString(input.publicKey)) out.publicKey = input.publicKey;
  if (isNonEmptyString(input.audience)) out.audience = input.audience.trim();
  const issuers = Array.isArray(input.issuers)
    ? input.issuers.filter(isNonEmptyString).map((s) => s.trim()).filter(Boolean)
    : [];
  if (issuers.length > 0) out.issuers = issuers;
  if (input.requireJti === true) out.requireJti = true;
  if (input.replayCache) out.replayCache = input.replayCache;
  return out;
}

/** Parse a comma / semicolon / whitespace separated list env var into entries. */
function parseListEnv(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseBoolEnv(raw: string | undefined): boolean {
  if (!raw) return false;
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

/**
 * True when the given verification material turns enforcement ON (i.e. a signed
 * `_token` becomes mandatory). Mirrors exactly what {@link resolveTrustedContext}
 * decides, so servers can log their mode at boot without duplicating the rule.
 */
export function isContextEnforcementEnabled(
  keys: ContextVerificationKeyInput,
): boolean {
  const k = normalizeVerificationKeys(keys);
  return Boolean(k.hs256Secret || k.publicKey);
}

/** Whether a verifier requires a signed `_token` (`enforced`) or trusts the caller's `_context` as sent (`passthrough`). */
export type ContextEnforcementMode = "enforced" | "passthrough";

/**
 * The structured record {@link logContextEnforcementMode} emits — the one line
 * that says, at boot, whether this server is verifying `_context` or passing it
 * through. Stable field names so a log query can find it fleet-wide:
 * `event == "context_enforcement"`.
 */
export interface ContextEnforcementReport {
  event: "context_enforcement";
  /** The server that booted (e.g. `"admin-mcp"`). */
  server: string;
  mode: ContextEnforcementMode;
  /** Which key material decided the mode (never the material itself). */
  reason: string;
  /** JWT algorithms this verifier will accept — empty in passthrough. */
  algorithms: string[];
  /** Required `aud` (AEGIS_CONTEXT_AUDIENCE), when configured. */
  audience?: string;
  /** Accepted `iss` values (AEGIS_CONTEXT_ISSUERS), when configured. */
  issuers?: string[];
  /** Whether id-less tokens are rejected (AEGIS_CONTEXT_REQUIRE_JTI). */
  requireJti: boolean;
}

/** The minimal logger shape — the shared `log()` satisfies it. */
export type ContextEnforcementLogger = (
  level: "info" | "warn",
  message: string,
  metadata?: Record<string, unknown>,
) => void;

/**
 * Describe the enforcement mode the given verification material puts a server
 * in, without logging it. Same rule as {@link isContextEnforcementEnabled} /
 * {@link resolveTrustedContext}; this is the structured form.
 */
export function describeContextEnforcement(
  serverName: string,
  keys: ContextVerificationKeyInput,
): ContextEnforcementReport {
  const k = normalizeVerificationKeys(keys);
  const algorithms: string[] = [];
  if (k.publicKey) algorithms.push(CONTEXT_TOKEN_ALG_EDDSA);
  if (k.hs256Secret) algorithms.push(CONTEXT_TOKEN_ALG_HS256);

  let reason: string;
  if (k.publicKey && k.hs256Secret) {
    reason = "public key present (dual-accept: shared HS256 secret also present)";
  } else if (k.publicKey) {
    reason = "public key present";
  } else if (k.hs256Secret) {
    reason = `shared HS256 secret present (no ${CONTEXT_SIGNING_ENV_VARS.publicKey})`;
  } else {
    reason = `no ${CONTEXT_SIGNING_ENV_VARS.publicKey}`;
  }

  const report: ContextEnforcementReport = {
    event: "context_enforcement",
    server: serverName,
    mode: algorithms.length > 0 ? "enforced" : "passthrough",
    reason,
    algorithms,
    requireJti: k.requireJti === true,
  };
  if (k.audience) report.audience = k.audience;
  if (k.issuers) report.issuers = [...k.issuers];
  return report;
}

/**
 * Log, ONCE at boot, whether this server enforces `_context` signatures.
 *
 * Why this exists: a verifying server and a no-key passthrough look identical
 * on every successful call — `resolveTrustedContext` returns a context either
 * way and nothing on the wire changes. The only observable proof of enforcement
 * was a rejection, so a server that silently lost its key (env drift, a
 * secret-mount miss, a bad deploy) kept answering and nobody could tell it was
 * trusting the caller again. This line makes the mode visible in the boot log.
 *
 * Emits one structured entry with `event: "context_enforcement"`, `server`,
 * `mode` (`"enforced"` | `"passthrough"`), `reason` and `algorithms`. Level is
 * `warn` in passthrough — the state that deserves a look — and `info` when
 * enforced. Never logs key material, only whether it is present.
 *
 * Call it from the server's boot path, before the transport starts:
 * `logContextEnforcementMode(log, "admin-mcp")`. `keys` defaults to
 * {@link contextVerificationKeysFromEnv}, i.e. the same material the context
 * boundary reads — pass it explicitly only if the boundary does.
 *
 * @returns The emitted report, for tests and for servers that also want to
 *          surface it on a health endpoint.
 */
export function logContextEnforcementMode(
  logger: ContextEnforcementLogger,
  serverName: string,
  keys: ContextVerificationKeyInput = contextVerificationKeysFromEnv(),
): ContextEnforcementReport {
  const report = describeContextEnforcement(serverName, keys);
  const { event, ...fields } = report;
  if (report.mode === "enforced") {
    logger("info", "context enforcement ON: _context._token is required and verified", {
      event,
      ...fields,
    });
  } else {
    logger(
      "warn",
      "context enforcement OFF: _context is trusted as sent (passthrough)",
      { event, ...fields },
    );
  }
  return report;
}

type EnvLike = Record<string, string | undefined>;

function defaultEnv(): EnvLike {
  return typeof process !== "undefined" && process?.env ? process.env : {};
}

/**
 * Read INJECTOR key material from the environment
 * (`AEGIS_CONTEXT_SIGNING_PRIVATE_KEY` + `AEGIS_CONTEXT_SIGNING_KEY`). Empty
 * values are treated as unset. Pass the result straight to
 * {@link signContextToken}.
 */
export function contextSigningKeysFromEnv(
  env: EnvLike = defaultEnv(),
): ContextSigningKeys {
  return normalizeSigningKeys({
    hs256Secret: env[CONTEXT_SIGNING_ENV_VARS.hs256Secret],
    privateKey: env[CONTEXT_SIGNING_ENV_VARS.privateKey],
  });
}

/**
 * Read VERIFIER key material from the environment
 * (`AEGIS_CONTEXT_SIGNING_PUBLIC_KEY` + `AEGIS_CONTEXT_SIGNING_KEY`) together
 * with the verifier policy (`AEGIS_CONTEXT_AUDIENCE`, `AEGIS_CONTEXT_ISSUERS`,
 * `AEGIS_CONTEXT_REQUIRE_JTI`). Empty values are treated as unset — with no key
 * set the result carries no key, which keeps {@link resolveTrustedContext} in
 * passthrough (no-op) mode regardless of policy.
 */
export function contextVerificationKeysFromEnv(
  env: EnvLike = defaultEnv(),
): ContextVerificationKeys {
  return normalizeVerificationKeys({
    hs256Secret: env[CONTEXT_SIGNING_ENV_VARS.hs256Secret],
    publicKey: env[CONTEXT_SIGNING_ENV_VARS.publicKey],
    audience: env[CONTEXT_SIGNING_ENV_VARS.audience],
    issuers: parseListEnv(env[CONTEXT_SIGNING_ENV_VARS.issuers]),
    requireJti: parseBoolEnv(env[CONTEXT_SIGNING_ENV_VARS.requireJti]),
  });
}

/**
 * Accept a PEM document supplied either raw, with literal `\n` escapes (how PEMs
 * usually survive a single-line env var), or base64-encoded whole. Returns the
 * normalized PEM text; throws `invalid_key` when it is neither.
 */
function toPem(material: string, label: "PUBLIC KEY" | "PRIVATE KEY"): string {
  const unescaped = material.replace(/\\n/g, "\n").trim();
  if (unescaped.includes("-----BEGIN")) return unescaped;

  // Not PEM — try base64-of-PEM.
  let decoded = "";
  try {
    decoded = Buffer.from(unescaped.replace(/\s+/g, ""), "base64")
      .toString("utf8")
      .replace(/\\n/g, "\n")
      .trim();
  } catch {
    decoded = "";
  }
  if (decoded.includes("-----BEGIN")) return decoded;

  throw new ContextTokenError(
    "invalid_key",
    `context signing ${label.toLowerCase()} is not a PEM document or base64 of one`,
  );
}

// Imported keys are cached by their exact (normalized) PEM text: importing is
// async crypto work and the fleet uses one key for the life of the process.
const publicKeyCache = new Map<string, Promise<ContextCryptoKey>>();
const privateKeyCache = new Map<string, Promise<ContextCryptoKey>>();

function cachedImport(
  cache: Map<string, Promise<ContextCryptoKey>>,
  pem: string,
  load: () => Promise<ContextCryptoKey>,
): Promise<ContextCryptoKey> {
  const hit = cache.get(pem);
  if (hit) return hit;
  const pending = load().catch((err) => {
    cache.delete(pem); // never cache a failed import
    throw err;
  });
  cache.set(pem, pending);
  return pending;
}

/**
 * Import the Ed25519 PUBLIC key a verifier was configured with (SPKI PEM or
 * base64 of it). Exported so servers can validate their configuration at boot —
 * call it once at startup and fail fast rather than discovering a typo on the
 * first tool call. Throws {@link ContextTokenError} (`invalid_key`).
 */
export async function importContextPublicKey(
  material: string,
): Promise<ContextCryptoKey> {
  const pem = toPem(material, "PUBLIC KEY");
  return cachedImport(publicKeyCache, pem, async () => {
    try {
      return await importSPKI(pem, CONTEXT_TOKEN_ALG_EDDSA);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new ContextTokenError(
        "invalid_key",
        `context signing public key is not a usable Ed25519 SPKI key: ${detail}`,
      );
    }
  });
}

/**
 * Import the Ed25519 PRIVATE key an injector was configured with (PKCS#8 PEM or
 * base64 of it). Throws {@link ContextTokenError} (`invalid_key`).
 */
export async function importContextPrivateKey(
  material: string,
): Promise<ContextCryptoKey> {
  const pem = toPem(material, "PRIVATE KEY");
  return cachedImport(privateKeyCache, pem, async () => {
    try {
      return await importPKCS8(pem, CONTEXT_TOKEN_ALG_EDDSA);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new ContextTokenError(
        "invalid_key",
        `context signing private key is not a usable Ed25519 PKCS#8 key: ${detail}`,
      );
    }
  });
}

/**
 * Generate a fresh Ed25519 keypair for the fleet, as PEM strings ready to drop
 * into `AEGIS_CONTEXT_SIGNING_PRIVATE_KEY` (injectors) and
 * `AEGIS_CONTEXT_SIGNING_PUBLIC_KEY` (verifiers).
 *
 * The private key is the ONLY minting capability in the asymmetric mode — store
 * it in your secrets manager and give it to injectors only.
 */
export async function generateContextKeyPair(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  const { privateKey, publicKey } = await generateKeyPair(
    CONTEXT_TOKEN_ALG_EDDSA,
    { crv: "Ed25519", extractable: true },
  );
  return {
    privateKey: await exportPKCS8(privateKey),
    publicKey: await exportSPKI(publicKey),
  };
}

/**
 * Lift the {@link SIGNED_CREDENTIAL_KEYS} entries (string-valued) out of a
 * credentials object. Returns `undefined` when none is present. Every other key
 * — the secrets — is left behind: nothing outside the list ever reaches a JWT.
 */
function pickSignedCredentials(
  credentials: unknown,
): Partial<Record<SignedCredentialKey, string>> | undefined {
  if (!credentials || typeof credentials !== "object") return undefined;
  const out: Partial<Record<SignedCredentialKey, string>> = {};
  let any = false;
  for (const key of SIGNED_CREDENTIAL_KEYS) {
    const v = (credentials as Record<string, unknown>)[key];
    if (typeof v === "string") {
      out[key] = v;
      any = true;
    }
  }
  return any ? out : undefined;
}

/**
 * Mint a signed context token (reference signer).
 *
 * TypeScript injectors call this; signers in other languages mirror it
 * exactly. Produces a JWT carrying {@link SignedContextClaims} with
 * `iat = now` and `exp = now + ttlSeconds`, signed with **EdDSA** when an
 * Ed25519 private key is configured and **HS256** otherwise.
 *
 * @param context Identity + permissions to sign over. When `credentials` is
 *                present, its {@link SIGNED_CREDENTIAL_KEYS} entries (and ONLY
 *                those — never a secret) are signed into the `creds` claim.
 * @param keys    Either the legacy shared HMAC secret as a string
 *                (`AEGIS_CONTEXT_SIGNING_KEY`) or a {@link ContextSigningKeys}
 *                object — see {@link contextSigningKeysFromEnv}. At least one
 *                key must be present.
 * @param opts.iss        Injector name → `iss` claim.
 * @param opts.aud        Target server name(s) → `aud` claim. Mint one token PER
 *                        target so a token for one server is useless at another.
 * @param opts.jti        Token id → `jti` claim. Defaults to a fresh random UUID;
 *                        pass one only to reproduce a token in tests.
 * @param opts.ttlSeconds Token lifetime (default {@link CONTEXT_TOKEN_TTL_SECONDS}).
 * @param opts.now        Override "now" (epoch seconds) — for testing.
 */
export async function signContextToken(
  context: Pick<
    McpToolContext,
    | "tenant_id"
    | "user_id"
    | "role_name"
    | "permissions"
    | "scopes"
    | "request_id"
    | "credentials"
  >,
  keys: ContextSigningKeyInput,
  opts: {
    iss?: string;
    aud?: string | string[];
    jti?: string;
    ttlSeconds?: number;
    now?: number;
  } = {},
): Promise<string> {
  const resolved = normalizeSigningKeys(keys);
  if (!resolved.privateKey && !resolved.hs256Secret) {
    throw new ContextTokenError(
      "missing_key",
      "signContextToken requires a non-empty signing key",
    );
  }
  const ttl = opts.ttlSeconds ?? CONTEXT_TOKEN_TTL_SECONDS;
  const iat = opts.now ?? Math.floor(Date.now() / 1000);
  const exp = iat + ttl;

  const claims: Record<string, unknown> = {
    tid: context.tenant_id,
    sub: context.user_id,
    role: context.role_name,
    perms: context.permissions ?? [],
    scopes: context.scopes ?? [],
  };
  if (context.request_id) claims.rid = context.request_id;
  const creds = pickSignedCredentials(context.credentials);
  if (creds) claims.creds = creds;

  // Asymmetric wins when available: the private key is the strictly stronger
  // credential and is only ever held by injectors.
  const alg = resolved.privateKey
    ? CONTEXT_TOKEN_ALG_EDDSA
    : CONTEXT_TOKEN_ALG_HS256;

  const signer = new SignJWT(claims)
    .setProtectedHeader({ alg, typ: "JWT" })
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    // Always minted: a token without an id cannot be replay-checked.
    .setJti(opts.jti ?? randomUUID());
  if (opts.iss) signer.setIssuer(opts.iss);
  if (opts.aud) signer.setAudience(opts.aud);

  if (resolved.privateKey) {
    return signer.sign(await importContextPrivateKey(resolved.privateKey));
  }
  return signer.sign(keyToSecret(resolved.hs256Secret as string));
}

function mapVerifyError(err: unknown): ContextTokenError {
  if (err instanceof ContextTokenError) return err;
  const code = (err as { code?: string })?.code;
  const detail = err instanceof Error ? err.message : String(err);
  if (code === "ERR_JWT_EXPIRED") {
    return new ContextTokenError("expired", `context token expired: ${detail}`);
  }
  if (code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") {
    return new ContextTokenError(
      "bad_signature",
      `context token signature verification failed: ${detail}`,
    );
  }
  if (code === "ERR_JOSE_ALG_NOT_ALLOWED") {
    return new ContextTokenError(
      "bad_signature",
      `context token uses a disallowed algorithm: ${detail}`,
    );
  }
  if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
    // jose only raises this AFTER the signature verified: a wrong/missing
    // `aud` or `iss` against the configured policy.
    return new ContextTokenError(
      "invalid_claims",
      `context token claim rejected by verifier policy: ${detail}`,
    );
  }
  return new ContextTokenError(
    "malformed",
    `context token could not be verified: ${detail}`,
  );
}

/**
 * When a dual-configured verifier rejects a token, both attempts failed; report
 * the most informative reason ("this token is expired" beats "it isn't mine").
 */
const VERIFY_ERROR_RANK: Record<string, number> = {
  expired: 4,
  invalid_claims: 3, // signature verified, policy (aud/iss) rejected it
  bad_signature: 2,
  malformed: 1,
};

function worseOf(
  a: ContextTokenError | undefined,
  b: ContextTokenError,
): ContextTokenError {
  if (!a) return b;
  return (VERIFY_ERROR_RANK[b.code] ?? 0) > (VERIFY_ERROR_RANK[a.code] ?? 0)
    ? b
    : a;
}

/**
 * Verify a signed context token and return the trusted context built from its
 * verified claims.
 *
 * Each configured key is tried against ITS OWN pinned algorithm — the Ed25519
 * public key only with `EdDSA`, the shared secret only with `HS256` — so the
 * token header can never steer key selection (no `alg` confusion, no
 * `alg: none`, no HMAC-with-the-public-key). `exp`/`iat` are validated with a
 * small clock-skew tolerance ({@link CONTEXT_TOKEN_CLOCK_SKEW_SECONDS}). When
 * the keys carry a {@link ContextVerificationPolicy}, `aud`/`iss` are matched
 * against it (a missing claim is a rejection) and, when `requireJti` is set, an
 * id-less token is rejected; any token carrying a `jti` is replay-checked. On
 * any problem — missing/malformed/expired token, bad signature, a missing/
 * ill-typed/off-policy claim, or a replayed id — throws a
 * {@link ContextTokenError}. It NEVER returns a partially-trusted context.
 *
 * The returned context carries `credentials` ONLY when the token has a `creds`
 * claim, and then only the {@link SIGNED_CREDENTIAL_KEYS} it names.
 *
 * @param token The `_context._token` JWT string.
 * @param keys  Legacy shared HMAC secret as a string, or a
 *              {@link ContextVerificationKeys} object (set both to dual-accept
 *              during the migration; add policy fields to require `aud`/`iss`/
 *              `jti`). At least one key must be present.
 */
export async function verifyContextToken(
  token: string,
  keys: ContextVerificationKeyInput,
): Promise<TrustedContext> {
  const resolved = normalizeVerificationKeys(keys);
  if (!resolved.publicKey && !resolved.hs256Secret) {
    throw new ContextTokenError(
      "missing_key",
      "verifyContextToken requires a non-empty signing key",
    );
  }
  if (!isNonEmptyString(token)) {
    throw new ContextTokenError(
      "malformed",
      "context token is empty or not a string",
    );
  }

  // Bind key material to its algorithm BEFORE looking at the token. A key that
  // cannot be imported is a configuration error and is raised as such — never
  // silently downgraded to the other (weaker) mode.
  const attempts: Array<{ key: ContextCryptoKey | Uint8Array; alg: string }> = [];
  if (resolved.publicKey) {
    attempts.push({
      key: await importContextPublicKey(resolved.publicKey),
      alg: CONTEXT_TOKEN_ALG_EDDSA,
    });
  }
  if (resolved.hs256Secret) {
    attempts.push({
      key: keyToSecret(resolved.hs256Secret),
      alg: CONTEXT_TOKEN_ALG_HS256,
    });
  }

  let payload: JWTPayload | undefined;
  let failure: ContextTokenError | undefined;
  for (const attempt of attempts) {
    try {
      ({ payload } = await jwtVerify(token, attempt.key, {
        algorithms: [attempt.alg], // pinned per key — NEVER read from the header
        clockTolerance: CONTEXT_TOKEN_CLOCK_SKEW_SECONDS,
        // Policy: when configured, jose REQUIRES the claim and matches it.
        ...(resolved.audience ? { audience: resolved.audience } : {}),
        ...(resolved.issuers ? { issuer: resolved.issuers } : {}),
      }));
      failure = undefined;
      break;
    } catch (err) {
      failure = worseOf(failure, mapVerifyError(err));
    }
  }
  if (!payload) {
    throw (
      failure ??
      new ContextTokenError("bad_signature", "context token did not verify")
    );
  }

  // Signature verified. Now assert the required claims are present and well
  // typed, and enforce iat/exp explicitly (jose only checks them when present,
  // and does not reject a future-dated iat).
  const now = Math.floor(Date.now() / 1000);
  const skew = CONTEXT_TOKEN_CLOCK_SKEW_SECONDS;

  if (typeof payload.exp !== "number") {
    throw new ContextTokenError("invalid_claims", "context token missing exp");
  }
  if (typeof payload.iat !== "number") {
    throw new ContextTokenError("invalid_claims", "context token missing iat");
  }
  if (payload.iat > now + skew) {
    throw new ContextTokenError(
      "expired",
      "context token iat is in the future",
    );
  }

  if (!isNonEmptyString(payload.tid)) {
    throw new ContextTokenError("invalid_claims", "context token missing tid");
  }
  if (!isNonEmptyString(payload.sub)) {
    throw new ContextTokenError("invalid_claims", "context token missing sub");
  }
  if (!isNonEmptyString(payload.role)) {
    throw new ContextTokenError("invalid_claims", "context token missing role");
  }
  if (!Array.isArray(payload.perms)) {
    throw new ContextTokenError(
      "invalid_claims",
      "context token perms must be an array",
    );
  }
  if (payload.scopes !== undefined && !Array.isArray(payload.scopes)) {
    throw new ContextTokenError(
      "invalid_claims",
      "context token scopes must be an array when present",
    );
  }
  if (payload.rid !== undefined && typeof payload.rid !== "string") {
    throw new ContextTokenError(
      "invalid_claims",
      "context token rid must be a string when present",
    );
  }
  if (payload.jti !== undefined && !isNonEmptyString(payload.jti)) {
    throw new ContextTokenError(
      "invalid_claims",
      "context token jti must be a non-empty string when present",
    );
  }
  if (resolved.requireJti && payload.jti === undefined) {
    throw new ContextTokenError(
      "invalid_claims",
      "context token missing jti (verifier requires one)",
    );
  }

  // `creds`: only the contract keys are lifted; a contract key that is not a
  // string is a malformed claim. Unknown keys are ignored (an injector may sign
  // a key this verifier does not know yet) — nothing else ever reaches
  // `credentials` from the token.
  let signedCredentials: Partial<Record<SignedCredentialKey, string>> | undefined;
  if (payload.creds !== undefined) {
    const creds = payload.creds;
    if (typeof creds !== "object" || creds === null || Array.isArray(creds)) {
      throw new ContextTokenError(
        "invalid_claims",
        "context token creds must be an object when present",
      );
    }
    for (const key of SIGNED_CREDENTIAL_KEYS) {
      const v = (creds as Record<string, unknown>)[key];
      if (v !== undefined && typeof v !== "string") {
        throw new ContextTokenError(
          "invalid_claims",
          `context token creds.${key} must be a string when present`,
        );
      }
    }
    signedCredentials = pickSignedCredentials(creds);
  }

  // Replay: record the id LAST, once every other check has passed, so a token
  // that fails for another reason never burns its id. A second presentation of
  // an accepted id within its lifetime is a replay.
  if (typeof payload.jti === "string") {
    const cache = resolved.replayCache ?? defaultReplayCache;
    if (!cache.claim(payload.jti, payload.exp + skew, now)) {
      throw new ContextTokenError(
        "replayed",
        "context token jti was already accepted by this verifier",
      );
    }
  }

  const trusted: McpToolContext = {
    tenant_id: payload.tid,
    user_id: payload.sub,
    role_name: payload.role,
    permissions: payload.perms as RolePermission[],
    scopes: (payload.scopes ?? []) as UserScope[],
    request_id: typeof payload.rid === "string" ? payload.rid : "",
  };
  if (signedCredentials) trusted.credentials = signedCredentials;
  return trusted;
}

/**
 * The single helper servers call at their context boundary.
 *
 * - Enforcement ON (at least one key configured): REQUIRE `rawContext._token`,
 *   verify it, and return the context built strictly from the VERIFIED CLAIMS —
 *   the unsigned AUTHORIZATION fields on `rawContext` (identity/role/perms/
 *   scopes) are ignored because they are attacker-controllable, so identity/authz
 *   can NEVER be smuggled through them. `rawContext.credentials` is split in two
 *   (see the module header): the {@link SIGNED_CREDENTIAL_KEYS} entries — the
 *   mailbox/drive allowlists that DECIDE what a tenant-wide token may touch —
 *   are DROPPED from the unsigned object and taken only from the verified
 *   `creds` claim; every other entry (secret runtime API material: a delegated
 *   OAuth access token, an app password) is preserved verbatim so servers that
 *   forward delegated API credentials keep working under enforcement. Throws
 *   {@link ContextTokenError} if `_token` is absent or fails verification.
 * - Enforcement OFF (no keys — unset/empty `AEGIS_CONTEXT_SIGNING_KEY` and
 *   `AEGIS_CONTEXT_SIGNING_PUBLIC_KEY`): returns `rawContext` unchanged
 *   (trust-the-caller behavior). This is the key-gated staging no-op.
 *
 * @param rawContext The incoming `_context` (already shape-validated by
 *                   `contextSchema` upstream). Treated as `unknown` here.
 * @param keys       `AEGIS_CONTEXT_SIGNING_KEY` as a bare string (legacy), or a
 *                   {@link ContextVerificationKeys} object from
 *                   {@link contextVerificationKeysFromEnv}. Falsy/empty ⇒ off.
 */
export async function resolveTrustedContext(
  rawContext: unknown,
  keys: ContextVerificationKeyInput,
): Promise<TrustedContext> {
  const resolved = normalizeVerificationKeys(keys);

  // Enforcement OFF — no-op passthrough.
  if (!resolved.publicKey && !resolved.hs256Secret) {
    return rawContext as TrustedContext;
  }

  // Enforcement ON — a signed token is mandatory.
  if (typeof rawContext !== "object" || rawContext === null) {
    throw new ContextTokenError(
      "missing_token",
      "context enforcement is on but no context object was provided",
    );
  }
  const token = (rawContext as { _token?: unknown })._token;
  if (!isNonEmptyString(token)) {
    throw new ContextTokenError(
      "missing_token",
      "context enforcement is on but _context._token is missing",
    );
  }
  const verified = await verifyContextToken(token, resolved);

  // Credentials: preserve the unsigned SECRET runtime API material verbatim (it
  // carries no authorization weight — the downstream service validates it), but
  // ⛔ never the SIGNED_CREDENTIAL_KEYS — those name WHICH mailbox/drives a
  // tenant-wide token may touch, and the consuming server builds its allowlists
  // from them. They arrive only via the verified `creds` claim; an unsigned
  // copy is dropped here, so a valid token plus a rewritten credentials object
  // cannot widen the operator's allowlist.
  const rawCredentials = (rawContext as { credentials?: unknown }).credentials;
  if (rawCredentials === undefined && verified.credentials === undefined) {
    return verified;
  }
  const credentials: Record<string, string> = {};
  if (rawCredentials && typeof rawCredentials === "object") {
    for (const [key, value] of Object.entries(rawCredentials)) {
      if (!SIGNED_CREDENTIAL_KEY_SET.has(key)) {
        credentials[key] = value as string;
      }
    }
  }
  Object.assign(credentials, verified.credentials ?? {});
  return { ...verified, credentials };
}
