/**
 * Structured JSON logger for MCP server observability.
 * Writes to stderr because MCP servers communicate on stdout.
 */

export type LogLevel = "info" | "warn" | "error";

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  request_id?: string;
  [key: string]: unknown;
}

/** Marker substituted for the value of any redacted (sensitive) key. */
export const REDACTED = "[REDACTED]";

/**
 * A key is sensitive if — after normalizing away case and separators
 * (`X-Api-Key`/`x_api_key`/`xApiKey` all compare equal) — it matches an exact
 * known-sensitive name or ends in a secret SUFFIX. Suffix (not substring)
 * matching keeps the breadth — `client_secret`, `proxy_authorization`,
 * `x-api-key`, `secret_key`, `id_token` are all caught — WITHOUT the collisions
 * substring matching caused: `secretary`, `authorization_url`, `has_credentials`,
 * `credential_type`, `public_key`, `idempotency_key` are NOT redacted. Opaque
 * pagination cursors that merely end in `token` are excluded explicitly
 * (paginating API clients log those routinely).
 */
const SECRET_EXACT: ReadonlySet<string> = new Set([
  "credentials",
  "credential",
  "token",
  "jwt",
  "cookie",
  "setcookie",
  "authorization",
  "auth",
  "bearer",
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "secret",
  "sig",
  "signature",
  "sas",
  "session",
  "sessionid",
  "connectionstring",
  "connstr",
  "dsn",
  "databaseurl",
  "dburl",
]);

/**
 * Normalized suffixes that mark a secret. Bare `token`/`key` are deliberately
 * absent — the `*key` family is enumerated (apikey/secretkey/privatekey/…) so
 * `public_key`/`idempotency_key` stay clear, and `token` cursors are excluded
 * by {@link CURSOR_SUFFIXES}.
 */
const SECRET_SUFFIXES: readonly string[] = [
  "token",
  "secret",
  "password",
  "passwd",
  "passphrase",
  "apikey",
  "secretkey",
  "privatekey",
  "signingkey",
  "accesskey",
  "encryptionkey",
  "authorization",
];

/** End in `token` but are opaque pagination cursors, not secrets. */
const CURSOR_SUFFIXES: readonly string[] = [
  "pagetoken",
  "nexttoken",
  "continuationtoken",
  "skiptoken",
  "cursortoken",
];

/** Lowercase and strip every non-alphanumeric separator. */
function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isSensitiveKey(key: string): boolean {
  const k = normalizeKey(key);
  if (CURSOR_SUFFIXES.some((c) => k.endsWith(c))) return false;
  if (SECRET_EXACT.has(k)) return true;
  return SECRET_SUFFIXES.some((s) => k.endsWith(s));
}

/**
 * Redact secrets embedded inside a string VALUE — the classic leak where a full
 * request URL or connection string is logged as a message or plain field, so
 * key-based redaction never sees it. Masks secret query-/semicolon-delimited
 * param values (`?api_key=LIVE`, `;Password=s3cr3t`) and URL userinfo
 * (`postgres://user:PASS@host`), keeping the surrounding shape legible.
 */
const SECRET_PARAM_RE =
  /([?&;](?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|token|password|passwd|pwd|secret|passphrase|authorization|tempauth|sig|signature)=)[^&;\s#"'<>]*/gi;

/**
 * `scheme://user:PASSWORD@host` → mask the password segment. The password class
 * is greedy and allows `@` (so an un-percent-encoded `@` in the password does
 * not truncate the mask), stopping only at the authority boundary (`/`, `?`,
 * `#`, whitespace); the trailing `(@)` then backtracks to the LAST `@` before
 * the host, which is where a URL parser splits userinfo from host.
 */
const USERINFO_RE = /(\/\/[^/:@\s]+:)[^/?#\s]*(@)/g;

function scrubString(value: string): string {
  return value
    .replace(SECRET_PARAM_RE, `$1${REDACTED}`)
    .replace(USERINFO_RE, `$1${REDACTED}$2`);
}

/**
 * Recursively mask the values of known-sensitive keys. A matching key has its
 * entire value replaced with {@link REDACTED} (so a nested `credentials` object
 * is dropped wholesale); non-sensitive keys are preserved and their
 * object/array values are walked. Defensive against `null`, primitives, arrays,
 * and circular references — never throws, always returns a fresh structure so
 * the caller's object is left untouched.
 */
function redactValue(value: unknown, seen: WeakSet<object>): unknown {
  if (typeof value === "string") {
    return scrubString(value);
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  // Break cycles rather than recursing forever. `seen` is kept for the whole
  // walk (NOT pruned on unwind): pruning would give exact DAG handling but
  // re-walks shared nodes once per incoming edge — O(2^depth) on a diamond
  // graph, a hang risk for a shared logger. The cost is that a value referenced
  // by two siblings shows "[Circular]" on its second occurrence; acceptable for
  // log output, and far cheaper than an unbounded walk.
  if (seen.has(value as object)) {
    return "[Circular]";
  }
  seen.add(value as object);

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, seen));
  }

  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    out[key] = isSensitiveKey(key) ? REDACTED : redactValue(val, seen);
  }
  return out;
}

/**
 * Return a copy of `metadata` with the values of known-sensitive keys masked at
 * every depth. Exported so consumers can redact ad-hoc payloads before logging
 * them through any sink, not only via {@link log}.
 */
export function redactSecrets<T>(metadata: T): T {
  return redactValue(metadata, new WeakSet<object>()) as T;
}

/** Alias of {@link redactSecrets} for call sites that think in "metadata". */
export const redactMetadata = redactSecrets;

export function log(
  level: LogLevel,
  message: string,
  metadata?: Record<string, unknown>,
): void {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    // Scrub the message too: it's a free-form string a caller may have built
    // from a URL (`fetch failed: https://…?api_key=LIVE`), which key-based
    // redaction of `metadata` would never reach.
    message: scrubString(message),
    ...(metadata ? redactSecrets(metadata) : undefined),
  };
  // Remove undefined request_id to keep output clean
  if (entry.request_id === undefined || entry.request_id === "") {
    delete entry.request_id;
  }
  process.stderr.write(JSON.stringify(entry) + "\n");
}
