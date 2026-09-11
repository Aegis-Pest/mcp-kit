# @aegis-pest/mcp-kit

[![npm](https://img.shields.io/npm/v/%40aegis-pest%2Fmcp-kit)](https://www.npmjs.com/package/@aegis-pest/mcp-kit)
[![CI](https://github.com/Aegis-Pest/mcp-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Aegis-Pest/mcp-kit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The plumbing an internet-facing [Model Context Protocol](https://modelcontextprotocol.io)
server needs and the SDK does not give you: an HTTP/SSE transport with bearer
auth and one isolated server per connection, a **signed-context** primitive so a
server can verify *who* is calling and *what they may do* instead of trusting
whatever the caller put in the request, a token-bucket rate limiter with an
interactive/background split, a JSON logger that redacts secrets before they
reach stderr, and a wrapper that turns thrown errors into well-formed tool
responses. Every piece is independent; take the ones you need.

- [Install](#install)
- [Quick start](#quick-start)
- [The four seams](#the-four-seams)
  - [1. HTTP/SSE transport](#1-httpsse-transport)
  - [2. Tool handlers and the `ToolResponse` contract](#2-tool-handlers-and-the-toolresponse-contract)
  - [3. Signed context](#3-signed-context)
  - [4. Rate limiter](#4-rate-limiter)
- [Logging](#logging)
- [Context schema](#context-schema)
- [Names that come from the original deployment](#names-that-come-from-the-original-deployment)
- [Versioning policy](#versioning-policy)
- [Security](#security)
- [Reference consumer](#reference-consumer)

## Install

```sh
npm install @aegis-pest/mcp-kit
```

Requirements: **Node 22 or newer**, ESM (`import`, not `require`).

Dependencies, and why they are where they are:

| Package | Kind | Why |
| --- | --- | --- |
| `jose` | runtime dependency | JWT signing/verification and Ed25519 key import/export for the signed-context primitive. |
| `zod` (v4) | runtime dependency | `contextSchema`, the validator for the `_context` argument every tool receives. |
| `@modelcontextprotocol/sdk` | **optional peer dependency** | Only `createHttpTransport` uses it, and only its `SSEServerTransport` class, loaded lazily on first call. A server already has the SDK; a signer (an injector that only mints tokens) does not need it. The range `>=1.23 <2` is the first SDK line that accepts zod v4 schemas. |

## Quick start

A complete server with one tool. Every line after the imports is explained in
the sections below.

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  createHttpTransport,
  createWrapHandler,
  RateLimiter,
  contextSchema,
  contextVerificationKeysFromEnv,
  resolveTrustedContext,
  requirePermission,
  logContextEnforcementMode,
  log,
} from "@aegis-pest/mcp-kit";

const SERVER = "jobs-mcp";
const keys = contextVerificationKeysFromEnv(); // reads AEGIS_CONTEXT_* (see §3)
logContextEnforcementMode(log, SERVER, keys); // one boot line: enforced or passthrough

const wrapHandler = createWrapHandler({
  rateLimiter: new RateLimiter(30, 30), // 30 calls/min to the downstream API
});

function buildServer(): McpServer {
  const server = new McpServer({ name: SERVER, version: "1.0.0" });
  server.registerTool(
    "list_jobs",
    {
      description: "List jobs for the caller's tenant",
      inputSchema: {
        _context: contextSchema,
        status: z.enum(["open", "closed"]).optional(),
      },
    },
    wrapHandler(async ({ _context, status }) => {
      const ctx = await resolveTrustedContext(_context, keys); // throws if forged
      requirePermission(ctx, "jobs", "view"); // throws if not granted
      const jobs = await jobsApi.list({ tenantId: ctx.tenant_id, status });
      return { content: [{ type: "text", text: JSON.stringify(jobs) }] };
    }),
  );
  return server;
}

await createHttpTransport(buildServer, {
  port: Number(process.env.PORT ?? 8080),
  apiSecret: process.env.MCP_API_SECRET!,
  serverName: SERVER,
});
```

## The four seams

### 1. HTTP/SSE transport

```ts
const handle = await createHttpTransport(buildServer, {
  port: 8080,
  apiSecret: process.env.MCP_API_SECRET!,
  serverName: "jobs-mcp",
  maxSessions: 1024,              // optional; default 1024
  sessionIdleTimeoutMs: 30 * 60_000, // optional; default 30 min
});
console.log(`listening on ${handle.port}`); // handle.port is the bound port (useful with port: 0)
// ...
await handle.close(); // stops the idle sweep, closes every session, closes the HTTP server
```

`createHttpTransport(buildServer, config)` binds a Node `http` server that
speaks the MCP HTTP+SSE transport:

| Method and path | Auth | Behaviour |
| --- | --- | --- |
| `GET /sse` | `Authorization: Bearer <apiSecret>` | Opens an SSE stream and a session. **Calls `buildServer()` to create a fresh server for this connection** and connects it. |
| `POST /messages?sessionId=…` | `Authorization: Bearer <apiSecret>` | Delivers a JSON-RPC message to that session. `400` if the session is unknown. |
| `GET /health` | none | `200 {"status":"ok","server":"<serverName>"}` for load balancers and uptime checks. |
| anything else | – | `404`. |

Design points:

- **Per-connection server factory.** An SDK `Server` holds exactly one
  transport binding. If one instance were shared between two SSE clients, the
  second `connect()` would overwrite the first and one user's tool results
  would be written to another user's stream. The factory makes that impossible.
  Passing a bare server instance still works for single-client deployments,
  with a one-time warning in the log.
- **Constant-time bearer check.** The secret is compared with
  `crypto.timingSafeEqual`, never `===`.
- **Bounded sessions.** Sessions are capped (`maxSessions`, least-recently-active
  evicted first) and idle sessions are swept (`sessionIdleTimeoutMs`), so a
  half-open connection that never fires `close` cannot leak a transport forever.
  Evicted transports are always closed.
- **No unhandled rejections.** A throw inside `connect()` or message handling
  becomes a `500` on that request and an `error` log line, not a process crash.
- The bearer secret authenticates the *caller process*. It says nothing about
  the end user; that is what [signed context](#3-signed-context) is for.

This is the HTTP+SSE transport from the 2024-11-05 protocol revision. The newer
Streamable HTTP transport is not implemented yet; it is the first item on the
roadmap and will ship as a new function alongside this one.

### 2. Tool handlers and the `ToolResponse` contract

```ts
const wrapHandler = createWrapHandler({
  rateLimiter,                                  // optional, see §4
  isApiError: (err) => err instanceof JobsApiError, // optional
});

server.registerTool("get_job", { inputSchema: { _context: contextSchema, id: z.string() } },
  wrapHandler(async ({ _context, id }) => {
    const ctx = await resolveTrustedContext(_context, keys);
    requirePermission(ctx, "jobs", "view");
    const job = await jobsApi.get(ctx.tenant_id, id); // may throw JobsApiError(404)
    return { content: [{ type: "text", text: JSON.stringify(job) }] };
  }),
);
```

`wrapHandler(fn)` returns the callback `registerTool` expects. Around your
function it does two things:

1. If a `rateLimiter` was given, `await rateLimiter.acquire()` first, so one
   limiter governs the total rate of every tool on the server.
2. Catch anything thrown and return it as a tool **error response** instead of
   letting it surface as a JSON-RPC failure that ends the model's turn.

A `ToolResponse` is what your handler returns and what the model sees:

```ts
interface ToolResponse {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  [key: string]: unknown; // structuredContent, _meta, ... pass through untouched
}
```

On a throw the response is `{ content: [{ type: "text", text }], isError: true }`
where `text` is `Error: <message>`, or `Error (<status>): <message>` when
`isApiError(err)` returns true and the error carries a numeric `status`. The
message is also logged at `error` level with secrets redacted. A rejected
`resolveTrustedContext` (`ContextTokenError`) or `requirePermission`
(`Permission denied: jobs:view is required`) therefore reaches the model as a
readable error it can act on, and never as a partially-trusted result.

### 3. Signed context

Every tool call carries a `_context` argument saying which tenant and user the
call is for and what they are allowed to do (the [schema](#context-schema)).
The problem: the caller of an MCP server is a process holding the shared
bearer, and anything it puts in `_context` is, from the server's point of view,
just a claim. Signed context makes that claim verifiable. The **injector** (the
process that actually authenticated the user: a web app, a chat bot, a job
runner) mints a short-lived JWT over the authorization fields and attaches it
as `_context._token`. The **verifier** (the MCP server) checks the signature
and rebuilds the context *from the verified claims*, ignoring the unsigned
copy. A leaked bearer no longer lets anyone impersonate anyone.

Two signature modes coexist so a fleet can migrate without downtime:

| Mode | `alg` | Injector holds | Verifier holds | When |
| --- | --- | --- | --- | --- |
| **EdDSA** (target) | `EdDSA` (Ed25519) | private key | public key only | Default for new deployments. A verifier that leaks its key cannot mint tokens. |
| HS256 (legacy) | `HS256` | shared secret | the same shared secret | Kept so existing HS256 injectors keep working during a migration. Every verifier can also mint. |

The verification algorithm is pinned **per key**, never read from the token
header: a public key is only ever tried with `EdDSA`, a shared secret only with
`HS256`. `alg: none`, `HS256`-with-the-public-key-bytes and every other
confusion attack are refused by construction.

#### Verifier side (the MCP server)

```ts
import {
  contextVerificationKeysFromEnv, resolveTrustedContext, requirePermission,
  logContextEnforcementMode, importContextPublicKey, ContextTokenError, log,
} from "@aegis-pest/mcp-kit";

const keys = contextVerificationKeysFromEnv();        // AEGIS_CONTEXT_* from process.env
if (keys.publicKey) await importContextPublicKey(keys.publicKey); // fail fast on a bad key
logContextEnforcementMode(log, "jobs-mcp", keys);      // {"event":"context_enforcement","mode":"enforced",...}

// inside a tool:
const ctx = await resolveTrustedContext(_context, keys); // TrustedContext (= McpToolContext)
requirePermission(ctx, "jobs", "view");
```

`resolveTrustedContext(rawContext, keys)` is the one call at the trust
boundary. Its behaviour is **key-gated**:

| Keys configured | Mode | Behaviour |
| --- | --- | --- |
| none (both env vars unset or empty) | `passthrough` | Returns `rawContext` unchanged. The server trusts the caller exactly as it did before the kit was introduced. Useful for staging a rollout; the boot line logs it at `warn`. |
| public key and/or HS256 secret | `enforced` | `_context._token` is **required**. It is verified, and the returned context is built only from the verified claims. Identity, role, permissions and scopes on the unsigned object are ignored. Throws `ContextTokenError` otherwise. |

`credentials` (runtime API material forwarded to the server: a delegated OAuth
token, an app password) is not signed, because a JWT is signed, not encrypted.
Under enforcement it is preserved verbatim **except** for the keys in
`SIGNED_CREDENTIAL_KEYS`, which are allowlists that decide what a tenant-wide
token may touch and are therefore authorization: those are dropped from the
unsigned object and accepted only from the signed `creds` claim.

Optional verifier **policy**, read from the environment by
`contextVerificationKeysFromEnv()` (or passed on the keys object):

| Env var | Field | Effect |
| --- | --- | --- |
| `AEGIS_CONTEXT_AUDIENCE` | `audience` | Token must carry an `aud` naming this server. Stops a token minted for server A being replayed at server B. |
| `AEGIS_CONTEXT_ISSUERS` | `issuers` | Comma/space list; token must carry an `iss` on it. |
| `AEGIS_CONTEXT_REQUIRE_JTI` | `requireJti` | `1`/`true`: reject tokens without a `jti`. |
| – | `replayCache` | Any token *with* a `jti` is replay-checked: a second presentation within its lifetime is rejected. The default cache is in-process; supply a shared one for cross-replica coverage. |

Error codes on `ContextTokenError.code`: `missing_token`, `missing_key`,
`invalid_key`, `malformed`, `expired`, `bad_signature`, `invalid_claims`,
`replayed`. A caught `ContextTokenError` always means "do not serve this call".

#### Injector side (the process that mints tokens)

Generate one key pair per fleet. The private key is the only minting
capability; keep it in a secrets manager and give it to injectors only.

```ts
import { generateContextKeyPair } from "@aegis-pest/mcp-kit";

const { privateKey, publicKey } = await generateContextKeyPair();
// privateKey: PKCS#8 PEM  -> AEGIS_CONTEXT_SIGNING_PRIVATE_KEY on the injector
// publicKey:  SPKI PEM    -> AEGIS_CONTEXT_SIGNING_PUBLIC_KEY on every verifier
// Either may be stored as-is, with literal "\n" escapes, or base64-encoded whole.
```

Mint a token **per tool call, per target server**, and send it inside
`_context`:

```ts
import { signContextToken, contextSigningKeysFromEnv } from "@aegis-pest/mcp-kit";

const signingKeys = contextSigningKeysFromEnv(); // AEGIS_CONTEXT_SIGNING_PRIVATE_KEY (or _KEY)

const context = {
  tenant_id, user_id, role_name, permissions, scopes, request_id,
  credentials: { graph_access_token: delegatedToken }, // optional
};
const _token = await signContextToken(context, signingKeys, {
  iss: "web-app",      // this injector's name (matches AEGIS_CONTEXT_ISSUERS)
  aud: "jobs-mcp",     // the target server's name (matches its AEGIS_CONTEXT_AUDIENCE)
});
await mcpClient.callTool({ name: "list_jobs", arguments: { status: "open", _context: { ...context, _token } } });
```

The claim contract. Tokens live **120 seconds** (`CONTEXT_TOKEN_TTL_SECONDS`)
with a 5-second clock-skew allowance, so mint at call time and do not cache.
A signer in any language produces exactly this:

| Claim | Type | From | Notes |
| --- | --- | --- | --- |
| `tid` | string | `tenant_id` | required |
| `sub` | string | `user_id` | required |
| `role` | string | `role_name` | required |
| `perms` | object[] | `permissions` | required; same objects as `_context.permissions` |
| `scopes` | object[] | `scopes` | optional; same objects as `_context.scopes` |
| `rid` | string | `request_id` | optional; omit rather than send `null` |
| `iss` | string | injector name | optional; required by verifiers that set `AEGIS_CONTEXT_ISSUERS` |
| `aud` | string or string[] | target server name | optional; required by verifiers that set `AEGIS_CONTEXT_AUDIENCE` |
| `jti` | string | random UUID | always mint one; required by verifiers that set `AEGIS_CONTEXT_REQUIRE_JTI` |
| `creds` | object | the `SIGNED_CREDENTIAL_KEYS` entries of `credentials` | optional; string values only; **never a secret** |
| `iat` | number | now | epoch seconds |
| `exp` | number | `iat + 120` | epoch seconds |

Header: `{ "alg": "EdDSA", "typ": "JWT" }` (or `"HS256"` in legacy mode). The
`alg` string must be exactly `EdDSA`; a verifier refuses `Ed25519` even though
some libraries accept it as an alias.

The same thing in Python, with [PyJWT](https://pyjwt.readthedocs.io/) and the
`cryptography` extra:

```python
import time, uuid, jwt

SIGNED_CREDENTIAL_KEYS = {"ms365_mailbox", "ms365_mailbox_allowlist", "ms365_sharepoint_drive_ids"}

def mint_context_token(ctx: dict, private_key_pem: str, *, iss: str, aud: str) -> str:
    now = int(time.time())
    claims = {
        "tid": ctx["tenant_id"], "sub": ctx["user_id"], "role": ctx["role_name"],
        "perms": ctx["permissions"], "scopes": ctx.get("scopes", []),
        "iss": iss, "aud": aud, "jti": str(uuid.uuid4()),
        "iat": now, "exp": now + 120,
    }
    if ctx.get("request_id"):
        claims["rid"] = ctx["request_id"]
    creds = {k: v for k, v in (ctx.get("credentials") or {}).items() if k in SIGNED_CREDENTIAL_KEYS}
    if creds:
        claims["creds"] = creds
    return jwt.encode(claims, private_key_pem, algorithm="EdDSA")
```

#### Rolling it out

Enforcement is off until a verifier has a key, so the safe order is always
**injectors first**:

1. Injectors start minting `_token` (they are harmless to a verifier with no
   key, which ignores them).
2. Verifiers get `AEGIS_CONTEXT_SIGNING_PUBLIC_KEY`. Check the boot line says
   `"mode":"enforced"` and watch for `ContextTokenError` rejections.
3. Tighten policy one variable at a time: `AEGIS_CONTEXT_AUDIENCE`, then
   `AEGIS_CONTEXT_ISSUERS`, then `AEGIS_CONTEXT_REQUIRE_JTI=1`.

Migrating an HS256 fleet to EdDSA: verifiers add the public key while keeping
the shared secret (they now accept both), injectors switch to the private key,
then the shared secret is removed everywhere.

Environment variables, all read by `contextSigningKeysFromEnv()` /
`contextVerificationKeysFromEnv()` and listed on `CONTEXT_SIGNING_ENV_VARS`:

| Variable | Who | Value |
| --- | --- | --- |
| `AEGIS_CONTEXT_SIGNING_PRIVATE_KEY` | injector | Ed25519 PKCS#8 PEM, or base64 of it |
| `AEGIS_CONTEXT_SIGNING_PUBLIC_KEY` | verifier | Ed25519 SPKI PEM, or base64 of it |
| `AEGIS_CONTEXT_SIGNING_KEY` | both (legacy HS256) | shared secret string |
| `AEGIS_CONTEXT_AUDIENCE` | verifier | this server's name |
| `AEGIS_CONTEXT_ISSUERS` | verifier | comma-separated injector names |
| `AEGIS_CONTEXT_REQUIRE_JTI` | verifier | `1` / `true` |

Both `…FromEnv()` helpers take an optional env-like object, so a deployment
that uses different variable names can map them:
`contextVerificationKeysFromEnv({ AEGIS_CONTEXT_SIGNING_PUBLIC_KEY: process.env.MY_PUBLIC_KEY })`,
or skip the helpers and pass `{ publicKey, audience, ... }` directly.

### 4. Rate limiter

```ts
import { RateLimiter, RateLimiterOverloadError } from "@aegis-pest/mcp-kit";

//                       maxTokens, refill/min, maxWaiters, backgroundReserve
const limiter = new RateLimiter(60,        60,         1000,       20);

await limiter.acquire();                       // interactive: may drain the bucket to 0
await limiter.acquire({ background: true });   // background: never takes the bucket below 20

try {
  await limiter.acquire();
} catch (err) {
  if (err instanceof RateLimiterOverloadError) { /* queue full: shed load */ }
}
```

A token bucket: `maxTokens` capacity, refilled at `refill/min`, `acquire()`
resolves immediately while tokens remain and otherwise waits, FIFO, for the
next refill. Two traffic classes share the one bucket so the downstream API's
total rate is still honoured:

- **Interactive** (default): a user is waiting. May consume every token and is
  always served before background waiters.
- **Background** (`{ background: true }`): a cache warmer, a bulk sync, a
  report. Only consumes tokens **above** `backgroundReserve`, so a bulk job
  paginating thousands of rows can never leave an interactive request starting
  from an empty bucket. With the default reserve of `0` the classes differ only
  in queue priority.

The pending queue is capped at `maxWaiters`; beyond that `acquire()` rejects
with `RateLimiterOverloadError` instead of growing without bound. Timers are
`unref`'d, so a waiting limiter never keeps the process alive on its own.
`availableTokens` and `pendingWaiters` are exposed for tests and metrics.

## Logging

```ts
import { log, redactSecrets } from "@aegis-pest/mcp-kit";

log("info", "job created", { request_id, job_id, api_key: "…" });
// stderr: {"timestamp":"…","level":"info","message":"job created","request_id":"…","job_id":"…","api_key":"[REDACTED]"}

const safe = redactSecrets(payload); // same masking, for any other sink
```

`log(level, message, metadata?)` writes one JSON line to **stderr** (stdout
belongs to the protocol when a server runs over stdio). Before writing it masks
the value of any key that names a secret, at any depth: `credentials`,
`authorization`, `password`, `*_token`, `*_secret`, `*api_key`, `*private_key`,
and so on, matched after normalising case and separators so `X-Api-Key`,
`x_api_key` and `xApiKey` are all caught. Suffix matching keeps
`public_key`, `idempotency_key`, `token_count` and pagination cursors like
`next_page_token` visible. Secrets embedded in *string values* are masked too:
`?api_key=…` query parameters, `;Password=…` connection-string segments and
`scheme://user:PASSWORD@host` userinfo, in the message as well as in metadata.
The walk is cycle-safe and never throws.

## Context schema

The `_context` object every tool call carries. `contextSchema` (zod) validates
it at the SDK boundary; [`src/rbac-schema.json`](src/rbac-schema.json) is the
same contract as JSON Schema for other languages; `McpToolContext` is the
TypeScript type.

```jsonc
{
  "tenant_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",   // uuid, required
  "user_id": "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",     // uuid, required
  "user_email": "alex@example.com",                       // optional, informational
  "role_name": "owner",                                   // required
  "permissions": [                                        // required (may be empty)
    { "resource": "jobs", "action": "view", "granted": true }
  ],
  "scopes": [                                             // optional
    { "scope_type": "company", "scope_ref_id": "c1", "fieldwork_entity": "service_route" }
  ],
  "request_id": "req-abc-123",                            // optional
  "credentials": { "graph_access_token": "…" },           // optional, string values
  "_token": "eyJhbGciOiJFZERTQSIs…"                        // the signed-context JWT (§3)
}
```

| Field | Meaning |
| --- | --- |
| `tenant_id` | The organisation the call is scoped to. Every query the server makes is filtered by it. |
| `user_id` | The end user the call is made on behalf of. |
| `user_email` | Display/lookup email for the user. Never an authorization input. |
| `role_name` | The user's role within the tenant (`owner`, `admin`, `tech`, ...). Informational; permissions are what `requirePermission` checks. |
| `permissions[]` | Effective grants: `{ resource, action, granted }`. `requirePermission(ctx, resource, action)` throws unless a matching entry has `granted: true`. The known values are in `RESOURCE_VALUES` and `ACTION_VALUES`. |
| `scopes[]` | Row-level visibility limits: the user may see only this `company` / `property` / `unit` (`scope_type: "all"` lifts the limit). `scope_ref_id` is the id and `fieldwork_entity` the entity type in the field-service system of record. Empty or absent means the role decides. |
| `request_id` | Correlation id for logs; echoed as `rid` in the token. |
| `credentials` | Runtime API material the server needs to act for the user (a delegated OAuth token, an app password). Carried unsigned, except the `SIGNED_CREDENTIAL_KEYS`. |
| `_token` | The signed-context JWT. Its presence alone confers no trust; only `resolveTrustedContext` does. |

## Names that come from the original deployment

The kit was extracted from a production fleet, and a few identifiers are part
of a wire or deployment contract that running services already depend on.
They are kept deliberately; renaming them would be a breaking change for no
functional gain.

| Kept | Why |
| --- | --- |
| `AEGIS_CONTEXT_*` environment variable names | Every deployed verifier and injector reads them. Both `…FromEnv()` helpers accept an env-like object, so a different naming scheme is a one-line mapping. |
| `SIGNED_CREDENTIAL_KEYS` = `ms365_mailbox`, `ms365_mailbox_allowlist`, `ms365_sharepoint_drive_ids` | The `creds` claim contract, mirrored by existing signers. They only matter if you forward Microsoft 365 allowlists in `credentials`; everything else is untouched. A configurable list is planned as an additive change. |
| `RESOURCE_VALUES` / `ACTION_VALUES` | The permission vocabulary of the platform the kit was built for. `contextSchema` validates `resource` and `action` as plain strings, so a different vocabulary passes through; only the `Resource` / `Action` TypeScript types are narrow. |
| `fieldwork_entity` on scopes, `_context` / `_token` argument names | Wire field names that injectors and verifiers already agree on. |

Nothing in the kit refers to any particular company, host or person; the
`@aegis-pest` scope is the publisher.

## Versioning policy

The package follows [Semantic Versioning](https://semver.org/). The public API
is everything exported from the package entry point **plus the wire contract**:
the `_context` shape, the signed-token claim names and types, the
`AEGIS_CONTEXT_*` variable names, the HTTP endpoints and status codes, and the
field names of the `context_enforcement` boot line.

- **Patch**: bug fixes, dependency bumps, documentation.
- **Minor**: additive changes: new exports, new optional claims or config
  fields, new vocabulary values, a new transport alongside the existing one.
  A verifier on an older minor ignores claims it does not know, so injectors
  may adopt a new minor first.
- **Major**: anything that removes or renames an export, changes an endpoint,
  tightens a verifier default (for example requiring `jti` without opting in),
  or drops a Node line. Such tightenings ship first as opt-in in a minor, then
  become the default in the next major.

Supported Node versions are the current LTS lines (22 and 24 today); dropping
one is a major. Deprecated APIs are marked `@deprecated` and listed in the
[CHANGELOG](CHANGELOG.md) for at least one minor release before removal. Every
release is cut from a `v*` tag by CI with an npm provenance attestation.

## Security

Report vulnerabilities privately through GitHub's
[Report a vulnerability](https://github.com/Aegis-Pest/mcp-kit/security/advisories/new)
form; see [SECURITY.md](SECURITY.md) for scope and response times. Please do
not open public issues for security problems.

Properties the kit is designed to hold, and that the test suite asserts:

- The verification algorithm is pinned per key and never read from the token.
- A verifier holding only a public key cannot mint a token.
- Under enforcement no identity, role, permission, scope or allowlist reaches a
  tool from the unsigned request.
- No secret is ever placed in a JWT payload.
- Secrets in log metadata and messages are masked before they are written.
- The bearer secret is compared in constant time.

## Reference consumer

[`Aegis-Pest/fieldwork-mcp`](https://github.com/Aegis-Pest/fieldwork-mcp) is a
production MCP server built on every seam in this kit (transport, wrapped
handlers, signed context, rate limiter, logger) and the best place to see them
composed. The repository is private at the time of writing; ask the maintainers
for access.

## License

[Apache-2.0](LICENSE). Copyright 2026 Aegis Pest Solutions LLC.
