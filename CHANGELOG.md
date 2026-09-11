# Changelog

All notable changes to `@aegis-pest/mcp-kit` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/) and the project adheres
to [Semantic Versioning](https://semver.org/). See the
[versioning policy](README.md#versioning-policy) for what counts as a breaking
change.

## [1.0.0] - 2026-09-11

First public release.

`@aegis-pest/mcp-kit` is the generic plumbing behind a fleet of Model Context
Protocol servers: an HTTP/SSE transport with bearer auth and per-connection
server isolation, a signed-context primitive that lets a server verify *who* is
calling and *what they may do* instead of trusting the caller, a token-bucket
rate limiter with an interactive/background split, a secret-redacting JSON
logger, and a wrapper that turns thrown errors into well-formed tool responses.

### Provenance

The modules in this release were extracted from a private library
(`@aegis-pest/shared` 1.7.0) where they had been running in production behind
four MCP servers. For the modules listed below the exported API is
**compatible with `@aegis-pest/shared` 1.7.x**: a consumer can switch the
import path and keep its code.

| Module | Exports |
| --- | --- |
| `context-signing` | `signContextToken`, `verifyContextToken`, `resolveTrustedContext`, `contextSigningKeysFromEnv`, `contextVerificationKeysFromEnv`, `isContextEnforcementEnabled`, `describeContextEnforcement`, `logContextEnforcementMode`, `generateContextKeyPair`, `importContextPublicKey`, `importContextPrivateKey`, `createContextReplayCache`, `ContextTokenError`, `SIGNED_CREDENTIAL_KEYS`, `CONTEXT_SIGNING_ENV_VARS`, `CONTEXT_TOKEN_*` constants and the associated types |
| `mcp-transport` | `createHttpTransport`, `HttpTransportConfig`, `HttpTransportHandle`, `McpServerLike`, `McpServerFactory` |
| `mcp-wrap-handler` | `createWrapHandler`, `WrapHandlerOptions` |
| `rate-limiter` | `RateLimiter`, `RateLimiterOverloadError` |
| `logger` | `log`, `redactSecrets`, `redactMetadata`, `REDACTED`, `LogLevel`, `LogEntry` |
| `rbac` | `contextSchema`, `requirePermission`, `RESOURCE_VALUES`, `ACTION_VALUES`, `McpToolContext`, `ToolResponse`, `RolePermission`, `UserScope`, `Resource`, `Action`, `ScopeType` |

Not included, by design: the private library's Microsoft Graph client
(`graph-base`). It is specific to one deployment and stays private.

### Changed relative to the private library

- `createWrapHandler`: the ignored second argument of a wrapped handler is
  typed `unknown` instead of `any`. Handlers remain assignable to the MCP SDK's
  `server.tool()` callback type; no caller change is needed.
- `rbac-schema.json` (the language-neutral JSON Schema for `_context`) now
  matches the TypeScript types: it lists every resource and action in
  `RESOURCE_VALUES` / `ACTION_VALUES` and declares the optional `user_email`,
  `credentials` and `_token` fields. A test keeps it in sync from now on.
- `createHttpTransport` logs the port it actually bound (`listening on
  http://localhost:<port>`) instead of the configured one, which is `0` when
  the caller asks for any free port.
- `createWrapHandler` now has its own test suite.
- Comments and tests refer to deployments generically (an "injector", a "mail
  server") rather than to any particular product.

### Packaging

- Published to the public npm registry under the Apache-2.0 license with
  provenance attestations; releases are cut from `v*` tags by GitHub Actions
  using npm trusted publishing.
- ESM only, `exports` map with `types` first, Node 22 or newer.
- Runtime dependencies: `jose` (JWT sign/verify, Ed25519 key handling) and
  `zod` (the `_context` validator). `@modelcontextprotocol/sdk` is an
  *optional* peer dependency, needed only by `createHttpTransport`.
