# Security policy

## Supported versions

Only the latest minor release of the current major line receives security
fixes. Upgrade to the newest `1.x` before reporting.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability** at
<https://github.com/Aegis-Pest/mcp-kit/security/advisories/new>.

Include the affected version, a minimal reproduction, and the impact you
believe it has (for example: forged identity, bypassed permission check,
secret leaked into logs). You will get an acknowledgement within five business
days. Fixes ship as a patch release with a CHANGELOG entry that credits the
reporter, unless you ask otherwise.

## Scope

In scope: everything exported from `@aegis-pest/mcp-kit`, in particular the
signed-context verifier (`verifyContextToken`, `resolveTrustedContext`), the
HTTP/SSE transport's bearer check, and the log redaction.

Out of scope: vulnerabilities in the MCP SDK, `jose` or `zod` themselves
(report those upstream), and misconfiguration of a deployment that uses the kit.
