import { z } from "zod";

// --- Resource & Action vocabulary ---

// The permission vocabulary. It mirrors the CHECK constraints on the platform's
// `role_permissions` table, which is the source of truth; `rbac-schema.json`
// carries the same lists for other languages. `contextSchema` deliberately
// validates `resource`/`action` as plain strings so a context minted by a newer
// platform still parses — but a tool that `z.enum()`s these constants rejects
// values it does not know, so widen the list here when the platform widens it.
export const RESOURCE_VALUES = [
  "contacts", "jobs", "financials", "internal_notes", "external_notes",
  "scheduling", "reports", "admin", "email", "issues", "receipts", "inventory",
] as const;

export type Resource = (typeof RESOURCE_VALUES)[number];

export const ACTION_VALUES = [
  "view", "add", "modify", "delete", "send", "manage",
  // expense / receipt workflow actions
  "submit", "submit_card", "submit_reimbursement", "use_shared_card",
  "review", "post", "view_own", "view_all",
] as const;

export type Action = (typeof ACTION_VALUES)[number];

// --- RBAC interfaces ---

export interface RolePermission {
  id: string;
  role_id: string;
  resource: Resource;
  action: Action;
  granted: boolean;
}

export type ScopeType = "all" | "company" | "property" | "unit";

export interface UserScope {
  id: string;
  user_id: string;
  scope_type: ScopeType;
  scope_ref_id: string;
  fieldwork_entity: string;
}

// --- MCP Tool Context (the identity + authorization envelope on every call) ---

export interface McpToolContext {
  tenant_id: string;
  user_id: string;
  user_email?: string;
  role_name: string;
  scopes: UserScope[];
  request_id: string;
  permissions: RolePermission[];
  /**
   * Runtime API material forwarded by the injector (e.g. a delegated OAuth
   * access token, an app password). These are NOT authorization data — the
   * downstream API validates them independently — so they are intentionally
   * carried UNSIGNED and preserved verbatim by `resolveTrustedContext` under
   * enforcement. The exception is the `SIGNED_CREDENTIAL_KEYS` (allowlists that
   * decide what a tenant-wide token may touch), which are accepted only from
   * the signed token. See context-signing.ts.
   */
  credentials?: Record<string, string>;
}

// --- Permission check ---

export function requirePermission(
  context: McpToolContext,
  resource: string,
  action: string,
): void {
  const has = context.permissions.some(
    (p) => p.resource === resource && p.action === action && p.granted,
  );
  if (!has) {
    throw new Error(`Permission denied: ${resource}:${action} is required`);
  }
}

// --- Zod schema for _context validation ---

export const contextSchema = z.object({
  tenant_id: z.string().uuid(),
  user_id: z.string().uuid(),
  user_email: z.string().optional(),
  role_name: z.string(),
  permissions: z.array(z.object({
    resource: z.string(),
    action: z.string(),
    granted: z.boolean(),
  })),
  scopes: z.array(z.object({
    scope_type: z.enum(["all", "company", "property", "unit"]),
    scope_ref_id: z.string(),
    fieldwork_entity: z.string(),
  })).optional(),
  request_id: z.string().optional(),
  credentials: z.record(z.string(), z.string()).optional(),
  // Signed-context token (see context-signing.ts). Optional so an injected
  // token passes shape validation; presence/verification is enforced separately
  // at the server's context boundary via resolveTrustedContext(). Its presence
  // alone confers NO trust — only a verified signature does.
  _token: z.string().optional(),
}).describe("RBAC context");

// --- MCP Tool Response ---

export interface ToolResponse {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  [key: string]: unknown;
}
