import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import {
  requirePermission,
  contextSchema,
  RESOURCE_VALUES,
  ACTION_VALUES,
} from "../rbac.js";
import type { McpToolContext, RolePermission } from "../rbac.js";

function makeContext(permissions: Partial<RolePermission>[] = []): McpToolContext {
  return {
    tenant_id: "t1",
    user_id: "u1",
    role_name: "admin",
    scopes: [],
    request_id: "r1",
    permissions: permissions.map((p, i) => ({
      id: `p${i}`,
      role_id: "role1",
      resource: "contacts" as const,
      action: "view" as const,
      granted: true,
      ...p,
    })),
  };
}

describe("requirePermission", () => {
  it("grants access when a matching granted permission exists", () => {
    const ctx = makeContext([{ resource: "jobs", action: "modify", granted: true }]);
    expect(() => requirePermission(ctx, "jobs", "modify")).not.toThrow();
  });

  it("denies access when no matching permission exists", () => {
    const ctx = makeContext([{ resource: "jobs", action: "view", granted: true }]);
    expect(() => requirePermission(ctx, "jobs", "modify")).toThrow("Permission denied");
  });

  it("denies access when permission exists but granted is false", () => {
    const ctx = makeContext([{ resource: "jobs", action: "modify", granted: false }]);
    expect(() => requirePermission(ctx, "jobs", "modify")).toThrow("Permission denied");
  });

  it("denies access when permissions array is empty", () => {
    const ctx = makeContext([]);
    expect(() => requirePermission(ctx, "contacts", "view")).toThrow("Permission denied");
  });

  it("includes resource:action in error message", () => {
    const ctx = makeContext([]);
    expect(() => requirePermission(ctx, "admin", "manage")).toThrow("admin:manage");
  });
});

describe("contextSchema", () => {
  it("accepts a valid context object", () => {
    const result = contextSchema.safeParse({
      tenant_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
      user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
      role_name: "admin",
      permissions: [{ resource: "jobs", action: "view", granted: true }],
    });
    expect(result.success).toBe(true);
  });

  it("accepts optional user_email", () => {
    const result = contextSchema.safeParse({
      tenant_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
      user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
      user_email: "alice@example.com",
      role_name: "admin",
      permissions: [],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.user_email).toBe("alice@example.com");
    }
  });

  it("accepts optional scopes and request_id", () => {
    const result = contextSchema.safeParse({
      tenant_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
      user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
      role_name: "tech",
      permissions: [],
      scopes: [{ scope_type: "company", scope_ref_id: "c1", fieldwork_entity: "contacts" }],
      request_id: "req-123",
    });
    expect(result.success).toBe(true);
  });

  it("rejects when tenant_id is not a UUID", () => {
    const result = contextSchema.safeParse({
      tenant_id: "not-a-uuid",
      user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
      role_name: "admin",
      permissions: [],
    });
    expect(result.success).toBe(false);
  });

  it("rejects when required fields are missing", () => {
    const result = contextSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it("rejects invalid scope_type", () => {
    const result = contextSchema.safeParse({
      tenant_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
      user_id: "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
      role_name: "admin",
      permissions: [],
      scopes: [{ scope_type: "galaxy", scope_ref_id: "x", fieldwork_entity: "contacts" }],
    });
    expect(result.success).toBe(false);
  });
});

describe("RBAC vocabulary is the published contract", () => {
  // These lists mirror the CHECK constraints on the platform's role_permissions
  // table. If they fail, the platform widened its vocabulary: update the
  // constants, rbac-schema.json and this test together, never just one.
  it("RESOURCE_VALUES is the documented resource list", () => {
    expect([...RESOURCE_VALUES].sort()).toEqual(
      ["contacts", "jobs", "financials", "internal_notes", "external_notes",
       "scheduling", "reports", "admin", "email", "issues", "receipts",
       "inventory"].sort(),
    );
  });

  it("ACTION_VALUES is the documented action list", () => {
    expect([...ACTION_VALUES].sort()).toEqual(
      ["view", "add", "modify", "delete", "send", "manage", "submit",
       "submit_card", "submit_reimbursement", "use_shared_card", "review",
       "post", "view_own", "view_all"].sort(),
    );
  });
});

describe("rbac-schema.json stays in sync with the TypeScript types", () => {
  // The JSON Schema is what non-TypeScript signers and validators read. It is
  // hand-maintained, so this test is the only thing that keeps it honest.
  const schema = JSON.parse(
    readFileSync(new URL("../rbac-schema.json", import.meta.url), "utf8"),
  ) as {
    required: string[];
    properties: Record<string, unknown> & {
      permissions: { items: { properties: { resource: { enum: string[] }; action: { enum: string[] } } } };
      scopes: { items: { properties: { scope_type: { enum: string[] } } } };
    };
  };

  it("resource and action enums match RESOURCE_VALUES / ACTION_VALUES", () => {
    expect([...schema.properties.permissions.items.properties.resource.enum].sort())
      .toEqual([...RESOURCE_VALUES].sort());
    expect([...schema.properties.permissions.items.properties.action.enum].sort())
      .toEqual([...ACTION_VALUES].sort());
  });

  it("scope_type enum matches the ScopeType union used by contextSchema", () => {
    expect([...schema.properties.scopes.items.properties.scope_type.enum].sort())
      .toEqual(["all", "company", "property", "unit"]);
  });

  it("declares every field contextSchema knows, and the same required set", () => {
    expect(Object.keys(schema.properties).sort()).toEqual(
      Object.keys(contextSchema.shape).sort(),
    );
    expect([...schema.required].sort()).toEqual(
      ["tenant_id", "user_id", "role_name", "permissions"].sort(),
    );
  });
});
