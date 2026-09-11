import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Only the TypeScript sources under src/ are tests. Excluding dist/ keeps a
    // stale compiled copy of the suite from running twice and masking drift.
    include: ["src/**/*.test.ts"],
    exclude: ["node_modules", "dist"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/__tests__/**", "src/index.ts"],
      reporter: ["text", "lcov", "json-summary"],
      reportsDirectory: "coverage",
      // The suite sits above these; they are a floor against regressions, not
      // a target. Raise them when coverage rises.
      thresholds: {
        lines: 85,
        functions: 85,
        branches: 80,
        statements: 85,
      },
    },
  },
});
