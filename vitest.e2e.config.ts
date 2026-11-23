import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Environment-dependent suites. These may call live APIs, access the npm
    // registry, or require symlink privileges that Windows does not grant.
    include: ["**/*.e2e.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**", "**/sandbox-test/**"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
