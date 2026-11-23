import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Default suite: deterministic, offline, and safe to run in a checkout.
    // Live API probes, registry access, and platform-specific symlink tests
    // live in `*.e2e.test.ts` and run through `npm run test:e2e`.
    exclude: [
      "**/node_modules/**",
      "**/dist/**",
      "**/sandbox-test/**",
      "**/*.e2e.test.ts",
    ],
    // Several suites exercise process-wide HOME redirection and in-process
    // model state. Run files serially so one suite cannot poison another.
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
