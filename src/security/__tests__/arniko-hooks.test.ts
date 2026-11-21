/**
 * Tests for Built-in Secret Scanner (`dirgha-builtin-secrets`) & Opt-in Arniko Hooks.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  scanTextForSecrets,
  scanDirectoryForSecrets,
} from "../builtin-secret-scanner.js";
import { checkArnikoToolGuard } from "../arniko-hooks.js";
import { runArnikoScan, toSarifV210 } from "../arniko-bridge.js";
import { PROFILE_PRESETS } from "../../safety/modules-config.js";
import { createRuntimePermissionEngine } from "../../safety/lokahi-runtime.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dirgha-arniko-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

// Construct test tokens dynamically so static repo scanners don't flag test fixtures
const FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
const FAKE_GH_PAT = "ghp_" + "1234567890abcdef1234567890abcdef1234";
const FAKE_PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----";

describe("dirgha-builtin-secrets scanner", () => {
  it("detects high-confidence credentials and redacts raw secret values", () => {
    const sample = [
      `const aws = "${FAKE_AWS_KEY}";`,
      `const gh = "${FAKE_GH_PAT}";`,
      FAKE_PEM,
    ].join("\n");

    const findings = scanTextForSecrets(sample, "src/config.ts");
    expect(findings.length).toBeGreaterThanOrEqual(3);
    expect(findings.every((f) => f.scanner === "dirgha-builtin-secrets")).toBe(true);
    // Must redact raw credential so it never echoes full secret into logs/SARIF
    for (const f of findings) {
      expect(f.message).not.toContain(FAKE_AWS_KEY);
      expect(f.message).not.toContain(FAKE_GH_PAT);
    }
  });

  it("ignores clean code and explicit placeholder comments", () => {
    const clean = [
      `const apiKey = process.env.OPENAI_API_KEY;`,
      `// placeholder: your_api_key_here`,
      `const ok = "hello world";`,
    ].join("\n");
    expect(scanTextForSecrets(clean, "src/app.ts")).toEqual([]);
  });

  it("integrates honestly with runArnikoScan & OASIS SARIF v2.1.0", async () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "leak.ts"), `export const k = "${FAKE_AWS_KEY}";\n`, "utf8");

    const report = await runArnikoScan({
      targetDir: dir,
      scanners: ["dirgha-builtin-secrets"],
    });
    expect(report.executedCount).toBe(1);
    expect(report.totalFindings).toBe(1);
    expect(report.results[0].scanner).toBe("dirgha-builtin-secrets");

    const sarif = toSarifV210(report) as { version: string; runs: Array<{ tool: { driver: { name: string } }; results: unknown[] }> };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("dirgha-arniko/dirgha-builtin-secrets");
    expect(sarif.runs[0].results.length).toBe(1);
  });
});

describe("checkArnikoToolGuard (opt-in runtime hooks)", () => {
  it("keeps developer profile 100% zero-friction (bypasses hooks)", () => {
    const dir = makeTempDir();
    const res = checkArnikoToolGuard(
      {
        id: "c1",
        name: "fs_write",
        input: { path: "app.ts", content: `const k = "${FAKE_AWS_KEY}";` },
      },
      PROFILE_PRESETS.developer,
      dir,
    );
    expect(res.allowed).toBe(true);
  });

  it("blocks fs_write containing leaked secret when enterprise profile (onAgentOutput) is active", () => {
    const dir = makeTempDir();
    const res = checkArnikoToolGuard(
      {
        id: "c2",
        name: "fs_write",
        input: { path: "app.ts", content: `const token = "${FAKE_GH_PAT}";` },
      },
      PROFILE_PRESETS.enterprise,
      dir,
    );
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain("arniko:onAgentOutput");
    expect(res.reason).toContain("dirgha-builtin-secrets");
  });

  it("allows clean fs_write under enterprise profile", () => {
    const dir = makeTempDir();
    const res = checkArnikoToolGuard(
      {
        id: "c3",
        name: "fs_write",
        input: { path: "app.ts", content: `export const port = Number(process.env.PORT ?? 3000);` },
      },
      PROFILE_PRESETS.enterprise,
      dir,
    );
    expect(res.allowed).toBe(true);
  });

  it("blocks git commit when onPreCommit detects a secret in the workspace", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "creds.ts"), `export const key = "${FAKE_AWS_KEY}";\n`, "utf8");

    const res = checkArnikoToolGuard(
      {
        id: "c4",
        name: "git",
        input: { args: ["commit", "-m", "feat: add service"] },
      },
      PROFILE_PRESETS.team,
      dir,
    );
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain("arniko:onPreCommit");
  });

  it("allows git commit on clean workspace under team profile", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "index.ts"), `export const ok = true;\n`, "utf8");

    const res = checkArnikoToolGuard(
      {
        id: "c5",
        name: "git",
        input: { args: ["commit", "-m", "feat: clean"] },
      },
      PROFILE_PRESETS.team,
      dir,
    );
    expect(res.allowed).toBe(true);
  });

  it("enforces Arniko hooks inside createRuntimePermissionEngine.checkCall", () => {
    const dir = makeTempDir();
    const engine = createRuntimePermissionEngine({
      cwd: dir,
      modules: {
        ...PROFILE_PRESETS.enterprise,
        lokahi: { mode: "off" },
      },
    });
    const decision = engine.checkCall({
      id: "c6",
      name: "fs_write",
      input: { path: join(dir, "secret.ts"), content: FAKE_PEM },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("arniko:onAgentOutput");
  });

  it("scanDirectoryForSecrets skips test files when excludeTests is true", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "sample.test.ts"), `const k = "${FAKE_AWS_KEY}";\n`, "utf8");
    const excluded = scanDirectoryForSecrets(dir, { excludeTests: true });
    expect(excluded.findings.length).toBe(0);
    const included = scanDirectoryForSecrets(dir, { excludeTests: false });
    expect(included.findings.length).toBe(1);
  });
});
