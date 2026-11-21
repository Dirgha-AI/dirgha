/**
 * Offline unit tests for the opt-in Arniko security scanner bridge (SARIF v2.1.0)
 * and the Ahimsa AI -> LOKAHI v1.1 manifest validator & merger.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  runArnikoScan,
  toSarifV210,
  type ScannerCommandRunner,
} from "../arniko-bridge.js";
import {
  DEFAULT_DIRGHA_TOOL_POLICY,
  mergeAhimsaWithToolPolicy,
  validateAhimsaManifest,
} from "../../safety/ahimsa-bridge.js";

describe("Arniko opt-in scanner bridge & OASIS SARIF v2.1.0 exporter", () => {
  it("reports skipped_cli_missing honestly with zero fabricated findings when scanners are absent", async () => {
    const missingRunner: ScannerCommandRunner = {
      async run() {
        return { exitCode: 127, stdout: "", stderr: "ENOENT", notFound: true };
      },
    };
    const report = await runArnikoScan({
      targetDir: process.cwd(),
      scanners: ["gitleaks", "semgrep", "trivy"],
      runner: missingRunner,
    });
    expect(report.totalFindings).toBe(0);
    expect(report.executedCount).toBe(0);
    expect(report.skippedCount).toBe(3);
    expect(report.results.every((r) => r.status === "skipped_cli_missing")).toBe(true);
  });

  it("parses gitleaks, semgrep, and trivy JSON outputs and exports valid OASIS SARIF v2.1.0", async () => {
    const mockRunner: ScannerCommandRunner = {
      async run(bin) {
        if (bin === "gitleaks") {
          return {
            exitCode: 1,
            stderr: "",
            stdout: JSON.stringify([
              {
                RuleID: "generic-api-key",
                Description: "Hardcoded API key detected",
                File: "src/config.ts",
                StartLine: 14,
              },
            ]),
          };
        }
        if (bin === "semgrep") {
          return {
            exitCode: 0,
            stderr: "",
            stdout: JSON.stringify({
              results: [
                {
                  check_id: "javascript.lang.security.child-process",
                  path: "src/run.ts",
                  start: { line: 42 },
                  extra: { severity: "WARNING", message: "Avoid shell interpolation" },
                },
              ],
            }),
          };
        }
        return {
          exitCode: 0,
          stderr: "",
          stdout: JSON.stringify({
            Results: [
              {
                Target: "package-lock.json",
                Vulnerabilities: [
                  {
                    VulnerabilityID: "CVE-2025-9999",
                    Severity: "HIGH",
                    Title: "Prototype pollution in test-pkg",
                  },
                ],
              },
            ],
          }),
        };
      },
    };

    const report = await runArnikoScan({
      targetDir: process.cwd(),
      scanners: ["gitleaks", "semgrep", "trivy"],
      runner: mockRunner,
    });
    expect(report.executedCount).toBe(3);
    expect(report.skippedCount).toBe(0);
    expect(report.totalFindings).toBe(3);

    const sarif = toSarifV210(report) as {
      version: string;
      $schema: string;
      runs: Array<{ results: Array<{ ruleId: string; level: string }> }>;
    };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-2.1.0");
    expect(sarif.runs).toHaveLength(3);
    expect(sarif.runs[0].results[0]).toMatchObject({
      ruleId: "generic-api-key",
      level: "error",
    });
    expect(sarif.runs[1].results[0]).toMatchObject({
      ruleId: "javascript.lang.security.child-process",
      level: "warning",
    });
    expect(sarif.runs[2].results[0]).toMatchObject({
      ruleId: "CVE-2025-9999",
      level: "error",
    });
  });
});

describe("Ahimsa AI -> LOKAHI v1.1 manifest validator & merger", () => {
  it("detects missing tools policy, demo/HMAC signature, and naive/expired timestamps", () => {
    const res = validateAhimsaManifest(
      {
        organization: "Pilot Org",
        signature: "hmac-demo-1234",
        signature_algorithm: "HMAC-SHA256-DEMO",
        expires: "2026-06-01T00:00:00", // naive (missing Z / offset)
        residency: ["IN", "EU"],
      },
      { now: new Date("2026-01-01T00:00:00Z") },
    );
    expect(res.compatibleWithLokahi).toBe(false);
    const codes = res.issues.map((i) => i.code);
    expect(codes).toContain("demo_signature_rejected");
    expect(codes).toContain("naive_or_expired_timestamp");
    expect(codes).toContain("missing_tools_policy");
  });

  it("merges Ahimsa residency with Dirgha tool policy, clears stale signature, and becomes LOKAHI-ready after signing", () => {
    const fixedNow = new Date("2026-05-01T00:00:00Z");
    const merged = mergeAhimsaWithToolPolicy(
      {
        organization: "Sovereign Labs",
        frameworks: ["EU-AI-ACT", "INDIA-DPDP"],
        residency: ["IN", "EU"],
        signature: "old-demo-sig",
      },
      DEFAULT_DIRGHA_TOOL_POLICY,
      { expiresInDays: 90, now: fixedNow },
    );

    expect(merged.signature).toBeUndefined();
    expect(merged.manifest_version).toBe("1.1");
    expect(merged.expires?.endsWith("Z")).toBe(true);
    expect(merged.tools?.gpu_compute?.jurisdiction).toBe("IN");

    // After signing with an Ed25519 signature, validation passes cleanly
    const signed = { ...merged, signature: "ed25519:a1b2c3d4e5f6" };
    const check = validateAhimsaManifest(signed, { now: fixedNow });
    expect(check.compatibleWithLokahi).toBe(true);
    expect(check.issues).toEqual([]);
  });
});
