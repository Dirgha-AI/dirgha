/**
 * `dirgha scan` — Opt-in Arniko security scan subcommand.
 *
 * Usage:
 *   dirgha scan [path] [--sarif] [--json] [--scanners=gitleaks,semgrep,trivy]
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { stdout, stderr } from "node:process";
import type { Subcommand, SubcommandCtx } from "./index.js";
import { parseFlags } from "../flags.js";
import { loadConfig } from "../config.js";
import { resolveModulesConfig } from "../../safety/modules-config.js";
import {
  runArnikoScan,
  toSarifV210,
  type ArnikoScannerName,
} from "../../security/arniko-bridge.js";

const VALID_SCANNERS = new Set<ArnikoScannerName>([
  "gitleaks",
  "semgrep",
  "trivy",
  "dirgha-builtin-secrets",
]);

export const scanSubcommand: Subcommand = {
  name: "scan",
  aliases: ["arniko"],
  description:
    "Opt-in Arniko security scan (gitleaks/semgrep/trivy/dirgha-builtin-secrets) with OASIS SARIF 2.1.0 output",
  async run(argv: string[], ctx: SubcommandCtx): Promise<number> {
    const { flags, positionals } = parseFlags(argv);

    if (flags.help || flags.h) {
      stdout.write(`Usage: dirgha scan [path] [options]

Opt-in Arniko security scanner bridge. Runs locally installed OSS scanners
(gitleaks, semgrep, trivy) and reports missing binaries honestly (never mocked).
Use --builtin to include the zero-dependency dirgha-builtin-secrets scanner.

Options:
  --scanners=<list>   Comma-separated subset of: gitleaks,semgrep,trivy,dirgha-builtin-secrets
  --builtin           Run the built-in zero-dependency secret scanner (dirgha-builtin-secrets)
  --sarif             Emit OASIS SARIF v2.1.0 JSON to stdout
  --json              Emit structured JSON report to stdout
  -h, --help          Show this help
`);
      return 0;
    }

    const config = await loadConfig(ctx.cwd);
    const modRes = resolveModulesConfig({
      profile: config.profile,
      configured: config.modules,
      flags,
    });
    if (modRes.errors.length > 0) {
      for (const e of modRes.errors) stderr.write(`[dirgha] policy error: ${e}\n`);
      return 1;
    }

    const targetDir = positionals[0] ?? ctx.cwd;
    let scanners: ArnikoScannerName[] =
      flags.builtin === true
        ? ["dirgha-builtin-secrets"]
        : ["gitleaks", "semgrep", "trivy"];
    if (typeof flags.scanners === "string" && flags.scanners.trim().length > 0) {
      const requested = flags.scanners
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter((s): s is ArnikoScannerName => VALID_SCANNERS.has(s as ArnikoScannerName));
      if (requested.length === 0) {
        stderr.write(
          "No valid scanners specified. Choose from: gitleaks, semgrep, trivy, dirgha-builtin-secrets\n",
        );
        return 1;
      }
      scanners = requested;
    }

    const report = await runArnikoScan({ targetDir, scanners });

    if (flags.sarif === true) {
      stdout.write(JSON.stringify(toSarifV210(report), null, 2) + "\n");
    } else if (flags.json === true) {
      stdout.write(JSON.stringify(report, null, 2) + "\n");
    } else {
      stdout.write(`Arniko Security Scan — ${report.targetDir}\n\n`);
      for (const r of report.results) {
        stdout.write(`  [${r.status.toUpperCase()}] ${r.scanner}: ${r.detail}\n`);
        for (const f of r.findings.slice(0, 10)) {
          stdout.write(
            `    - (${f.severity}) ${f.ruleId}${f.file ? ` @ ${f.file}${f.line ? `:${f.line}` : ""}` : ""}: ${f.message}\n`,
          );
        }
      }
      stdout.write(
        `\nSummary: ${report.executedCount} executed, ${report.skippedCount} skipped (CLI missing), ${report.totalFindings} finding(s).\n`,
      );
    }

    return report.totalFindings > 0 ? 1 : 0;
  },
};
