/**
 * Opt-in Arniko Security Scanner Bridge & OASIS SARIF v2.1.0 Exporter.
 *
 * Orchestrates real locally installed security scanners (`gitleaks`, `semgrep`, `trivy`)
 * using `execFile` (never `shell: true`). Honors AGENTS.md Rule #2 strictly:
 * if a scanner CLI is not installed, it reports `status: "skipped_cli_missing"`
 * and NEVER fabricates findings or fake passing results.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import { scanDirectoryForSecrets } from "./builtin-secret-scanner.js";

const execFileAsync = promisify(execFile);

export type ArnikoScannerName =
  | "gitleaks"
  | "semgrep"
  | "trivy"
  | "dirgha-builtin-secrets";

export type ArnikoSeverity = "error" | "warning" | "note";

export interface ArnikoFinding {
  scanner: ArnikoScannerName;
  ruleId: string;
  message: string;
  severity: ArnikoSeverity;
  file?: string;
  line?: number;
}

export interface ScannerExecutionResult {
  scanner: ArnikoScannerName;
  status: "completed" | "skipped_cli_missing" | "error";
  findings: ArnikoFinding[];
  detail: string;
}

export interface ArnikoScanReport {
  targetDir: string;
  generatedAt: string;
  scannersRequested: ArnikoScannerName[];
  results: ScannerExecutionResult[];
  totalFindings: number;
  executedCount: number;
  skippedCount: number;
}

export interface ScannerCommandRunner {
  run(
    bin: string,
    args: string[],
    cwd: string,
  ): Promise<{ exitCode: number; stdout: string; stderr: string; notFound?: boolean }>;
}

const defaultRunner: ScannerCommandRunner = {
  async run(bin, args, cwd) {
    try {
      const { stdout, stderr } = await execFileAsync(bin, args, {
        cwd,
        timeout: 60_000,
        maxBuffer: 10 * 1024 * 1024,
      });
      return { exitCode: 0, stdout: String(stdout), stderr: String(stderr) };
    } catch (err: unknown) {
      const e = err as {
        code?: string | number;
        stdout?: string;
        stderr?: string;
        message?: string;
      };
      if (e.code === "ENOENT") {
        return { exitCode: 127, stdout: "", stderr: "ENOENT", notFound: true };
      }
      return {
        exitCode: typeof e.code === "number" ? e.code : 1,
        stdout: String(e.stdout ?? ""),
        stderr: String(e.stderr ?? e.message ?? ""),
      };
    }
  },
};

function parseGitleaksOutput(stdout: string): ArnikoFinding[] {
  const trimmed = stdout.trim();
  if (!trimmed || trimmed === "null" || trimmed === "[]") return [];
  try {
    const arr = JSON.parse(trimmed) as Array<Record<string, unknown>>;
    if (!Array.isArray(arr)) return [];
    return arr.map((item) => ({
      scanner: "gitleaks",
      ruleId: String(item.RuleID ?? "gitleaks-secret"),
      message: String(item.Description ?? "Secret detected by gitleaks"),
      severity: "error",
      file: typeof item.File === "string" ? item.File : undefined,
      line: typeof item.StartLine === "number" ? item.StartLine : undefined,
    }));
  } catch {
    return [];
  }
}

function parseSemgrepOutput(stdout: string): ArnikoFinding[] {
  const trimmed = stdout.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed) as { results?: Array<Record<string, unknown>> };
    const results = parsed.results ?? [];
    return results.map((r) => {
      const extra = (r.extra ?? {}) as Record<string, unknown>;
      const start = (r.start ?? {}) as Record<string, unknown>;
      const rawSev = String(extra.severity ?? "WARNING").toUpperCase();
      const severity: ArnikoSeverity =
        rawSev === "ERROR" ? "error" : rawSev === "INFO" ? "note" : "warning";
      return {
        scanner: "semgrep",
        ruleId: String(r.check_id ?? "semgrep-rule"),
        message: String(extra.message ?? "Semgrep finding"),
        severity,
        file: typeof r.path === "string" ? r.path : undefined,
        line: typeof start.line === "number" ? start.line : undefined,
      };
    });
  } catch {
    return [];
  }
}

function parseTrivyOutput(stdout: string): ArnikoFinding[] {
  const trimmed = stdout.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed) as {
      Results?: Array<{ Target?: string; Vulnerabilities?: Array<Record<string, unknown>> }>;
    };
    const findings: ArnikoFinding[] = [];
    for (const target of parsed.Results ?? []) {
      for (const v of target.Vulnerabilities ?? []) {
        const rawSev = String(v.Severity ?? "MEDIUM").toUpperCase();
        const severity: ArnikoSeverity =
          rawSev === "CRITICAL" || rawSev === "HIGH"
            ? "error"
            : rawSev === "LOW"
              ? "note"
              : "warning";
        findings.push({
          scanner: "trivy",
          ruleId: String(v.VulnerabilityID ?? "trivy-vuln"),
          message: String(v.Title ?? v.PkgName ?? "Trivy vulnerability finding"),
          severity,
          file: target.Target,
        });
      }
    }
    return findings;
  } catch {
    return [];
  }
}

async function runSingleScanner(
  scanner: ArnikoScannerName,
  targetDir: string,
  runner: ScannerCommandRunner,
): Promise<ScannerExecutionResult> {
  if (scanner === "dirgha-builtin-secrets") {
    const { filesScanned, findings } = scanDirectoryForSecrets(targetDir);
    return {
      scanner: "dirgha-builtin-secrets",
      status: "completed",
      findings: findings.map((f) => ({
        scanner: "dirgha-builtin-secrets",
        ruleId: f.ruleId,
        message: f.message,
        severity: f.severity,
        file: f.file,
        line: f.line,
      })),
      detail: `dirgha-builtin-secrets scanned ${filesScanned} file(s) (${findings.length} finding(s))`,
    };
  }

  let bin: string;
  let args: string[];

  switch (scanner) {
    case "gitleaks":
      bin = "gitleaks";
      args = ["detect", "--no-git", "--source", targetDir, "--report-format", "json", "--report-path", "-"];
      break;
    case "semgrep":
      bin = "semgrep";
      args = ["scan", "--config", "auto", "--json", "--quiet", targetDir];
      break;
    case "trivy":
      bin = "trivy";
      args = ["fs", "--format", "json", "--quiet", targetDir];
      break;
  }

  const res = await runner.run(bin, args, targetDir);
  if (res.notFound) {
    return {
      scanner,
      status: "skipped_cli_missing",
      findings: [],
      detail: `${bin} CLI not found on PATH; install ${bin} to enable real ${scanner} scanning`,
    };
  }

  let findings: ArnikoFinding[] = [];
  if (scanner === "gitleaks") findings = parseGitleaksOutput(res.stdout);
  else if (scanner === "semgrep") findings = parseSemgrepOutput(res.stdout);
  else if (scanner === "trivy") findings = parseTrivyOutput(res.stdout);

  // gitleaks exits 1 when leaks are found; semgrep/trivy exit 0 or 1 with JSON stdout
  if (res.exitCode !== 0 && findings.length === 0 && res.stdout.trim() === "") {
    return {
      scanner,
      status: "error",
      findings: [],
      detail: `${bin} exited with code ${res.exitCode}: ${res.stderr.slice(0, 200)}`,
    };
  }

  return {
    scanner,
    status: "completed",
    findings,
    detail: `${bin} completed (${findings.length} finding(s))`,
  };
}

/**
 * Run opt-in Arniko security scanning across requested local scanners.
 */
export async function runArnikoScan(opts: {
  targetDir: string;
  scanners?: ArnikoScannerName[];
  runner?: ScannerCommandRunner;
}): Promise<ArnikoScanReport> {
  const targetDir = resolve(opts.targetDir);
  const scanners: ArnikoScannerName[] =
    opts.scanners && opts.scanners.length > 0
      ? opts.scanners
      : ["gitleaks", "semgrep", "trivy"];
  const runner = opts.runner ?? defaultRunner;

  const results: ScannerExecutionResult[] = [];
  for (const s of scanners) {
    results.push(await runSingleScanner(s, targetDir, runner));
  }

  const totalFindings = results.reduce((acc, r) => acc + r.findings.length, 0);
  const executedCount = results.filter((r) => r.status === "completed").length;
  const skippedCount = results.filter((r) => r.status === "skipped_cli_missing").length;

  return {
    targetDir,
    generatedAt: new Date().toISOString(),
    scannersRequested: scanners,
    results,
    totalFindings,
    executedCount,
    skippedCount,
  };
}

/**
 * Convert an ArnikoScanReport into a standards-compliant OASIS SARIF v2.1.0 document
 * compatible with GitHub Code Scanning, GitLab Security, and Azure DevOps.
 */
export function toSarifV210(report: ArnikoScanReport): Record<string, unknown> {
  const runs = report.results.map((r) => ({
    tool: {
      driver: {
        name: `dirgha-arniko/${r.scanner}`,
        informationUri: "https://github.com/Dirgha-AI/arniko",
        version: "2.0.0",
      },
    },
    invocations: [
      {
        executionSuccessful: r.status !== "error",
        properties: {
          status: r.status,
          detail: r.detail,
        },
      },
    ],
    results: r.findings.map((f) => ({
      ruleId: f.ruleId,
      level: f.severity,
      message: { text: f.message },
      ...(f.file
        ? {
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  ...(f.line ? { region: { startLine: f.line } } : {}),
                },
              },
            ],
          }
        : {}),
    })),
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs,
  };
}
