/**
 * Built-in Zero-Dependency Secret & Credential Scanner (`dirgha-builtin-secrets`).
 *
 * Provides deterministic offline secret detection when external CLIs
 * (`gitleaks`, `semgrep`, `trivy`) are not installed. Every finding is
 * explicitly tagged `scanner: "dirgha-builtin-secrets"` (AGENTS.md Rule #2:
 * never masquerade as gitleaks) and matched secret literals are redacted so
 * scan reports and SARIF exports never leak raw credentials.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

export interface BuiltinSecretFinding {
  scanner: "dirgha-builtin-secrets";
  ruleId: string;
  message: string;
  severity: "error" | "warning";
  file?: string;
  line: number;
  redactedMatch: string;
}

interface SecretRule {
  id: string;
  description: string;
  severity: "error" | "warning";
  pattern: RegExp;
}

const SECRET_RULES: SecretRule[] = [
  {
    id: "builtin-aws-access-key",
    description: "AWS Access Key ID detected",
    severity: "error",
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "builtin-github-pat",
    description: "GitHub Personal Access Token detected",
    severity: "error",
    pattern: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b/g,
  },
  {
    id: "builtin-anthropic-key",
    description: "Anthropic API key detected",
    severity: "error",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "builtin-openrouter-key",
    description: "OpenRouter API key detected",
    severity: "error",
    pattern: /\bsk-or-v1-[A-Fa-f0-9]{32,}\b/g,
  },
  {
    id: "builtin-openai-or-stripe-key",
    description: "Provider secret key (sk- / sk_live_ / rk_live_) detected",
    severity: "error",
    pattern: /\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|(?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g,
  },
  {
    id: "builtin-slack-token",
    description: "Slack API token detected",
    severity: "error",
    pattern: /\bxox[baprs]-[0-9]{10,}-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    id: "builtin-google-api-key",
    description: "Google Cloud / AI API key detected",
    severity: "error",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: "builtin-private-key-header",
    description: "PEM private key block detected",
    severity: "error",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ED25519 |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    id: "builtin-generic-secret-assignment",
    description: "Hardcoded secret/token assignment detected",
    severity: "warning",
    pattern:
      /\b(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|DATABASE_URL|STRIPE_SECRET)\s*[:=]\s*["'](?!\s*(?:your_|example|placeholder|changeme|dummy|test|<|\$))[A-Za-z0-9+/=._:@-]{20,}["']/g,
  },
];

const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "target",
  ".playwright-cli",
  ".next",
  "coverage",
  "vendor",
]);

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".wasm",
  ".parquet",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".woff",
  ".woff2",
  ".ttf",
  ".bin",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
]);

const MAX_SCAN_FILE_BYTES = 512 * 1024;
const MAX_SCAN_FILES = 2000;

function redactSecret(raw: string): string {
  if (raw.length <= 10) return "***";
  return `${raw.slice(0, 6)}…${raw.slice(-3)}`;
}

function isPlaceholderLine(line: string): boolean {
  const lower = line.toLowerCase();
  return (
    lower.includes("dirgha-ignore-secret") ||
    lower.includes("example_key") ||
    lower.includes("your_api_key") ||
    lower.includes("placeholder")
  );
}

/**
 * Scan a text string (e.g., an agent `fs_write` payload or code snippet)
 * for leaked credentials and private keys.
 */
export function scanTextForSecrets(
  text: string,
  fileLabel?: string,
): BuiltinSecretFinding[] {
  if (!text || text.length === 0) return [];
  const findings: BuiltinSecretFinding[] = [];
  const lines = text.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx] ?? "";
    if (line.length === 0 || isPlaceholderLine(line)) continue;

    for (const rule of SECRET_RULES) {
      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(line);
      if (match) {
        findings.push({
          scanner: "dirgha-builtin-secrets",
          ruleId: rule.id,
          message: `${rule.description} (${redactSecret(match[0])})`,
          severity: rule.severity,
          ...(fileLabel ? { file: fileLabel } : {}),
          line: idx + 1,
          redactedMatch: redactSecret(match[0]),
        });
      }
    }
  }

  return findings;
}

export interface DirectoryScanOptions {
  maxFiles?: number;
  excludeTests?: boolean;
}

/**
 * Recursively scan a directory for hardcoded secrets, skipping binaries,
 * build directories, and oversized files.
 */
export function scanDirectoryForSecrets(
  targetDir: string,
  opts: DirectoryScanOptions = {},
): { filesScanned: number; findings: BuiltinSecretFinding[] } {
  const root = resolve(targetDir);
  const maxFiles = opts.maxFiles ?? MAX_SCAN_FILES;
  const excludeTests = opts.excludeTests ?? false;
  const findings: BuiltinSecretFinding[] = [];
  let filesScanned = 0;

  function walk(dir: string): void {
    if (filesScanned >= maxFiles) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (filesScanned >= maxFiles) break;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        walk(join(dir, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;

      const ext = extname(entry.name).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;

      const fullPath = join(dir, entry.name);
      const relPath = relative(root, fullPath).replace(/\\/g, "/");
      if (
        excludeTests &&
        /(?:^|\/)(?:__tests__|fixtures|test|tests)\/|\.test\.|\.spec\./i.test(relPath)
      ) {
        continue;
      }

      try {
        const st = statSync(fullPath);
        if (st.size === 0 || st.size > MAX_SCAN_FILE_BYTES) continue;
        const content = readFileSync(fullPath, "utf8");
        if (content.includes("\u0000")) continue;
        filesScanned += 1;
        const fileFindings = scanTextForSecrets(content, relPath);
        findings.push(...fileFindings);
      } catch {
        // Ignore unreadable files
      }
    }
  }

  walk(root);
  return { filesScanned, findings };
}
