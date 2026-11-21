/**
 * Opt-in Arniko Runtime Hooks (`onAgentOutput` & `onPreCommit`).
 *
 * Strictly zero-friction for the `developer` profile: immediately returns
 * `allowed: true` when `modules.arniko.enabled` is false.
 *
 * When enabled (e.g. `team` or `enterprise` profile, or `--arniko`):
 * - `onAgentOutput`: inspects file write/edit tool payloads before disk mutation
 *   and blocks hardcoded secrets or private keys.
 * - `onPreCommit`: intercepts `git` commit/push calls (or `shell` invocations
 *   running `git commit` / `git push`) and runs `dirgha-builtin-secrets` across
 *   the workspace before allowing code to be committed or pushed.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import type { ToolCall } from "../kernel/types.js";
import type { ModulesConfig } from "../safety/modules-config.js";
import type { PermissionDecision } from "../tools/permission.js";
import {
  scanDirectoryForSecrets,
  scanTextForSecrets,
  type BuiltinSecretFinding,
} from "./builtin-secret-scanner.js";

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function extractWrittenContent(call: ToolCall): { fileLabel: string; payloads: string[] } {
  const input = asRecord(call.input);
  const fileLabel =
    (typeof input.path === "string" && input.path) ||
    (typeof input.filePath === "string" && input.filePath) ||
    (typeof input.file === "string" && input.file) ||
    call.name;

  const payloads: string[] = [];
  for (const key of ["content", "new_string", "newText", "replacement", "text"]) {
    if (typeof input[key] === "string" && input[key].length > 0) {
      payloads.push(input[key]);
    }
  }
  if (Array.isArray(input.edits)) {
    for (const edit of input.edits) {
      const rec = asRecord(edit);
      if (typeof rec.new_string === "string") payloads.push(rec.new_string);
      if (typeof rec.content === "string") payloads.push(rec.content);
    }
  }
  if (Array.isArray(input.files)) {
    for (const f of input.files) {
      const rec = asRecord(f);
      if (typeof rec.content === "string") payloads.push(rec.content);
    }
  }
  return { fileLabel, payloads };
}

function isGitCommitOrPushCall(call: ToolCall): boolean {
  const input = asRecord(call.input);
  if (call.name === "git") {
    const sub =
      (Array.isArray(input.args) ? input.args.map(String).join(" ") : "") ||
      (typeof input.command === "string" ? input.command : "") ||
      (typeof input.subcommand === "string" ? input.subcommand : "") ||
      (typeof input.args === "string" ? input.args : "");
    return /\b(commit|push)\b/i.test(sub);
  }
  if (call.name === "shell") {
    const cmd =
      (typeof input.command === "string" ? input.command : "") ||
      (typeof input.cmd === "string" ? input.cmd : "");
    return /\bgit\s+(?:[^\n;&|]*\s)?(commit|push)\b/i.test(cmd);
  }
  return false;
}

function formatBlockReason(hookName: string, findings: BuiltinSecretFinding[]): string {
  const preview = findings
    .slice(0, 3)
    .map((f) => `${f.ruleId}@${f.file ?? "payload"}:${f.line}`)
    .join(", ");
  return `arniko:${hookName} blocked (${findings.length} secret finding(s) via dirgha-builtin-secrets: ${preview})`;
}

/**
 * Evaluate opt-in Arniko security hooks against an incoming ToolCall.
 */
export function checkArnikoToolGuard(
  call: ToolCall,
  modules: ModulesConfig,
  cwd: string,
): PermissionDecision {
  if (!modules.arniko.enabled) {
    return { allowed: true, reason: "arniko disabled", requiresApproval: false };
  }

  // 1. onAgentOutput: scan file writes/edits before touching disk
  if (
    modules.arniko.onAgentOutput &&
    (call.name === "fs_write" ||
      call.name === "fs_edit" ||
      call.name === "transactional_write")
  ) {
    const { fileLabel, payloads } = extractWrittenContent(call);
    const findings: BuiltinSecretFinding[] = [];
    for (const payload of payloads) {
      findings.push(...scanTextForSecrets(payload, fileLabel));
    }
    const blocking = findings.filter((f) => f.severity === "error");
    if (blocking.length > 0) {
      return {
        allowed: false,
        reason: formatBlockReason("onAgentOutput", blocking),
        requiresApproval: false,
      };
    }
  }

  // 2. onPreCommit: scan workspace before git commit / push
  if (modules.arniko.onPreCommit && isGitCommitOrPushCall(call)) {
    const { findings } = scanDirectoryForSecrets(cwd, { excludeTests: true });
    const blocking = findings.filter((f) => f.severity === "error");
    if (blocking.length > 0) {
      return {
        allowed: false,
        reason: formatBlockReason("onPreCommit", blocking),
        requiresApproval: false,
      };
    }
  }

  return { allowed: true, reason: "arniko hooks passed", requiresApproval: false };
}
