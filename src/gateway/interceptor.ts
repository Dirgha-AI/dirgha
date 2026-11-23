/**
 * Tool call and prompt interception engine for Dirgha Agent Gateway.
 * Evaluates every tool invocation against the LOKAHI WebAssembly gate
 * and declarative policy engine before execution.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  createPolicyEngine,
  evaluateLokahiGateSync,
  type PolicyEngine,
} from "../safety/policy.js";
import type { PermissionCheck, PermissionDecision } from "../tools/permission.js";

export interface ToolInterceptionResult {
  allowed: boolean;
  requiresApproval: boolean;
  reason: string;
  action: PermissionCheck["action"];
  target: string;
}

// In-memory or persistent S2 activity record with cryptographic Ed25519 signature
export interface S2LedgerEntry {
  index: number;
  timestamp: string;
  tool: string;
  action: string;
  target: string;
  verdict: "ALLOW" | "ESCALATE" | "REFUSE";
  reason: string;
  prevHash: string;
  hash: string;
  ed25519_pubkey_hex?: string;
  ed25519_sig_hex?: string;
}

export interface AuditKeyPair {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  pubKeyHex: string;
}

let cachedAuditKeyPair: AuditKeyPair | null = null;

/**
 * Derives or loads the host Ed25519 signing keypair from data/keys/lokahi_ed25519.key
 * ensuring strict cryptographic compatibility with the Rust crates/lokahi-gate ledger.
 */
export function getOrCreateAuditKeyPair(cwd: string = process.cwd()): AuditKeyPair {
  if (cachedAuditKeyPair) return cachedAuditKeyPair;

  const keysDir = path.join(cwd, "data", "keys");
  const keyPath = path.join(keysDir, "lokahi_ed25519.key");
  const pubPath = path.join(keysDir, "lokahi_ed25519.pub");

  let seed: Buffer;
  if (fs.existsSync(keyPath)) {
    const raw = fs.readFileSync(keyPath, "utf-8").trim();
    if (raw.length === 64) {
      seed = Buffer.from(raw, "hex");
    } else {
      seed = crypto.randomBytes(32);
      try {
        fs.writeFileSync(keyPath, seed.toString("hex"), { mode: 0o600 });
      } catch {
        // Fallback for non-posix or restricted fs
      }
    }
  } else {
    try {
      if (!fs.existsSync(keysDir)) {
        fs.mkdirSync(keysDir, { recursive: true });
      }
      seed = crypto.randomBytes(32);
      fs.writeFileSync(keyPath, seed.toString("hex"), { mode: 0o600 });
    } catch {
      seed = crypto.randomBytes(32);
    }
  }

  // RFC 8410 prefix for Ed25519 private key in PKCS8 DER
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const pkcs8Der = Buffer.concat([pkcs8Prefix, seed] as unknown as Uint8Array[]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8Der as unknown as Buffer, format: "der", type: "pkcs8" });
  const publicKey = crypto.createPublicKey(privateKey);
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const rawPub = pubDer.subarray(pubDer.length - 32);
  const pubKeyHex = rawPub.toString("hex");

  try {
    if (!fs.existsSync(pubPath)) {
      fs.writeFileSync(pubPath, pubKeyHex, "utf-8");
    }
  } catch {
    // Non-fatal
  }

  cachedAuditKeyPair = { privateKey, publicKey, pubKeyHex };
  return cachedAuditKeyPair;
}

let activePolicyEngine: PolicyEngine | null = null;
const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

interface LedgerState {
  index: number;
  lastBlockHash: string;
}

const ledgerStates = new Map<string, LedgerState>();

function concatenateBytes(parts: readonly Uint8Array[]): Uint8Array {
  const totalLength = parts.reduce((total, part) => total + part.byteLength, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function readLastLedgerEntry(auditFile: string, size: number): Record<string, unknown> {
  const fd = fs.openSync(auditFile, "r");
  const tailChunks: Uint8Array[] = [];
  let position = size;

  try {
    while (position > 0) {
      const start = Math.max(0, position - 8192);
      const chunk = new Uint8Array(new ArrayBuffer(position - start));
      let bytesRead = 0;
      while (bytesRead < chunk.length) {
        const count = fs.readSync(fd, chunk, bytesRead, chunk.length - bytesRead, start + bytesRead);
        if (count === 0) throw new Error("Unexpected end of file while reading the final record");
        bytesRead += count;
      }
      position = start;

      const suffix = concatenateBytes([chunk, ...tailChunks]);
      let end = suffix.length;
      while (end > 0 && (suffix[end - 1] === 0x0a || suffix[end - 1] === 0x0d)) end--;
      const delimiter = suffix.lastIndexOf(0x0a, end - 1);
      if (delimiter !== -1) {
        const line = new TextDecoder().decode(suffix.subarray(delimiter + 1, end)).trim();
        if (!line) throw new Error("The final audit ledger record is empty");
        const parsed: unknown = JSON.parse(line);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new Error("The final audit ledger record must be a JSON object");
        }
        return parsed as Record<string, unknown>;
      }

      tailChunks.unshift(chunk);
    }

    const line = new TextDecoder().decode(concatenateBytes(tailChunks)).trim();
    if (!line) throw new Error("The audit ledger contains no final record");
    const parsed: unknown = JSON.parse(line);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("The final audit ledger record must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } finally {
    fs.closeSync(fd);
  }
}

function ensureLedgerInitialized(cwd: string = process.cwd()): { auditFile: string; state: LedgerState } {
  const auditFile = path.resolve(cwd, "data", "gateway_audit.jsonl");
  const existing = ledgerStates.get(auditFile);
  if (existing) return { auditFile, state: existing };

  const state: LedgerState = { index: 0, lastBlockHash: GENESIS_HASH };
  try {
    if (fs.existsSync(auditFile)) {
      const stat = fs.statSync(auditFile);
      if (stat.size > 0) {
        const lastEntry = readLastLedgerEntry(auditFile, stat.size);
        if (
          !Number.isSafeInteger(lastEntry.index) ||
          (lastEntry.index as number) < 1 ||
          typeof lastEntry.hash !== "string" ||
          !/^[a-f0-9]{64}$/i.test(lastEntry.hash)
        ) {
          throw new Error("The final audit ledger record has an invalid index or hash");
        }

        const requiredStrings = ["timestamp", "tool", "action", "target", "verdict", "reason", "prevHash"];
        if (requiredStrings.some((field) => typeof lastEntry[field] !== "string")) {
          throw new Error("The final audit ledger record is missing required fields");
        }

        const payload = `${lastEntry.index}|${lastEntry.timestamp}|${lastEntry.tool}|${lastEntry.action}|${lastEntry.target}|${lastEntry.verdict}|${lastEntry.reason}|${lastEntry.prevHash}`;
        const computedHash = crypto.createHash("sha256").update(payload).digest("hex");
        if (computedHash !== lastEntry.hash) {
          throw new Error("The final audit ledger record hash is invalid");
        }

        state.index = lastEntry.index as number;
        state.lastBlockHash = lastEntry.hash;
      }
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Cannot resume gateway audit ledger at ${auditFile}: ${detail}`, { cause: error });
  }

  ledgerStates.set(auditFile, state);
  return { auditFile, state };
}

export function getOrCreatePolicyEngine(cwd: string = process.cwd()): PolicyEngine {
  if (!activePolicyEngine) {
    activePolicyEngine = createPolicyEngine({ cwd });
  }
  return activePolicyEngine;
}

/**
 * Classifies a tool call name and arguments into a canonical PermissionCheck
 */
export function classifyToolCall(
  toolName: string,
  args: Record<string, unknown> = {}
): { action: PermissionCheck["action"]; target: string } {
  const norm = toolName.toLowerCase();

  // 1. Shell and execution tools (Claude Code 'bash', Cursor 'terminal', etc.)
  if (
    norm === "bash" ||
    norm === "execute_command" ||
    norm === "run_command" ||
    norm === "sh" ||
    norm === "shell" ||
    norm === "exec"
  ) {
    const cmd = String(args.command || args.cmd || args.input || "");
    const isDelete = /(?:^|\s)(?:rm\s+-rf?|del\s+\/f|rmdir\s+\/s)/i.test(cmd);
    return {
      action: isDelete ? "delete" : "exec",
      target: cmd,
    };
  }

  // 2. File write, edit, replace tools
  if (
    norm === "str_replace_editor" ||
    norm === "write_file" ||
    norm === "edit_file" ||
    norm === "create_file" ||
    norm === "save_file" ||
    norm === "fs_write" ||
    norm === "fs_edit"
  ) {
    const targetPath = String(args.path || args.file || args.filename || args.target_file || "");
    return {
      action: "write",
      target: targetPath,
    };
  }

  // 3. File view, read, search tools
  if (
    norm === "read_file" ||
    norm === "view" ||
    norm === "cat" ||
    norm === "get_file_contents" ||
    norm === "open_file" ||
    norm === "fs_read" ||
    norm === "fs_ls" ||
    norm === "ls" ||
    norm === "list_directory" ||
    norm === "list_files" ||
    norm === "search_grep" ||
    norm === "grep" ||
    norm === "search_glob" ||
    norm === "glob"
  ) {
    const targetPath = String(args.path || args.file || args.filename || args.query || args.pattern || "");
    return {
      action: "read",
      target: targetPath,
    };
  }

  // 4. File delete tools
  if (norm === "delete_file" || norm === "remove_file" || norm === "unlink" || norm === "fs_delete") {
    const targetPath = String(args.path || args.file || "");
    return {
      action: "delete",
      target: targetPath,
    };
  }

  // 5. Network tools (curl, fetch, http_request)
  if (norm === "http_request" || norm === "fetch" || norm === "curl" || norm === "browse") {
    const url = String(args.url || args.uri || args.endpoint || "");
    return {
      action: "network",
      target: url,
    };
  }

  // Catch-all: Unmapped / unknown tools are classified as unknown action for fail-closed policy denial
  return {
    action: "unknown" as unknown as PermissionCheck["action"],
    target: JSON.stringify(args),
  };
}

/**
 * Evaluates an intercepted tool call through LOKAHI Gate & Policy Engine
 */
export function evaluateInterceptedToolCall(
  toolName: string,
  args: Record<string, unknown> = {},
  cwd: string = process.cwd()
): ToolInterceptionResult {
  const { action, target } = classifyToolCall(toolName, args);
  const isS2Critical = action === "delete" || action === "exec";

  // 1. Direct WebAssembly Gate check
  const gate = evaluateLokahiGateSync(target, isS2Critical);
  if (!gate.allowed) {
    logActivity({
      tool: toolName,
      action,
      target,
      verdict: "REFUSE",
      reason: `Blocked by WebAssembly safety gate (${gate.reason})`,
    }, cwd);
    return {
      allowed: false,
      requiresApproval: false,
      reason: `[LOKAHI GATE REFUSAL]: WebAssembly capability boundary violation. Reason: ${gate.reason}`,
      action,
      target,
    };
  }

  // 2. Declarative Policy Engine check
  const engine = getOrCreatePolicyEngine(cwd);
  const decision: PermissionDecision = engine.evaluate({
    tool: toolName,
    action,
    target,
  });

  const verdict = !decision.allowed
    ? "REFUSE"
    : decision.requiresApproval
    ? "ESCALATE"
    : "ALLOW";

  logActivity({
    tool: toolName,
    action,
    target,
    verdict,
    reason: decision.reason,
  }, cwd);

  return {
    allowed: decision.allowed,
    requiresApproval: decision.requiresApproval,
    reason: decision.reason,
    action,
    target,
  };
}

/**
 * Constructs protocol-compliant refusal arguments that satisfy client-side
 * tool schemas (e.g. Claude Code Zod schemas requiring `command` or `path`),
 * replacing unsafe execution with safe stderr notification.
 */
export function createCompliantRefusalArgs(
  toolName: string,
  target: string,
  reason: string
): Record<string, unknown> {
  const norm = toolName.toLowerCase();
  const escapedReason = reason.replace(/"/g, '\\"');

  if (
    norm === "bash" ||
    norm === "terminal" ||
    norm === "exec" ||
    norm === "execute_command" ||
    norm === "run_command" ||
    norm === "shell"
  ) {
    return {
      command: `echo "[LOKAHI REFUSED]: ${escapedReason}" >&2; exit 1`,
      _refused: true,
      _reason: reason,
    };
  }

  if (norm === "write_file" || norm === "str_replace_editor" || norm === "edit_file") {
    return {
      path: target || "DENIED.txt",
      content: `[LOKAHI REFUSED]: ${reason}`,
      _refused: true,
      _reason: reason,
    };
  }

  if (norm === "read_file" || norm === "view") {
    return {
      path: target || "DENIED.txt",
      _refused: true,
      _reason: reason,
    };
  }

  return {
    error: `[LOKAHI GATE REFUSAL]: Execution denied by safety policy. ${reason}`,
    refused: true,
  };
}

/**
 * Appends activity to local tamper-evident cryptographic S2 ledger
 * using genuine SHA-256 block chaining and Ed25519 digital signatures.
 */
export function logActivity(entry: {
  tool: string;
  action: string;
  target: string;
  verdict: "ALLOW" | "ESCALATE" | "REFUSE";
  reason: string;
}, cwd: string = process.cwd()): S2LedgerEntry {
  const { auditFile, state } = ensureLedgerInitialized(cwd);
  const index = state.index + 1;
  const timestamp = new Date().toISOString();
  
  // High-assurance SHA-256 cryptographic hash chaining
  const payload = `${index}|${timestamp}|${entry.tool}|${entry.action}|${entry.target}|${entry.verdict}|${entry.reason}|${state.lastBlockHash}`;
  const currentHash = crypto.createHash("sha256").update(payload).digest("hex");

  // Ed25519 DSSE envelope signature over the chained entry hash
  const keyPair = getOrCreateAuditKeyPair();
  const sig = crypto.sign(null, Buffer.from(currentHash, "utf-8") as unknown as Uint8Array, keyPair.privateKey);
  const sigHex = sig.toString("hex");

  const record: S2LedgerEntry = {
    index,
    timestamp,
    tool: entry.tool,
    action: entry.action,
    target: entry.target,
    verdict: entry.verdict,
    reason: entry.reason,
    prevHash: state.lastBlockHash,
    hash: currentHash,
    ed25519_pubkey_hex: keyPair.pubKeyHex,
    ed25519_sig_hex: sigHex,
  };

  try {
    const dataDir = path.dirname(auditFile);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    const fd = fs.openSync(auditFile, "a+");
    try {
      const size = fs.fstatSync(fd).size;
      if (size > 0) {
        const lastByte = new Uint8Array(new ArrayBuffer(1));
        const bytesRead = fs.readSync(fd, lastByte, 0, 1, size - 1);
        if (bytesRead !== 1) throw new Error("Could not verify the final audit ledger byte");
        if (lastByte[0] !== 0x0a) fs.writeSync(fd, "\n");
      }
      fs.writeSync(fd, `${JSON.stringify(record)}\n`, undefined, "utf-8");
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Cannot append to gateway audit ledger at ${auditFile}: ${detail}`, { cause: error });
  }

  state.index = index;
  state.lastBlockHash = currentHash;
  return record;
}

/**
 * Validates the full cryptographic chain and Ed25519 signatures of the gateway audit ledger.
 */
export function verifyGatewayAuditLedger(
  filePath: string = path.join(process.cwd(), "data", "gateway_audit.jsonl"),
  trustedPubKeyHex?: string
): { valid: boolean; entriesVerified: number; error?: string } {
  if (!fs.existsSync(filePath)) {
    return { valid: true, entriesVerified: 0 };
  }

  const lines = fs
    .readFileSync(filePath, "utf-8")
    .trim()
    .split("\n")
    .filter((l) => l.trim().length > 0);

  let expectedPrev = "0000000000000000000000000000000000000000000000000000000000000000";

  for (let i = 0; i < lines.length; i++) {
    let entry: S2LedgerEntry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      return { valid: false, entriesVerified: i, error: `Malformed JSON at line ${i + 1}` };
    }

    if (entry.prevHash !== expectedPrev) {
      return {
        valid: false,
        entriesVerified: i,
        error: `Chain break at line ${i + 1}: expected prev ${expectedPrev}, found ${entry.prevHash}`,
      };
    }

    const payload = `${entry.index}|${entry.timestamp}|${entry.tool}|${entry.action}|${entry.target}|${entry.verdict}|${entry.reason}|${entry.prevHash}`;
    const computedHash = crypto.createHash("sha256").update(payload).digest("hex");
    if (computedHash !== entry.hash) {
      return {
        valid: false,
        entriesVerified: i,
        error: `Hash mismatch at line ${i + 1}: computed ${computedHash}, entry claims ${entry.hash}`,
      };
    }

    if (entry.ed25519_sig_hex && entry.ed25519_pubkey_hex) {
      if (trustedPubKeyHex && entry.ed25519_pubkey_hex !== trustedPubKeyHex) {
        return { valid: false, entriesVerified: i, error: `Untrusted public key at line ${i + 1}` };
      }
      const pubDerPrefix = Buffer.from("302a300506032b6570032100", "hex");
      const pubDer = Buffer.concat([
        pubDerPrefix,
        Buffer.from(entry.ed25519_pubkey_hex, "hex"),
      ] as unknown as Uint8Array[]);
      const pubKey = crypto.createPublicKey({
        key: pubDer as unknown as Buffer,
        format: "der",
        type: "spki",
      });
      const verified = crypto.verify(
        null,
        Buffer.from(entry.hash, "utf-8") as unknown as Uint8Array,
        pubKey,
        Buffer.from(entry.ed25519_sig_hex, "hex") as unknown as Uint8Array
      );
      if (!verified) {
        return { valid: false, entriesVerified: i, error: `Ed25519 signature invalid at line ${i + 1}` };
      }
    }

    expectedPrev = entry.hash;
  }

  return { valid: true, entriesVerified: lines.length };
}
