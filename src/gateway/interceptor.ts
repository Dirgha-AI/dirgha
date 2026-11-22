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
let ledgerIndex = 0;
let lastBlockHash = "0000000000000000000000000000000000000000000000000000000000000000";
let ledgerInitialized = false;

function ensureLedgerInitialized(cwd: string = process.cwd()): void {
  if (ledgerInitialized) return;
  ledgerInitialized = true;
  try {
    const auditFile = path.join(cwd, "data", "gateway_audit.jsonl");
    if (fs.existsSync(auditFile)) {
      const content = fs.readFileSync(auditFile, "utf-8").trim();
      if (content) {
        const lines = content.split("\n").filter((l) => l.trim().length > 0);
        if (lines.length > 0) {
          const lastEntry = JSON.parse(lines[lines.length - 1]);
          if (typeof lastEntry.index === "number" && typeof lastEntry.hash === "string") {
            ledgerIndex = lastEntry.index;
            lastBlockHash = lastEntry.hash;
          }
        }
      }
    }
  } catch {
    // Start from genesis if unreadable
  }
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
    norm === "save_file"
  ) {
    const targetPath = String(args.path || args.file || args.filename || args.target_file || "");
    return {
      action: "write",
      target: targetPath,
    };
  }

  // 3. File view, read tools
  if (
    norm === "read_file" ||
    norm === "view" ||
    norm === "cat" ||
    norm === "get_file_contents" ||
    norm === "open_file"
  ) {
    const targetPath = String(args.path || args.file || args.filename || "");
    return {
      action: "read",
      target: targetPath,
    };
  }

  // 4. File delete tools
  if (norm === "delete_file" || norm === "remove_file" || norm === "unlink") {
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

  // Catch-all
  return {
    action: "exec",
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
    });
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
  });

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
}): S2LedgerEntry {
  ensureLedgerInitialized();
  ledgerIndex++;
  const timestamp = new Date().toISOString();
  
  // High-assurance SHA-256 cryptographic hash chaining
  const payload = `${ledgerIndex}|${timestamp}|${entry.tool}|${entry.action}|${entry.target}|${entry.verdict}|${entry.reason}|${lastBlockHash}`;
  const currentHash = crypto.createHash("sha256").update(payload).digest("hex");

  // Ed25519 DSSE envelope signature over the chained entry hash
  const keyPair = getOrCreateAuditKeyPair();
  const sig = crypto.sign(null, Buffer.from(currentHash, "utf-8") as unknown as Uint8Array, keyPair.privateKey);
  const sigHex = sig.toString("hex");

  const record: S2LedgerEntry = {
    index: ledgerIndex,
    timestamp,
    tool: entry.tool,
    action: entry.action,
    target: entry.target,
    verdict: entry.verdict,
    reason: entry.reason,
    prevHash: lastBlockHash,
    hash: currentHash,
    ed25519_pubkey_hex: keyPair.pubKeyHex,
    ed25519_sig_hex: sigHex,
  };

  lastBlockHash = currentHash;

  try {
    const dataDir = path.join(process.cwd(), "data");
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.appendFileSync(
      path.join(dataDir, "gateway_audit.jsonl"),
      JSON.stringify(record) + "\n",
      "utf-8"
    );
  } catch {
    // Fail-safe logging
  }

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
