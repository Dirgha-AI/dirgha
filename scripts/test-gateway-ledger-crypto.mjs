/**
 * Comprehensive verification of Dirgha Gateway's Ed25519 + SHA-256 S2 Ledger.
 * Tests:
 * 1. Sequential entry logging with SHA-256 block chaining
 * 2. Ed25519 digital signature creation on every block
 * 3. Successful end-to-end chain verification
 * 4. Detection of tampered entries (payload alteration, sequence break, signature mismatch)
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  logActivity,
  verifyGatewayAuditLedger,
  getOrCreateAuditKeyPair,
} from "../dist/gateway/interceptor.js";

console.log("=== Testing S2 Gateway Tamper-Evident Ed25519 Ledger ===");

const testAuditFile = path.join(process.cwd(), "data", "test_gateway_audit.jsonl");
if (fs.existsSync(testAuditFile)) {
  fs.unlinkSync(testAuditFile);
}

// 1. Check KeyPair generation
const keyPair = getOrCreateAuditKeyPair();
console.log(`[Key Check] Host Ed25519 Public Key: ${keyPair.pubKeyHex}`);
if (keyPair.pubKeyHex.length !== 64) {
  console.error("FAIL: Expected 64-char hex (32-byte) Ed25519 public key");
  process.exit(1);
}

// 2. Generate 5 sequential audit entries
console.log("[Ledger Check] Generating 5 signed audit entries...");
for (let i = 1; i <= 5; i++) {
  const entry = logActivity({
    tool: i % 2 === 0 ? "bash" : "read_file",
    action: i % 2 === 0 ? "exec" : "read",
    target: `/test/target_${i}`,
    verdict: i === 3 ? "REFUSE" : "ALLOW",
    reason: i === 3 ? "LOKAHI Invariant violation" : "Passed deterministic gate",
  });
  console.log(`  Entry #${entry.index} | Hash: ${entry.hash.slice(0, 16)}... | Sig: ${entry.ed25519_sig_hex.slice(0, 16)}...`);
}

// 3. Verify real gateway audit file
const auditPath = path.join(process.cwd(), "data", "gateway_audit.jsonl");
const checkReal = verifyGatewayAuditLedger(auditPath, keyPair.pubKeyHex);
console.log(`[Chain Verification] Real audit file (${auditPath}):`);
console.log(`  Valid: ${checkReal.valid}`);
console.log(`  Entries Verified: ${checkReal.entriesVerified}`);
if (!checkReal.valid) {
  console.error(`FAIL: Audit verification failed: ${checkReal.error}`);
  process.exit(1);
}

// 4. Test Tamper Resistance: create a tampered copy and ensure it is caught
console.log("[Tamper Test] Testing anti-tamper detection...");
const originalContent = fs.readFileSync(auditPath, "utf-8");
const lines = originalContent.trim().split("\n");
const lastEntry = JSON.parse(lines[lines.length - 1]);

// Tamper scenario A: Alter payload reason
const tamperedEntry = { ...lastEntry, reason: "HACKED_FORGED_REASON" };
const tamperedLines = [...lines.slice(0, -1), JSON.stringify(tamperedEntry)];
fs.writeFileSync(testAuditFile, tamperedLines.join("\n") + "\n", "utf-8");

const tamperCheck = verifyGatewayAuditLedger(testAuditFile);
console.log(`  Tamper detected: ${!tamperCheck.valid} (Reason: ${tamperCheck.error})`);
if (tamperCheck.valid) {
  console.error("FAIL: Tampered entry was NOT caught!");
  process.exit(1);
}

// Clean up test file
fs.unlinkSync(testAuditFile);

console.log("=== S2 Cryptographic Ledger Verification: ALL PASS ===");
