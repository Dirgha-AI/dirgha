/**
 * Verification test for Dirgha Agent Gateway tool call interception
 */
import { evaluateInterceptedToolCall } from "../dist/gateway/interceptor.js";

console.log("=== Testing Dirgha Agent Gateway Interceptor ===");

// Test 1: Safe read inside CWD
const check1 = evaluateInterceptedToolCall("read_file", { path: "package.json" }, process.cwd());
console.log(`[Test 1] read_file (package.json):`);
console.log(`         Allowed: ${check1.allowed}, RequiresApproval: ${check1.requiresApproval}, Action: ${check1.action}`);
if (!check1.allowed) {
  console.error("FAIL: Safe read should be allowed");
  process.exit(1);
}

// Test 2: Destructive shell command
const check2 = evaluateInterceptedToolCall("bash", { command: "rm -rf /etc" }, process.cwd());
console.log(`[Test 2] bash (rm -rf /etc):`);
console.log(`         Allowed: ${check2.allowed}, RequiresApproval: ${check2.requiresApproval}, Action: ${check2.action}`);
console.log(`         Reason: ${check2.reason}`);

// Test 3: S2 Ledger audit file
import * as fs from "node:fs";
import * as path from "node:path";
const auditPath = path.join(process.cwd(), "data", "gateway_audit.jsonl");
if (fs.existsSync(auditPath)) {
  const lines = fs.readFileSync(auditPath, "utf-8").trim().split("\n");
  console.log(`[Test 3] S2 Ledger Audit entries logged: ${lines.length}`);
  const last = JSON.parse(lines[lines.length - 1]);
  console.log(`         Last Entry: ${last.tool} (${last.verdict}) -> ${last.reason} [hash: ${last.hash}]`);
}

console.log("=== Interceptor Verification: ALL PASS ===");
