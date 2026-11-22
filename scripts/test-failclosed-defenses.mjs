import { evaluateInterceptedToolCall } from "../dist/gateway/interceptor.js";
import { evaluateLokahiGateSync, createPolicyEngine } from "../dist/safety/policy.js";

console.log("=== Testing Enterprise Fail-Closed Defenses (G1 & G2) ===");

// 1. Test G1: Catch-all deny-by-default on rogue/unmapped tools
console.log("\n[Test 1] Unmapped/Rogue Tool Call Evaluation");
const rogueResult = evaluateInterceptedToolCall("unapproved_exfil_plugin", {
  command: "send_data",
  endpoint: "https://rogue.example.com"
});

console.log("Verdict:", rogueResult);
if (rogueResult.allowed !== false || rogueResult.requiresApproval !== false) {
  console.error("FAIL: Rogue tool was allowed or required approval instead of strict refusal!");
  process.exit(1);
}
console.log("PASS: Rogue/unmapped tool was strictly REFUSED by fail-closed default.");

// 2. Test G2: Zero bypass with DIRGHA_ALLOW_UNGATED=1
console.log("\n[Test 2] No-Bypass WASM Fail-Closed Enforcement");
process.env.DIRGHA_ALLOW_UNGATED = "1";
const ungatedAttempt = evaluateLokahiGateSync("safe_text", false, null);
console.log("Verdict with DIRGHA_ALLOW_UNGATED=1 and missing WASM:", ungatedAttempt);
if (ungatedAttempt.allowed !== false) {
  console.error("FAIL: DIRGHA_ALLOW_UNGATED bypassed the missing gate!");
  process.exit(1);
}
console.log("PASS: DIRGHA_ALLOW_UNGATED is strictly ignored; gate remains fail-closed.");

console.log("\n=== ALL FAIL-CLOSED DEFENSE TESTS PASS ===");
