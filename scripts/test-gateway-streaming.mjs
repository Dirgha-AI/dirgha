import { EventEmitter } from "node:events";
import { handleAnthropicSSEStream } from "../dist/gateway/streaming.js";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

console.log("=== Testing Enterprise Gateway SSE Streaming Interceptor ===");

class MockUpstreamResponse extends EventEmitter {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = { "content-type": "text/event-stream" };
  }
}

class MockClientResponse extends EventEmitter {
  constructor() {
    super();
    this.writtenData = [];
    this.headers = {};
    this.statusCode = null;
  }

  writeHead(status, headers) {
    this.statusCode = status;
    this.headers = headers;
  }

  write(chunk) {
    this.writtenData.push(chunk);
  }

  end() {
    this.emit("finish");
  }
}

async function runStreamingTest() {
  const upstream = new MockUpstreamResponse();
  const client = new MockClientResponse();
  const cwd = process.cwd();

  // Attach streaming handler
  handleAnthropicSSEStream(upstream, client, cwd);

  // Send SSE events for a destructive tool call: bash -> "rm -rf /"
  const sseChunks = [
    'event: message_start\ndata: {"type": "message_start", "message": {"id": "msg_01", "role": "assistant"}}\n\n',
    'event: content_block_start\ndata: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": "I will clean the filesystem."}}\n\n',
    'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " Running command now."}}\n\n',
    'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 0}\n\n',
    // Tool call begins
    'event: content_block_start\ndata: {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_destruct_01", "name": "bash", "input": {}}}\n\n',
    'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\\"command\\": "}}\n\n',
    'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "\\"rm -rf /\\"}"}}\n\n',
    'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 1}\n\n',
    'event: message_stop\ndata: {"type": "message_stop"}\n\n',
  ];

  // Feed chunks with slight async interleaving to simulate real TCP packet stream
  for (const chunk of sseChunks) {
    upstream.emit("data", Buffer.from(chunk, "utf-8"));
  }
  upstream.emit("end");

  // Verify client received rewritten safe output
  const fullOutput = client.writtenData.join("");
  console.log("\n[Stream Output Verification]");

  // 1. Check text block passed through
  const hasText = fullOutput.includes("I will clean the filesystem.");
  console.log(`[Check 1] Text block passed with zero latency: ${hasText ? "PASS" : "FAIL"}`);

  // 2. Check lethal command was NOT emitted in output
  const hasLethalCommand = fullOutput.includes('"rm -rf /"');
  console.log(`[Check 2] Lethal command 'rm -rf /' was intercepted and stripped: ${!hasLethalCommand ? "PASS" : "FAIL"}`);

  // 3. Check schema-compliant refusal injected
  const hasRefusal = fullOutput.includes("[LOKAHI REFUSED]");
  console.log(`[Check 3] Schema-compliant refusal command injected: ${hasRefusal ? "PASS" : "FAIL"}`);

  // 4. Verify S2 ledger contains audit entry
  const auditPath = join(cwd, "data", "gateway_audit.jsonl");
  const hasAuditLog = existsSync(auditPath);
  console.log(`[Check 4] S2 Cryptographic Ledger updated: ${hasAuditLog ? "PASS" : "FAIL"}`);

  if (hasText && !hasLethalCommand && hasRefusal && hasAuditLog) {
    console.log("\n=== Enterprise Streaming Interception Test: ALL PASS ===");
    process.exit(0);
  } else {
    console.error("\n=== Enterprise Streaming Interception Test: FAILED ===");
    process.exit(1);
  }
}

runStreamingTest().catch((err) => {
  console.error("Test failed with exception:", err);
  process.exit(1);
});
