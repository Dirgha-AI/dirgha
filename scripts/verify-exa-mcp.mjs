#!/usr/bin/env node
// Dependency-free smoke test for the Exa MCP registration in .mcp.json.
// Performs initialize + tools/list and asserts the two configured tools exist.

const URL = process.env.EXA_MCP_URL ||
  "https://mcp.exa.ai/mcp?tools=web_search_exa,web_fetch_exa";
const REQUIRED = ["web_search_exa", "web_fetch_exa"];

async function rpc(message, sessionId) {
  const headers = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;

  const res = await fetch(URL, {
    method: "POST",
    headers,
    body: JSON.stringify(message),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);

  // Exa answers with SSE (`data: {...}`); tolerate plain JSON too.
  const dataLine = text.split(/\r?\n/).find((line) => line.startsWith("data:"));
  const payload = JSON.parse(dataLine ? dataLine.slice(5).trim() : text);
  if (payload.error) throw new Error(JSON.stringify(payload.error));
  return { payload, sessionId: res.headers.get("mcp-session-id") || sessionId };
}

const init = await rpc({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "dirgha-exa-verify", version: "1" },
  },
});

const listed = await rpc(
  { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  init.sessionId,
);

const tools = (listed.payload.result?.tools || []).map((tool) => tool.name);
const missing = REQUIRED.filter((name) => !tools.includes(name));
if (missing.length) {
  console.error(`FAIL: missing tools: ${missing.join(", ")}`);
  console.error(`Saw: ${tools.join(", ") || "(none)"}`);
  process.exit(1);
}

console.log(`OK: ${init.payload.result?.serverInfo?.name || "Exa MCP"} reachable`);
console.log(`Tools: ${tools.join(", ")}`);
