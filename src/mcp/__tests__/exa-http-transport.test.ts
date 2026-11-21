/**
 * Offline verification of .mcp.json Exa registration & Streamable HTTP
 * `mcp-session-id` + SSE handling in HttpTransport.
 *
 * Zero external network calls (uses an ephemeral 127.0.0.1 server).
 * Licensed under the Apache License, Version 2.0.
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { HttpTransport } from "../transport.js";

let activeServer: Server | null = null;

afterEach(async () => {
  if (activeServer) {
    await new Promise<void>((r) => activeServer!.close(() => r()));
    activeServer = null;
  }
});

describe("Exa MCP reconciliation & Streamable HTTP transport", () => {
  it("registers both dirgha-sovereign-kernel and official Exa MCP in .mcp.json", () => {
    const raw = readFileSync(resolve(process.cwd(), ".mcp.json"), "utf8");
    const parsed = JSON.parse(raw) as {
      mcpServers: Record<string, { command?: string; url?: string }>;
    };
    expect(parsed.mcpServers["dirgha-sovereign-kernel"]?.command).toBeTruthy();
    expect(parsed.mcpServers.exa?.url).toBe(
      "https://mcp.exa.ai/mcp?tools=web_search_exa,web_fetch_exa",
    );
  });

  it("persists mcp-session-id and flushes CRLF/EOF-terminated SSE responses", async () => {
    let seenSessionHeader: string | undefined;

    activeServer = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          id: number;
          method: string;
        };
        if (body.method === "initialize") {
          res.writeHead(200, {
            "content-type": "text/event-stream",
            "mcp-session-id": "exa-sess-42",
          });
          // CRLF + no trailing blank line at EOF
          res.end(
            `event: message\r\ndata: ${JSON.stringify({
              jsonrpc: "2.0",
              id: body.id,
              result: { serverInfo: { name: "exa-mock" } },
            })}\r\n`,
          );
          return;
        }
        seenSessionHeader = req.headers["mcp-session-id"] as string | undefined;
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.end(
          `data: ${JSON.stringify({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              tools: [{ name: "web_search_exa" }, { name: "web_fetch_exa" }],
            },
          })}\n\n`,
        );
      });
    });

    await new Promise<void>((r) => activeServer!.listen(0, "127.0.0.1", () => r()));
    const addr = activeServer.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;

    const transport = new HttpTransport({ url: `http://127.0.0.1:${port}/mcp` });
    const received: Array<{ id?: number; result?: Record<string, unknown> }> = [];
    transport.onMessage((msg) => received.push(msg as { id?: number; result?: Record<string, unknown> }));

    await transport.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    await transport.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    await transport.close();

    expect(seenSessionHeader).toBe("exa-sess-42");
    expect(received.length).toBe(2);
    const tools = (received[1].result?.tools as Array<{ name: string }>) ?? [];
    expect(tools.map((t) => t.name)).toEqual(["web_search_exa", "web_fetch_exa"]);
  });
});
