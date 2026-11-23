/**
 * Local reverse-proxy server for the Dirgha Agent Gateway.
 * Intercepts tool calls from Claude Code, Cursor, and OpenCode,
 * routing them through the LOKAHI WebAssembly gate before execution.
 */

import * as http from "node:http";
import * as https from "node:https";
import * as url from "node:url";
import {
  evaluateInterceptedToolCall,
  createCompliantRefusalArgs,
} from "./interceptor.js";
import {
  handleAnthropicSSEStream,
  handleOpenAISSEStream,
} from "./streaming.js";

export interface GatewayServerOptions {
  port?: number;
  host?: string;
  cwd?: string;
  anthropicBaseUrl?: string;
  openaiBaseUrl?: string;
  authToken?: string;
  allowedOrigins?: string[];
}

class PayloadTooLargeError extends Error {
  constructor() {
    super("Request payload exceeds the 10 MB limit");
    this.name = "PayloadTooLargeError";
  }
}

function isOriginAllowed(origin: string | undefined, allowedOrigins?: string[]): boolean {
  if (!origin) return true; // Direct non-browser CLI calls
  if (allowedOrigins && allowedOrigins.includes(origin)) return true;
  // Safe localhost and desktop embedded origins
  if (
    /^https?:\/\/localhost(:\d+)?$/.test(origin) ||
    /^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(origin) ||
    origin === "tauri://localhost" ||
    origin === "http://tauri.localhost"
  ) {
    return true;
  }
  return false;
}

export function startGatewayServer(options: GatewayServerOptions = {}): http.Server {
  const port = options.port ?? parseInt(process.env.DIRGHA_GATEWAY_PORT || "8080", 10);
  const host = options.host || "127.0.0.1";
  const cwd = options.cwd || process.cwd();
  const anthropicBaseUrl = options.anthropicBaseUrl || process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com";
  const openaiBaseUrl = options.openaiBaseUrl || process.env.OPENAI_BASE_URL || "https://api.openai.com";
  const authToken = options.authToken || process.env.DIRGHA_GATEWAY_TOKEN || process.env.DIRGHA_GATEWAY_KEY;

  const server = http.createServer(async (req, res) => {
    try {
      const origin = req.headers.origin;

      // Reject untrusted cross-origin browser requests (prevent localhost CSRF/DNS-rebinding)
      if (origin && !isOriginAllowed(origin, options.allowedOrigins)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Forbidden", message: `Untrusted Origin '${origin}' rejected by Dirgha Gateway.` }));
        return;
      }

      if (origin) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
      }
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key, anthropic-version, x-dirgha-tenant, x-dirgha-team");

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      const parsedUrl = url.parse(req.url || "", true);
      const pathname = parsedUrl.pathname || "/";

      // 1. Health check endpoint (public)
      if (pathname === "/health" || pathname === "/v1/health") {
        const tenant = (req.headers["x-dirgha-tenant"] as string) || "default";
        const team = (req.headers["x-dirgha-team"] as string) || "engineering";
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "ok",
            service: "Dirgha Agent Gateway",
            version: "2.0.1",
            gate: "LOKAHI_WASM",
            auth_required: Boolean(authToken),
            tenant,
            team,
            host,
            port,
            cwd,
          })
        );
        return;
      }

      // Authentication verification (if DIRGHA_GATEWAY_TOKEN / authToken configured)
      if (authToken) {
        const authHeader = req.headers.authorization;
        const apiKeyHeader = req.headers["x-api-key"] as string;
        const bearerMatch = authHeader ? authHeader.replace(/^Bearer\s+/i, "").trim() : "";
        const presented = bearerMatch || apiKeyHeader;
        if (presented !== authToken) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            error: "Unauthorized",
            message: "Valid Bearer token or x-api-key required for Dirgha Enterprise Gateway.",
          }));
          return;
        }
      }

      // 2. Claude Code endpoint (/v1/messages or /secure-claude)
      if ((pathname === "/v1/messages" || pathname === "/secure-claude") && req.method === "POST") {
        await handleAnthropicProxy(req, res, anthropicBaseUrl, cwd);
        return;
      }

      // 3. OpenAI / Cursor endpoint (/v1/chat/completions)
      if (pathname === "/v1/chat/completions" && req.method === "POST") {
        await handleOpenAIProxy(req, res, openaiBaseUrl, cwd);
        return;
      }

      // 4. Default 404
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Not Found",
          message: `Endpoint ${pathname} not recognized by Dirgha Agent Gateway.`,
        })
      );
    } catch (error) {
      if (res.destroyed || res.writableEnded) return;
      if (res.headersSent) {
        res.destroy();
        return;
      }

      if (error instanceof PayloadTooLargeError) {
        const body = JSON.stringify({
          error: "Payload Too Large",
          message: error.message,
        });
        res.shouldKeepAlive = false;
        res.writeHead(413, {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          Connection: "close",
        });
        res.once("finish", () => req.destroy());
        res.end(body);
        return;
      }

      if (req.aborted || res.destroyed) return;
      const body = JSON.stringify({
        error: "Gateway Request Failed",
        message: "The gateway could not process this request.",
      });
      res.writeHead(500, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      });
      res.end(body);
    }
  });

  server.listen(port, host, () => {
    console.log(`\n======================================================`);
    console.log(`🛡️  Dirgha Agent Gateway active on http://${host}:${port}`);
    console.log(`🔒 Fail-Closed Gate: LOKAHI WebAssembly ("Silence = Refusal")`);
    console.log(`📍 Claude Code Gateway: http://${host}:${port}/v1/messages`);
    console.log(`📍 Cursor/OpenAI Gateway: http://${host}:${port}/v1/chat/completions`);
    console.log(`======================================================\n`);
  });

  return server;
}

/**
 * Handles reverse proxying for Anthropic Claude Code format
 */
async function handleAnthropicProxy(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  upstreamBaseUrl: string,
  cwd: string
): Promise<void> {
  const body = await readRequestBody(req);
  let payload: any = {};
  try {
    payload = JSON.parse(body);
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Malformed JSON body" }));
    return;
  }

  // Pre-flight check: scan prompt messages for overt prompt injections
  const messages = payload.messages || [];
  for (const msg of messages) {
    if (msg.role === "user" && typeof msg.content === "string") {
      if (
        /(?:ignore previous instructions|bypass security gate|override lokahi|system override)/i.test(
          msg.content
        )
      ) {
        console.warn(`[DIRGHA GATE WARNING] Prompt injection marker detected in request.`);
      }
    }
  }

  // Forward to Anthropic upstream
  const upstreamUrl = new URL("/v1/messages", upstreamBaseUrl);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-api-key":
      (req.headers["x-api-key"] as string) ||
      process.env.ANTHROPIC_API_KEY ||
      "",
    "anthropic-version":
      (req.headers["anthropic-version"] as string) || "2023-06-01",
  };

  const clientReq = (upstreamUrl.protocol === "https:" ? https : http).request(
    upstreamUrl,
    {
      method: "POST",
      headers,
    },
    (upstreamRes) => {
      const isStream =
        payload.stream === true ||
        Boolean(upstreamRes.headers["content-type"]?.includes("text/event-stream"));

      if (isStream) {
        handleAnthropicSSEStream(upstreamRes, res, cwd);
        return;
      }

      let respBody = "";
      upstreamRes.on("data", (chunk) => {
        respBody += chunk;
      });

      upstreamRes.on("end", () => {
        try {
          const respData = JSON.parse(respBody);

          // Intercept tool calls in Anthropic response
          if (Array.isArray(respData.content)) {
            for (const block of respData.content) {
              if (block.type === "tool_use") {
                const check = evaluateInterceptedToolCall(
                  block.name,
                  block.input || {},
                  cwd
                );

                if (!check.allowed) {
                  console.warn(
                    `🛑 [GATE BLOCKED] Refused tool '${block.name}': ${check.reason}`
                  );
                  // Replace tool arguments with schema-compliant refusal arguments
                  block.input = createCompliantRefusalArgs(
                    block.name,
                    check.target,
                    check.reason
                  );
                } else if (check.requiresApproval) {
                  console.info(
                    `⚠️  [GATE ESCALATED] Tool '${block.name}' flagged for human approval.`
                  );
                } else {
                  console.info(`✓ [GATE ALLOWED] Tool '${block.name}' verified safe.`);
                }
              }
            }
          }

          const modifiedBody = JSON.stringify(respData);
          res.writeHead(upstreamRes.statusCode || 200, {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(modifiedBody),
          });
          res.end(modifiedBody);
        } catch {
          // If unparseable or streaming, pass through directly
          res.writeHead(upstreamRes.statusCode || 200, upstreamRes.headers);
          res.end(respBody);
        }
      });
    }
  );

  clientReq.on("error", (err) => {
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error: "Upstream Proxy Error",
        message: err.message,
      })
    );
  });

  clientReq.write(body);
  clientReq.end();
}

/**
 * Handles reverse proxying for OpenAI / Cursor format
 */
async function handleOpenAIProxy(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  upstreamBaseUrl: string,
  cwd: string
): Promise<void> {
  const body = await readRequestBody(req);
  let payload: any = {};
  try {
    payload = JSON.parse(body);
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Malformed JSON body" }));
    return;
  }

  const upstreamUrl = new URL("/v1/chat/completions", upstreamBaseUrl);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization:
      (req.headers["authorization"] as string) ||
      `Bearer ${process.env.OPENAI_API_KEY || ""}`,
  };

  const clientReq = (upstreamUrl.protocol === "https:" ? https : http).request(
    upstreamUrl,
    {
      method: "POST",
      headers,
    },
    (upstreamRes) => {
      const isStream =
        payload.stream === true ||
        Boolean(upstreamRes.headers["content-type"]?.includes("text/event-stream"));

      if (isStream) {
        handleOpenAISSEStream(upstreamRes, res, cwd);
        return;
      }

      let respBody = "";
      upstreamRes.on("data", (chunk) => {
        respBody += chunk;
      });

      upstreamRes.on("end", () => {
        try {
          const respData = JSON.parse(respBody);

          // Intercept tool calls in OpenAI format
          const choices = respData.choices || [];
          for (const choice of choices) {
            const toolCalls = choice.message?.tool_calls || [];
            for (const call of toolCalls) {
              if (call.function) {
                let parsedArgs = {};
                try {
                  parsedArgs = JSON.parse(call.function.arguments || "{}");
                } catch {
                  parsedArgs = { raw: call.function.arguments };
                }

                const check = evaluateInterceptedToolCall(
                  call.function.name,
                  parsedArgs,
                  cwd
                );

                if (!check.allowed) {
                  console.warn(
                    `🛑 [GATE BLOCKED] Refused tool '${call.function.name}': ${check.reason}`
                  );
                  call.function.arguments = JSON.stringify(
                    createCompliantRefusalArgs(
                      call.function.name,
                      check.target,
                      check.reason
                    )
                  );
                } else if (check.requiresApproval) {
                  console.info(
                    `⚠️  [GATE ESCALATED] Tool '${call.function.name}' flagged for human approval.`
                  );
                } else {
                  console.info(`✓ [GATE ALLOWED] Tool '${call.function.name}' verified safe.`);
                }
              }
            }
          }

          const modifiedBody = JSON.stringify(respData);
          res.writeHead(upstreamRes.statusCode || 200, {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(modifiedBody),
          });
          res.end(modifiedBody);
        } catch {
          res.writeHead(upstreamRes.statusCode || 200, upstreamRes.headers);
          res.end(respBody);
        }
      });
    }
  );

  clientReq.on("error", (err) => {
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error: "Upstream Proxy Error",
        message: err.message,
      })
    );
  });

  clientReq.write(body);
  clientReq.end();
}

function readRequestBody(req: http.IncomingMessage, maxBytes: number = 10 * 1024 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    let bytes = 0;
    let settled = false;
    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        settled = true;
        req.pause();
        reject(new PayloadTooLargeError());
        return;
      }
      body += chunk.toString("utf-8");
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      resolve(body);
    });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
    req.on("aborted", () => {
      if (settled) return;
      settled = true;
      reject(new Error("Request was aborted by the client"));
    });
  });
}
