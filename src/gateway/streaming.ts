/**
 * Enterprise Server-Sent Events (SSE) Streaming Interceptor.
 * Enables zero-latency streaming for agent text and thinking blocks while
 * providing fail-closed buffering and real-time LOKAHI evaluation of tool calls.
 */

import type * as http from "node:http";
import {
  evaluateInterceptedToolCall,
  createCompliantRefusalArgs,
} from "./interceptor.js";

interface ActiveAnthropicToolBlock {
  index: number;
  id: string;
  name: string;
  jsonAccumulator: string;
  rawStart: string;
}

interface ActiveOpenAIToolCall {
  index: number;
  id: string;
  name: string;
  argumentsAccumulator: string;
}

/**
 * Intercepts Anthropic `/v1/messages` SSE streams.
 * Pass-through text deltas instantly; hold tool call inputs until `content_block_stop`.
 */
export function handleAnthropicSSEStream(
  upstreamRes: http.IncomingMessage,
  clientRes: http.ServerResponse,
  cwd: string
): void {
  // Write initial SSE headers
  clientRes.writeHead(upstreamRes.statusCode || 200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  let buffer = "";
  const anthropicToolsMap = new Map<number, ActiveAnthropicToolBlock>();

  upstreamRes.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf-8");
    const parts = buffer.split("\n\n");
    // The last element is either empty (if ended with \n\n) or incomplete chunk
    buffer = parts.pop() || "";

    for (const part of parts) {
      if (!part.trim()) continue;
      processAnthropicEvent(part);
    }
  });

  upstreamRes.on("end", () => {
    if (buffer.trim()) {
      processAnthropicEvent(buffer);
    }
    clientRes.end();
  });

  upstreamRes.on("error", (err) => {
    console.error(`[GATEWAY STREAM ERROR] Anthropic stream error: ${err.message}`);
    clientRes.end();
  });

  function processAnthropicEvent(rawEvent: string): void {
    let eventType = "";
    let eventData = "";

    const lines = rawEvent.split("\n");
    for (const line of lines) {
      if (line.startsWith("event:")) {
        eventType = line.slice(6).trim();
      } else if (line.startsWith("data:")) {
        eventData += line.slice(5).trim();
      }
    }

    // 1. Tool Block Start: Hold until tool input finishes
    if (eventType === "content_block_start") {
      try {
        const parsed = JSON.parse(eventData);
        if (parsed.content_block && parsed.content_block.type === "tool_use") {
          anthropicToolsMap.set(parsed.index, {
            index: parsed.index,
            id: parsed.content_block.id,
            name: parsed.content_block.name,
            jsonAccumulator: "",
            rawStart: rawEvent,
          });
          return; // Buffer and do not emit yet
        }
      } catch {
        // Non-JSON data or unexpected format, pass through
      }
    }

    // 2. Tool Input JSON Delta: Accumulate chunk
    if (eventType === "content_block_delta") {
      try {
        const parsed = JSON.parse(eventData);
        const activeTool = anthropicToolsMap.get(parsed.index);
        if (activeTool && parsed.delta?.type === "input_json_delta") {
          activeTool.jsonAccumulator += parsed.delta.partial_json || "";
          return; // Buffer delta chunks
        }
      } catch {
        // Pass through
      }
    }

    // 3. Tool Block Stop: Evaluate tool call with LOKAHI WASM Gate
    if (eventType === "content_block_stop") {
      try {
        const parsed = JSON.parse(eventData);
        const activeTool = anthropicToolsMap.get(parsed.index);
        if (activeTool) {
          let toolInput = {};
          let check: { allowed: boolean; reason: string; target: string };
          try {
            toolInput = JSON.parse(activeTool.jsonAccumulator || "{}");
            check = evaluateInterceptedToolCall(activeTool.name, toolInput, cwd);
          } catch (e: any) {
            check = {
              allowed: false,
              reason: `Malformed JSON payload in tool arguments: ${e?.message || "parse error"}`,
              target: activeTool.name,
            };
          }

          if (check.allowed) {
            console.info(`✓ [GATE STREAM ALLOWED] Tool '${activeTool.name}' verified safe.`);
            // Flush original start
            clientRes.write(activeTool.rawStart + "\n\n");
            // Flush single accumulated delta
            const deltaEvent = `event: content_block_delta\ndata: ${JSON.stringify({
              type: "content_block_delta",
              index: activeTool.index,
              delta: {
                type: "input_json_delta",
                partial_json: activeTool.jsonAccumulator,
              },
            })}\n\n`;
            clientRes.write(deltaEvent);
            // Flush block stop
            clientRes.write(rawEvent + "\n\n");
          } else {
            console.warn(
              `🛑 [GATE STREAM BLOCKED] Refused tool '${activeTool.name}': ${check.reason}`
            );
            // Synthesize compliant refusal arguments
            const safeArgs = createCompliantRefusalArgs(
              activeTool.name,
              check.target,
              check.reason
            );
            // Flush original start
            clientRes.write(activeTool.rawStart + "\n\n");
            // Flush refusal delta
            const safeDeltaEvent = `event: content_block_delta\ndata: ${JSON.stringify({
              type: "content_block_delta",
              index: activeTool.index,
              delta: {
                type: "input_json_delta",
                partial_json: JSON.stringify(safeArgs),
              },
            })}\n\n`;
            clientRes.write(safeDeltaEvent);
            // Flush block stop
            clientRes.write(rawEvent + "\n\n");
          }

          anthropicToolsMap.delete(parsed.index);
          return;
        }
      } catch {
        // Pass through
      }
    }

    // 4. All other events (message_start, text deltas, message_delta, etc.): Stream immediately
    clientRes.write(rawEvent + "\n\n");
  }
}

/**
 * Intercepts OpenAI `/v1/chat/completions` SSE streams.
 * Buffers tool call arguments across chunks, evaluating upon completion.
 */
export function handleOpenAISSEStream(
  upstreamRes: http.IncomingMessage,
  clientRes: http.ServerResponse,
  cwd: string
): void {
  clientRes.writeHead(upstreamRes.statusCode || 200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  let buffer = "";
  const toolCallsMap = new Map<number, ActiveOpenAIToolCall>();

  upstreamRes.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf-8");
    const parts = buffer.split("\n\n");
    buffer = parts.pop() || "";

    for (const part of parts) {
      if (!part.trim()) continue;
      processOpenAIEvent(part);
    }
  });

  upstreamRes.on("end", () => {
    if (buffer.trim()) {
      processOpenAIEvent(buffer);
    }
    clientRes.end();
  });

  upstreamRes.on("error", (err) => {
    console.error(`[GATEWAY STREAM ERROR] OpenAI stream error: ${err.message}`);
    clientRes.end();
  });

  function processOpenAIEvent(rawEvent: string): void {
    if (rawEvent.trim() === "data: [DONE]") {
      clientRes.write("data: [DONE]\n\n");
      return;
    }

    let jsonStr = "";
    const lines = rawEvent.split("\n");
    for (const line of lines) {
      if (line.startsWith("data:")) {
        jsonStr += line.slice(5).trim();
      }
    }

    if (!jsonStr) {
      clientRes.write(rawEvent + "\n\n");
      return;
    }

    try {
      const parsed = JSON.parse(jsonStr);
      const choice = parsed.choices?.[0];
      const delta = choice?.delta;

      // 1. Tool call delta
      if (Array.isArray(delta?.tool_calls)) {
        for (const tc of delta.tool_calls) {
          const idx = tc.index ?? 0;
          if (!toolCallsMap.has(idx)) {
            toolCallsMap.set(idx, {
              index: idx,
              id: tc.id || `call_${idx}`,
              name: tc.function?.name || "",
              argumentsAccumulator: "",
            });
          }
          const active = toolCallsMap.get(idx)!;
          if (tc.function?.name) {
            active.name = tc.function.name;
          }
          if (tc.function?.arguments) {
            active.argumentsAccumulator += tc.function.arguments;
          }
        }
        // Do not forward intermediate raw tool call deltas until evaluated
        return;
      }

      // 2. Finish reason: tool_calls -> evaluate all accumulated tools
      if (choice?.finish_reason === "tool_calls") {
        for (const [idx, tool] of toolCallsMap.entries()) {
          let parsedArgs = {};
          let check: { allowed: boolean; reason: string; target: string };
          try {
            parsedArgs = JSON.parse(tool.argumentsAccumulator || "{}");
            check = evaluateInterceptedToolCall(tool.name, parsedArgs, cwd);
          } catch (e: any) {
            check = {
              allowed: false,
              reason: `Malformed JSON payload in tool arguments: ${e?.message || "parse error"}`,
              target: tool.name,
            };
          }

          let finalArgsStr = tool.argumentsAccumulator;
          if (!check.allowed) {
            console.warn(
              `🛑 [GATE STREAM BLOCKED] Refused tool '${tool.name}': ${check.reason}`
            );
            const safeArgs = createCompliantRefusalArgs(
              tool.name,
              check.target,
              check.reason
            );
            finalArgsStr = JSON.stringify(safeArgs);
          } else {
            console.info(`✓ [GATE STREAM ALLOWED] Tool '${tool.name}' verified safe.`);
          }

          // Emit synthesized complete tool call delta
          const toolCallChunk = {
            id: parsed.id,
            object: "chat.completion.chunk",
            created: parsed.created,
            model: parsed.model,
            choices: [
              {
                index: 0,
                delta: {
                  tool_calls: [
                    {
                      index: idx,
                      id: tool.id,
                      type: "function",
                      function: {
                        name: tool.name,
                        arguments: finalArgsStr,
                      },
                    },
                  ],
                },
                finish_reason: null,
              },
            ],
          };
          clientRes.write(`data: ${JSON.stringify(toolCallChunk)}\n\n`);
        }
        toolCallsMap.clear();

        // Emit final finish chunk
        clientRes.write(rawEvent + "\n\n");
        return;
      }

      // 3. Regular assistant text deltas
      clientRes.write(rawEvent + "\n\n");
    } catch {
      clientRes.write(rawEvent + "\n\n");
    }
  }
}
