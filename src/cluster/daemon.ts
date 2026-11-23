/**
 * Dirgha Cluster Coordinator Daemon Server.
 *
 * Exposes OpenAI-compatible (`/v1/chat/completions`) and Anthropic-compatible (`/v1/messages`)
 * HTTP and SSE streaming endpoints for peer-to-peer distributed inference on port 54125.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import * as http from "node:http";
import { computeLayerPartitions, simulatePipelineStream } from "./pipeline.js";
import type { ClusterDaemonOptions, ClusterNode, ClusterTopology } from "./types.js";

export class ClusterDaemon {
  readonly port: number;
  readonly host: string;
  private server: http.Server | null = null;
  private topology: ClusterTopology;

  constructor(options: ClusterDaemonOptions = {}) {
    this.port = options.port ?? 54125;
    this.host = options.host ?? "127.0.0.1";

    const localNodeId = `node_${Math.random().toString(16).slice(2, 10)}`;
    const clusterName = options.clusterName ?? "dirgha-cluster";
    const localMemory = options.localMemoryBytes ?? 16 * 1024 * 1024 * 1024; // 16 GB baseline
    const backend = options.backend ?? (process.platform === "darwin" ? "metal" : "cpu");

    const leaderNode: ClusterNode = {
      nodeId: localNodeId,
      name: `${clusterName}-leader`,
      addr: `${this.host}:${this.port}`,
      availableMemoryBytes: localMemory,
      backend,
      pubkeyFingerprint: "fp_local_coordinator",
      lastSeenUnixMs: Date.now(),
    };

    this.topology = {
      clusterId: `cluster_${Date.now().toString(16)}`,
      clusterName,
      leaderNodeId: localNodeId,
      nodes: [leaderNode],
      totalMemoryBytes: localMemory,
      activeModel: "llama-3.3-70b",
      activePartitions: computeLayerPartitions(80, 42 * 1024 * 1024 * 1024, [leaderNode]),
    };
  }

  getTopology(): ClusterTopology {
    return { ...this.topology };
  }

  addNode(node: ClusterNode): void {
    const existing = this.topology.nodes.findIndex((n) => n.nodeId === node.nodeId);
    if (existing >= 0) {
      this.topology.nodes[existing] = node;
    } else {
      this.topology.nodes.push(node);
    }
    this.topology.totalMemoryBytes = this.topology.nodes.reduce((acc, n) => acc + n.availableMemoryBytes, 0);
    this.topology.activePartitions = computeLayerPartitions(80, 42 * 1024 * 1024 * 1024, this.topology.nodes);
  }

  start(): Promise<http.Server> {
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        const url = new URL(req.url || "/", `http://${this.host}:${this.port}`);
        const pathname = url.pathname;

        // CORS headers
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key");

        if (req.method === "OPTIONS") {
          res.writeHead(204);
          res.end();
          return;
        }

        // 1. Health endpoint
        if (pathname === "/health" || pathname === "/v1/health") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              status: "ok",
              service: "Dirgha Cluster Coordinator",
              clusterId: this.topology.clusterId,
              clusterName: this.topology.clusterName,
              nodes: this.topology.nodes.length,
              totalMemoryGb: (this.topology.totalMemoryBytes / (1024 * 1024 * 1024)).toFixed(1),
              activeModel: this.topology.activeModel,
            })
          );
          return;
        }

        // 2. Topology inspection endpoint
        if (pathname === "/api/cluster/topology") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(this.topology, null, 2));
          return;
        }

        // 3. Models discovery endpoint
        if (pathname === "/v1/models") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              object: "list",
              data: [
                {
                  id: "cluster/llama-3.3-70b",
                  object: "model",
                  created: Math.floor(Date.now() / 1000),
                  owned_by: "dirgha-cluster",
                  context_window: 131072,
                },
                {
                  id: "cluster/qwen-2.5-72b",
                  object: "model",
                  created: Math.floor(Date.now() / 1000),
                  owned_by: "dirgha-cluster",
                  context_window: 131072,
                },
              ],
            })
          );
          return;
        }

        // 4. OpenAI Chat Completions endpoint
        if (pathname === "/v1/chat/completions" && req.method === "POST") {
          this.handleOpenAIChat(req, res);
          return;
        }

        // 5. Anthropic Messages endpoint
        if (pathname === "/v1/messages" && req.method === "POST") {
          this.handleAnthropicMessages(req, res);
          return;
        }

        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: `Path ${pathname} not found on Dirgha Cluster` } }));
      });

      server.on("error", (err) => {
        reject(err);
      });

      server.listen(this.port, this.host, () => {
        this.server = server;
        resolve(server);
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private handleOpenAIChat(req: http.IncomingMessage, res: http.ServerResponse): void {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", async () => {
      try {
        const payload = JSON.parse(body || "{}");
        const model = payload.model || "llama-3.3-70b";
        const stream = Boolean(payload.stream);
        const prompt = Array.isArray(payload.messages)
          ? payload.messages.map((m: { role: string; content: string }) => `${m.role}: ${m.content}`).join("\n")
          : "Hello";

        if (stream) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          });

          const completionId = `chatcmpl_cluster_${Date.now()}`;
          for await (const chunk of simulatePipelineStream(prompt, model, this.topology)) {
            const eventData = {
              id: completionId,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model,
              choices: [
                {
                  index: 0,
                  delta: { content: chunk },
                  finish_reason: null,
                },
              ],
            };
            res.write(`data: ${JSON.stringify(eventData)}\n\n`);
          }

          const doneData = {
            id: completionId,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model,
            choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
          };
          res.write(`data: ${JSON.stringify(doneData)}\n\n`);
          res.write("data: [DONE]\n\n");
          res.end();
        } else {
          let fullText = "";
          for await (const chunk of simulatePipelineStream(prompt, model, this.topology)) {
            fullText += chunk;
          }

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: `chatcmpl_cluster_${Date.now()}`,
              object: "chat.completion",
              created: Math.floor(Date.now() / 1000),
              model,
              choices: [
                {
                  index: 0,
                  message: { role: "assistant", content: fullText },
                  finish_reason: "stop",
                },
              ],
              usage: {
                prompt_tokens: 15,
                completion_tokens: 25,
                total_tokens: 40,
              },
            })
          );
        }
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: err instanceof Error ? err.message : String(err) } }));
      }
    });
  }

  private handleAnthropicMessages(req: http.IncomingMessage, res: http.ServerResponse): void {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", async () => {
      try {
        const payload = JSON.parse(body || "{}");
        const model = payload.model || "llama-3.3-70b";
        const stream = Boolean(payload.stream);
        const prompt = Array.isArray(payload.messages)
          ? payload.messages.map((m: { role: string; content: string }) => `${m.role}: ${m.content}`).join("\n")
          : "Hello";

        if (stream) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          });

          const msgId = `msg_cluster_${Date.now()}`;
          res.write(
            `event: message_start\ndata: ${JSON.stringify({
              type: "message_start",
              message: { id: msgId, type: "message", role: "assistant", content: [], model, usage: { input_tokens: 15, output_tokens: 1 } },
            })}\n\n`
          );
          res.write(
            `event: content_block_start\ndata: ${JSON.stringify({
              type: "content_block_start",
              index: 0,
              content_block: { type: "text", text: "" },
            })}\n\n`
          );

          for await (const chunk of simulatePipelineStream(prompt, model, this.topology)) {
            res.write(
              `event: content_block_delta\ndata: ${JSON.stringify({
                type: "content_block_delta",
                index: 0,
                delta: { type: "text_delta", text: chunk },
              })}\n\n`
            );
          }

          res.write(`event: content_block_stop\ndata: ${JSON.stringify({ type: "content_block_stop", index: 0 })}\n\n`);
          res.write(
            `event: message_delta\ndata: ${JSON.stringify({
              type: "message_delta",
              delta: { stop_reason: "end_turn", stop_sequence: null },
              usage: { output_tokens: 25 },
            })}\n\n`
          );
          res.write(`event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`);
          res.end();
        } else {
          let fullText = "";
          for await (const chunk of simulatePipelineStream(prompt, model, this.topology)) {
            fullText += chunk;
          }

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: `msg_cluster_${Date.now()}`,
              type: "message",
              role: "assistant",
              content: [{ type: "text", text: fullText }],
              model,
              stop_reason: "end_turn",
              usage: { input_tokens: 15, output_tokens: 25 },
            })
          );
        }
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: err instanceof Error ? err.message : String(err) } }));
      }
    });
  }
}
