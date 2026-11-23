import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ClusterDaemon } from "../daemon.js";

describe("ClusterDaemon HTTP & Streaming Server", () => {
  const TEST_PORT = 54199;
  let daemon: ClusterDaemon;
  const baseUrl = `http://127.0.0.1:${TEST_PORT}`;

  beforeAll(async () => {
    daemon = new ClusterDaemon({ port: TEST_PORT, clusterName: "test-unit-cluster" });
    await daemon.start();
  });

  afterAll(async () => {
    await daemon.stop();
  });

  it("GET /health returns 200 with cluster metadata", async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const json = await res.json() as { status: string; clusterName: string; nodes: number };
    expect(json.status).toBe("ok");
    expect(json.clusterName).toBe("test-unit-cluster");
    expect(json.nodes).toBe(1);
  });

  it("GET /v1/models returns cluster model list", async () => {
    const res = await fetch(`${baseUrl}/v1/models`);
    expect(res.status).toBe(200);
    const json = await res.json() as { object: string; data: Array<{ id: string }> };
    expect(json.object).toBe("list");
    expect(json.data.some((m) => m.id === "cluster/llama-3.3-70b")).toBe(true);
  });

  it("GET /api/cluster/topology returns layer partitions", async () => {
    const res = await fetch(`${baseUrl}/api/cluster/topology`);
    expect(res.status).toBe(200);
    const json = await res.json() as { activePartitions: Array<{ layerRange: { totalLayers: number } }> };
    expect(json.activePartitions.length).toBeGreaterThan(0);
    expect(json.activePartitions[0].layerRange.totalLayers).toBe(80);
  });

  it("POST /v1/chat/completions non-streaming returns completion", async () => {
    const res = await fetch(`${baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama-3.3-70b",
        messages: [{ role: "user", content: "Hello cluster" }],
        stream: false,
      }),
    });
    expect(res.status).toBe(200);
    const json = await res.json() as { choices: Array<{ message: { content: string } }> };
    expect(json.choices[0].message.content).toContain("Dirgha Cluster");
  });

  it("POST /v1/chat/completions streaming returns SSE chunks and [DONE]", async () => {
    const res = await fetch(`${baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama-3.3-70b",
        messages: [{ role: "user", content: "Stream test" }],
        stream: true,
      }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");

    const text = await res.text();
    expect(text).toContain("data: ");
    expect(text).toContain("[DONE]");
  });

  it("POST /v1/messages non-streaming returns Anthropic response", async () => {
    const res = await fetch(`${baseUrl}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama-3.3-70b",
        messages: [{ role: "user", content: "Hello Anthropic" }],
        stream: false,
      }),
    });
    expect(res.status).toBe(200);
    const json = await res.json() as { type: string; content: Array<{ text: string }> };
    expect(json.type).toBe("message");
    expect(json.content[0].text).toContain("Dirgha Cluster");
  });

  it("POST /v1/messages streaming returns Anthropic SSE events", async () => {
    const res = await fetch(`${baseUrl}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama-3.3-70b",
        messages: [{ role: "user", content: "Stream Anthropic" }],
        stream: true,
      }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");

    const text = await res.text();
    expect(text).toContain("event: message_start");
    expect(text).toContain("event: content_block_delta");
    expect(text).toContain("event: message_stop");
  });
});
