/**
 * Dirgha Cluster provider — Peer-to-Peer (P2P) distributed inference runtime.
 *
 * Directs inference calls for `cluster/*` and `local/*` models to the local
 * Dirgha Cluster coordinator node (default: http://localhost:54125/v1), which executes
 * pipeline-parallel layer forward passes across pooled local workstations.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import type { AgentEvent } from "../kernel/types.js";
import type { Provider, StreamRequest, ProviderConfig } from "./iface.js";
import { streamChatCompletions } from "./openai-compat.js";

const DEFAULT_CLUSTER_BASE = "http://localhost:54125/v1";

export class ClusterProvider implements Provider {
  readonly id = "cluster";
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(config: ProviderConfig = {}) {
    this.baseUrl = (config.baseUrl ?? DEFAULT_CLUSTER_BASE).replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? 180_000;
  }

  supportsTools(_modelId: string): boolean {
    return true;
  }

  supportsThinking(_modelId: string): boolean {
    return false;
  }

  stream(req: StreamRequest): AsyncIterable<AgentEvent> {
    const model = req.model.replace(/^(cluster|local)\//, "");
    return streamChatCompletions({
      providerName: this.id,
      endpoint: `${this.baseUrl}/chat/completions`,
      apiKey: "dirgha-cluster-local",
      model,
      messages: req.messages,
      tools: req.tools,
      temperature: req.temperature,
      maxTokens: req.maxTokens,
      signal: req.signal,
      timeoutMs: this.timeoutMs,
    });
  }
}
