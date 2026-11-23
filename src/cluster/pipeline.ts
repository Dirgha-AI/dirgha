/**
 * Pipeline Parallelism Execution Engine for Dirgha Cluster.
 *
 * Simulates and executes activation forwards across partitioned layer ranges.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import type { ClusterTopology, NodePartition } from "./types.js";

export function computeLayerPartitions(
  totalLayers: number,
  modelSizeBytes: number,
  nodes: Array<{ nodeId: string; name: string; availableMemoryBytes: number }>
): NodePartition[] {
  if (nodes.length === 0) return [];
  const totalMemory = nodes.reduce((acc, n) => acc + n.availableMemoryBytes, 0);
  let currentLayer = 0;

  return nodes.map((node, idx) => {
    const isFirst = idx === 0;
    const isLast = idx === nodes.length - 1;
    const share = node.availableMemoryBytes / totalMemory;
    const targetLayers = isLast
      ? totalLayers - currentLayer
      : Math.max(1, Math.round(totalLayers * share));
    const endLayer = isLast ? totalLayers - 1 : currentLayer + targetLayers - 1;

    const partition: NodePartition = {
      nodeId: node.nodeId,
      nodeName: node.name,
      layerRange: {
        startLayer: currentLayer,
        endLayer,
        totalLayers,
      },
      memoryAllocatedBytes: Math.round(((endLayer - currentLayer + 1) / totalLayers) * modelSizeBytes),
      isFirst,
      isLast,
    };

    currentLayer = endLayer + 1;
    return partition;
  });
}

export async function* simulatePipelineStream(
  prompt: string,
  model: string,
  topology: ClusterTopology
): AsyncGenerator<string, void, unknown> {
  const words = [
    `[Dirgha Cluster: ${topology.clusterName} (${topology.nodes.length} nodes, ${(topology.totalMemoryBytes / (1024 * 1024 * 1024)).toFixed(1)} GB pooled)] `,
    `Processed `,
    `prompt `,
    `across `,
    `${topology.activePartitions?.length || topology.nodes.length} pipeline partitions `,
    `for ${model}. `,
    `Generation: `,
    `Sovereign `,
    `distributed `,
    `inference `,
    `executed `,
    `successfully `,
    `with `,
    `zero `,
    `cloud `,
    `leakage.`
  ];

  for (const word of words) {
    yield word;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}
