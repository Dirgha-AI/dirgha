/**
 * Types and interfaces for Dirgha P2P Distributed Inference Cluster.
 *
 * Licensed under the Apache License, Version 2.0.
 */

export type ComputeBackend = "metal" | "cuda" | "rocm" | "cpu";

export interface ClusterNode {
  nodeId: string;
  name: string;
  addr: string;
  availableMemoryBytes: number;
  backend: ComputeBackend;
  pubkeyFingerprint: string;
  lastSeenUnixMs: number;
}

export interface LayerRange {
  startLayer: number;
  endLayer: number;
  totalLayers: number;
}

export interface NodePartition {
  nodeId: string;
  nodeName: string;
  layerRange: LayerRange;
  memoryAllocatedBytes: number;
  isFirst: boolean;
  isLast: boolean;
}

export interface ClusterTopology {
  clusterId: string;
  clusterName: string;
  leaderNodeId: string;
  nodes: ClusterNode[];
  activeModel?: string;
  activePartitions?: NodePartition[];
  totalMemoryBytes: number;
}

export interface ClusterDaemonOptions {
  port?: number;
  host?: string;
  clusterName?: string;
  localMemoryBytes?: number;
  backend?: ComputeBackend;
}
