//! Mathematical pipeline partitioning for distributed model layer slicing.

use crate::discovery::ClusterNode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PartitionError {
    #[error("No nodes available in cluster")]
    NoNodes,
    #[error("Insufficient total memory: required {required_bytes} bytes, available {available_bytes} bytes")]
    InsufficientMemory {
        required_bytes: u64,
        available_bytes: u64,
    },
    #[error("Invalid layer configuration: total layers {0}")]
    InvalidLayers(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerRange {
    pub start_layer: usize,
    pub end_layer: usize,
    pub total_layers: usize,
}

impl LayerRange {
    pub fn layer_count(&self) -> usize {
        if self.end_layer >= self.start_layer {
            self.end_layer - self.start_layer + 1
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePartition {
    pub node_id: String,
    pub node_name: String,
    pub layer_range: LayerRange,
    pub memory_allocated_bytes: u64,
    pub is_first: bool,
    pub is_last: bool,
}

/// Slices a model's transformer layers across the cluster proportional to each node's memory.
pub fn partition_layers(
    total_layers: usize,
    model_weight_bytes: u64,
    nodes: &[ClusterNode],
) -> Result<Vec<NodePartition>, PartitionError> {
    if nodes.is_empty() {
        return Err(PartitionError::NoNodes);
    }
    if total_layers == 0 {
        return Err(PartitionError::InvalidLayers(total_layers));
    }

    let total_avail: u64 = nodes.iter().map(|n| n.available_memory_bytes).sum();
    // Headroom safety: require available memory to cover model weights + 10% KV-cache buffer
    let required_with_headroom = (model_weight_bytes as f64 * 1.10) as u64;
    if total_avail < required_with_headroom {
        return Err(PartitionError::InsufficientMemory {
            required_bytes: required_with_headroom,
            available_bytes: total_avail,
        });
    }

    let mut partitions = Vec::with_capacity(nodes.len());
    let mut current_layer = 0;

    for (idx, node) in nodes.iter().enumerate() {
        let is_first = idx == 0;
        let is_last = idx == nodes.len() - 1;

        let share = node.available_memory_bytes as f64 / total_avail as f64;
        let target_layers = if is_last {
            total_layers.saturating_sub(current_layer)
        } else {
            let allocated = (total_layers as f64 * share).round() as usize;
            // Bound so at least 1 layer if possible, and doesn't exceed remainder
            let remaining = total_layers.saturating_sub(current_layer);
            allocated.max(1).min(remaining.saturating_sub(nodes.len() - idx - 1))
        };

        let end_layer = (current_layer + target_layers).saturating_sub(1);
        let range = LayerRange {
            start_layer: current_layer,
            end_layer,
            total_layers,
        };

        let mem_alloc = (model_weight_bytes as f64 * (range.layer_count() as f64 / total_layers as f64)) as u64;

        partitions.push(NodePartition {
            node_id: node.node_id.clone(),
            node_name: node.name.clone(),
            layer_range: range,
            memory_allocated_bytes: mem_alloc,
            is_first,
            is_last,
        });

        current_layer = end_layer + 1;
    }

    Ok(partitions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::ComputeBackend;

    #[test]
    fn test_partition_math_70b_three_heterogeneous_nodes() {
        let nodes = vec![
            ClusterNode {
                node_id: "node_1".into(),
                name: "MacBook M3 Pro".into(),
                addr: "192.168.1.10:54125".into(),
                available_memory_bytes: 18 * 1024 * 1024 * 1024, // 18 GB
                backend: ComputeBackend::Metal,
                pubkey_fingerprint: "fp1".into(),
                last_seen_unix_ms: 0,
            },
            ClusterNode {
                node_id: "node_2".into(),
                name: "RTX 4090 Desktop".into(),
                addr: "192.168.1.11:54125".into(),
                available_memory_bytes: 24 * 1024 * 1024 * 1024, // 24 GB
                backend: ComputeBackend::Cuda,
                pubkey_fingerprint: "fp2".into(),
                last_seen_unix_ms: 0,
            },
            ClusterNode {
                node_id: "node_3".into(),
                name: "Mac Mini M2".into(),
                addr: "192.168.1.12:54125".into(),
                available_memory_bytes: 16 * 1024 * 1024 * 1024, // 16 GB
                backend: ComputeBackend::Metal,
                pubkey_fingerprint: "fp3".into(),
                last_seen_unix_ms: 0,
            },
        ];

        let total_layers = 80;
        let model_size_bytes = 42 * 1024 * 1024 * 1024; // 42 GB (Llama 3 70B Q4)

        let parts = partition_layers(total_layers, model_size_bytes, &nodes).expect("partition should succeed");
        assert_eq!(parts.len(), 3);

        // Verify contiguous layer ranges from 0 to 79
        assert_eq!(parts[0].layer_range.start_layer, 0);
        assert_eq!(parts[0].is_first, true);
        assert_eq!(parts[1].layer_range.start_layer, parts[0].layer_range.end_layer + 1);
        assert_eq!(parts[2].layer_range.start_layer, parts[1].layer_range.end_layer + 1);
        assert_eq!(parts[2].layer_range.end_layer, 79);
        assert_eq!(parts[2].is_last, true);

        let total_assigned: usize = parts.iter().map(|p| p.layer_range.layer_count()).sum();
        assert_eq!(total_assigned, 80);
    }
}
