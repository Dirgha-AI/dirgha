//! High-level peer-to-peer distributed inference coordinator and worker engine.

use crate::discovery::{ClusterNode, ClusterTopology};
use crate::partitioner::{partition_layers, NodePartition};
use crate::transport::{PacketType, TensorFrame};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Cluster has not been initialized")]
    NotInitialized,
    #[error("Model partition failed: {0}")]
    Partition(#[from] crate::partitioner::PartitionError),
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    #[error("Inference step failed: {0}")]
    Execution(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClusterRole {
    Leader,
    Worker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub cluster_id: String,
    pub cluster_name: String,
    pub role: ClusterRole,
    pub local_node_id: String,
    pub peer_count: usize,
    pub total_memory_gb: f64,
    pub assigned_layers: Option<crate::partitioner::LayerRange>,
    pub active_model: Option<String>,
}

pub struct ClusterEngine {
    pub topology: Option<ClusterTopology>,
    pub local_node: ClusterNode,
    pub role: ClusterRole,
    pub active_partitions: Vec<NodePartition>,
    pub active_model_id: Option<String>,
}

impl ClusterEngine {
    pub fn new_leader(cluster_name: &str, local_node: ClusterNode) -> Self {
        let topology = ClusterTopology::new(cluster_name, local_node.clone());
        Self {
            topology: Some(topology),
            local_node,
            role: ClusterRole::Leader,
            active_partitions: Vec::new(),
            active_model_id: None,
        }
    }

    pub fn new_worker(local_node: ClusterNode) -> Self {
        Self {
            topology: None,
            local_node,
            role: ClusterRole::Worker,
            active_partitions: Vec::new(),
            active_model_id: None,
        }
    }

    pub fn status(&self) -> ClusterStatus {
        let (cluster_id, cluster_name, peer_count, total_mem) = if let Some(topo) = &self.topology {
            (
                topo.cluster_id.clone(),
                topo.cluster_name.clone(),
                topo.nodes.len().saturating_sub(1),
                topo.total_cluster_memory() as f64 / (1024.0 * 1024.0 * 1024.0),
            )
        } else {
            ("unconnected".into(), "none".into(), 0, self.local_node.available_memory_bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        };

        let assigned_layers = self.active_partitions
            .iter()
            .find(|p| p.node_id == self.local_node.node_id)
            .map(|p| p.layer_range);

        ClusterStatus {
            cluster_id,
            cluster_name,
            role: self.role,
            local_node_id: self.local_node.node_id.clone(),
            peer_count,
            total_memory_gb: (total_mem * 100.0).round() / 100.0,
            assigned_layers,
            active_model: self.active_model_id.clone(),
        }
    }

    pub fn load_and_partition_model(
        &mut self,
        model_id: &str,
        total_layers: usize,
        weight_bytes: u64,
    ) -> Result<Vec<NodePartition>, EngineError> {
        let topo = self.topology.as_ref().ok_or(EngineError::NotInitialized)?;
        let partitions = partition_layers(total_layers, weight_bytes, &topo.nodes)?;
        self.active_partitions = partitions.clone();
        self.active_model_id = Some(model_id.to_string());
        Ok(partitions)
    }

    pub fn step_forward(&self, session_id: u64, sequence_nonce: u64, step_index: u32, input_activation: &[u8]) -> TensorFrame {
        // Simulates passing the activation through the locally assigned layer slice
        let assigned = self.active_partitions
            .iter()
            .find(|p| p.node_id == self.local_node.node_id)
            .map(|p| p.layer_range)
            .unwrap_or(crate::partitioner::LayerRange { start_layer: 0, end_layer: 0, total_layers: 1 });

        TensorFrame {
            packet_type: PacketType::ActivationForward,
            session_id,
            sequence_nonce,
            step_index,
            layer_index: assigned.end_layer as u16,
            hidden_dimension: 8192,
            tensor_payload: input_activation.to_vec(),
        }
    }
}
