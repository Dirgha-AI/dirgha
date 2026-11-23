//! Dirgha Sovereign P2P Distributed Inference Cluster Engine.
//!
//! Provides zero-dependency memory pooling and pipeline-parallel model execution across
//! developer workstations and private on-premise data centers.

pub mod discovery;
pub mod engine;
pub mod partitioner;
pub mod transport;

pub use discovery::{ClusterAuth, ClusterNode, ClusterTopology, ComputeBackend};
pub use engine::{ClusterEngine, ClusterRole, ClusterStatus};
pub use partitioner::{partition_layers, LayerRange, NodePartition};
pub use transport::{PacketType, TensorFrame, DIRGHA_MAGIC, HEADER_SIZE, PROTOCOL_VERSION};
