//! Cluster discovery, node hardware profiling, and cryptographic membership handshake.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Node verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("Node not found in topology: {0}")]
    NodeNotFound(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComputeBackend {
    Metal,
    Cuda,
    Rocm,
    Cpu,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub node_id: String,
    pub name: String,
    pub addr: String,
    pub available_memory_bytes: u64,
    pub backend: ComputeBackend,
    pub pubkey_fingerprint: String,
    pub last_seen_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTopology {
    pub cluster_id: String,
    pub cluster_name: String,
    pub leader_node_id: String,
    pub nodes: Vec<ClusterNode>,
    pub created_at_unix_ms: u64,
}

impl ClusterTopology {
    pub fn new(cluster_name: &str, leader: ClusterNode) -> Self {
        let cluster_id = format!("cluster_{}", blake3::hash(cluster_name.as_bytes()).to_hex().as_str()[..16].to_string());
        let leader_id = leader.node_id.clone();
        Self {
            cluster_id,
            cluster_name: cluster_name.to_string(),
            leader_node_id: leader_id,
            nodes: vec![leader],
            created_at_unix_ms: 0,
        }
    }

    pub fn total_cluster_memory(&self) -> u64 {
        self.nodes.iter().map(|n| n.available_memory_bytes).sum()
    }

    pub fn add_or_update_node(&mut self, node: ClusterNode) {
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.node_id == node.node_id) {
            *existing = node;
        } else {
            self.nodes.push(node);
        }
    }

    pub fn remove_node(&mut self, node_id: &str) -> bool {
        let prev_len = self.nodes.len();
        self.nodes.retain(|n| n.node_id != node_id);
        self.nodes.len() < prev_len
    }
}

pub struct ClusterAuth;

impl ClusterAuth {
    pub fn generate_join_token(signing_key: &SigningKey, cluster_id: &str, expire_unix_sec: u64) -> String {
        let msg = format!("{}:{}", cluster_id, expire_unix_sec);
        let sig: Signature = signing_key.sign(msg.as_bytes());
        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        format!("dirgha-join_{}:{}:{}:{}", cluster_id, expire_unix_sec, pubkey_hex, sig_hex)
    }

    pub fn verify_join_token(token: &str, expected_cluster_id: &str, current_unix_sec: u64) -> Result<(), DiscoveryError> {
        let trimmed = token.strip_prefix("dirgha-join_").ok_or(DiscoveryError::InvalidTokenFormat)?;
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() != 4 {
            return Err(DiscoveryError::InvalidTokenFormat);
        }

        let cluster_id = parts[0];
        let expire_sec: u64 = parts[1].parse().map_err(|_| DiscoveryError::InvalidTokenFormat)?;
        let pubkey_hex = parts[2];
        let sig_hex = parts[3];

        if cluster_id != expected_cluster_id {
            return Err(DiscoveryError::VerificationFailed("Cluster ID mismatch".into()));
        }
        if current_unix_sec > expire_sec {
            return Err(DiscoveryError::VerificationFailed("Token expired".into()));
        }

        let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| DiscoveryError::InvalidTokenFormat)?;
        let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| DiscoveryError::InvalidTokenFormat)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| DiscoveryError::VerificationFailed(e.to_string()))?;

        let sig_bytes = hex::decode(sig_hex).map_err(|_| DiscoveryError::InvalidTokenFormat)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| DiscoveryError::InvalidTokenFormat)?;
        let signature = Signature::from_bytes(&sig_arr);

        let msg = format!("{}:{}", cluster_id, expire_sec);
        verifying_key.verify(msg.as_bytes(), &signature)
            .map_err(|e| DiscoveryError::VerificationFailed(format!("Signature invalid: {}", e)))
    }
}
