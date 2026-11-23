//! Wire protocol and binary frame serialization for zero-copy tensor activation transfers.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DIRGHA_MAGIC: u32 = 0x44495247; // 'DIRG'
pub const PROTOCOL_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 70;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Invalid magic number: expected 0x{DIRGHA_MAGIC:08X}, got 0x{0:08X}")]
    InvalidMagic(u32),
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
    #[error("Packet length mismatch: expected {expected}, actual {actual}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("Checksum verification failed")]
    ChecksumFailed,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    Handshake = 1,
    Ping = 2,
    ActivationForward = 3,
    ActivationResult = 4,
    Error = 5,
}

impl TryFrom<u8> for PacketType {
    type Error = TransportError;

    fn try_from(val: u8) -> Result<Self, TransportError> {
        match val {
            1 => Ok(PacketType::Handshake),
            2 => Ok(PacketType::Ping),
            3 => Ok(PacketType::ActivationForward),
            4 => Ok(PacketType::ActivationResult),
            5 => Ok(PacketType::Error),
            _ => Err(TransportError::Serialization(format!("Unknown packet type {}", val))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TensorFrame {
    pub packet_type: PacketType,
    pub session_id: u64,
    pub sequence_nonce: u64,
    pub step_index: u32,
    pub layer_index: u16,
    pub hidden_dimension: u32,
    pub tensor_payload: Vec<u8>,
}

impl TensorFrame {
    /// Encodes a tensor activation frame into wire binary format:
    /// [Magic: 4B][Ver: 2B][Type: 1B][Reserved: 1B][Session: 8B][SeqNonce: 8B][Step: 4B][Layer: 2B][HiddenDim: 4B][PayloadLen: 4B][Blake3: 32B][Payload: NB]
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.tensor_payload.len() as u32;
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.tensor_payload.len());

        buf.extend_from_slice(&DIRGHA_MAGIC.to_be_bytes());
        buf.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        buf.push(self.packet_type as u8);
        buf.push(0); // Reserved
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.sequence_nonce.to_be_bytes());
        buf.extend_from_slice(&self.step_index.to_be_bytes());
        buf.extend_from_slice(&self.layer_index.to_be_bytes());
        buf.extend_from_slice(&self.hidden_dimension.to_be_bytes());
        buf.extend_from_slice(&payload_len.to_be_bytes());

        // Full 32-byte Blake3 checksum across header metadata (0..38) and payload
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf[..38]);
        hasher.update(&self.tensor_payload);
        let hash = hasher.finalize();
        buf.extend_from_slice(hash.as_bytes());

        buf.extend_from_slice(&self.tensor_payload);
        buf
    }

    /// Decodes a tensor activation frame from wire binary format.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < HEADER_SIZE {
            return Err(TransportError::LengthMismatch {
                expected: HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if magic != DIRGHA_MAGIC {
            return Err(TransportError::InvalidMagic(magic));
        }

        let ver = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        if ver != PROTOCOL_VERSION {
            return Err(TransportError::UnsupportedVersion(ver));
        }

        let packet_type = PacketType::try_from(bytes[6])?;
        let session_id = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let sequence_nonce = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        let step_index = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let layer_index = u16::from_be_bytes(bytes[28..30].try_into().unwrap());
        let hidden_dimension = u32::from_be_bytes(bytes[30..34].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[34..38].try_into().unwrap()) as usize;
        let expected_checksum = &bytes[38..70];

        if bytes.len() < HEADER_SIZE + payload_len {
            return Err(TransportError::LengthMismatch {
                expected: HEADER_SIZE + payload_len,
                actual: bytes.len(),
            });
        }

        let payload = bytes[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes[..38]);
        hasher.update(&payload);
        let hash = hasher.finalize();

        if hash.as_bytes() != expected_checksum {
            return Err(TransportError::ChecksumFailed);
        }

        Ok(Self {
            packet_type,
            session_id,
            sequence_nonce,
            step_index,
            layer_index,
            hidden_dimension,
            tensor_payload: payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_frame_roundtrip() {
        let fake_activation = vec![0xAB; 16384]; // 16 KB simulated hidden state
        let frame = TensorFrame {
            packet_type: PacketType::ActivationForward,
            session_id: 123456789,
            sequence_nonce: 101,
            step_index: 42,
            layer_index: 26,
            hidden_dimension: 8192,
            tensor_payload: fake_activation,
        };

        let encoded = frame.encode();
        assert_eq!(encoded.len(), HEADER_SIZE + 16384);

        let decoded = TensorFrame::decode(&encoded).expect("decode must succeed");
        assert_eq!(decoded.packet_type, PacketType::ActivationForward);
        assert_eq!(decoded.session_id, 123456789);
        assert_eq!(decoded.sequence_nonce, 101);
        assert_eq!(decoded.step_index, 42);
        assert_eq!(decoded.layer_index, 26);
        assert_eq!(decoded.hidden_dimension, 8192);
        assert_eq!(decoded.tensor_payload.len(), 16384);
    }

    #[test]
    fn test_tampered_frame_detection() {
        let frame = TensorFrame {
            packet_type: PacketType::ActivationForward,
            session_id: 123456789,
            sequence_nonce: 1,
            step_index: 1,
            layer_index: 0,
            hidden_dimension: 4096,
            tensor_payload: vec![1, 2, 3, 4],
        };
        let mut encoded = frame.encode();
        // Tamper with sequence nonce in header
        encoded[16] ^= 0xFF;
        assert!(matches!(TensorFrame::decode(&encoded), Err(TransportError::ChecksumFailed)));

        // Tamper with payload
        let mut encoded2 = frame.encode();
        encoded2[HEADER_SIZE] ^= 0xFF;
        assert!(matches!(TensorFrame::decode(&encoded2), Err(TransportError::ChecksumFailed)));
    }
}
