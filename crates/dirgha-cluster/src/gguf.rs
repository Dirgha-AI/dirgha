//! GGUF binary model format inspector and tensor layer slicer.
//!
//! Provides zero-dependency reading of GGUF headers, extracting model architecture,
//! layer counts, context windows, and per-layer tensor mappings for distributed slicing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read, Seek};
use thiserror::Error;

pub const GGUF_MAGIC: u32 = 0x46554747; // 'GGUF' in LE: 0x47, 0x47, 0x55, 0x46
pub const GGUF_VERSION_2: u32 = 2;
pub const GGUF_VERSION_3: u32 = 3;

#[derive(Debug, Error)]
pub enum GgufError {
    #[error("Invalid GGUF magic: expected 0x{GGUF_MAGIC:08X}, got 0x{0:08X}")]
    InvalidMagic(u32),
    #[error("Unsupported GGUF version: {0} (supported: 2, 3)")]
    UnsupportedVersion(u32),
    #[error("IO error while reading GGUF: {0}")]
    Io(#[from] io::Error),
    #[error("String decoding error: {0}")]
    StringDecode(#[from] std::string::FromUtf8Error),
    #[error("Invalid metadata value type: {0}")]
    InvalidMetadataType(u32),
    #[error("Corrupt or truncated GGUF header")]
    TruncatedHeader,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GgufMetadataValue {
    Uint8(u8),
    Int8(i8),
    Uint16(u16),
    Int16(i16),
    Uint32(u32),
    Int32(i32),
    Float32(f32),
    Bool(bool),
    String(String),
    Array(Vec<GgufMetadataValue>),
    Uint64(u64),
    Int64(i64),
    Float64(f64),
}

impl GgufMetadataValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint8(v) => Some(*v as u64),
            Self::Uint16(v) => Some(*v as u64),
            Self::Uint32(v) => Some(*v as u64),
            Self::Uint64(v) => Some(*v),
            Self::Int32(v) if *v >= 0 => Some(*v as u64),
            Self::Int64(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GgufTensorInfo {
    pub name: String,
    pub dimensions: Vec<u64>,
    pub tensor_type: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GgufModelSummary {
    pub version: u32,
    pub tensor_count: u64,
    pub metadata_kv_count: u64,
    pub architecture: String,
    pub layer_count: usize,
    pub embedding_dimension: u32,
    pub context_length: u32,
    pub metadata: HashMap<String, GgufMetadataValue>,
    pub tensors: Vec<GgufTensorInfo>,
}

pub struct GgufReader;

impl GgufReader {
    pub fn parse_summary<R: Read + Seek>(reader: &mut R) -> Result<GgufModelSummary, GgufError> {
        let mut magic_buf = [0u8; 4];
        reader.read_exact(&mut magic_buf)?;
        let magic = u32::from_le_bytes(magic_buf);
        if magic != GGUF_MAGIC {
            return Err(GgufError::InvalidMagic(magic));
        }

        let mut ver_buf = [0u8; 4];
        reader.read_exact(&mut ver_buf)?;
        let version = u32::from_le_bytes(ver_buf);
        if version != GGUF_VERSION_2 && version != GGUF_VERSION_3 {
            return Err(GgufError::UnsupportedVersion(version));
        }

        let mut counts_buf = [0u8; 16];
        reader.read_exact(&mut counts_buf)?;
        let tensor_count = u64::from_le_bytes(counts_buf[0..8].try_into().unwrap());
        let metadata_kv_count = u64::from_le_bytes(counts_buf[8..16].try_into().unwrap());

        let mut metadata = HashMap::new();
        for _ in 0..metadata_kv_count {
            let key = Self::read_string(reader)?;
            let val = Self::read_metadata_value(reader)?;
            metadata.insert(key, val);
        }

        let mut tensors = Vec::with_capacity(tensor_count as usize);
        for _ in 0..tensor_count {
            let name = Self::read_string(reader)?;
            let mut n_dims_buf = [0u8; 4];
            reader.read_exact(&mut n_dims_buf)?;
            let n_dims = u32::from_le_bytes(n_dims_buf);

            let mut dimensions = Vec::with_capacity(n_dims as usize);
            for _ in 0..n_dims {
                let mut dim_buf = [0u8; 8];
                reader.read_exact(&mut dim_buf)?;
                dimensions.push(u64::from_le_bytes(dim_buf));
            }

            let mut type_buf = [0u8; 4];
            reader.read_exact(&mut type_buf)?;
            let tensor_type = u32::from_le_bytes(type_buf);

            let mut offset_buf = [0u8; 8];
            reader.read_exact(&mut offset_buf)?;
            let offset = u64::from_le_bytes(offset_buf);

            tensors.push(GgufTensorInfo {
                name,
                dimensions,
                tensor_type,
                offset,
            });
        }

        // Infer architecture and layer parameters
        let architecture = metadata.get("general.architecture")
            .and_then(|v| v.as_str())
            .unwrap_or("llama")
            .to_string();

        let block_count_key = format!("{}.block_count", architecture);
        let layer_count = metadata.get(&block_count_key)
            .and_then(|v| v.as_u64())
            .or_else(|| metadata.get("llama.block_count").and_then(|v| v.as_u64()))
            .unwrap_or(32) as usize;

        let emb_key = format!("{}.embedding_length", architecture);
        let embedding_dimension = metadata.get(&emb_key)
            .and_then(|v| v.as_u64())
            .or_else(|| metadata.get("llama.embedding_length").and_then(|v| v.as_u64()))
            .unwrap_or(4096) as u32;

        let ctx_key = format!("{}.context_length", architecture);
        let context_length = metadata.get(&ctx_key)
            .and_then(|v| v.as_u64())
            .or_else(|| metadata.get("llama.context_length").and_then(|v| v.as_u64()))
            .unwrap_or(8192) as u32;

        Ok(GgufModelSummary {
            version,
            tensor_count,
            metadata_kv_count,
            architecture,
            layer_count,
            embedding_dimension,
            context_length,
            metadata,
            tensors,
        })
    }

    fn read_string<R: Read>(reader: &mut R) -> Result<String, GgufError> {
        let mut len_buf = [0u8; 8];
        reader.read_exact(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        reader.read_exact(&mut bytes)?;
        Ok(String::from_utf8(bytes)?)
    }

    fn read_metadata_value<R: Read>(reader: &mut R) -> Result<GgufMetadataValue, GgufError> {
        let mut type_buf = [0u8; 4];
        reader.read_exact(&mut type_buf)?;
        let val_type = u32::from_le_bytes(type_buf);

        match val_type {
            0 => {
                let mut b = [0u8; 1];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Uint8(b[0]))
            }
            1 => {
                let mut b = [0u8; 1];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Int8(b[0] as i8))
            }
            2 => {
                let mut b = [0u8; 2];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Uint16(u16::from_le_bytes(b)))
            }
            3 => {
                let mut b = [0u8; 2];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Int16(i16::from_le_bytes(b)))
            }
            4 => {
                let mut b = [0u8; 4];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Uint32(u32::from_le_bytes(b)))
            }
            5 => {
                let mut b = [0u8; 4];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Int32(i32::from_le_bytes(b)))
            }
            6 => {
                let mut b = [0u8; 4];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Float32(f32::from_le_bytes(b)))
            }
            7 => {
                let mut b = [0u8; 1];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Bool(b[0] != 0))
            }
            8 => {
                let s = Self::read_string(reader)?;
                Ok(GgufMetadataValue::String(s))
            }
            9 => {
                let mut arr_type_buf = [0u8; 4];
                reader.read_exact(&mut arr_type_buf)?;
                let _arr_type = u32::from_le_bytes(arr_type_buf);

                let mut arr_len_buf = [0u8; 8];
                reader.read_exact(&mut arr_len_buf)?;
                let arr_len = u64::from_le_bytes(arr_len_buf) as usize;

                let mut items = Vec::with_capacity(arr_len);
                for _ in 0..arr_len {
                    items.push(Self::read_metadata_value(reader)?);
                }
                Ok(GgufMetadataValue::Array(items))
            }
            10 => {
                let mut b = [0u8; 8];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Uint64(u64::from_le_bytes(b)))
            }
            11 => {
                let mut b = [0u8; 8];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Int64(i64::from_le_bytes(b)))
            }
            12 => {
                let mut b = [0u8; 8];
                reader.read_exact(&mut b)?;
                Ok(GgufMetadataValue::Float64(f64::from_le_bytes(b)))
            }
            other => Err(GgufError::InvalidMetadataType(other)),
        }
    }

    /// Groups model tensors by layer index (e.g. `blk.0.attn_q.weight` -> layer 0).
    /// Non-layer tensors (e.g. `token_embd.weight`, `output.weight`) belong to `None`.
    pub fn group_tensors_by_layer(tensors: &[GgufTensorInfo]) -> HashMap<Option<usize>, Vec<GgufTensorInfo>> {
        let mut grouped: HashMap<Option<usize>, Vec<GgufTensorInfo>> = HashMap::new();

        for t in tensors {
            let layer_idx = Self::extract_layer_index(&t.name);
            grouped.entry(layer_idx).or_default().push(t.clone());
        }

        grouped
    }

    fn extract_layer_index(tensor_name: &str) -> Option<usize> {
        // Common GGUF layer naming schemes:
        // blk.{idx}.* (LLaMA/Mistral/Qwen)
        // model.layers.{idx}.* (HuggingFace format)
        // layers.{idx}.*
        if let Some(rest) = tensor_name.strip_prefix("blk.") {
            let dot_idx = rest.find('.')?;
            return rest[..dot_idx].parse::<usize>().ok();
        }
        if let Some(rest) = tensor_name.strip_prefix("model.layers.") {
            let dot_idx = rest.find('.')?;
            return rest[..dot_idx].parse::<usize>().ok();
        }
        if let Some(rest) = tensor_name.strip_prefix("layers.") {
            let dot_idx = rest.find('.')?;
            return rest[..dot_idx].parse::<usize>().ok();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_synthetic_gguf() -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic: 'GGUF' (0x46554747 in LE)
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        // Version: 3
        buf.extend_from_slice(&3u32.to_le_bytes());
        // Tensor count: 2
        buf.extend_from_slice(&2u64.to_le_bytes());
        // Metadata KV count: 3
        buf.extend_from_slice(&3u64.to_le_bytes());

        // KV 1: general.architecture = "llama" (type 8: string)
        let k1 = "general.architecture";
        buf.extend_from_slice(&(k1.len() as u64).to_le_bytes());
        buf.extend_from_slice(k1.as_bytes());
        buf.extend_from_slice(&8u32.to_le_bytes()); // string type
        let v1 = "llama";
        buf.extend_from_slice(&(v1.len() as u64).to_le_bytes());
        buf.extend_from_slice(v1.as_bytes());

        // KV 2: llama.block_count = 32 (type 4: u32)
        let k2 = "llama.block_count";
        buf.extend_from_slice(&(k2.len() as u64).to_le_bytes());
        buf.extend_from_slice(k2.as_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes()); // u32 type
        buf.extend_from_slice(&32u32.to_le_bytes());

        // KV 3: llama.embedding_length = 4096 (type 4: u32)
        let k3 = "llama.embedding_length";
        buf.extend_from_slice(&(k3.len() as u64).to_le_bytes());
        buf.extend_from_slice(k3.as_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes()); // u32 type
        buf.extend_from_slice(&4096u32.to_le_bytes());

        // Tensor 1: "token_embd.weight" (non-layer)
        let t1_name = "token_embd.weight";
        buf.extend_from_slice(&(t1_name.len() as u64).to_le_bytes());
        buf.extend_from_slice(t1_name.as_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes()); // 2 dims
        buf.extend_from_slice(&4096u64.to_le_bytes());
        buf.extend_from_slice(&32000u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // type F32
        buf.extend_from_slice(&0u64.to_le_bytes()); // offset 0

        // Tensor 2: "blk.0.attn_q.weight" (layer 0)
        let t2_name = "blk.0.attn_q.weight";
        buf.extend_from_slice(&(t2_name.len() as u64).to_le_bytes());
        buf.extend_from_slice(t2_name.as_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes()); // 2 dims
        buf.extend_from_slice(&4096u64.to_le_bytes());
        buf.extend_from_slice(&4096u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // type F32
        buf.extend_from_slice(&524288000u64.to_le_bytes()); // offset

        buf
    }

    #[test]
    fn test_gguf_summary_parsing() {
        let raw = build_synthetic_gguf();
        let mut cursor = Cursor::new(raw);

        let summary = GgufReader::parse_summary(&mut cursor).expect("GGUF summary parse must succeed");
        assert_eq!(summary.version, 3);
        assert_eq!(summary.architecture, "llama");
        assert_eq!(summary.layer_count, 32);
        assert_eq!(summary.embedding_dimension, 4096);
        assert_eq!(summary.tensors.len(), 2);

        // Test layer grouping
        let grouped = GgufReader::group_tensors_by_layer(&summary.tensors);
        assert_eq!(grouped.get(&None).unwrap().len(), 1); // token_embd.weight
        assert_eq!(grouped.get(&Some(0)).unwrap().len(), 1); // blk.0.attn_q.weight
        assert_eq!(grouped.get(&Some(0)).unwrap()[0].name, "blk.0.attn_q.weight");
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut raw = build_synthetic_gguf();
        raw[0] = 0xFF; // corrupt magic
        let mut cursor = Cursor::new(raw);
        assert!(matches!(GgufReader::parse_summary(&mut cursor), Err(GgufError::InvalidMagic(_))));
    }
}
