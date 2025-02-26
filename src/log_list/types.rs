use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogList {
    pub is_all_logs: bool,
    pub version: String,
    pub log_list_timestamp: DateTime<Utc>,
    pub operators: Vec<Operator>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Operator {
    pub name: String,
    pub email: Vec<String>,
    pub logs: Vec<Log>,
    pub tiled_logs: Vec<TiledLog>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Log {
    pub description: String,
    pub log_id: String,
    #[serde_as(as = "Base64")]
    pub key: Vec<u8>,
    pub url: String,
    pub mmd: i32,
    #[serde(default)]
    pub state: Option<LogState>,
    #[serde(default)]
    pub temporal_interval: Option<TemporalInterval>,
    #[serde(default)]
    pub log_type: Option<String>,
}

impl Log {
    pub fn is_usable(&self) -> bool {
        matches!(self.state, Some(LogState::Usable { .. }))
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TiledLog {
    pub description: String,
    pub log_id: String,
    #[serde_as(as = "Base64")]
    pub key: Vec<u8>,
    pub submission_url: String,
    pub monitoring_url: String,
    pub mmd: i32,
    #[serde(default)]
    pub state: Option<LogState>,
    #[serde(default)]
    pub temporal_interval: Option<TemporalInterval>,
    #[serde(default)]
    pub log_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TemporalInterval {
    pub start_inclusive: DateTime<Utc>,
    pub end_exclusive: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum LogState {
    Pending {
        timestamp: DateTime<Utc>,
    },
    Usable {
        timestamp: DateTime<Utc>,
    },
    Readonly {
        timestamp: DateTime<Utc>,
        final_tree_head: TreeHead,
    },
    Retired {
        timestamp: DateTime<Utc>,
    },
    Rejected {
        timestamp: DateTime<Utc>,
    },
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TreeHead {
    #[serde_as(as = "Base64")]
    pub sha256_root_hash: Vec<u8>,
    pub tree_size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub timestamp: u64,
    pub root_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedTreeHead {
    pub fn from_ctclient_sth(sth: ctclient::SignedTreeHead) -> Self {
        Self {
            tree_size: sth.tree_size,
            timestamp: sth.timestamp,
            root_hash: sth.root_hash,
            signature: sth.signature,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + 32 + 16);
        bytes.extend(&self.tree_size.to_le_bytes());
        bytes.extend(&self.timestamp.to_le_bytes());
        bytes.extend(&self.root_hash);
        bytes.extend(&self.signature);
        bytes
    }
    pub fn serialize_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}
