use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEvent {
    pub path: String,
    pub event_type: EventType,
    pub sha256: Option<String>,
    pub severity: Severity,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Created,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventBatch {
    pub events: Vec<FileEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivationRequest {
    pub license_key: String,
    pub hardware_id: String,
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivationResponse {
    pub valid: bool,
    pub token: Option<String>,
    pub tier: Option<String>,
    pub expires_at: Option<String>,
}
