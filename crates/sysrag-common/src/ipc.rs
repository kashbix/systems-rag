use serde::{Deserialize, Serialize};

/// Represents a flagged anomaly detected by the eBPF/RAG pipeline
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnomalyReport {
    pub id: String,             // Unique UUID for the anomaly
    pub timestamp: u64,         // Unix timestamp of occurrence
    pub pid: u32,               // The Process ID that triggered it
    pub command: String,        // The command executed (e.g., "curl", "nc")
    pub similarity_score: f32,  // How close it was to the baseline (0.0 to 1.0)
    pub raw_log: String,        // The raw context log
}

/// All possible commands the CLI can send to the Daemon
#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Ping the daemon to check health
    Status,
    /// Fetch the most recent anomalies
    GetAnomalies { tail: usize },
    /// Ask the LLM to analyze a specific anomaly
    Investigate { id: String },
}

/// All possible responses the Daemon can send back to the CLI
#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Daemon is healthy and reporting stats
    StatusOk { 
        uptime_seconds: u64, 
        events_processed: u64,
        db_size: usize 
    },
    /// Returning a list of anomalies
    AnomaliesList(Vec<AnomalyReport>),
    /// Returning the LLM's plain-English analysis
    InvestigationResult(String),
    /// Something went wrong on the daemon side
    Error(String),
}