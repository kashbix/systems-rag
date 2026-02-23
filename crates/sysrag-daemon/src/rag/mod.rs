pub mod embed;
pub mod store;

use sysrag_common::ipc::AnomalyReport;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use self::embed::LogEmbedder;
use self::store::VectorStore;

/// The central AI engine that orchestrates embeddings and vector math
pub struct RagEngine {
    embedder: LogEmbedder,
    store: VectorStore,
}

impl RagEngine {
    /// Initializes the AI models and the local vector database
    pub fn new() -> Result<Self, anyhow::Error> {
        println!("Initializing RAG Engine and loading local AI models...");
        
        let embedder = LogEmbedder::new()?;
        // We set a strict anomaly threshold. 
        // Anything with a similarity below 0.6 is flagged.
        let store = VectorStore::new(0.6); 

        Ok(Self { embedder, store })
    }

    /// Processes a raw log from the eBPF kernel sensor.
    /// Returns `Some(AnomalyReport)` if it's suspicious, or `None` if it's normal.
    pub fn process_log(&mut self, raw_log: &str) -> Result<Option<AnomalyReport>, anyhow::Error> {
        // 1. Parse the raw log (e.g., "execve: pid=1337 uid=1000 comm=curl")
        // In a production app, we'd use Regex or pass a proper struct, 
        // but simple string splitting works for our prototype.
        let pid_str = extract_value(raw_log, "pid=").unwrap_or("0".to_string());
        let pid: u32 = pid_str.parse().unwrap_or(0);
        let command = extract_value(raw_log, "comm=").unwrap_or("unknown".to_string());

        // 2. Convert the log into a mathematical vector
        let vector = self.embedder.embed_log(raw_log)?;

        // 3. Check it against our baseline in the Vector Store
        let (is_anomaly, similarity_score) = self.store.check_anomaly(&command, &vector);

        if is_anomaly {
            // It's an anomaly! Generate a report.
            let report = AnomalyReport {
                id: Uuid::new_v4().to_string(), // Generates a unique ID like "550e8400-e29b..."
                timestamp: current_timestamp(),
                pid,
                command: command.clone(),
                similarity_score,
                raw_log: raw_log.to_string(),
            };

            // Even though it's an anomaly, we add it to the baseline now so it 
            // becomes part of the system's "memory" for future context.
            self.store.add_to_baseline(&command, vector);

            return Ok(Some(report));
        }

        // 4. If it's completely normal, just update the baseline and move on
        self.store.add_to_baseline(&command, vector);
        Ok(None)
    }
}

// --- Helper Functions ---

/// Extracts a value from our formatted log string (e.g., finds "curl" from "comm=curl")
fn extract_value(log: &str, key: &str) -> Option<String> {
    log.split_whitespace()
        .find(|word| word.starts_with(key))
        .map(|word| word.trim_start_matches(key).to_string())
}

/// Gets the current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}