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
        
        let mut embedder = LogEmbedder::new()?;
        // We set a strict anomaly threshold. 
        // Anything with a similarity below 0.6 is flagged.
        let mut store = VectorStore::new(0.2); 

        // --- THE FIX: Seed the Baseline ---
        // Pre-load the VectorStore with background noise so it doesn't freak out on boot
        let safe_commands = vec![
            "systemd", "crond", "NetworkManager", "bash", "sh", 
            "python3", "gnome-shell", "polkitd", "Xwayland", "env",
            "spotify", "flatpak", "gio-launch-desktop", "(sd-worker)",
            "run-parts", "0anacron", "ThreadPoolSingl", "(tmpfiles)",
            "gsd-xsettings", "p11-kit", "get-scale-facto", "ollama", "sh"
        ];

        println!("🌱 Seeding baseline with {} standard Linux processes...", safe_commands.len());
        
        for cmd in safe_commands {
            if let Ok(vector) = embedder.embed_log(cmd) {
                // Add these directly to the store before we process any real logs
                store.add_to_baseline(cmd, vector);
            }
        }
        // -----------------------------------

        Ok(Self { embedder, store })
    }

    /// Processes a raw log from the eBPF kernel sensor.
    /// Returns `Some(AnomalyReport)` if it's suspicious, or `None` if it's normal.
    pub fn process_log(&mut self, raw_log: &str) -> Result<Option<AnomalyReport>, anyhow::Error> {
        // 1. Parse the raw log
        let pid_str = extract_value(raw_log, "pid=").unwrap_or("0".to_string());
        let pid: u32 = pid_str.parse().unwrap_or(0);
        let command = extract_value(raw_log, "comm=").unwrap_or("unknown".to_string());

        // 2. Convert the COMMAND (not the raw_log) into a mathematical vector.
        // This ensures "systemd" matches our seeded "systemd" perfectly.
        let vector = self.embedder.embed_log(&command)?;

        // 3. Check it against our baseline in the Vector Store
        let (is_anomaly, similarity_score) = self.store.check_anomaly(&command, &vector);

        if is_anomaly {
            // It's an anomaly! Generate a report.
            let report = AnomalyReport {
                id: Uuid::new_v4().to_string(), 
                timestamp: current_timestamp(),
                pid,
                command: command.clone(),
                similarity_score,
                raw_log: raw_log.to_string(),
            };

            // Add it to the baseline so it becomes part of the system's "memory"
            self.store.add_to_baseline(&command, vector);

            return Ok(Some(report));
        }

        // 4. If it's normal, just update the baseline and move on
        self.store.add_to_baseline(&command, vector);
        Ok(None)
    }
}

// --- Helper Functions ---

fn extract_value(log: &str, key: &str) -> Option<String> {
    log.split_whitespace()
        .find(|word| word.starts_with(key))
        .map(|word| word.trim_start_matches(key).to_string())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
