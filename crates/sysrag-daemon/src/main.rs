mod bpf;
mod llm;
mod rag;
mod server;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use sysrag_common::ipc::AnomalyReport;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting sysragd (Systems RAG Daemon)...");

    // 1. Shared State: This holds our detected anomalies in memory. 
    // We wrap it in an Arc<Mutex> so both the AI engine (which writes to it) 
    // and the IPC server (which reads from it) can access it safely across threads.
    let anomalies_store: Arc<Mutex<Vec<AnomalyReport>>> = Arc::new(Mutex::new(Vec::new()));

    // 2. Setup the communication channel: Kernel Sensor -> AI Engine
    // This allows the eBPF sensor to instantly drop logs into a queue without waiting for the math.
    let (log_tx, mut log_rx) = mpsc::channel::<String>(1000);

    // 3. Initialize the RAG Engine (Local Vector DB & Embedding Models)
    let mut rag_engine = rag::RagEngine::new()?;

    // 4. Start the IPC Server in the background to listen for CLI commands
    // (In our prototype `server.rs` we mocked the response, but in production, 
    // you would pass `anomalies_store.clone()` into `start_ipc_server` here!)
    tokio::spawn(async move {
        server::start_ipc_server().await;
    });

    // 5. Initialize and inject the eBPF Kernel Sensor
    let mut bpf_manager = bpf::BpfManager::new()?;
    
    // Spawn the kernel listener in the background
    tokio::spawn(async move {
        if let Err(e) = bpf_manager.start_listening(log_tx).await {
            eprintln!("🔥 Kernel Sensor Error: {}", e);
        }
    });

    println!("🟢 Systems RAG AI Engine online. Monitoring kernel events in real-time...");

    // 6. The Main Event Loop: Consume kernel logs and do the math
    while let Some(raw_log) = log_rx.recv().await {
        // Pass the raw Linux kernel string into the AI embedding math
        match rag_engine.process_log(&raw_log) {
            Ok(Some(anomaly)) => {
                println!(
                    "🚨 ANOMALY DETECTED: [{}] Score: {:.2}", 
                    anomaly.command, anomaly.similarity_score
                );
                
                // Save the anomaly to our shared state so the CLI can fetch it later
                let mut store = anomalies_store.lock().await;
                store.push(anomaly);
            }
            Ok(None) => {
                // Normal system behavior. The RAG engine silently updates its baseline.
            }
            Err(e) => {
                eprintln!("⚠️ RAG Engine Error: {}", e);
            }
        }
    }

    Ok(())
}