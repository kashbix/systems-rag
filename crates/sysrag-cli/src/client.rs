use sysrag_common::ipc::{DaemonRequest, DaemonResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The client responsible for communicating with the background daemon
pub struct DaemonClient {
    socket_path: String,
}

impl DaemonClient {
    /// Initializes a new client pointing to the daemon's socket file
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    /// Opens a connection, sends the request, waits for the response, and closes the connection
    pub async fn send_request(&self, req: DaemonRequest) -> Result<DaemonResponse, anyhow::Error> {
        // 1. Connect to the daemon's Unix Domain Socket
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon at {}. Is sysragd running? Error: {}", self.socket_path, e))?;

        // 2. Serialize our Rust Enum request into a JSON byte array
        let req_bytes = serde_json::to_vec(&req)?;
        
        // 3. Fire the bytes over the socket
        stream.write_all(&req_bytes).await?;
        
        // Tell the daemon we are done writing so it can start processing
        stream.shutdown().await?; 

        // 4. Read the daemon's response back into a buffer
        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await?;

        // 5. Deserialize the JSON bytes back into our expected Rust Enum
        let response: DaemonResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| anyhow::anyhow!("Daemon sent invalid response format: {}", e))?;
        
        Ok(response)
    }
}