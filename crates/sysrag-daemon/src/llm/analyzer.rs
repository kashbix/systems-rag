use sysrag_common::ipc::AnomalyReport;
use std::time::Duration;
use anyhow::{Context, Result};

/// The LLM Analyzer responsible for turning raw math and logs into human security alerts
pub struct LlmAnalyzer {
    model_name: String,
    inference_url: String, 
    client: reqwest::Client, // PRODUCTION UPGRADE: Connection pooling
}

impl LlmAnalyzer {
    /// Initializes the connection to the local LLM inference engine
    pub fn new() -> Self {
        println!("🚀 Initializing Production LLM Analyzer (Ollama backend)...");
        Self {
            model_name: "llama3".to_string(), 
            inference_url: "http://127.0.0.1:11434/api/generate".to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Takes the mathematical anomaly and asks the LLM to explain it
    pub async fn analyze_anomaly(&self, anomaly: &AnomalyReport) -> Result<String> {
        let base_prompt = self.build_security_prompt(anomaly);

        // --- PROMPT ENGINEERING ---
        // Force the AI into a strict, professional persona
        let prompt = format!(
            "{}\n\nCRITICAL INSTRUCTION: Do not use any conversational filler, greetings, or excitement. \
            Output ONLY the technical analysis and actionable steps. Be cold, concise, and professional.",
            base_prompt
        );

        // --- THE ACTUAL INFERENCE EXECUTION ---
        let res = self.client.post(&self.inference_url)
            .json(&serde_json::json!({
                "model": self.model_name,
                "prompt": prompt,
                "stream": false
            }))
            .send()
            .await
            .context("Failed to connect to Ollama. Is the Ollama service running on port 11434?")?;

        // Catch non-200 HTTP errors gracefully
        if !res.status().is_success() {
            anyhow::bail!("Ollama returned an error status: {}", res.status());
        }

        // Parse the JSON safely
        let json_res: serde_json::Value = res.json().await
            .context("Failed to parse JSON response from Ollama")?;

        let analysis = json_res["response"]
            .as_str()
            .context("Malformed JSON: Missing 'response' field from Ollama")?;
        
        Ok(analysis.to_string())
    }

    /// Constructs the context-rich prompt (The "RAG" part of the project)
    fn build_security_prompt(&self, anomaly: &AnomalyReport) -> String {
        format!(
            "You are an expert Linux Security Architect. \n\
            Analyze the following OS-level event intercepted via eBPF. \n\
            \n\
            [EVENT CONTEXT]\n\
            Timestamp: {}\n\
            Process ID: {}\n\
            Command Executed: {}\n\
            Mathematical Similarity to Baseline: {:.2} (0.0 is completely unknown, 1.0 is normal)\n\
            Raw Kernel Log: {}\n\
            \n\
            [TASK]\n\
            Explain in 2-3 short sentences what this command does, why it might be a security risk \
            based on its low similarity score, and what the user should do next.",
            anomaly.timestamp, 
            anomaly.pid, 
            anomaly.command, 
            anomaly.similarity_score, 
            anomaly.raw_log
        )
    }
}