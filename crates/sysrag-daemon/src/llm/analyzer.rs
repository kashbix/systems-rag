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
            "You are a strict, air-gapped Linux kernel security analyzer. \
            Your job is to analyze the following intercepted process execution and explain the threat. \
            \
            CRITICAL INSTRUCTIONS: \
            1. DO NOT hallucinate, guess, or invent command flags, IP addresses, or arguments. \
            2. ONLY analyze the exact characters present in the command string. \
            3. Be brutally concise and factual. \
            4. If a flag like '-e' is used, explain exactly what '-e' does, do not substitute it with '-c'. \
            \
            ANOMALY DATA: \
            Command: {} \
            Similarity Score: {:.2} \
            \
            Provide your forensic analysis now.",
            anomaly.command, anomaly.similarity_score
            anomaly.pid, 
            anomaly.command, 
            anomaly.similarity_score, 
            anomaly.raw_log
        )
    }
}