use std::collections::HashMap;

pub struct VectorStore {
    // Stores our baseline "normal" embeddings. 
    // Key: Command name (e.g., "bash"), Value: Its normal vector representation
    baseline: HashMap<String, Vec<f32>>,
    // The threshold below which a log is considered an anomaly
    anomaly_threshold: f32, 
}

impl VectorStore {
    pub fn new(threshold: f32) -> Self {
        Self {
            baseline: HashMap::new(),
            anomaly_threshold: threshold,
        }
    }

    /// Add a known "good" log to the baseline
    pub fn add_to_baseline(&mut self, command: &str, vector: Vec<f32>) {
        self.baseline.insert(command.to_string(), vector);
    }

    /// Compares a new log vector against the baseline. 
    /// Returns (is_anomaly, similarity_score)
    pub fn check_anomaly(&self, command: &str, new_vector: &[f32]) -> (bool, f32) {
        // If we've never seen this command before, it's instantly an anomaly (Score: 0.0)
        let baseline_vector = match self.baseline.get(command) {
            Some(v) => v,
            None => return (true, 0.0), 
        };

        // Calculate Cosine Similarity
        let score = self.cosine_similarity(baseline_vector, new_vector);
        
        // If the score is lower than our threshold, flag it!
        let is_anomaly = score < self.anomaly_threshold;
        
        (is_anomaly, score)
    }

    /// The math engine: Calculates the distance between two vectors
    fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f32 {
        let mut dot_product = 0.0;
        let mut norm_a = 0.0;
        let mut norm_b = 0.0;

        for i in 0..a.len() {
            dot_product += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        dot_product / (norm_a.sqrt() * norm_b.sqrt())
    }
}