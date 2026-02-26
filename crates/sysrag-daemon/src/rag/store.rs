pub struct VectorStore {
    // A flat list of our known "safe" mathematical vectors
    baseline: Vec<Vec<f32>>,
    // The threshold below which a log is considered an anomaly
    anomaly_threshold: f32, 
}

impl VectorStore {
    pub fn new(threshold: f32) -> Self {
        Self {
            baseline: Vec::new(),
            anomaly_threshold: threshold,
        }
    }

    /// Add a known "good" vector to the baseline
    pub fn add_to_baseline(&mut self, _command: &str, vector: Vec<f32>) {
        self.baseline.push(vector);
    }

    /// Compares a new log vector against ALL baseline vectors. 
    /// Returns (is_anomaly, highest_similarity_score)
    pub fn check_anomaly(&self, _command: &str, new_vector: &[f32]) -> (bool, f32) {
        // Fail-safe: if the baseline is empty, everything looks alien
        if self.baseline.is_empty() {
            return (true, 0.0);
        }

        let mut max_score = 0.0;

        // Semantic Search: Compare the new vector against EVERY known safe vector
        for safe_vector in &self.baseline {
            let score = self.cosine_similarity(safe_vector, new_vector);
            if score > max_score {
                max_score = score;
            }
        }
        
        // If its highest match is still lower than our threshold, flag it!
        let is_anomaly = max_score < self.anomaly_threshold;
        
        (is_anomaly, max_score)
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