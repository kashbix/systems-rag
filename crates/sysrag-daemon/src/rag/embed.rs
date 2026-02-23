use fastembed::{TextEmbedding, InitOptions, EmbeddingModel};

pub struct LogEmbedder {
    model: TextEmbedding,
}

impl LogEmbedder {
    /// Initializes the local embedding model
    pub fn new() -> Result<Self, anyhow::Error> {
        // We use a tiny, lightning-fast model perfect for short logs
        let model = TextEmbedding::try_new(InitOptions::new(
            EmbeddingModel::AllMiniLML6V2
        ))?;
        
        Ok(Self { model })
    }

    /// Converts a raw OS log string into a vector of f32 numbers.
    /// Notice the `&mut self` here! The AI model needs a mutable memory buffer.
    pub fn embed_log(&mut self, log_text: &str) -> Result<Vec<f32>, anyhow::Error> {
        let documents = vec![log_text.to_string()];
        
        // Generate embeddings. It returns a Vec of Vecs (one per document)
        let mut embeddings = self.model.embed(documents, None)?;
        
        // Return the first (and only) embedding
        Ok(embeddings.pop().unwrap())
    }
}