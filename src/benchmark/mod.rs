use serde::{Deserialize, Serialize};

#[cfg(test)]
pub(crate) mod gadgets;

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchConfig {
    pub num_of_users: usize,
    pub num_of_bits: usize,
    pub num_of_groups: usize,
}

#[derive(Serialize, Deserialize)]
pub struct PoLReport {
    pub interpolation_time: String,
    pub proving_time: String,
    pub verifying_time: String,
    pub proof_size: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CSVRecord {
    pub num_of_users: usize,
    pub num_of_bits: usize,
    pub num_of_groups: usize,
    pub interpolation_time: String,
    pub proving_time: String,
    pub verifying_time: String,
    pub proof_size: String,
    pub timestamp: String,
}