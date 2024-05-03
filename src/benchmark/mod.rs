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
pub struct PoLCSVRecord {
    pub num_of_users: usize,
    pub num_of_bits: usize,
    pub num_of_groups: usize,
    pub interpolation_time: String,
    pub proving_time: String,
    pub verifying_time: String,
    pub proof_size: String,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PoACSVRecord {
    pub num_of_keys: usize,
    pub pre_proving_time: u128,
    pub pre_verifying_time: u128,
    pub post_proving_time: u128,
    pub post_verifying_proof_time: u128,
    pub post_validating_balance_time: u128,
}

impl PoACSVRecord {
    pub fn empty() -> PoACSVRecord {
        Self { num_of_keys: 0, pre_proving_time: 0, pre_verifying_time: 0, post_proving_time: 0, post_verifying_proof_time: 0, post_validating_balance_time: 0 }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AffinePoint {
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AffineQuadExt {
    pub c0: String,
    pub c1: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AffineQuadExtPoint {
    pub x: AffineQuadExt,
    pub y: AffineQuadExt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub sk: String,
    pub pk: AffinePoint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelectorPoly {
    pub values: Vec<bool>,
    pub coeffs: Vec<String>,
    pub randomness: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PoAPrecompute {
    pub interpolate_selector: u128,
    pub proving_time: u128,
    pub verifying_time: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustSetupParams {
    pub powers_of_g: Vec<AffinePoint>,
    pub powers_of_gamma_g: Vec<AffinePoint>,
    pub h: AffineQuadExtPoint,
    pub beta_h: AffineQuadExtPoint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PoAProverJSON {
    pub params: TrustSetupParams,
    pub selector: SelectorPoly,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PoAReport {
    pub interpolate_balance_time: u128,
    pub accumulator_proving_time: u128,
    pub verifying_proof_time: u128,
    pub validating_balance_time: u128,
}
