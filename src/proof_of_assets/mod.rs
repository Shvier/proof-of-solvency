use ark_test_curves::secp256k1;
use num_bigint::BigUint;

use self::prover::Prover;

pub mod prover;
pub mod sigma;
pub mod verifier;

#[cfg(test)]
mod test_poa;

pub struct PoA {
    prover: Prover,
}

impl PoA {
    pub fn setup(selector: &Vec<bool>) -> Self {
        let prover = Prover::setup(selector);
        Self {
            prover,
        }
    }

    pub fn run(&self, pks: &Vec<secp256k1::G1Affine>, sks: &Vec<BigUint>) {
        let prover = &self.prover;
        prover.generate_proof(pks, sks);
    }
}
