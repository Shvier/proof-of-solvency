use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rand::distributions::Uniform, test_rng, UniformRand};
use ark_poly::EvaluationDomain;

use crate::proof_of_liability::{prover::intermediate::Intermediate, verifier::Verifier};

use super::Prover;

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;

#[test]
fn test_prover() {
    use ark_std::rand::Rng;

    let group_size: usize = 128;
    let max_degree: usize = 256;
    let max_bits = 63;
    let prover = Prover::setup(group_size, max_degree);
    
    let rng = &mut test_rng();
    let range = 0..50;
    let upper_bound = 2_u64.pow(63);
    let balances: Vec<u64> = range.clone().into_iter().map(| _ |
        rng.sample(Uniform::new(1, upper_bound))
    )
    .collect();
    let gamma = BlsScalarField::rand(rng);
    let inter = Intermediate::<Bls12_381>::new(&balances, max_bits, gamma).unwrap();
    let (cms, randoms) = inter.compute_commitments(&prover.powers, rng);
    let tau = inter.domain.sample_element_outside_domain(rng);
    let proof = inter.generate_proof(&prover.powers, cms, randoms, tau, rng);
    Verifier::validate_intermediate_proof(&prover.vk, proof, tau, gamma, rng);
}
