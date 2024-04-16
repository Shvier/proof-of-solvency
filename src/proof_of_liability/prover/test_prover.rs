use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rand::distributions::Uniform, test_rng, UniformRand};

use crate::utils::{batch_check, calculate_hash, BatchCheckProof, HashBox};

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
    let inter_proof = prover.construct_intermediate_node(&balances, max_bits, gamma, rng);
    let hash_boxes: Vec<HashBox> = inter_proof.cms.clone().into_iter().map(| cm | HashBox::Bls(cm.0.into())).collect();
    let tau = BlsScalarField::from(calculate_hash(&hash_boxes));

    batch_check(
        &prover.vk, 
        &BatchCheckProof {
            commitments: vec![inter_proof.cms],
            witnesses: vec![inter_proof.proof_at_tau.0],
            points: vec![tau],
            open_evals: vec![inter_proof.proof_at_tau.1],
            gammas: vec![inter_proof.proof_at_tau.2],
        }, 
        rng);
}
