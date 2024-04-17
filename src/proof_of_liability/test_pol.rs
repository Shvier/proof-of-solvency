use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly_commit::{kzg10::Commitment, PCCommitment};
use ark_std::{rand::{distributions::Uniform, Rng}, test_rng, UniformRand, One};
use ark_poly::{Polynomial, EvaluationDomain};

use std::ops::{AddAssign, Mul};

use super::{prover::Prover, verifier::Verifier};

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;

#[test]
fn test_pol() {
    let group_size: usize = 128;
    let max_degree: usize = 256;
    let max_bits = 63;
    
    let rng = &mut test_rng();
    let upper_bound = 2_u64.pow(63);
    let num_of_groups: usize = 3;

    let balances: Vec<u64> = (0..num_of_groups * group_size).map(| _ | rng.sample(Uniform::new(1, upper_bound))).collect();
    let prover = Prover::setup(&balances, group_size, max_degree);

    let mut sum_comm_p0 = Commitment::<Bls12_381>::empty();
    let sum_bals: BlsScalarField = balances.into_iter().map(| bal | BlsScalarField::from(bal)).sum();

    let gamma = BlsScalarField::rand(rng);
    let (inters, comms, rands) = prover.run(max_bits, gamma, rng);

    let taus = inters.iter().map(| inter | inter.domain.sample_element_outside_domain(rng)).collect();
    let (proof, rand_sigma_p0) = prover.generate_proof(&inters, &comms, &rands, &taus, rng);

    for inter_proof in proof.clone().intermediate_proofs {
        let comm_p0 = inter_proof.cms[0];
        sum_comm_p0.add_assign((BlsScalarField::one(), &comm_p0));
    }
    let hiding = rand_sigma_p0.blinding_polynomial.evaluate(&BlsScalarField::one());
    let liability = prover.vk.g.mul(sum_bals) + prover.vk.gamma_g.mul(hiding);
    assert_eq!(liability, proof.sigma_p0_eval.into_committed_value());

    Verifier::validate_liability_proof(&prover.vk, proof.clone(), sum_comm_p0, &taus, gamma, rng);
}
