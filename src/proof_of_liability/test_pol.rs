use ark_std::{rand::{distributions::Uniform, Rng}, test_rng, UniformRand, One};
use ark_poly::{Polynomial, EvaluationDomain};

use std::ops::Mul;

use crate::types::BlsScalarField;

use super::{prover::Prover, verifier::Verifier};

#[test]
fn test_pol() {
    let total_number = 2usize.pow(10);
    let group_size: usize = 8;
    // let total_number: usize = 131072;
    // let group_size: usize = 131072;
    let max_degree = group_size * 2;
    let max_bits = 64;
    
    let rng = &mut test_rng();
    let upper_bound = u64::MAX;
    let num_of_groups = total_number / group_size;

    let balances: Vec<u64> = (0..num_of_groups * group_size).map(| _ | rng.sample(Uniform::new(1, upper_bound))).collect();
    let prover = Prover::setup(&balances, group_size, max_degree);

    let sum_bals: BlsScalarField = balances.into_iter().map(| bal | BlsScalarField::from(bal)).sum();

    let gamma = BlsScalarField::rand(rng);

    /* concurrent */
    let concurrent_pol = | | {
        let rng = &mut test_rng();
        let (inters, comms, rands) = prover.concurrent_run(max_bits, gamma);
        let taus = inters.iter().map(| inter | inter.domain.sample_element_outside_domain(rng)).collect();
        let (proof, rand_sigma_p0) = prover.concurrent_generate_proof(&inters, &comms, &rands, &taus);
        let hiding = rand_sigma_p0.blinding_polynomial.evaluate(&BlsScalarField::one());
        let liability = prover.vk.g.mul(sum_bals) + prover.vk.gamma_g.mul(hiding);
        assert_eq!(liability, proof.sigma_p0_eval.into_committed_value());
        Verifier::validate_liability_proof(&prover.vk, proof.clone(), &taus, gamma, rng);
    };

    println!("====================================");
    println!("******* Concurrent PoL start *******");
    concurrent_pol();
    println!("******* Concurrent PoL end   *******");
    println!("====================================");

    /* for loop */
    // let single_thread_pol = | | {
    //     let rng = &mut test_rng();
    //     let (inters, comms, rands) = prover.run(max_bits, gamma, rng);
    //     let taus = inters.iter().map(| inter | inter.domain.sample_element_outside_domain(rng)).collect();
    //     let (proof, rand_sigma_p0) = prover.generate_proof(&inters, &comms, &rands, &taus, rng);
    //     let hiding = rand_sigma_p0.blinding_polynomial.evaluate(&BlsScalarField::one());
    //     let liability = prover.vk.g.mul(sum_bals) + prover.vk.gamma_g.mul(hiding);
    //     assert_eq!(liability, proof.sigma_p0_eval.into_committed_value());
    
    //     Verifier::validate_liability_proof(&prover.vk, proof.clone(), &taus, gamma, rng);
    // };

    // println!("====================================");
    // println!("***** Single-thread PoL start ******");
    // single_thread_pol();
    // println!("***** Single-thread PoL end   ******");
    // println!("====================================");
}

#[test]
fn test_pol_multi_times() {
    for i in 0..100  {
        println!("====================================");
        println!("*********** Job {} start ***********", i);
        test_pol();
        println!("*********** Job {} done  ***********", i);
        println!("====================================");
    }
}
