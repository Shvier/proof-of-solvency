use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_poly::{univariate::DenseOrSparsePolynomial, EvaluationDomain, Radix2EvaluationDomain, Polynomial};
use ark_poly_commit::kzg10::{Proof, KZG10};
use ark_std::{rand::Rng, test_rng, UniformRand, Zero};
use ark_ff::Field;
use num_bigint::{BigUint, RandomBits};

use crate::proof_of_assets::verifier::Verifier;

use super::{Prover, UniPoly_381};

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;

#[test]
fn test_prover() {
    let rng = &mut test_rng();
    let selector: Vec<bool> = (0..10).into_iter().map(| _ | {
        let rand = rng.gen_range(0..10);
        rand % 2 == 1
    })
    .collect();
    let prover = Prover::setup(&selector);
    let omega = prover.omega;
    let vk = &prover.vk;
    for i in 0..selector.len() {
        let s = selector[i];
        let (cm, randomness) = prover.commit_to_selector();
        let point = omega.pow(&[i as u64]);
        let proof = prover.open_selector(point, &randomness);
        let proof = Proof {
            w: proof.witness,
            random_v: Some(proof.rand),
        };
        let result = KZG10::<Bls12_381, UniPoly_381>::check(&vk, &cm, point, Fr::from(s), &proof).unwrap();
        assert!(result);
    }
}

#[test]
fn test_prover_multi_times() {
    for i in 0..100  {
        println!("Job {} start", i);
        test_prover();
        println!("Job {} done", i);
    }
}

#[test]
fn test_accumulator() {
    let rng = &mut test_rng();
    let range = 0..16;
    let selector: Vec<bool> = range.clone().into_iter().map(| _ | {
        let rand = rng.gen_range(0..10);
        rand % 2 == 1
    })
    .collect();
    let balances: Vec<BlsScalarField> = range.clone().into_iter().map(| _ | {
        let bal: BigUint = rng.sample(RandomBits::new(16u64));
        BlsScalarField::from(bal)
    })
    .collect();
    let bal_poly = Verifier::generate_balance_poly(&balances);
    let prover = Prover::setup(&selector);
    let domain = Radix2EvaluationDomain::<BlsScalarField>::new(prover.domain_size).unwrap();
    let accum_poly = prover.construct_accumulator(&bal_poly, domain);
    let omega = prover.omega;
    let last = omega.pow(&[15 as u64]);
    let a = accum_poly.evaluate(&last);
    let b = bal_poly.evaluate(&last);
    match selector[15] {
        true => {
            assert_eq!(a, b);
        }
        false => {
            assert_eq!(a, BlsScalarField::zero());
        }
    }
    for i in (0..15).rev() {
        let cur_point = omega.pow(&[i as u64]);
        let next = omega.pow(&[(i + 1) as u64]);
        let cur = accum_poly.evaluate(&cur_point);
        let next = accum_poly.evaluate(&next);
        let bal = bal_poly.evaluate(&cur_point);
        match selector[i] {
            true => {
                assert_eq!(cur, next + bal);
            }
            false => {
                assert_eq!(cur, next);
            }
        }
    }
}

#[test]
fn test_compute_w1_w2() {
    let rng = &mut test_rng();
    let range = 0..16;
    let selector: Vec<bool> = range.clone().into_iter().map(| _ | {
        let rand = rng.gen_range(0..10);
        rand % 2 == 1
    })
    .collect();
    let balances: Vec<BlsScalarField> = range.clone().into_iter().map(| _ |
        BlsScalarField::rand(rng)
    )
    .collect();
    let bal_poly = Verifier::generate_balance_poly(&balances);
    let prover = Prover::setup(&selector);
    let domain = Radix2EvaluationDomain::<BlsScalarField>::new(prover.domain_size).unwrap();
    let accum_poly = prover.construct_accumulator(&bal_poly, domain);
    let (w1, w2) = prover.compute_w1_w2(&accum_poly, &bal_poly, domain);
    let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());

    let omega = prover.omega;
    for i in range {
        let point = omega.pow(&[i as u64]);
        println!("{} - {}", i, w1.evaluate(&point).is_zero());
    }

    let (_, r) = DenseOrSparsePolynomial::from(w1).divide_with_q_and_r(&zed).unwrap();
    assert!(r.is_zero());
    let (_, r) = DenseOrSparsePolynomial::from(w2).divide_with_q_and_r(&zed).unwrap();
    assert!(r.is_zero());
}
