use std::ops::Mul;
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_bls12_381::g1::Config;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{univariate::DenseOrSparsePolynomial, EvaluationDomain, Radix2EvaluationDomain, Polynomial};
use ark_poly_commit::{kzg10::{Commitment, KZG10, Proof, Randomness}, PCRandomness};
use ark_std::{rand::{Rng, seq::SliceRandom}, test_rng, UniformRand, Zero};
use ark_ff::Field;
use num_bigint::{BigUint, RandomBits};

use crate::{proof_of_assets::verifier::Verifier, utils::{lagrange_commitments, convert_to_bigints}};
#[cfg(test)]
use crate::types::BlsScalarField;
use crate::utils::skip_leading_zeros_and_convert_to_bigints;
use super::{Prover, UniPoly_381};

#[test]
fn test_prover() {
    let rng = &mut test_rng();
    let selector: Vec<bool> = (0..10).into_iter().map(| _ | {
        let rand = rng.gen_range(0..10);
        rand % 2 == 1
    })
    .collect();
    let mut prover = Prover::setup(&selector);
    let omega = prover.omega;
    let vk = prover.vk.clone();
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
fn test_prover_lagrange() {
    let num_assets = 5;
    let rng = &mut test_rng();
    let mut indices: Vec<usize> = (0..16).collect();
    indices.shuffle(rng);
    let mut selector = vec![false; 16];
    for &idx in indices.iter().take(num_assets) {
        selector[idx] = true;
    }
    let mut selector = vec![false, false, false, true];
    println!("selector: {:?}", selector);
    let mut prover = Prover::setup(&selector);

    let (lag_comms, lag_rand_comm, lag_polys, _) = lagrange_commitments::<Bls12<ark_bls12_381::Config>, UniPoly_381>(&prover.powers, prover.domain_size - 1);
    assert_eq!(lag_polys.len(), prover.domain_size - 1);

    let lag_evals = prover.prepare_selector_quotient_evals();
    let quotients: Vec<_> = lag_evals.iter().enumerate().map(| (i, evals) | {
        let mut acc = UniPoly_381::zero();
        let mut k = 0;
        for (j, e) in evals.iter().enumerate() {
            if i == j {
                k += 1;
                continue;
            }
            let term = DensePolynomial::from_coefficients_vec(vec![*e]);
            let p = &lag_polys[k];
            let term = term.mul(p);
            acc += &term;
            k += 1;
        }
        acc
    })
    .collect();


    let quotient_comms = lag_evals
        .iter()
        .map(|evals| {
            let bigints = convert_to_bigints(evals);
            let affines = lag_comms.iter().map(|c| c.0).collect::<Vec<_>>();
            let comm = <Bls12_381 as Pairing>::G1::msm_bigint(&affines, &bigints);
            comm
        })
        .collect::<Vec<_>>();

    let (cm, randomness) = prover.commit_to_selector();
    let omega = prover.omega;
    let poly = prover.poly;
    let powers = prover.powers;
    for i in (0..selector.len()).rev() {
        let point = omega.pow(&[i as u64]);
        let (witness_polynomial, random) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(&poly, point, &randomness).unwrap();
        // let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);
        //
        // let w = <Bls12_381 as Pairing>::G1::msm_bigint(
        //     &powers.powers_of_g[num_leading_zeros..],
        //     &witness_coeffs,
        // );

        println!("{}", i);
        assert_eq!(witness_polynomial.degree(), quotients[i].degree());
        for (w_coeff, q_coeff) in witness_polynomial.coeffs().iter().zip(quotients[i].coeffs.iter()) {
            assert_eq!(w_coeff, q_coeff);
        }
        // assert_eq!(w, quotient_comms[i]);
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
