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
use ark_std::{rand::{Rng, seq::SliceRandom}, test_rng, One, UniformRand, Zero};
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
fn test_prover_prepare_selector_quotient_evals() {
    let num_assets = 5;
    let rng = &mut test_rng();
    let mut indices: Vec<usize> = (0..16).collect();
    indices.shuffle(rng);
    let mut selector = vec![false; 16];
    for &idx in indices.iter().take(num_assets) {
        selector[idx] = true;
    }
    let prover = Prover::setup(&selector);
    let evals = prover.prepare_selector_quotient_evals();
    let domain_size = prover.domain_size;
    let p = DenseOrSparsePolynomial::from(prover.poly.clone());
    let omega = prover.omega;
    for i in 0..domain_size {
        // a
        let point = omega.pow(&[i as u64]);
        // X - a
        let denominator = DensePolynomial::from_coefficients_vec(vec![-point, BlsScalarField::one()]);
        // s(a)
        let p_eval = prover.poly.evaluate(&point);
        let p_eval = DensePolynomial::from_coefficients_vec(vec![p_eval]);
        // s(X) - s(a)
        let numerator = &prover.poly - &p_eval;
        // [s(X) - s(a)] / (X - a)
        let (q, r) = DenseOrSparsePolynomial::from(numerator).divide_with_q_and_r(&DenseOrSparsePolynomial::from(denominator)).unwrap();
        assert!(r.is_zero());
        assert_eq!(evals[i].len(), q.degree() + 1);
        for (j, e1) in evals[i].iter().enumerate() {
            let point = omega.pow(&[j as u64]);
            let e2 = q.evaluate(&point);
            assert_eq!(*e1, e2);
        }
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
    let mut prover = Prover::setup(&selector);

    let (lag_comms, lag_polys) = lagrange_commitments::<Bls12<ark_bls12_381::Config>, UniPoly_381>(&prover.powers, prover.domain_size - 1);
    for i in 0..lag_polys.len() {
        for j in 0..lag_polys.len() {
            let point = prover.omega.pow(&[j as u64]);
            let eval = lag_polys[i].evaluate(&point);
            if i == j {
                assert_eq!(eval, BlsScalarField::one());
            } else {
                assert_eq!(eval, BlsScalarField::zero());
            }
        }
    }
    assert_eq!(lag_polys.len(), prover.domain_size - 1);

    let lag_evals = prover.prepare_selector_quotient_evals();
    let quotients: Vec<_> = lag_evals.iter().map(| evals | {
        let mut acc = UniPoly_381::zero();
        for (i, e) in evals.iter().enumerate() {
            let term = DensePolynomial::from_coefficients_vec(vec![*e]);
            let p = &lag_polys[i];
            let term = term.mul(p);
            acc += &term;
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
    for i in 0..selector.len() {
        let point = omega.pow(&[i as u64]);
        let (witness_polynomial, random) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(&poly, point, &randomness).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);
        
        let w = <Bls12_381 as Pairing>::G1::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );

        assert_eq!(witness_polynomial.degree(), quotients[i].degree());
        for (j, e1) in lag_evals[i].iter().enumerate() {
            let point = omega.pow(&[j as u64]);
            let e2 = witness_polynomial.evaluate(&point);
            assert_eq!(*e1, e2);
        }
        for (w_coeff, q_coeff) in witness_polynomial.coeffs().iter().zip(quotients[i].coeffs.iter()) {
            assert_eq!(w_coeff, q_coeff);
        }
        assert_eq!(w, quotient_comms[i]);
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
