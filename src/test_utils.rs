use std::time::Instant;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, VerifierKey, KZG10};
use ark_ff::{FftField, Field};
use ark_std::{rand::Rng, test_rng, UniformRand};

use crate::{types::BlsScalarField, utils::{batch_check, batch_open, build_bit_vector, build_up_bits, convert_to_zk_polynomial, BatchCheckProof, OpenEval}};

#[cfg(test)]
fn compare_vecs(va: &[u64], vb: &[u64]) -> bool {
    (va.len() == vb.len()) &&
     va.iter()
       .zip(vb)
       .all(|(a,b)| *a == *b)
}

#[test]
fn test_build_up_bits() {
    let bits_8 = [0, 0, 1, 2, 5, 10, 20];
    let bits = build_up_bits(20, 7);
    assert!(compare_vecs(&bits_8, &bits));

    let bits_16 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 6, 12, 25, 50];
    let bits = build_up_bits(50, 15);
    assert!(compare_vecs(&bits_16, &bits));
}

#[test]
fn test_build_bit_vector() {
    let liab: Vec<u64> = [20, 50, 30, 40, 10, 60, 80, 70].to_vec();
    let vec = build_bit_vector(&liab, 16);
    println!("{:?}", vec);
}

#[test]
fn test_batch_check() {
    let rng = &mut test_rng();
    let degree: usize = 10;
    let domain_size = degree.checked_next_power_of_two().expect("Unsupported domain size");

    let pp = KZG10::<Bls12_381, DensePolynomial<BlsScalarField>>::setup(domain_size, false, rng).unwrap();
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    let powers_of_g = pp.powers_of_g[..=domain_size].to_vec();
    let powers_of_gamma_g = (0..=domain_size)
        .map(|i| pp.powers_of_gamma_g[&i])
        .collect();
    let powers: Powers<Bls12_381> = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    let mut polys = Vec::<DensePolynomial<BlsScalarField>>::new();
    let mut cms = Vec::<Commitment<Bls12_381>>::new();
    let mut randoms = Vec::<Randomness<BlsScalarField, DensePolynomial<BlsScalarField>>>::new();
    for _ in 0..17 {
        let poly = DensePolynomial::<BlsScalarField>::rand(degree, rng);
        let (cm, randomness) = 
            KZG10::<Bls12_381, DensePolynomial<BlsScalarField>>::commit(&powers, &poly, Some(degree), Some(rng)).unwrap();
        polys.push(poly);
        cms.push(cm);
        randoms.push(randomness);
    }

    let perfect_hiding = true;

    let omega = BlsScalarField::get_root_of_unity(domain_size.try_into().unwrap()).unwrap();
    let mut open_points = Vec::<BlsScalarField>::new();
    let mut commitments = Vec::<Vec<Commitment<Bls12_381>>>::new();
    let mut witnesses = Vec::<<Bls12_381 as Pairing>::G1>::new();
    let mut evals = Vec::<Vec<OpenEval<Bls12_381>>>::new();
    let mut gammas = Vec::<BlsScalarField>::new();
    for _ in 0..2 {
        let power = rng.gen::<u64>();
        let point = omega.pow(&[power]);
        open_points.push(point);
        let (witness, open_evals, gamma) = 
            batch_open(&powers, &polys.iter().collect(), &randoms.iter().collect(), point, perfect_hiding, rng);
        witnesses.push(witness);
        evals.push(open_evals);
        gammas.push(gamma);
        commitments.push(cms.clone());
    }

    let power = rng.gen::<u64>();
    let point = omega.pow(&[power]);
    open_points.push(point);
    let (witness, open_evals, gamma) = 
        batch_open(&powers, &[&polys[1]].to_vec(), &[&randoms[1]].to_vec(), point, perfect_hiding, rng);
    witnesses.push(witness);
    evals.push(open_evals);
    gammas.push(gamma);
    commitments.push([cms[1].clone()].to_vec());

    let start_time = Instant::now();
    batch_check(
        &vk, 
        &BatchCheckProof {
            commitments,
            witnesses,
            points: open_points,
            open_evals: evals,
            gammas,
        }, 
        rng
    );
    let total_time =
        start_time.elapsed().as_secs() as f64 + start_time.elapsed().subsec_nanos() as f64 / 1e9;
    println!("batch check executed time: {}", total_time);
}

#[test]
fn test_batch_check_multi_times() {
    for i in 0..100  {
        println!("Job {} start", i);
        test_batch_check();
        println!("Job {} done", i);
    }
}

#[test]
fn test_convert_to_zk_polynomial() {
    let rng = &mut test_rng();
    let range = 0..10;
    let evals: Vec<BlsScalarField> = range.clone().into_iter().map(| _ |
        BlsScalarField::rand(rng)
    )
    .collect();
    let domain = Radix2EvaluationDomain::<BlsScalarField>::new(evals.len().checked_next_power_of_two().unwrap()).unwrap();
    let evaluations = Evaluations::<BlsScalarField, Radix2EvaluationDomain<BlsScalarField>>::from_vec_and_domain(evals.clone(), domain);
    let poly = evaluations.interpolate();
    let (zk_poly, extra_evals) = convert_to_zk_polynomial(&poly, domain, 2, rng);
    let new_evals = zk_poly.clone().evaluate_over_domain(domain).evals;
    for (left, right) in new_evals.into_iter().zip(evals.clone()) {
        assert_eq!(left, right);
    }

    for (point, extra_eval) in extra_evals {
        assert_eq!(extra_eval, zk_poly.evaluate(&point));
    }
}
