use ark_bls12_381::{Bls12_381, Fr};
use ark_poly_commit::kzg10::{Proof, VerifierKey, KZG10};
use ark_std::{rand::Rng, test_rng};
use ark_ff::{FftField, Field};

use super::{BlsScalarField, Prover, UniPoly_381};

#[test]
fn test_prover() {
    let rng = &mut test_rng();
    let selector: Vec<u8> = (0..10).into_iter().map(| _ | {
        let rand = rng.gen_range(0..10);
        rand % 2
    })
    .collect();
    let prover = Prover::setup(&selector);
    let omega = BlsScalarField::get_root_of_unity(prover.domain_size.try_into().unwrap()).unwrap();
    let pp = &prover.pp;
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    for i in 0..selector.len() {
        let s = selector[i];
        let (cm, randomness) = prover.commit();
        let point = omega.pow(&[i as u64]);
        let proof = prover.open(point, &randomness);
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
