use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::{rand::Rng, test_rng};
use ark_ff::Field;
use ark_test_curves::secp256k1;
use num_bigint::{BigUint, RandomBits};

use std::ops::Mul;

use super::PoA;

#[test]
fn test_poa() {
    let rng = &mut test_rng();
    let range = 0..10;
    let selector: Vec<bool> = range.clone().into_iter().map(| _ | {
        let rand = rng.gen_range(0..10);
        rand % 2 == 1
    })
    .collect();

    let poa = PoA::setup(&selector);

    let mut pks = Vec::<secp256k1::G1Affine>::new();
    let mut sks = Vec::<BigUint>::new();

    for _ in range {
        let private_key: BigUint = rng.sample(RandomBits::new(256u64));
        let public_key = poa.prover.sigma.gs.mul_bigint(private_key.to_u64_digits());
        sks.push(private_key);
        pks.push(public_key.into_affine());
    }
    
    let proofs = poa.prover.generate_proof(&pks, &sks);
    let vk = &poa.prover.vk;
    let omega = &poa.prover.omega;
    let mut i = 0;
    for (cm, pc_proof, sigma_proof) in proofs {        
        poa.prover.sigma.validate(sigma_proof, pks[i], pc_proof.committed_eval);

        let point = omega.pow(&[i as u64]);
        let inner = cm.0.into_group() - &pc_proof.committed_eval;
        let lhs = Bls12_381::pairing(inner, vk.h);
        let inner = vk.beta_h.into_group() - &vk.h.mul(point);
        let rhs = Bls12_381::pairing(pc_proof.witness, inner);
        assert_eq!(lhs, rhs);

        i += 1;
    }
}

#[test]
fn test_poa_multi_times() {
    for i in 0..100  {
        println!("Job {} start", i);
        test_poa();
        println!("Job {} done", i);
    }
}
