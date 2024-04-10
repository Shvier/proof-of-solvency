use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::Rng, test_rng};
use ark_test_curves::secp256k1;
use num_bigint::{BigUint, RandomBits};

use crate::proof_of_assets::verifier::Verifier;

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

    Verifier::batch_check(vk, &proofs, pks, *omega);

    // single check
    // use ark_ff::Field;
    // let mut i = 0;
    // for (cm, pc_proof, sigma_proof) in proofs {
    //     let point = omega.pow(&[i as u64]);
    //     Verifier::check(vk, cm, pc_proof, sigma_proof, pks[i], point);
    //     i += 1;
    // }
}

#[test]
fn test_poa_multi_times() {
    for i in 0..100  {
        println!("Job {} start", i);
        test_poa();
        println!("Job {} done", i);
    }
}
