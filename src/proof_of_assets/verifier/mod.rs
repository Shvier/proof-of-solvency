use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_poly_commit::kzg10::{Commitment, VerifierKey};
use ark_test_curves::secp256k1;

use std::ops::Mul;

use crate::proof_of_assets::sigma::SigmaProtocol;

use super::{prover::PolyCommitProof, sigma::SigmaProtocolProof};

pub struct Verifier {

}

impl Verifier {
    pub fn check(
        vk: &VerifierKey<Bls12_381>, 
        cm: Commitment<Bls12_381>, 
        pc_proof: PolyCommitProof, 
        sigma_proof: SigmaProtocolProof,
        pk: secp256k1::G1Affine,
        point: <Bls12_381 as Pairing>::ScalarField,
    ) {
        SigmaProtocol::validate(secp256k1::G1Affine::generator(), vk.g, vk.gamma_g, sigma_proof, pk, pc_proof.committed_eval);
        
        let inner = cm.0.into_group() - &pc_proof.committed_eval;
        let lhs = Bls12_381::pairing(inner, vk.h);
        let inner = vk.beta_h.into_group() - &vk.h.mul(point);
        let rhs = Bls12_381::pairing(pc_proof.witness, inner);
        assert_eq!(lhs, rhs);
    }
}
