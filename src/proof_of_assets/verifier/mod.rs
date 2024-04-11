use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::{Commitment, VerifierKey};
use ark_ff::Field;
use ark_std::{rand::RngCore, test_rng, One};
use ark_test_curves::secp256k1;

use std::ops::Mul;

use crate::{proof_of_assets::sigma::SigmaProtocol, utils::{batch_check, BatchCheckProof, OpenEval}};

use super::{prover::{AssetsProof, PolyCommitProof}, sigma::SigmaProtocolProof};

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;

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
        SigmaProtocol::validate(secp256k1::G1Affine::generator(), vk.g, vk.gamma_g, &sigma_proof, pk, pc_proof.committed_eval);
        
        let inner = cm.0.into_group() - &pc_proof.committed_eval;
        let lhs = Bls12_381::pairing(inner, vk.h);
        let inner = vk.beta_h.into_group() - &vk.h.mul(point);
        let rhs = Bls12_381::pairing(pc_proof.witness, inner);
        assert_eq!(lhs, rhs);
    }

    pub fn batch_check(
        vk: &VerifierKey<Bls12_381>,
        proofs: &Vec<(Commitment<Bls12_381>, PolyCommitProof, SigmaProtocolProof)>,
        pks: Vec<secp256k1::G1Affine>,
        omega: <Bls12_381 as Pairing>::ScalarField,
    ) {
        let mut i = 0;
        let mut points = Vec::<BlsScalarField>::new();
        let mut cms = Vec::<Vec<Commitment<Bls12_381>>>::new();
        let mut witnesses = Vec::<<Bls12_381 as Pairing>::G1>::new();
        let mut evals = Vec::<Vec<OpenEval<Bls12_381>>>::new();
        let mut gammas = Vec::<BlsScalarField>::new();
        for (cm, pc_proof, sigma_proof) in proofs {
            SigmaProtocol::validate(secp256k1::G1Affine::generator(), vk.g, vk.gamma_g, sigma_proof, pks[i], pc_proof.committed_eval);
            let point = omega.pow(&[i as u64]);
            points.push(point);
            cms.push(vec![*cm]);
            witnesses.push(pc_proof.witness.into_group());
            gammas.push(BlsScalarField::one());
            evals.push(vec![OpenEval::Committed(pc_proof.committed_eval)]);
            i += 1;
        }
        let rng = &mut test_rng();
        batch_check(
            vk, 
            BatchCheckProof {
                commitments: cms,
                witnesses: witnesses,
                points: points,
                open_evals: evals,
                gammas: gammas,
            }, rng);
    }

    pub fn generate_balance_poly(bals: &Vec<BlsScalarField>) -> DensePolynomial<BlsScalarField> {
        let domain_size = bals.len().checked_next_power_of_two().expect("Unsupported domain size");
        let domain = Radix2EvaluationDomain::new(domain_size).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(bals.to_vec(), domain);
        evaluations.interpolate()
    }
    }
}
