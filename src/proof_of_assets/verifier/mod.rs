use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::{Commitment, VerifierKey};
use ark_ff::Field;
use ark_std::{rand::RngCore, test_rng, One};
use ark_test_curves::secp256k1;

use std::ops::Mul;

use crate::{proof_of_assets::sigma::SigmaProtocol, types::BlsScalarField, utils::{batch_check, calculate_hash, BatchCheckProof, HashBox, OpenEval}};

use super::{prover::{AssetsProof, PolyCommitProof}, sigma::SigmaProtocolProof};

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
            &BatchCheckProof {
                commitments: cms,
                witnesses: witnesses,
                points: points,
                open_evals: evals,
                gammas: gammas,
            }, 
            rng);
    }

    pub fn generate_balance_poly(bals: &Vec<BlsScalarField>) -> DensePolynomial<BlsScalarField> {
        let domain_size = bals.len().checked_next_power_of_two().expect("Unsupported domain size");
        let domain = Radix2EvaluationDomain::new(domain_size).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(bals.to_vec(), domain);
        evaluations.interpolate()
    }

    pub fn validate_assets_proof<R: RngCore>(vk: &VerifierKey<Bls12_381>, proof: &AssetsProof, gamma: BlsScalarField, rng: &mut R) {
        let cm_accum = &proof.batch_check_proof.commitments[0][0];
        let cm_bal = &proof.batch_check_proof.commitments[0][1];
        let cm_selector = &proof.batch_check_proof.commitments[0][2];
        let cm_q = &proof.batch_check_proof.commitments[0][3];
        let challenge = calculate_hash(&vec![
            HashBox::Bls(cm_accum.0.into_group()), 
            HashBox::Bls(cm_bal.0.into_group()),
            HashBox::Bls(cm_selector.0.into_group()),
            HashBox::Bls(cm_q.0.into_group()),
        ]);
        let challenge_point = BlsScalarField::from(challenge);
        assert_eq!(challenge_point, proof.batch_check_proof.points[0]);
        assert_eq!(challenge_point * proof.omega, proof.batch_check_proof.points[1]);
        assert_eq!(BlsScalarField::one(), proof.batch_check_proof.points[2]);

        let accum_tau = &proof.batch_check_proof.open_evals[0][0].into_plain_value().0;
        let b_tau = &proof.batch_check_proof.open_evals[0][1].into_plain_value().0;
        let s_tau = &proof.batch_check_proof.open_evals[0][2].into_plain_value().0;
        let q_tau = &proof.batch_check_proof.open_evals[0][3].into_plain_value().0;
        let accum_tau_omega = &proof.batch_check_proof.open_evals[1][0].into_plain_value().0;

        let last = proof.omega.pow(&[(proof.domain_size - 1) as u64]);
        let x_minus_last_omega = DensePolynomial::<BlsScalarField>::from_coefficients_vec(vec![-last, BlsScalarField::one()]);
        let x_minus_last_omega_at_tau = x_minus_last_omega.evaluate(&challenge_point);

        let s_tau_times_b_tau = s_tau * b_tau;
        let mut w1_tau = accum_tau - accum_tau_omega - &s_tau_times_b_tau;
        w1_tau = w1_tau * x_minus_last_omega_at_tau;

        let mut w2_tau = accum_tau - &s_tau_times_b_tau;
        let domain = Radix2EvaluationDomain::<BlsScalarField>::new(proof.domain_size).unwrap();
        let zed = domain.vanishing_polynomial();
        let zed_tau = zed.evaluate(&challenge_point);
        let zed = DenseOrSparsePolynomial::from(zed);
        let (quotient, _) = zed.divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_last_omega)).unwrap();
        w2_tau = w2_tau * quotient.evaluate(&challenge_point);

        let w_tau = w1_tau + gamma * w2_tau;
        let q_tau_times_zed_tau = q_tau * &zed_tau;
        assert_eq!(w_tau, q_tau_times_zed_tau);
        
        batch_check(vk, &proof.batch_check_proof, rng);
    }
}
