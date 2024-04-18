use std::time::Instant;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, EvaluationDomain, Polynomial};
use ark_poly_commit::kzg10::{Commitment, VerifierKey};
use ark_std::{rand::RngCore, test_rng, One, Zero};
use ark_ff::Field;
use crossbeam::thread;

use crate::utils::{batch_check, BatchCheckProof};

use super::prover::{intermediate::IntermediateProof, LiabilityProof};

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;

pub struct Verifier {

}

impl Verifier {
    pub fn validate_intermediate_proof<R: RngCore>(
        vk: &VerifierKey<Bls12_381>,
        proof: IntermediateProof<Bls12_381, DensePolynomial<BlsScalarField>>,
        tau: BlsScalarField,
        gamma: BlsScalarField,
        rng: &mut R,
    ) {
        let last = proof.omega.pow(&[(proof.domain.size - 1) as u64]);
        let x_minus_last_omega = DensePolynomial::<BlsScalarField>::from_coefficients_vec(vec![-last, BlsScalarField::one()]);

        let zed = proof.domain.vanishing_polynomial();
        let zed_tau = zed.evaluate(&tau);

        let evals_at_tau_omega = proof.proof_at_tau_omega.1.clone();
        let p0_tau_omega = evals_at_tau_omega[0].into_plain_value().0;
        let evals_at_tau = proof.proof_at_tau.1.clone();
        let p0_tau = evals_at_tau[0].into_plain_value().0;
        let p1_tau = evals_at_tau[1].into_plain_value().0;

        let x_minus_last_omega_tau = x_minus_last_omega.evaluate(&tau);
        let w1_tau = (p0_tau - p0_tau_omega - p1_tau) * x_minus_last_omega_tau;

        let (q, r) = DenseOrSparsePolynomial::from(zed).divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_last_omega)).unwrap();
        assert!(r.is_zero());
        let q_tau = q.evaluate(&tau);
        let w2_tau = (p0_tau - p1_tau) * q_tau;

        let pm_tau = evals_at_tau[evals_at_tau.len() - 2].into_plain_value().0;
        let w3_tau = pm_tau * (pm_tau - BlsScalarField::one());

        let mut factor = gamma * gamma;
        let mut lhs = w1_tau + gamma * w2_tau + factor * w3_tau;

        for i in 1..evals_at_tau.len() - 2 {
            let pi_tau = evals_at_tau[i].into_plain_value().0;
            let next_p_tau = evals_at_tau[i + 1].into_plain_value().0;
            let double_next_p_tau = next_p_tau + next_p_tau;
            let zero_term = pi_tau - double_next_p_tau;
            let v_tau = zero_term * (BlsScalarField::one() - zero_term);
            factor *= gamma;
            lhs += factor * v_tau;
        }

        let q_tau = evals_at_tau.last().unwrap().into_plain_value().0;
        let rhs = q_tau * zed_tau;

        assert_eq!(lhs, rhs);

        let cm_p0 = proof.cms.first().unwrap().clone();
        batch_check(
            &vk, 
            &BatchCheckProof {
                commitments: vec![proof.cms, vec![cm_p0]],
                witnesses: vec![proof.proof_at_tau.0, proof.proof_at_tau_omega.0],
                points: vec![tau, tau * proof.omega],
                open_evals: vec![proof.proof_at_tau.1, proof.proof_at_tau_omega.1],
                gammas: vec![proof.proof_at_tau.2, proof.proof_at_tau_omega.2],
            }, 
            rng);
    }

    pub fn validate_liability_proof<R: RngCore>(
        vk: &VerifierKey<Bls12_381>,
        proof: LiabilityProof,
        sum_comm_p0: Commitment<Bls12_381>,
        taus: &Vec<BlsScalarField>,
        gamma: BlsScalarField,
        rng: &mut R,
    ) {
        let now = Instant::now();
        println!("Start verifying the liablity proof");

        batch_check(&vk, &BatchCheckProof {
            commitments: vec![vec![sum_comm_p0]],
            witnesses: vec![proof.witness_sigma_p0],
            points: vec![BlsScalarField::one()],
            open_evals: vec![vec![proof.sigma_p0_eval]],
            gammas: vec![BlsScalarField::zero()],
        }, rng);

        let elapsed = now.elapsed();
        println!("The committed liability checking passed: {:.2?}", elapsed);

        let now = Instant::now();
        println!("Start verifying the intermediate proofs");
        thread::scope(| s | {
            let mut i = 1usize;
            for (inter_proof, tau) in proof.intermediate_proofs.into_iter().zip(taus) {            
                s.spawn(move | _ | {
                    let rng = &mut test_rng();
                    Self::validate_intermediate_proof(vk, inter_proof, *tau, gamma, rng);
                    println!("The intermediate proof {} checking passed", i);
                });
                i += 1;
            }
        })
        .unwrap();
        let elapsed = now.elapsed();
        println!("The intermediate proofs are verified: {:.2?}", elapsed);
    }
}
