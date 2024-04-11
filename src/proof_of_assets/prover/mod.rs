use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, FftField, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, UniversalParams, VerifierKey, KZG10};
use ark_std::{rand::RngCore, test_rng, Zero, One};
use ark_test_curves::secp256k1;
use num_bigint::BigUint;

use std::{borrow::Borrow, ops::Mul};

use crate::{proof_of_liability::utils::linear_combine_polys, utils::{batch_open, calculate_hash, convert_to_bigints, skip_leading_zeros_and_convert_to_bigints, BatchCheckProof, HashBox, OpenEval}};

use super::sigma::{SigmaProtocol, SigmaProtocolProof};

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;
type UniPoly_381 = DensePolynomial<BlsScalarField>;

#[cfg(test)]
mod test_prover;

pub struct PolyCommitProof {
    pub witness: <Bls12_381 as Pairing>::G1Affine,
    pub rand: BlsScalarField,
    pub committed_eval: <Bls12_381 as Pairing>::G1Affine,
}

pub struct AssetsProof {
    batch_check_proof: BatchCheckProof<Bls12_381>,
    committed_assets: <Bls12_381 as Pairing>::G1Affine,
}

pub struct Prover {
    pub sigma: SigmaProtocol,
    pub omega: BlsScalarField,
    pub vk: VerifierKey<Bls12_381>,
    pub pp: UniversalParams<Bls12_381>,
    pub domain_size: usize,
    poly: DensePolynomial<<Bls12_381 as Pairing>::ScalarField>,
    selector: Vec<bool>,
    max_degree: usize,
}

impl Prover {
    pub fn setup(selector: &Vec<bool>) -> Self {
        let max_degree: usize = 256;
        let domain_size = selector.len().checked_next_power_of_two().expect("Unsupported domain size");
        let omega = BlsScalarField::get_root_of_unity(domain_size.try_into().unwrap()).unwrap();
        let domain = Radix2EvaluationDomain::<BlsScalarField>::new(domain_size).unwrap();
        let evals = selector.into_iter().map(| s | Fr::from(*s)).collect();
        let evaluations = Evaluations::from_vec_and_domain(evals, domain);
        let poly = evaluations.interpolate();
        let rng = &mut test_rng();
        let pp = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).unwrap();
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[&0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };
        let sigma = SigmaProtocol::setup(secp256k1::G1Affine::generator(), vk.g, vk.gamma_g);
        Self {
            sigma,
            omega,
            vk,
            pp,
            domain_size,
            poly,
            selector: selector.to_vec(),
            max_degree,
        }
    }

    pub fn commit_to_selector(&self) -> (Commitment<Bls12_381>, Randomness<BlsScalarField, UniPoly_381>) {
        let max_degree = self.domain_size;
        let powers_of_g = self.pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| self.pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        let rng = &mut test_rng();
        KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &self.poly, Some(self.poly.degree()), Some(rng)).unwrap()
    }

    pub fn commit<R: RngCore>(&self, poly: &DensePolynomial<BlsScalarField>, rng: &mut R) -> (Commitment<Bls12_381>, Randomness<BlsScalarField, UniPoly_381>) {
        let max_degree = self.max_degree;
        let powers_of_g = self.pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| self.pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &poly, Some(poly.degree()), Some(rng)).unwrap()
    }

    pub fn open(&self, point: BlsScalarField, randomness: &Randomness<BlsScalarField, UniPoly_381>) -> PolyCommitProof {
        let max_degree = self.max_degree;
        let powers_of_g = self.pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| self.pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        let (witness_polynomial, random) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(&self.poly, point, randomness).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);

        let mut w = <Bls12_381 as Pairing>::G1::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );

        let blinding_p = &randomness.blinding_polynomial;
        let blinding_evaluation = blinding_p.evaluate(&point);

        let random_witness_coeffs = convert_to_bigints(&random.unwrap().coeffs());
        w += &<<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_gamma_g,
            &random_witness_coeffs,
        );

        let eval = self.poly.evaluate(&point);
        let committed_eval = self.sigma.gb.mul(eval) + self.sigma.hb.mul(blinding_evaluation);

        PolyCommitProof {
            witness: w.into_affine(),
            rand: blinding_evaluation,
            committed_eval: committed_eval.into_affine(),
        }
    }

    pub fn generate_proof(&self, pks: &Vec<secp256k1::G1Affine>, sks: &Vec<BigUint>) -> Vec<(Commitment<Bls12_381>, PolyCommitProof, SigmaProtocolProof)> {
        let (cm, randomness) = self.commit_to_selector();
        let omega = &self.omega;
        let selector = &self.selector;
        let mut proofs = Vec::<(Commitment<Bls12_381>, PolyCommitProof, SigmaProtocolProof)>::new();
        for i in 0..selector.len() {
            let s = selector[i];
            let pk = pks[i];
            let sk = &sks[i];
            let point = omega.pow(&[i as u64]);
            let pc_proof = self.open(point, &randomness);
            let sigma_proof = self.sigma.generate_proof(pk, pc_proof.rand.into_bigint().into(), s, sk.clone());
            proofs.push((cm, pc_proof, sigma_proof))
        }
        proofs
    }

    pub fn construct_accumulator(&self, bal_poly: &DensePolynomial<BlsScalarField>, domain: Radix2EvaluationDomain<BlsScalarField>) -> UniPoly_381 {
        let bal_poly_degree = &bal_poly.degree();
        let degree = self.poly.degree();
        assert_eq!(*bal_poly_degree, degree);
        let balances = bal_poly.clone().evaluate_over_domain(domain).evals;
        let mut accum_evals = vec![BlsScalarField::zero(); self.selector.len()];
        let upper_bound = self.selector.len() - 1;
        accum_evals[upper_bound] = match self.selector[upper_bound] {
            true => balances[upper_bound],
            false => BlsScalarField::zero(),
        };
        for i in (0..upper_bound).rev() {
            let s = self.selector[i];
            let bal = balances[i];
            match s {
                true => {
                    accum_evals[i] = accum_evals[i + 1] + bal
                }
                false => {
                    accum_evals[i] = accum_evals[i + 1]
                }
            }
        }

        Evaluations::from_vec_and_domain(accum_evals, domain).interpolate()
    }

    pub fn compute_w1_w2(&self, accum_poly: &UniPoly_381, bal_poly: &UniPoly_381, domain: Radix2EvaluationDomain<BlsScalarField>) -> (UniPoly_381, UniPoly_381) {
        let mut accum_evals = accum_poly.clone().evaluate_over_domain(domain).evals;
        accum_evals.rotate_left(1);
        let accum_plus_one = Evaluations::from_vec_and_domain(accum_evals, domain).interpolate();
        let selector_times_bal = &self.poly * bal_poly;

        let mut w_1 = accum_poly - &accum_plus_one;
        w_1 -= &selector_times_bal;
        let last = self.omega.pow(&[(self.domain_size - 1) as u64]);
        let x_minus_last_omega = DensePolynomial::<BlsScalarField>::from_coefficients_vec(vec![-last, BlsScalarField::one()]);
        w_1 = &w_1 * &x_minus_last_omega;

        let mut w_2 = accum_poly - &selector_times_bal;
        let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());
        let (quotient, remainder) = zed.divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_last_omega)).unwrap();
        assert!(remainder.is_zero());
        w_2 = &w_2 * &quotient;

        (w_1, w_2)
    }
}
