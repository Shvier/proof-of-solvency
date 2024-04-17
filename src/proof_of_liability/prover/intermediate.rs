use ark_ec::pairing::Pairing;
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use ark_ff::{FftField, Field};
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, KZG10};
use ark_std::{rand::RngCore, One, Zero};

use crate::{proof_of_liability::error::Error, utils::{batch_open, build_bit_vector, compute_accumulative_vector, interpolate_poly, linear_combine_polys, substitute_x, OpenEval}};

#[derive(Clone)]
pub struct IntermediateProof<E: Pairing, P: DenseUVPolynomial<E::ScalarField>> {
    pub proof_at_tau: (E::G1, Vec<OpenEval<E>>, E::ScalarField),
    pub proof_at_tau_omega: (E::G1, Vec<OpenEval<E>>, E::ScalarField),
    pub cms: Vec<Commitment<E>>,
    pub omega: E::ScalarField,
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
    randoms: Vec<Randomness<E::ScalarField, P>>,
}

pub struct Intermediate<E: Pairing> {
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
    pub(super) polys: Vec<DensePolynomial<E::ScalarField>>,
    q_w: DensePolynomial<E::ScalarField>,
}

impl<E: Pairing> Intermediate<E> {
    pub fn new(
        balances: &Vec<u64>,
        max_bits: usize,
        gamma: E::ScalarField,
    ) -> Result<Self, Error> {
        let bit_vec = build_bit_vector(balances, max_bits);
        let accumulator = compute_accumulative_vector::<E::ScalarField>(&balances);

        let domain_size = balances.len().checked_next_power_of_two().unwrap();
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size).expect("Unsupported domain length");

        let mut polys = Vec::<DensePolynomial<E::ScalarField>>::new();

        let evaluations = Evaluations::from_vec_and_domain(accumulator, domain);
        let p0 = evaluations.interpolate();
        polys.push(p0);
        for vec in bit_vec {
            let p = interpolate_poly(&vec, domain);
            polys.push(p);
        }

        let w1 = Self::compute_w1(&polys, domain);
        let w2 = Self::compute_w2(&polys, domain);
        let w3 = Self::compute_w3(&polys);
        let mut combined_polys = Vec::<DensePolynomial<E::ScalarField>>::from([w1, w2, w3]);
        for idx in 1..polys.len() - 1 {
            let v = Self::compute_v(&polys, idx);
            combined_polys.push(v);
        }
        let w = linear_combine_polys::<E>(&combined_polys, gamma);
        let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());
        let (q_w, r) = DenseOrSparsePolynomial::from(w).divide_with_q_and_r(&zed).unwrap();
        assert!(r.is_zero());

        Ok(Self {
            domain,
            polys,
            q_w,
        })
    }

    pub(super) fn compute_w1(polys: &Vec<DensePolynomial<E::ScalarField>>, domain: Radix2EvaluationDomain<E::ScalarField>) -> DensePolynomial<E::ScalarField> {
        let p0 = &polys[0];
        let p0_plus_1 = substitute_x::<E::ScalarField, Radix2EvaluationDomain<E::ScalarField>>(&p0, 1, 1);
        let p1 = &polys[1];
        let domain_size = domain.size;
        let omega = E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        let x_minus_last_omega = DensePolynomial::<E::ScalarField>::from_coefficients_vec([-omega.pow(&[domain_size - 1]), E::ScalarField::one()].to_vec());
        let mut w1 = p0 - &p0_plus_1;
        w1 = &w1 - p1;
        w1 = &w1 * &x_minus_last_omega;
        w1
    }

    pub(super) fn compute_w2(polys: &Vec<DensePolynomial<E::ScalarField>>, domain: Radix2EvaluationDomain<E::ScalarField>) -> DensePolynomial<E::ScalarField> {
        let p0 = &polys[0];
        let p1 = &polys[1];
        let mut w2 = p0 - p1;
        let domain_size = domain.size;
        let omega = E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        for idx in 0..domain_size - 1 {
            let point = omega.pow(&[idx]);
            let linear_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([-point, E::ScalarField::one()].to_vec());
            w2 = &w2 * &linear_term;
        }
        w2
    }

    pub(super) fn compute_w3(polys: &Vec<DensePolynomial<E::ScalarField>>) -> DensePolynomial<E::ScalarField> {
        let len = polys.len();
        let pm = &polys[len - 1];
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([E::ScalarField::one()].to_vec());
        let mut w3 = pm - &constant_term;
        w3 = &w3 * pm;
        w3
    }

    pub(super) fn compute_v(polys: &Vec<DensePolynomial<E::ScalarField>>, idx: usize) -> DensePolynomial<E::ScalarField> {
        assert!(idx > 0 && idx < polys.len() - 1);
        let cur = &polys[idx];
        let next = &polys[idx + 1];
        let next_double = next + next;
        let zero_term = cur - &next_double;
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([E::ScalarField::one()].to_vec());
        let one_term = &constant_term - &zero_term;
        let v = &zero_term * &one_term;
        v
    }

    fn commit<R: RngCore>(
        &self,
        powers: &Powers<E>,
        poly: &DensePolynomial<E::ScalarField>,
        rng: &mut R,
    ) -> (Commitment<E>, Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>) {
        KZG10::<E, DensePolynomial<E::ScalarField>>::commit(&powers, &poly, Some(poly.degree()), Some(rng)).unwrap()
    }

    pub fn compute_commitments<R: RngCore>(&self, powers: &Powers<E>, rng: &mut R) 
        -> (Vec<Commitment<E>>, Vec<Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>) {
        let mut cms = Vec::<Commitment<E>>::new();
        let mut randoms = Vec::<Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>::new();
        for p in &self.polys {
            let (cm_p, random_p) = self.commit(&powers, &p, rng);
            cms.push(cm_p);
            randoms.push(random_p);
        }

        let (cm_q, random_q) = self.commit(&powers, &self.q_w, rng);
        cms.push(cm_q);
        randoms.push(random_q);
        (cms, randoms)
    }

    pub fn generate_proof<R: RngCore>(
        &self,
        powers: &Powers<E>,
        cms: &Vec<Commitment<E>>,
        randoms: &Vec<Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>,
        tau: E::ScalarField,
        rng: &mut R,
    ) -> IntermediateProof<E, DensePolynomial<E::ScalarField>> {
        let omega = self.domain.element(1);
        let (h_1, open_evals_1, gamma_1) = batch_open(&powers, &vec![self.polys.as_slice(), vec![self.q_w.clone()].as_slice()].concat(), &randoms, tau, false, rng);
        let (h_2, open_evals_2, gamma_2) = batch_open(&powers, &vec![self.polys.first().unwrap().clone()], &vec![randoms.first().unwrap().clone()], tau * omega, false, rng);

        IntermediateProof { 
            proof_at_tau: (h_1, open_evals_1, gamma_1), 
            proof_at_tau_omega: (h_2, open_evals_2, gamma_2), 
            cms: cms.to_vec(), 
            omega: omega,
            domain: self.domain,
            randoms: randoms.to_vec(), 
        }
    }
}
