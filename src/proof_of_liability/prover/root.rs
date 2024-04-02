use std::borrow::Borrow;

use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, Fp, FpConfig};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use ark_std::{Zero, One};

use crate::proof_of_liability::{error::Error, utils::{compute_accumulative_vector, substitute_x}};

use super::intermediate::Intermediate;

pub struct Root<E: Pairing> {
    pub r0: DensePolynomial<E::ScalarField>,
    pub r1: DensePolynomial<E::ScalarField>,
    pub p0s: Vec<DensePolynomial<E::ScalarField>>,
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
}

impl<E: Pairing> Root<E> {
    pub fn new(
        intermediates: Vec<Intermediate<E>>,
    ) -> Result<Self, Error> {
        let p0s: Vec<DensePolynomial<E::ScalarField>> = intermediates
        .iter()
        .enumerate()
        .map(|(_, intern)| {
            let p0 = &intern.polys[0];
            p0.clone()
        })
        .collect();
        let group_liabs: Vec<E::ScalarField> = p0s
        .iter()
        .enumerate()
        .map(|(_, p0)| {
            let liab = p0.evaluate(&E::ScalarField::one());
            return liab;
        })
        .collect();
        let domain_size = intermediates.len();
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size).expect("Unsupported domain size");
        let r0_evals = Self::compute_accumulator(&group_liabs);
        let r0 = Evaluations::from_vec_and_domain(r0_evals, domain).interpolate();
        let r1 = Evaluations::from_vec_and_domain(group_liabs, domain).interpolate();
        Ok(Self {
            r0,
            r1,
            p0s,
            domain,
        })
    }

    pub(super) fn compute_w1(&self) -> DensePolynomial<E::ScalarField> {
        let r0_plus_1 = substitute_x::<E::ScalarField, Radix2EvaluationDomain<E::ScalarField>>(&self.r0, 1, 1);
        let domain_size = self.domain.size;
        let omega = E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        let x_minus_last_omega = DensePolynomial::<E::ScalarField>::from_coefficients_vec([-omega.pow(&[domain_size - 1]), E::ScalarField::one()].to_vec());
        let mut w1 = &self.r0 - &r0_plus_1;
        w1 = &w1 - &self.r1;
        w1 = &w1 * &x_minus_last_omega;
        w1
    }

    pub(super) fn compute_w2(&self) -> DensePolynomial<E::ScalarField> {
        let mut w2 = &self.r0 - &self.r1;
        let domain_size = self.domain.size;
        let omega = E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        for idx in 0..domain_size - 1 {
            let point = omega.pow(&[idx]);
            let linear_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([-point, E::ScalarField::one()].to_vec());
            w2 = &w2 * &linear_term;
        }
        w2
    }

    pub(super) fn compute_vs(&self) -> Vec<DensePolynomial<E::ScalarField>> {
        let mut v = Vec::<DensePolynomial<E::ScalarField>>::new();
        let domain_size = self.domain.size;
        let omega = E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        for i in 0..self.p0s.len() {
            let p0 = &self.p0s[i];
            let r1_shifted = substitute_x::<E::ScalarField, Radix2EvaluationDomain<E::ScalarField>>(&self.r1, 1, i);
            let mut tmp = &r1_shifted - p0;
            for idx in 1..domain_size {
                let point = omega.pow(&[idx]);
                let linear_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([-point, E::ScalarField::one()].to_vec());
                tmp = &tmp * &linear_term;
            }
            v.push(tmp);
        }
        v
    }

    fn compute_accumulator(
        vec: &[E::ScalarField]
    ) -> Vec<E::ScalarField> {
        let len = vec.len();
        let mut acc = Vec::<E::ScalarField>::with_capacity(len);
        for _ in 0..len { acc.push(E::ScalarField::zero()); }
        acc[len - 1] = vec[len - 1];
        for i in (0..len - 1).rev() {
            acc[i] = acc[i + 1] + vec[i];
        }
        acc
    }
}
