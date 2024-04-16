use ark_ec::pairing::Pairing;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use ark_ff::{FftField, Field};
use ark_std::One;

use crate::{proof_of_liability::error::Error, utils::{build_bit_vector, compute_accumulative_vector, substitute_x, interpolate_poly}};

pub struct Intermediate<E: Pairing> {
    pub polys: Vec<DensePolynomial<E::ScalarField>>,
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
}

impl<E: Pairing> Intermediate<E> {
    pub fn new(
        balances: &Vec<u64>,
        max_bits: usize,
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
        Ok(Self {
            polys,
            domain,
        })
    }

    pub(super) fn compute_w1(&self) -> DensePolynomial<E::ScalarField> {
        let p0 = &self.polys[0];
        let p0_plus_1 = substitute_x::<E::ScalarField, Radix2EvaluationDomain<E::ScalarField>>(&p0, 1, 1);
        let p1 = &self.polys[1];
        let domain_size = self.domain.size;
        let omega = E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        let x_minus_last_omega = DensePolynomial::<E::ScalarField>::from_coefficients_vec([-omega.pow(&[domain_size - 1]), E::ScalarField::one()].to_vec());
        let mut w1 = p0 - &p0_plus_1;
        w1 = &w1 - p1;
        w1 = &w1 * &x_minus_last_omega;
        w1
    }

    pub(super) fn compute_w2(&self) -> DensePolynomial<E::ScalarField> {
        let p0 = &self.polys[0];
        let p1 = &self.polys[1];
        let mut w2 = p0 - p1;
        let domain_size = self.domain.size;
        let omega = E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        for idx in 0..domain_size - 1 {
            let point = omega.pow(&[idx]);
            let linear_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([-point, E::ScalarField::one()].to_vec());
            w2 = &w2 * &linear_term;
        }
        w2
    }

    pub(super) fn compute_w3(&self) -> DensePolynomial<E::ScalarField> {
        let len = self.polys.len();
        let pm = &self.polys[len - 1];
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([E::ScalarField::one()].to_vec());
        let mut w3 = pm - &constant_term;
        w3 = &w3 * pm;
        w3
    }

    pub(super) fn compute_v(&self, idx: usize) -> DensePolynomial<E::ScalarField> {
        assert!(idx > 0 && idx < self.polys.len() - 1);
        let cur = &self.polys[idx];
        let next = &self.polys[idx + 1];
        let next_double = next + next;
        let zero_term = cur - &next_double;
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([E::ScalarField::one()].to_vec());
        let one_term = &constant_term - &zero_term;
        let v = &zero_term * &one_term;
        v
    }
}
