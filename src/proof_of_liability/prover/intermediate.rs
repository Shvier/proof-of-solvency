use ark_ec::pairing::Pairing;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_ff::{FftField, Field, Fp, FpConfig, Zero};
use ark_poly_commit::{kzg10::KZG10, LabeledCommitment};
use ark_std::One;

use crate::proof_of_liability::{error::Error, utils::{build_bit_vector, calculate_hash, compute_accumulative_vector, interpolate_poly, linear_combine_polys, substitute_x}};

#[derive(Clone)]
pub struct Intermediate<E: Pairing> {
    pub polys: Vec<DensePolynomial<E::ScalarField>>,
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
}

impl<E: Pairing> Intermediate<E> {
    pub fn new(
        liabilities: &Vec<u64>,
        max_bits: usize,
    ) -> Result<Self, Error> {
        let bit_vec = build_bit_vector(liabilities, max_bits);
        let accumulator = compute_accumulative_vector(&liabilities);

        let domain_size = liabilities.len();
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size).expect("Unsupported domain length");

        let mut polys = Vec::<DensePolynomial<E::ScalarField>>::new();
        let p0 = interpolate_poly(&accumulator, domain);
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

    pub(super) fn compute_w(&self, gamma: E::ScalarField) -> DensePolynomial<E::ScalarField> {
        let w1 = self.compute_w1();
        let w2 = self.compute_w2();
        let w3 = self.compute_w3();
        let mut polys = Vec::<DensePolynomial<E::ScalarField>>::from([w1, w2, w3]);
        for idx in 1..self.polys.len() - 1 {
            let v = self.compute_v(idx);
            polys.push(v);
        }
        linear_combine_polys::<E>(&polys, gamma)
    }
}
