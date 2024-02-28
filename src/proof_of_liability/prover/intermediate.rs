use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_ff::{FftField, Field, Fp, FpConfig};

use crate::proof_of_liability::{error::Error, utils::{build_bit_vector, compute_accumulative_vector, interpolate_poly, substitute_x}};

#[derive(Clone)]
pub struct Intermediate<P: FpConfig<N>, const N: usize> {
    pub polys: Vec<DensePolynomial<Fp<P, N>>>,
    pub domain: Radix2EvaluationDomain<Fp<P, N>>,
}

impl<P: FpConfig<N>, const N: usize> Intermediate<P, N> {
    pub fn new(
        liabilities: &Vec<u64>,
        max_bits: usize,
    ) -> Result<Self, Error> {
        let bit_vec = build_bit_vector(liabilities, max_bits);
        let accumulator = compute_accumulative_vector(&liabilities);

        let domain_size = liabilities.len();
        let domain = Radix2EvaluationDomain::<Fp<P, N>>::new(domain_size).expect("Unsupported domain length");
        let mut polys = Vec::<DensePolynomial<Fp<P, N>>>::new();
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

    pub(super) fn compute_w1(&self) -> DensePolynomial<Fp<P, N>> {
        let p0 = &self.polys[0];
        let p0_plus_1 = substitute_x::<Fp<P, N>, Radix2EvaluationDomain<Fp<P, N>>>(&p0, 1, 1);
        let p1 = &self.polys[1];
        let domain_size = self.domain.size;
        let omega = Fp::<P, N>::get_root_of_unity(domain_size).expect("Unsupported domain size");
        let x_minus_last_omega = DensePolynomial::<Fp<P, N>>::from_coefficients_vec([-omega.pow(&[domain_size - 1]), Fp::<P, N>::from(1)].to_vec());
        let mut w1 = p0 - &p0_plus_1;
        w1 = &w1 - p1;
        w1 = &w1 * &x_minus_last_omega;
        w1
    }

    pub(super) fn compute_w2(&self) -> DensePolynomial<Fp<P, N>> {
        let p0 = &self.polys[0];
        let p1 = &self.polys[1];
        let mut w2 = p0 - p1;
        let domain_size = self.domain.size;
        let omega = Fp::<P, N>::get_root_of_unity(domain_size).expect("Unsupported domain size");
        for idx in 0..domain_size - 1 {
            let point = omega.pow(&[idx]);
            let linear_term = DensePolynomial::<Fp<P, N>>::from_coefficients_vec([-point, Fp::<P, N>::from(1)].to_vec());
            w2 = &w2 * &linear_term;
        }
        w2
    }

    pub(super) fn compute_w3(&self) -> DensePolynomial<Fp<P, N>> {
        let len = self.polys.len();
        let mut w3 = DensePolynomial::<Fp<P, N>>::from_coefficients_vec(vec![]);
        for idx in 1..len - 1 {
            let cur = &self.polys[idx];
            let next = &self.polys[idx + 1];
            let next_double = next + next;
            let zero_term = cur - &next_double;
            let constant_term = DensePolynomial::<Fp<P, N>>::from_coefficients_vec([Fp::<P, N>::from(1)].to_vec());
            let one_term = &constant_term - &zero_term;
            let tmp = &zero_term * &one_term;
            w3 = &w3 + &tmp;
        }
        w3
    }

    pub(super) fn compute_w4(&self) -> DensePolynomial<Fp<P, N>> {
        let len = self.polys.len();
        let pm = &self.polys[len - 1];
        let constant_term = DensePolynomial::<Fp<P, N>>::from_coefficients_vec([Fp::<P, N>::from(1)].to_vec());
        let mut w4 = pm - &constant_term;
        w4 = &w4 * pm;
        w4
    }
}
