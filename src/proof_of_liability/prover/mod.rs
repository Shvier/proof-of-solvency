use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain, Polynomial};
use ark_bls12_381::Fr as F;
use ark_ff::{FftField, Field};

use super::{error::Error, utils::{build_bit_vector, compute_accumulative_vector, interpolate_poly, substitute_x}};

type D = Radix2EvaluationDomain::<F>;

pub struct Prover {
    polys: Vec<DensePolynomial<F>>,
    domain: D,
}

impl Prover {
    pub fn setup(
        liabilities: &Vec<u64>,
        max_bits: usize,
    ) -> Result<Self, Error> {
        let bit_vec = build_bit_vector(liabilities, max_bits);
        let accumulator = compute_accumulative_vector(&liabilities);

        let domain_size = liabilities.len();
        let domain = D::new(domain_size).expect("Unsupported domain length");
        let mut polys = Vec::<DensePolynomial<F>>::new();
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

    fn compute_w1(&self) -> DensePolynomial<F> {
        let p0 = &self.polys[0];
        let p0_plus_1 = substitute_x::<F, D>(&p0, 1, 1);
        let p1 = &self.polys[1];
        let domain_size = self.domain.size;
        let omega = F::get_root_of_unity(domain_size).expect("Unsupported domain size");
        let x_minus_last_omega = DensePolynomial::<F>::from_coefficients_vec([-omega.pow(&[domain_size - 1]), F::from(1)].to_vec());
        let mut w1 = p0 - &p0_plus_1;
        w1 = &w1 - p1;
        w1 = &w1 * &x_minus_last_omega;
        w1
    }

    fn compute_w2(&self) -> DensePolynomial<F> {
        let p0 = &self.polys[0];
        let p1 = &self.polys[1];
        let mut w2 = p0 - p1;
        let domain_size = self.domain.size;
        let omega = F::get_root_of_unity(domain_size).expect("Unsupported domain size");
        for idx in 0..domain_size - 1 {
            let point = omega.pow(&[idx]);
            let linear_term = DensePolynomial::<F>::from_coefficients_vec([-point, F::from(1)].to_vec());
            w2 = &w2 * &linear_term;
        }
        w2
    }

    fn compute_w3(&self) -> DensePolynomial<F> {
        let len = self.polys.len();
        let mut w3 = DensePolynomial::<F>::from_coefficients_vec([].to_vec());
        for idx in 1..len - 1 {
            let cur = &self.polys[idx];
            let next = &self.polys[idx + 1];
            let next_double = next + next;
            let zero_term = cur - &next_double;
            let constant_term = DensePolynomial::<F>::from_coefficients_vec([F::from(1)].to_vec());
            let one_term = &constant_term - &zero_term;
            let tmp = &zero_term * &one_term;
            w3 = &w3 + &tmp;
        }
        w3
    }

    fn compute_w4(&self) -> DensePolynomial<F> {
        let len = self.polys.len();
        let pm = &self.polys[len - 1];
        let constant_term = DensePolynomial::<F>::from_coefficients_vec([F::from(1)].to_vec());
        let mut w4 = pm - &constant_term;
        w4 = &w4 * pm;
        w4
    }
}

#[cfg(test)]
fn generate_prover() -> Prover {
    const MAX_BITS: usize = 16;

    let liab: Vec<u64> = [20, 50, 30, 40, 10, 60, 80, 70].to_vec();

    Prover::setup(&liab, MAX_BITS).unwrap()
}

#[test]
fn test_compute_w1() {
    use ark_ff::Zero;

    let prover = generate_prover();
    let w1 = prover.compute_w1();
    let omega = F::get_root_of_unity(prover.domain.size).unwrap();
    for idx in 0..prover.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w1.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w2() {
    use ark_ff::Zero;

    let prover = generate_prover();
    let w2 = prover.compute_w2();
    let omega = F::get_root_of_unity(prover.domain.size).unwrap();
    for idx in 0..prover.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w2.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w3() {
    use ark_ff::Zero;

    let prover = generate_prover();
    let w3 = prover.compute_w3();
    let omega = F::get_root_of_unity(prover.domain.size).unwrap();
    for idx in 0..prover.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w3.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w4() {
    use ark_ff::Zero;

    let prover = generate_prover();
    let w4 = prover.compute_w4();
    let omega = F::get_root_of_unity(prover.domain.size).unwrap();
    for idx in 0..prover.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w4.evaluate(&point);
        assert!(eval.is_zero());
    }
}
