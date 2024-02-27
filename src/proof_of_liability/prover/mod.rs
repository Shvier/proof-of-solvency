use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain, Polynomial};
use ark_bls12_381::Fr as F;
use ark_ff::{FftField, Field};

use super::{error::Error, utils::{build_bit_vector, compute_accumulative_vector, interpolate_poly, substitute_x}};

mod intermediate;

type D = Radix2EvaluationDomain::<F>;

pub struct Prover {
    polys: Vec<DensePolynomial<F>>,
    domain: D,
}

impl Prover {
    
}
