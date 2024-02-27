use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain, Polynomial};
use ark_bls12_381::Fr as F;
use ark_ff::{FftField, Field};

use super::{error::Error, utils::{build_bit_vector, compute_accumulative_vector, interpolate_poly, substitute_x}};

#[cfg(test)]
mod test_intermediate;

mod intermediate;
mod root;

pub struct Prover {

}

impl Prover {
    
}
