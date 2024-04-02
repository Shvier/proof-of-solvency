use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, Fp, FpConfig, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial};
use ark_poly_commit::{marlin_pc, LabeledCommitment, PolynomialCommitment};
use ark_std::{rand::Rng, test_rng};
use ark_relations::r1cs::{
    ConstraintSystem,
    ConstraintSynthesizer,
    Result,
};
use ark_std::{convert::TryInto, ops::AddAssign, ops::Mul};

use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}};

use super::constraints::PolyTransConstraints;
use super::error::Error;

pub fn build_up_bits(value: u64, max_bits: usize) -> Vec<u64> {
    assert!(value <= 2_u64.pow(u32::try_from(max_bits).unwrap()));
    let mut bits: Vec<u64> = Vec::with_capacity(max_bits);
    for _ in 0..max_bits {
        bits.push(0);
    }
    let mut v = value;
    bits[max_bits - 1] = value;
    let mut i = bits.len() - 2;
    loop {
        bits[i] = v / 2;
        v = bits[i];
        if i == 0 {
            break;
        }
        i -= 1;
    }
    bits
}

pub fn build_bit_vector(
    liabilities: &Vec<u64>,
    max_bits: usize,
) -> Vec<Vec<u64>> {
    let num_of_l = liabilities.len();
    let mut vec = Vec::<Vec<u64>>::with_capacity(max_bits);
    for _ in 0..max_bits {
        let mut v = Vec::<u64>::with_capacity(num_of_l);
        for _ in 0..num_of_l {
            v.push(0);
        }
        vec.push(v);
    }
    for i in 0..num_of_l {
        let liab = liabilities[i];
        let bits = build_up_bits(liab, max_bits);
        for j in 0..max_bits {
            vec[j][i] = bits[max_bits - j - 1];
        }
    }
    vec
}

pub fn compute_accumulative_vector(
    vec: &[u64]
) -> Vec<u64> {
    let len = vec.len();
    let mut acc = Vec::<u64>::with_capacity(len);
    for _ in 0..len { acc.push(0); }
    acc[len - 1] = vec[len - 1];
    for i in (0..len - 1).rev() {
        acc[i] = acc[i + 1] + vec[i];
    }
    acc
}

pub fn interpolate_poly<
F: FftField,
D: EvaluationDomain<F>,
>(
    vectors: &Vec<u64>, 
    domain: D
) -> DensePolynomial<F> {
    let ff_vectors = vectors.into_iter().map(|v| {F::from(*v)}).collect();
    let evaluations = Evaluations::from_vec_and_domain(ff_vectors, domain);
    evaluations.interpolate()
}

pub fn substitute_x<
F: PrimeField,
D: EvaluationDomain<F>,
>(
    p: &DensePolynomial<F>, 
    scale: usize, 
    shift: usize,
) -> DensePolynomial<F> {
    let deg = p.coeffs.len();
    let domain = D::new(deg).unwrap();
    let mut new_evals = Vec::<F>::new();
    let root = F::get_root_of_unity(deg as u64).unwrap();
    let mut pos = shift;
    for _ in 0..deg {
        let point: F = root.pow(&[pos as u64]);
        let eval = p.evaluate(&point);
        new_evals.push(eval);
        pos = pos + scale;
    }
    let new_eval = Evaluations::<F, D>::from_vec_and_domain(new_evals, domain);
    let new_p = new_eval.interpolate();
    let result = constrain_polys(&p.coeffs, &new_p.coeffs, scale, shift);
    result.expect("Failed to satisfy transform constraints");
    new_p
}

pub fn constrain_polys<
F: PrimeField,
>(
    old_coeffs: &Vec<F>, 
    new_coeffs: &Vec<F>, 
    scale_factor: usize, 
    shift_factor: usize,
) -> Result<()> {
    let root_of_unity = F::get_root_of_unity(old_coeffs.len() as u64).expect("Cannot find root of unity");
    let mut rng = test_rng();
    let point = rng.gen_range(0..new_coeffs.len());
    let circuit = PolyTransConstraints::<F> {
        point,
        root_of_unity,
        scale_factor,
        shift_factor,
        old_coeffs: old_coeffs.to_vec(),
        new_coeffs: new_coeffs.to_vec(),
    };
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs)
}

pub fn linear_combine_polys<
E: Pairing,
>(
    polys: &Vec<DensePolynomial<E::ScalarField>>,
    gamma: E::ScalarField,
) -> DensePolynomial<E::ScalarField> {
    let mut w = DensePolynomial::<E::ScalarField>::zero();
    for idx in 0..polys.len() {
        let p = &polys[idx];
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec([E::ScalarField::from(gamma.pow(&[idx as u64]))].to_vec());
        let tmp = &constant_term * p;
        w += &tmp;
    }
    w
}

pub fn combine_commitments_and_values<
'a,
E: Pairing,
>(
    commitments: impl IntoIterator<Item = &'a LabeledCommitment<marlin_pc::Commitment<E>>>,
    values: impl IntoIterator<Item = E::ScalarField>,
    challenge: E::ScalarField,
) -> (E::G1, E::ScalarField) {
    let mut combined_comm = E::G1::zero();
    let mut combined_value = E::ScalarField::zero();
    for (labeled_commitment, value) in commitments.into_iter().zip(values) {
        let commitment = labeled_commitment.commitment();
        combined_comm += &commitment.comm.0.mul(challenge);
        combined_value += &(value * &challenge);
    }
    (combined_comm, combined_value)
}

pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

#[cfg(test)]
fn compare_vecs(va: &[u64], vb: &[u64]) -> bool {
    (va.len() == vb.len()) &&
     va.iter()
       .zip(vb)
       .all(|(a,b)| *a == *b)
}

#[test]
fn test_build_up_bits() {
    let bits_8 = [0, 0, 1, 2, 5, 10, 20];
    let bits = build_up_bits(20, 7);
    assert!(compare_vecs(&bits_8, &bits));

    let bits_16 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 6, 12, 25, 50];
    let bits = build_up_bits(50, 15);
    assert!(compare_vecs(&bits_16, &bits));
}

#[test]
fn test_build_bit_vector() {
    let liab: Vec<u64> = [20, 50, 30, 40, 10, 60, 80, 70].to_vec();
    let vec = build_bit_vector(&liab, 16);
    println!("{:?}", vec);
}

#[test]
fn test_compute_accumulative_vector() {
    let liab: Vec<u64> = [20, 50, 30, 40, 10, 60, 80, 70].to_vec();
    let vec = compute_accumulative_vector(&liab);
    println!("{:?}", vec);
}
