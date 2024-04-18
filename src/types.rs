use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;

pub type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;
#[allow(non_camel_case_types)]
pub type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
