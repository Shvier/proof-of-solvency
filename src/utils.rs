use ark_ec::{pairing::Pairing, short_weierstrass::Projective, AffineRepr, VariableBaseMSM, CurveGroup};
use ark_ff::{PrimeField, Field};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, VerifierKey, KZG10};
use ark_std::{rand::RngCore, UniformRand, Zero};
use ark_test_curves::secp256k1;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use std::ops::Mul;

pub enum HashBox {
    Secp(secp256k1::G1Projective),
    Bls(Projective<ark_bls12_381::g1::Config>),
}

pub fn calculate_hash(objects: &Vec<HashBox>) -> BigUint {
    let mut hasher = Sha256::default();
    let mut msg: String = "".to_owned();
    for obj in objects {
        match obj {
            HashBox::Secp(g) => msg.push_str(&format!("{}", g)),
            HashBox::Bls(g) => msg.push_str(&format!("{}", g)),
        }
    }
    hasher.update(msg);
    let digest = hasher.finalize();
    BigUint::from_bytes_le(&digest)
}

pub fn pedersen_commit<G: AffineRepr>(
    g: G,
    h: G,
    s: impl AsRef<[u64]>,
    t: impl AsRef<[u64]>,
)  -> G::Group {
    g.mul_bigint(s) + h.mul_bigint(t)
}

pub enum OpenEval<E: Pairing> {
    Plain(E::ScalarField, E::ScalarField),
    Committed(E::G1Affine),
}

// the batched KZG opening scheme in [GWC19]
pub fn batch_open<E: Pairing, R: RngCore>(
    powers: &Powers<E>,
    polys: &Vec<DensePolynomial<E::ScalarField>>,
    randoms: &Vec<Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>,
    point: E::ScalarField,
    perfect_hiding: bool,
    rng: &mut R,
) -> (E::G1, Vec<OpenEval<E>>, E::ScalarField) {
    assert!(polys.len() == randoms.len());
    let gamma = E::ScalarField::rand(rng);
    let mut h = E::G1::zero();
    let mut plain_evals = Vec::<(E::ScalarField, E::ScalarField)>::new();
    let mut committed_evals = Vec::<E::G1Affine>::new();
    let mut i = 0u64;
    for (p, random) in polys.into_iter().zip(randoms) {
        let eval = p.evaluate(&point);
        let blinding_eval = random.blinding_polynomial.evaluate(&point);

        let (witness, random_witness) =
            KZG10::<E, DensePolynomial<E::ScalarField>>::compute_witness_polynomial(&p, point, &random).unwrap();

        let (num_leading_zeros, witness_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&witness);

        let mut w = E::G1::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            witness_coeffs.as_slice(),
        );
        let random_witness_coeffs =
            convert_to_bigints(&random_witness.unwrap().coeffs());
        w += &<E::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_gamma_g,
            random_witness_coeffs.as_slice(),
        );

        h += &(w.mul(gamma.pow(&[i])));

        i += 1;

        let committed_eval = powers.powers_of_g[0].mul(eval) + powers.powers_of_gamma_g[0].mul(blinding_eval);

        plain_evals.push((eval, blinding_eval));
        committed_evals.push(committed_eval.into_affine());
    }

    let open_evals: Vec<OpenEval<E>> = match perfect_hiding {
        true => committed_evals.into_iter().map(| eval | OpenEval::Committed(eval)).collect(),
        false => plain_evals.into_iter().map(| (eval, blind) | OpenEval::Plain(eval, blind)).collect(),
    };
    (h, open_evals, gamma)
}

// the batched KZG opening scheme in [GWC19]
pub fn batch_check<E: Pairing, R: RngCore>(
    vk: &VerifierKey<E>,
    cms: &Vec<Commitment<E>>,
    witnesses: &Vec<E::G1>,
    points: &Vec<E::ScalarField>,
    open_evals: &Vec<Vec<OpenEval<E>>>,
    gammas: &Vec<E::ScalarField>,
    is_committed_eval: bool,
    rng: &mut R,
) {
    assert!(&points.len() == &open_evals.len() && &points.len() == &witnesses.len() && &gammas.len() == &points.len());
    assert_eq!(&cms.len(), &open_evals[0].len());
    let mut left = E::G1::zero();
    let mut right = E::G1::zero();
    let mut i: usize = 0;
    let r = E::ScalarField::rand(rng);
    for (evals, gamma) in open_evals.into_iter().zip(gammas) {
        let mut j = 0u64;
        let mut sum_cm = E::G1::zero();
        let mut sum_committed_eval = E::G1::zero();
        let mut sum_value = E::ScalarField::zero();
        let mut sum_blinding = E::ScalarField::zero();
        for (cm, eval) in cms.into_iter().zip(evals) {
            let factor = gamma.pow(&[j]);
            sum_cm += cm.0.mul(factor);
            match eval {
                OpenEval::Plain(value, blinding) => {
                    sum_value += value.mul(factor);
                    sum_blinding += blinding.mul(factor);
                }
                OpenEval::Committed(committed_eval) => sum_committed_eval += committed_eval.mul(factor)
            };
            j += 1;
        }
        let sum_committed_eval = if is_committed_eval {
            sum_committed_eval
        } else {
            vk.g.mul(sum_value) + vk.gamma_g.mul(sum_blinding)
        };
        let factor = r.pow(&[i as u64]);
        left += (sum_cm - sum_committed_eval).mul(factor);
        let witness = witnesses[i];
        let point = points[i];
        let r_times_w = witness.mul(factor);
        left += r_times_w.mul(point);
        right += r_times_w;
        i += 1;
    }
    let lhs = E::pairing(left, vk.h);
    let rhs = E::pairing(right, vk.beta_h);
    assert_eq!(lhs, rhs);
}

pub fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: DenseUVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

pub fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();
    coeffs
}
