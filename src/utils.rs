use ark_ec::{pairing::Pairing, short_weierstrass::Projective, AffineRepr, VariableBaseMSM, CurveGroup};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial};
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

pub fn build_up_bits(value: u64, max_bits: usize) -> Vec<u64> {
    assert!(value <= u64::MAX);
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
    balances: &Vec<u64>,
    max_bits: usize,
) -> Vec<Vec<u64>> {
    let num_of_l = balances.len();
    let mut vec = Vec::<Vec<u64>>::with_capacity(max_bits);
    for _ in 0..max_bits {
        let mut v = Vec::<u64>::with_capacity(num_of_l);
        for _ in 0..num_of_l {
            v.push(0);
        }
        vec.push(v);
    }
    for i in 0..num_of_l {
        let bal = balances[i];
        let bits = build_up_bits(bal, max_bits);
        for j in 0..max_bits {
            vec[j][i] = bits[max_bits - j - 1];
        }
    }
    vec
}

pub fn compute_accumulative_vector<F: FftField>(
    vec: &[u64]
) -> Vec<F> {
    let vec: Vec<F> = vec.into_iter().map(| e | F::from(*e)).collect();
    let len = vec.len();
    let mut acc = Vec::<F>::with_capacity(len);
    for _ in 0..len { acc.push(F::zero()); }
    acc[len - 1] = vec[len - 1];
    for i in (0..len - 1).rev() {
        acc[i] = acc[i + 1] + vec[i];
    }
    acc
}

pub fn interpolate_poly<F: FftField, D: EvaluationDomain<F>,>(
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
    // let result = constrain_polys(&p.coeffs, &new_p.coeffs, scale, shift);
    // result.expect("Failed to satisfy transform constraints");
    new_p
}

// pub fn constrain_polys<
// F: PrimeField,
// >(
//     old_coeffs: &Vec<F>, 
//     new_coeffs: &Vec<F>, 
//     scale_factor: usize, 
//     shift_factor: usize,
// ) -> Result<()> {
//     let root_of_unity = F::get_root_of_unity(old_coeffs.len() as u64).expect("Cannot find root of unity");
//     let mut rng = test_rng();
//     let point = rng.gen_range(0..new_coeffs.len());
//     let circuit = PolyTransConstraints::<F> {
//         point,
//         root_of_unity,
//         scale_factor,
//         shift_factor,
//         old_coeffs: old_coeffs.to_vec(),
//         new_coeffs: new_coeffs.to_vec(),
//     };
//     let cs = ConstraintSystem::<F>::new_ref();
//     circuit.generate_constraints(cs)
// }

pub fn linear_combine_polys<E: Pairing>(
    polys: &Vec<DensePolynomial<E::ScalarField>>,
    gamma: E::ScalarField,
) -> DensePolynomial<E::ScalarField> {
    let mut w = DensePolynomial::<E::ScalarField>::zero();
    let mut factor = E::ScalarField::from(1u64);
    for idx in 0..polys.len() {
        let p = &polys[idx];
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec(vec![factor]);
        let tmp = &constant_term * p;
        w += &tmp;
        factor *= gamma;
    }
    w
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

#[derive(Clone)]
pub enum OpenEval<E: Pairing> {
    Plain(E::ScalarField, E::ScalarField),
    Committed(E::G1Affine),
}

impl<E> OpenEval<E> where E: Pairing {
    pub fn into_committed_value(&self) -> E::G1Affine {
        if let OpenEval::Committed(value) = self {
            *value
        } else {
            panic!("Not a committed value")
        }
    }

    pub fn into_plain_value(&self) -> (E::ScalarField, E::ScalarField) {
        if let OpenEval::Plain(value, r) = self {
            (*value, *r)
        } else {
            panic!("Not a plain value")
        }
    } 
}

// the batched KZG opening scheme in [GWC19]
#[inline]
pub fn batch_open<E: Pairing, R: RngCore>(
    powers: &Powers<E>,
    polys: &Vec<&DensePolynomial<E::ScalarField>>,
    randoms: &Vec<&Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>,
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

pub struct BatchCheckProof<E: Pairing> {
    pub commitments: Vec<Vec<Commitment<E>>>,
    pub witnesses: Vec<E::G1>,
    pub points: Vec<E::ScalarField>,
    pub open_evals: Vec<Vec<OpenEval<E>>>,
    pub gammas: Vec<E::ScalarField>,
}

// the batched KZG opening scheme in [GWC19]
pub fn batch_check<E: Pairing, R: RngCore>(
    vk: &VerifierKey<E>,
    proof: &BatchCheckProof<E>,
    rng: &mut R,
) {
    let BatchCheckProof { commitments, witnesses, points, open_evals, gammas } = proof;
    assert!(&points.len() == &open_evals.len() && &points.len() == &witnesses.len() && &gammas.len() == &points.len());
    let mut left = E::G1::zero();
    let mut right = E::G1::zero();
    let mut i: usize = 0;
    let r = E::ScalarField::rand(rng);
    for gamma in gammas {
        let cms = &commitments[i];
        let evals = &open_evals[i];
        assert_eq!(&cms.len(), &evals.len());
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
        sum_committed_eval += vk.g.mul(sum_value) + vk.gamma_g.mul(sum_blinding);
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

#[inline]
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

#[inline]
pub fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();
    coeffs
}

pub fn convert_to_zk_polynomial<F: PrimeField, D: EvaluationDomain<F>, R: RngCore>(
    p: &DensePolynomial<F>,
    domain: D,
    number_of_points: usize,
    rng: &mut R,
) -> (DensePolynomial<F>, Vec<(F, F)>) {
    let points: Vec<(F, F)> = (0..number_of_points).into_iter().map(| _ | {
        let point = domain.sample_element_outside_domain(rng);
        let eval = F::rand(rng);
        (point, eval)
    })
    .collect();

    let new_p = incremental_interpolate(&p, domain, &points);
    (new_p, points)
}

pub fn incremental_interpolate<F: FftField, D: EvaluationDomain<F>>(
    p: &DensePolynomial<F>, 
    domain: D, 
    points: &Vec<(F, F)>, 
) -> DensePolynomial<F> {
    let evaluations = p.clone().evaluate_over_domain(domain);
    let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());

    let mut new_p = p.clone();

    let mut eval_points = Vec::<(F, F)>::new();
    
    for (p_x, p_y) in points {
        let mut divisor = F::one();
        for i in 0..evaluations.evals.len() {
            let x = domain.element(i);
            let point_minus_x = *p_x - x;
            divisor *= point_minus_x;
        }

        let mut x_minus_extra_point = DensePolynomial::<F>::from_coefficients_vec(vec![F::one()]);
        for (prev_point, _) in eval_points.clone() {
            let point_minus_prv = *p_x - prev_point;
            divisor *= point_minus_prv;
            let x_minus_prev = DensePolynomial::<F>::from_coefficients_vec(vec![-prev_point, F::one()]);
            x_minus_extra_point = &x_minus_extra_point * &x_minus_prev;
        }

        let divisor_poly = DenseOrSparsePolynomial::from(DensePolynomial::from_coefficients_vec(vec![divisor]));
        let (q, r) = zed.divide_with_q_and_r(&divisor_poly).unwrap();
        assert!(r.is_zero());
        let q = &q * &x_minus_extra_point;

        let eval_minus_p = *p_y - new_p.evaluate(&p_x);
        let m = &q * &DensePolynomial::from_coefficients_vec(vec![eval_minus_p]);
        new_p = &new_p + &m;
        eval_points.push((*p_x, *p_y));
    }

    for (x, y) in points {
        assert_eq!(*y, new_p.evaluate(&x));
    }

    new_p
}
