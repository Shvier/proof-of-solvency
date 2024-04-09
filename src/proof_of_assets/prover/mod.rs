use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, FftField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain, Polynomial, DenseUVPolynomial};
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, UniversalParams, VerifierKey, KZG10};
use ark_std::test_rng;

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;
type UniPoly_381 = DensePolynomial<BlsScalarField>;

#[cfg(test)]
mod test_prover;

pub struct PolyCommitProof {
    witness: <Bls12_381 as Pairing>::G1Affine,
    rand: BlsScalarField,
}

pub struct Prover {
    pp: UniversalParams<Bls12_381>,
    degree: usize,
    domain_size: usize,
    pub omega: BlsScalarField,
    vk: VerifierKey<Bls12_381>,
    poly: DensePolynomial<<Bls12_381 as Pairing>::ScalarField>,
}

impl Prover {
    pub fn setup(selector: &Vec<u8>) -> Self {
        let degree = selector.len();
        let domain_size = degree.checked_next_power_of_two().expect("Unsupported domain size");
        let omega = BlsScalarField::get_root_of_unity(domain_size.try_into().unwrap()).unwrap();
        let domain = Radix2EvaluationDomain::<BlsScalarField>::new(domain_size).unwrap();
        let evals = selector.into_iter().map(| s | Fr::from(*s)).collect();
        let evaluations = Evaluations::from_vec_and_domain(evals, domain);
        let poly = evaluations.interpolate();
        let rng = &mut test_rng();
        let pp = KZG10::<Bls12_381, UniPoly_381>::setup(domain_size, false, rng).unwrap();
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[&0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };
        Self {
            pp,
            degree,
            domain_size,
            omega,
            vk,
            poly,
        }
    }

    pub fn commit(&self) -> (Commitment<Bls12_381>, Randomness<BlsScalarField, UniPoly_381>) {
        let max_degree = self.domain_size;
        let powers_of_g = self.pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| self.pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        let rng = &mut test_rng();
        KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &self.poly, Some(self.degree), Some(rng)).unwrap()
    }

    pub fn open(&self, point: BlsScalarField, randomness: &Randomness<BlsScalarField, UniPoly_381>) -> PolyCommitProof {
        let max_degree = self.domain_size;
        let powers_of_g = self.pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| self.pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        let (witness_polynomial, random) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(&self.poly, point, randomness).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);

        let mut w = <Bls12_381 as Pairing>::G1::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );

        let blinding_p = &randomness.blinding_polynomial;
        let blinding_evaluation = blinding_p.evaluate(&point);

        let random_witness_coeffs = convert_to_bigints(&random.unwrap().coeffs());
        w += &<<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_gamma_g,
            &random_witness_coeffs,
        );

        PolyCommitProof {
            witness: w.into_affine(),
            rand: blinding_evaluation,
        }
    }
}

fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: DenseUVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();
    coeffs
}
