use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::Bls12_381;
use ark_poly_commit::kzg10::{Powers, UniversalParams, VerifierKey, KZG10};
use ark_std::test_rng;

#[cfg(test)]
mod test_intermediate;

#[cfg(test)]
mod test_prover;

pub mod intermediate;

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

pub struct Prover<'a> {
    pub vk: VerifierKey<Bls12_381>,
    pp: UniversalParams<Bls12_381>,
    powers: Powers<'a, Bls12_381>,
    group_size: usize,
}

impl Prover<'_> {
    pub fn setup(
        group_size: usize,
        max_degree: usize,
    ) -> Self {
        assert!(group_size < max_degree);
        let rng = &mut test_rng();
        let pp = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, true, rng).expect("KZG setup failed");
        let powers_of_g = pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[&0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };
        Self {
            vk,
            pp,
            powers,
            group_size,
        }
    }
}
