use ark_ec::{pairing::Pairing, AffineRepr};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_bls12_381::Bls12_381;
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, UniversalParams, VerifierKey, KZG10};
use ark_std::{rand::RngCore, test_rng, Zero};

use crate::{proof_of_liability::prover::intermediate::Intermediate, utils::{batch_open, calculate_hash, linear_combine_polys, HashBox, OpenEval}};

#[cfg(test)]
mod test_intermediate;

#[cfg(test)]
mod test_prover;

mod intermediate;

type BlsScalarField = <Bls12_381 as Pairing>::ScalarField;
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

#[derive(Clone)]
pub struct IntermediateProof {
    pub proof_at_tau: (<Bls12_381 as Pairing>::G1, Vec<OpenEval<Bls12_381>>, BlsScalarField),
    pub proof_at_tau_omega: (<Bls12_381 as Pairing>::G1, Vec<OpenEval<Bls12_381>>, BlsScalarField),
    pub cms: Vec<Commitment<Bls12_381>>,
    pub omega: BlsScalarField,
    pub domain: Radix2EvaluationDomain<BlsScalarField>,
    randoms: Vec<Randomness<BlsScalarField, UniPoly_381>>,
}

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

    pub fn construct_intermediate_node<R: RngCore>(
        &self,
        balances: &Vec<u64>,
        max_bits: usize,
        gamma: BlsScalarField,
        rng: &mut R,
    ) -> IntermediateProof {
        assert!(balances.len() <= self.group_size);
        let inter = Intermediate::<Bls12_381>::new(balances, max_bits).unwrap();
        let w1 = inter.compute_w1();
        let w2 = inter.compute_w2();
        let w3 = inter.compute_w3();
        let mut polys = Vec::<DensePolynomial<BlsScalarField>>::from([w1, w2, w3]);
        for idx in 1..inter.polys.len() - 1 {
            let v = inter.compute_v(idx);
            polys.push(v);
        }
        let w = linear_combine_polys::<Bls12_381>(&polys, gamma);
        let zed = DenseOrSparsePolynomial::from(inter.domain.vanishing_polynomial());
        let (q, r) = DenseOrSparsePolynomial::from(w).divide_with_q_and_r(&zed).unwrap();
        assert!(r.is_zero());

        let mut cms = Vec::<Commitment<Bls12_381>>::new();
        let mut randoms = Vec::<Randomness<BlsScalarField, UniPoly_381>>::new();
        let mut hash_boxes = Vec::<HashBox>::new();
        for p in &inter.polys {
            let (cm_p, random_p) = self.commit(&p, rng);
            cms.push(cm_p);
            randoms.push(random_p);
            hash_boxes.push(HashBox::Bls(cm_p.0.into_group()));
        }

        let (cm_q, random_q) = self.commit(&q, rng);
        cms.push(cm_q);
        randoms.push(random_q);
        hash_boxes.push(HashBox::Bls(cm_q.0.into_group()));

        let tau = BlsScalarField::from(calculate_hash(&hash_boxes));
        let omega = inter.domain.element(1);

        let (h_1, open_evals_1, gamma_1) = batch_open(&self.powers, &vec![inter.polys.as_slice(), vec![q].as_slice()].concat(), &randoms, tau, false, rng);
        let (h_2, open_evals_2, gamma_2) = batch_open(&self.powers, &vec![inter.polys.first().unwrap().clone()], &vec![randoms.first().unwrap().clone()], tau * omega, false, rng);

        IntermediateProof { 
            proof_at_tau: (h_1, open_evals_1, gamma_1), 
            proof_at_tau_omega: (h_2, open_evals_2, gamma_2), 
            cms: cms, 
            omega: omega,
            domain: inter.domain,
            randoms: randoms, 
        }
    }

    fn commit<R: RngCore>(
        &self,
        poly: &DensePolynomial<BlsScalarField>,
        rng: &mut R,
    ) -> (Commitment<Bls12_381>, Randomness<BlsScalarField, UniPoly_381>) {
        KZG10::<Bls12_381, UniPoly_381>::commit(&self.powers, &poly, Some(poly.degree()), Some(rng)).unwrap()
    }
}
