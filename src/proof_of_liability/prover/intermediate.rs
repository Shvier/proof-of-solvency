use std::{
    mem::size_of,
    sync::{Arc, Mutex},
};

use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain,
};
use ark_poly_commit::kzg10::{Commitment, Powers, Randomness, KZG10};
use ark_std::{rand::RngCore, test_rng, One, Zero};

use crate::utils::{
    batch_open, build_bit_vector, compute_accumulative_vector, convert_to_zk_polynomial,
    incremental_interpolate, interpolate_poly, linear_combine_polys, OpenEval,
};

#[derive(Clone)]
pub struct IntermediateProof<E: Pairing> {
    pub proof_at_tau: (E::G1, Vec<OpenEval<E>>, E::ScalarField),
    pub proof_at_tau_omega: (E::G1, Vec<OpenEval<E>>, E::ScalarField),
    pub cms: Vec<Commitment<E>>,
    pub omega: E::ScalarField,
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
    // randoms: Vec<Randomness<E::ScalarField, P>>,
}

impl<E: Pairing> IntermediateProof<E> {
    pub fn deep_size(&self) -> usize {
        size_of::<E::G1>() * 2
            + size_of::<OpenEval<E>>()
                * (self.proof_at_tau.1.len() + self.proof_at_tau_omega.1.len())
            + size_of::<E::ScalarField>() * 3
            + size_of::<Commitment<E>>() * self.cms.len()
            + size_of::<Radix2EvaluationDomain<E::ScalarField>>()
    }
}

#[derive(Clone)]
pub struct Intermediate<E: Pairing> {
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
    pub p0_extra_points: Vec<(E::ScalarField, E::ScalarField)>,
    pub(super) polys: Vec<DensePolynomial<E::ScalarField>>,
    pub(super) q_w: DensePolynomial<E::ScalarField>,
}

impl<E: Pairing> Intermediate<E> {
    pub fn new<R: RngCore>(
        balances: &Vec<u64>,
        max_bits: usize,
        gamma: E::ScalarField,
        rng: &mut R,
    ) -> Self {
        let bit_vec = build_bit_vector(balances, max_bits);
        let accumulator = compute_accumulative_vector::<E::ScalarField>(&balances);

        let domain_size = balances.len().checked_next_power_of_two().unwrap();
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size)
            .expect("Unsupported domain length");

        let mut polys = Vec::<DensePolynomial<E::ScalarField>>::new();

        let evaluations = Evaluations::from_vec_and_domain(accumulator, domain);
        let p0 = evaluations.interpolate();
        let (p0, extra_points) = convert_to_zk_polynomial(&p0, domain, 2, rng);
        polys.push(p0);
        for vec in bit_vec {
            let p = interpolate_poly(&vec, domain);
            let (p, _) = convert_to_zk_polynomial(&p, domain, 1, rng);
            polys.push(p);
        }

        let w1 = Self::compute_w1(&polys, domain, &extra_points);
        let w2 = Self::compute_w2(&polys, domain);
        let w3 = Self::compute_w3(&polys);
        let mut combined_polys = Vec::<DensePolynomial<E::ScalarField>>::from([w1, w2, w3]);
        for idx in 1..polys.len() - 1 {
            let v = Self::compute_v(&polys, idx);
            combined_polys.push(v);
        }
        let w = linear_combine_polys::<E>(&combined_polys, gamma);
        let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());
        let (q_w, r) = DenseOrSparsePolynomial::from(w)
            .divide_with_q_and_r(&zed)
            .unwrap();
        assert!(r.is_zero());

        Self {
            domain,
            polys,
            q_w,
            p0_extra_points: extra_points,
        }
    }

    pub(super) fn compute_w1(
        polys: &Vec<DensePolynomial<E::ScalarField>>,
        domain: Radix2EvaluationDomain<E::ScalarField>,
        extra_points: &Vec<(E::ScalarField, E::ScalarField)>,
    ) -> DensePolynomial<E::ScalarField> {
        let domain_size = domain.size;
        let omega =
            E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");

        let p0 = &polys[0];
        let mut p0_evals = p0.clone().evaluate_over_domain(domain).evals;
        p0_evals.rotate_left(1);
        let p0_plus_1 = Evaluations::from_vec_and_domain(p0_evals, domain).interpolate();

        let points = extra_points
            .into_iter()
            .map(|(x, y)| (*x / omega, *y))
            .collect();
        let p0_plus_1 = incremental_interpolate(&p0_plus_1, domain, &points);
        let p1 = &polys[1];
        let x_minus_last_omega = DensePolynomial::<E::ScalarField>::from_coefficients_vec(
            [-omega.pow(&[domain_size - 1]), E::ScalarField::one()].to_vec(),
        );
        let mut w1 = p0 - &p0_plus_1;
        w1 = &w1 - p1;
        w1 = &w1 * &x_minus_last_omega;
        w1
    }

    pub(super) fn compute_w2(
        polys: &Vec<DensePolynomial<E::ScalarField>>,
        domain: Radix2EvaluationDomain<E::ScalarField>,
    ) -> DensePolynomial<E::ScalarField> {
        let p0 = &polys[0];
        let p1 = &polys[1];
        let mut w2 = p0 - p1;
        let domain_size = domain.size;
        let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());
        let omega =
            E::ScalarField::get_root_of_unity(domain_size).expect("Unsupported domain size");
        let x_minus_last_omega = DensePolynomial::<E::ScalarField>::from_coefficients_vec(
            [-omega.pow(&[domain_size - 1]), E::ScalarField::one()].to_vec(),
        );
        let (q, r) = zed.divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_last_omega)).unwrap();
        assert!(r.is_zero());
        w2 = &w2 * &q;
        w2
    }

    pub(super) fn compute_w3(
        polys: &Vec<DensePolynomial<E::ScalarField>>,
    ) -> DensePolynomial<E::ScalarField> {
        let len = polys.len();
        let pm = &polys[len - 1];
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec(
            [E::ScalarField::one()].to_vec(),
        );
        let mut w3 = pm - &constant_term;
        w3 = &w3 * pm;
        w3
    }

    pub(super) fn compute_v(
        polys: &Vec<DensePolynomial<E::ScalarField>>,
        idx: usize,
    ) -> DensePolynomial<E::ScalarField> {
        assert!(idx > 0 && idx < polys.len() - 1);
        let cur = &polys[idx];
        let next = &polys[idx + 1];
        let next_double = next + next;
        let zero_term = cur - &next_double;
        let constant_term = DensePolynomial::<E::ScalarField>::from_coefficients_vec(
            [E::ScalarField::one()].to_vec(),
        );
        let one_term = &constant_term - &zero_term;
        let v = &zero_term * &one_term;
        v
    }

    fn commit<R: RngCore>(
        &self,
        powers: &Powers<E>,
        poly: &DensePolynomial<E::ScalarField>,
        rng: &mut R,
    ) -> (
        Commitment<E>,
        Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>,
    ) {
        KZG10::<E, DensePolynomial<E::ScalarField>>::commit(
            &powers,
            &poly,
            Some(poly.degree()),
            Some(rng),
        )
        .unwrap()
    }

    pub fn compute_commitments<R: RngCore>(
        &self,
        powers: &Powers<E>,
        rng: &mut R,
    ) -> (
        Vec<Commitment<E>>,
        Vec<Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>,
    ) {
        let mut cms = Vec::<Commitment<E>>::new();
        let mut randoms = Vec::<Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>::new();
        for p in &self.polys {
            let (cm_p, random_p) = self.commit(&powers, &p, rng);
            cms.push(cm_p);
            randoms.push(random_p);
        }

        let (cm_q, random_q) = self.commit(&powers, &self.q_w, rng);
        cms.push(cm_q);
        randoms.push(random_q);
        (cms, randoms)
    }

    pub fn concurrent_compute_commitments<'a>(
        polys: &Vec<DensePolynomial<E::ScalarField>>,
        q_w: &DensePolynomial<E::ScalarField>,
        powers: Arc<&'a Mutex<Powers<'a, E>>>,
    ) -> Vec<(
        Commitment<E>,
        Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>,
    )> {
        let rng = &mut test_rng();

        let mut commitments = Vec::<(Commitment<E>,
        Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>)>::new();

        for p in polys.as_slice() {
            let powers = powers.clone();
            let powers = powers.lock().unwrap();
            let (cm_p, random_p) = KZG10::<E, DensePolynomial<E::ScalarField>>::commit(
                &powers,
                &p,
                Some(p.degree()),
                Some(rng),
            )
            .unwrap();
            commitments.push((cm_p, random_p));
        }

        let powers = powers.lock().unwrap();
        let (cm_q, random_q) = KZG10::<E, DensePolynomial<E::ScalarField>>::commit(
            &powers,
            &q_w,
            Some(q_w.degree()),
            Some(rng),
        )
        .unwrap();
        commitments.push((cm_q, random_q));
        commitments
    }

    #[inline]
    pub fn generate_proof<R: RngCore>(
        &self,
        powers: &Powers<E>,
        cms: &Vec<Commitment<E>>,
        randoms: &Vec<&Randomness<E::ScalarField, DensePolynomial<E::ScalarField>>>,
        tau: E::ScalarField,
        rng: &mut R,
    ) -> IntermediateProof<E> {
        let omega = self.domain.element(1);
        let polys: Vec<_> = self.polys.iter().chain(vec![&self.q_w]).collect();
        let (h_1, open_evals_1, gamma_1) = batch_open(
            &powers,
            &polys,
            &randoms,
            tau,
            false,
            rng,
        );
        let (h_2, open_evals_2, gamma_2) = batch_open(
            &powers,
            &vec![&self.polys.first().unwrap()],
            &vec![&randoms.first().unwrap()],
            tau * omega,
            false,
            rng,
        );

        IntermediateProof {
            proof_at_tau: (h_1, open_evals_1, gamma_1),
            proof_at_tau_omega: (h_2, open_evals_2, gamma_2),
            cms: cms.to_vec(),
            omega: omega,
            domain: self.domain,
            // randoms: randoms.to_vec(),
        }
    }
}
