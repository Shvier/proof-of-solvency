use ark_bls12_381::Bls12_381;
use ark_ff::{FftField, Field};
use ark_poly::Polynomial;
use ark_std::{rand::Rng, test_rng, UniformRand, Zero};

use super::intermediate::Intermediate;

use crate::types::BlsScalarField;

#[cfg(test)]
impl Intermediate<Bls12_381> {
    pub fn random() -> Intermediate<Bls12_381> {
        const MAX_BITS: usize = 16;
        let rng = &mut test_rng();
        let mut liabs = Vec::<u64>::new();
        for _ in 0..8 {
            let rand = rng.gen_range(0..100);
            liabs.push(rand);
        }
        let liab: Vec<u64> = liabs;
        let gamma = BlsScalarField::rand(rng);
        Intermediate::new(&liab, MAX_BITS, gamma, rng)
    }
}

#[test]
fn test_compute_w1() {
    let inter = Intermediate::random();
    let w1 = Intermediate::<Bls12_381>::compute_w1(&inter.polys, inter.domain, &inter.p0_extra_points);
    let omega = BlsScalarField::get_root_of_unity(inter.domain.size).unwrap();
    for idx in 0..inter.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w1.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w2() {
    let inter = Intermediate::random();
    let w2 = Intermediate::<Bls12_381>::compute_w2(&inter.polys, inter.domain);
    let omega = BlsScalarField::get_root_of_unity(inter.domain.size).unwrap();
    for idx in 0..inter.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w2.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w3() {
    let inter = Intermediate::random();
    let w3 = Intermediate::<Bls12_381>::compute_w3(&inter.polys);
    let omega = BlsScalarField::get_root_of_unity(inter.domain.size).unwrap();
    for idx in 0..inter.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w3.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_v() {
    let inter = Intermediate::random();
    for idx in 1..inter.polys.len() - 1 {
        let v = Intermediate::<Bls12_381>::compute_v(&inter.polys, idx);
        let omega = BlsScalarField::get_root_of_unity(inter.domain.size).unwrap();
        for idx in 0..inter.domain.size {
            let point = omega.pow(&[idx as u64]);
            let eval = v.evaluate(&point);
            assert!(eval.is_zero());
        }
    }
}
