use ark_bls12_381::{Fr, FrConfig};
use ark_poly::Polynomial;
use ark_ff::{FftField, Field, MontBackend, Zero};
use ark_std::{rand::Rng, test_rng};

use super::intermediate::Intermediate;

#[cfg(test)]
impl Intermediate<MontBackend<FrConfig, 4>, 4> {
    pub fn random() -> Intermediate<MontBackend<FrConfig, 4>, 4> {
        const MAX_BITS: usize = 16;
        let rng = &mut test_rng();
        let mut liabs = Vec::<u64>::new();
        for _ in 0..8 {
            let rand = rng.gen_range(0..100);
            liabs.push(rand);
        }
        let liab: Vec<u64> = liabs;
        Intermediate::new(&liab, MAX_BITS).unwrap()
    }
}

#[test]
fn test_compute_w1() {
    let inter = Intermediate::random();
    let w1 = inter.compute_w1();
    let omega = Fr::get_root_of_unity(inter.domain.size).unwrap();
    for idx in 0..inter.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w1.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w2() {
    let inter = Intermediate::random();
    let w2 = inter.compute_w2();
    let omega = Fr::get_root_of_unity(inter.domain.size).unwrap();
    for idx in 0..inter.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w2.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w3() {
    let inter = Intermediate::random();
    let w3 = inter.compute_w3();
    let omega = Fr::get_root_of_unity(inter.domain.size).unwrap();
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
        let v = inter.compute_v(idx);
        let omega = Fr::get_root_of_unity(inter.domain.size).unwrap();
        for idx in 0..inter.domain.size {
            let point = omega.pow(&[idx as u64]);
            let eval = v.evaluate(&point);
            assert!(eval.is_zero());
        }
    }
}
