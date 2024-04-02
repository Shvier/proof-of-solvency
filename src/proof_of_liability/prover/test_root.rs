use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, Zero};
use ark_poly::Polynomial;

use super::{intermediate::Intermediate, root::Root};

type BLSScalarField = <Bls12_381 as Pairing>::ScalarField;

#[cfg(test)]
impl Root<Bls12_381> {
    pub fn random() -> Root<Bls12_381> {
        let mut interns = Vec::<Intermediate<Bls12_381>>::new();
        for _ in 0..8 {
            let intern = Intermediate::random();
            interns.push(intern);
        }
        Root::<Bls12_381>::new(interns).unwrap()
    }
}

#[test]
fn test_compute_w1() {
    let root = Root::random();
    let w1 = root.compute_w1();
    let omega = BLSScalarField::get_root_of_unity(root.domain.size).unwrap();
    for idx in 0..root.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w1.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_w2() {
    let root = Root::random();
    let w2 = root.compute_w2();
    let omega = BLSScalarField::get_root_of_unity(root.domain.size).unwrap();
    for idx in 0..root.domain.size {
        let point = omega.pow(&[idx as u64]);
        let eval = w2.evaluate(&point);
        assert!(eval.is_zero());
    }
}

#[test]
fn test_compute_vs() {
    let root = Root::random();
    let vs = root.compute_vs();
    let omega = BLSScalarField::get_root_of_unity(root.domain.size).unwrap();
    for v in vs {
        for idx in 0..root.domain.size {
            let point = omega.pow(&[idx as u64]);
            let eval = v.evaluate(&point);
            assert!(eval.is_zero());
        }
    }
}
