use ark_bls12_381::{Fr, FrConfig};
use ark_ff::{MontBackend, FftField, Field, Zero};
use ark_poly::Polynomial;

use super::{intermediate::Intermediate, root::Root};

#[cfg(test)]
impl Root<MontBackend<FrConfig, 4>, 4> {
    pub fn random() -> Root<MontBackend<FrConfig, 4>, 4> {
        let mut interns = Vec::<Intermediate<MontBackend<FrConfig, 4>, 4>>::new();
        for _ in 0..8 {
            let intern = Intermediate::random();
            interns.push(intern);
        }
        Root::<MontBackend<FrConfig, 4>, 4>::new(interns).unwrap()
    }
}

#[test]
fn test_compute_w1() {
    let root = Root::random();
    let w1 = root.compute_w1();
    let omega = Fr::get_root_of_unity(root.domain.size).unwrap();
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
    let omega = Fr::get_root_of_unity(root.domain.size).unwrap();
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
    let omega = Fr::get_root_of_unity(root.domain.size).unwrap();
    for v in vs {
        for idx in 0..root.domain.size {
            let point = omega.pow(&[idx as u64]);
            let eval = v.evaluate(&point);
            assert!(eval.is_zero());
        }
    }
}
